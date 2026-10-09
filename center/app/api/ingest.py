"""Ingest API — приём телеметрии от агентов (FR-C3).

Эндпоинты намеренно выглядят как обычные веб-ресурсы (MASK-2): путь задаётся
в профиле (cover_path), nginx проксирует его в центр, а снаружи это выглядит
как загрузка «аналитики» на CDN. Аутентификация агента: HMAC подпись beacon'а
секретом ловушки + ключ коллектора (X-HF-Key выдаёт только nginx/realtime-слой).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.db import Honeypot
from app.schemas.api import BeaconOut
from app.services import core_services as svc

router = APIRouter(tags=["ingest"])


def _verify_agent(db: Session, body: dict, sig: str | None, ts: str | None) -> None:
    """Проверка подписи beacon'а: HMAC(secret, timestamp + body)."""
    h = db.query(Honeypot).filter(Honeypot.uuid == body.get("uuid", "")).first()
    if not h:
        raise HTTPException(404, "unknown node")
    if not sig or not ts:
        raise HTTPException(401, "missing signature")
    try:
        t = float(ts)
    except ValueError:
        raise HTTPException(401, "bad timestamp")
    if abs(time.time() - t) > 300:  # защита от replay
        raise HTTPException(401, "stale timestamp")
    raw = ts.encode() + b"." + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    expect = hmac.new(h.agent_secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        raise HTTPException(401, "bad signature")


@router.post("/collect/beacon")
async def beacon(
    request: Request,
    db: Session = Depends(get_db),
    x_hf_key: str | None = Header(None, alias="X-HF-Key"),
    x_sig: str | None = Header(None, alias="X-Sig"),
    x_ts: str | None = Header(None, alias="X-Ts"),
):
    # Коллектор принимает телеметрию только через свой контур (realtime-слой/nginx),
    # а не напрямую из сегмента приманки (MASK-3).
    if x_hf_key != settings.AGGREGATOR_KEY:
        raise HTTPException(403, "forbidden channel")

    raw = await request.body()
    # MASK-1/MASK-2: тело beacon'а запечатано (XOR-keystream от agent_secret+ts, base64),
    # поэтому даже внутри TLS содержимое не читается как JSON и не имеет сигнатуры API.
    # Envelope: {"u": "<node uuid>", "d": "<base64 sealed body>"} — uuid в открытом виде
    # нужен только для выбора ключа; сами события/креды видны лишь центру.
    try:
        env = json.loads(raw)
        node = str(env["u"])
        body = _unopen(str(env["d"]), _secret_of(db, node), x_ts or "")
    except KeyError:
        raise HTTPException(400, "malformed envelope")
    except Exception:
        raise HTTPException(400, "malformed payload")

    _verify_agent(db, body, x_sig, x_ts)
    result = svc.ingest_beacon(db, body)
    if not result.get("ok"):
        raise HTTPException(404, "unknown trap")
    # Агент подтвердил применение конфига версией в следующем beacon'e;
    # если прислал applied_profile_version — фиксируем.
    if body.get("applied_profile_version"):
        svc.finalize_applied_version(db, node, int(body["applied_profile_version"]))
    resp = BeaconOut(
        ok=True,
        config_version=result["config_version"],
        config_hash=result.get("config_hash", ""),
        profile=result["profile"],
        commands=result["commands"],
        next_beacon_delay_sec=result["next_beacon_delay_sec"],
    )
    # Ответ агенту тоже печатаем, чтобы нарушитель, сниффирующий трафик ловушки,
    # не увидел ни профиля, ни команд (MASK-1/MASK-4).
    secret = _secret_of(db, node)
    out_body = json.dumps({"d": _openseal(resp.model_dump_json().encode(), secret, x_ts or "")})
    return Response(out_body, media_type="application/octet-stream")


def _stream_key(secret: str, ts: str) -> bytes:
    return hashlib.sha256(f"{secret}|{ts}".encode()).digest()


def _unopen(sealed_b64: str, secret: str, ts: str) -> dict:
    kb = _stream_key(secret, ts)
    data = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(base64.b64decode(sealed_b64)))
    return json.loads(data)


def _openseal(data: bytes, secret: str, ts: str) -> str:
    kb = _stream_key(secret, ts)
    return base64.b64encode(bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))).decode()


def _secret_of(db: Session, node: str) -> str:
    hp = db.query(Honeypot).filter(Honeypot.uuid == node).first()
    if not hp:
        raise HTTPException(404, "unknown node")
    return hp.agent_secret


@router.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    """Стандартный health endpoint для балансировщика (не раскрывает суть системы)."""
    n = db.query(Honeypot).count()
    return {"status": "ok", "nodes": n}
