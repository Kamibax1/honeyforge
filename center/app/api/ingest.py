"""Ingest API — приём телеметрии от агентов (FR-C3).

Эндпоинты намеренно выглядят как обычные веб-ресурсы (MASK-2): путь задаётся
в профиле (cover_path), nginx проксирует его в центр, а снаружи это выглядит
как загрузка «аналитики» на CDN. Аутентификация агента: HMAC подпись beacon'а
секретом ловушки + ключ коллектора (X-HF-Key выдаёт только nginx/realtime-слой).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.db import Honeypot
from app.schemas.api import BeaconIn, BeaconOut
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


@router.post("/collect/beacon", response_model=BeaconOut)
async def beacon(
    request: Request,
    db: Session = Depends(get_db),
    x_sig: str | None = Header(None, alias="X-Sig"),
    x_ts: str | None = Header(None, alias="X-Ts"),
):
    body = await request.json()
    _verify_agent(db, body, x_sig, x_ts)
    result = svc.ingest_beacon(db, body)
    if not result.get("ok"):
        raise HTTPException(404, "unknown trap")
    # Агент подтвердил применение конфига версией в следующем beacon'e;
    # если прислал applied_profile_version — фиксируем.
    if body.get("applied_profile_version"):
        svc.finalize_applied_version(db, body["uuid"], int(body["applied_profile_version"]))
    return BeaconOut(
        ok=True,
        config_version=result["config_version"],
        profile=result["profile"],
        commands=result["commands"],
        next_beacon_delay_sec=result["next_beacon_delay_sec"],
    )


@router.get("/healthz")
def healthz(db: Session = Depends(get_db)):
    """Стандартный health endpoint для балансировщика (не раскрывает суть системы)."""
    n = db.query(Honeypot).count()
    return {"status": "ok", "nodes": n}
