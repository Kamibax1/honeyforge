"""Сервисы центра: профили, ловушки, приём телеметрии, алерты, аудит, экспорт IoC."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets
import uuid as uuidlib
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import (
    Alert, AttackEvent, AuditLog, Honeypot, HoneyToken, Operator, Session as TrapSession,
    TrapProfile, Artifact,
)


# ---------------- Аудит ----------------
def audit(db: Session, actor: str, action: str, obj: str = "", meta: dict | None = None) -> None:
    db.add(AuditLog(actor=actor, action=action, object_ref=obj,
                    meta=json.dumps(meta or {}, ensure_ascii=False)))


# ---------------- Профили ----------------
def _profile_to_dict(p: TrapProfile) -> dict[str, Any]:
    """Конфиг для агента: без «маркеров» honeypot в ключах (MASK-4)."""
    return {
        "version": p.version,
        "level": p.level,
        "services": json.loads(p.services_json),
        "creds": json.loads(p.credentials_json),
        "masking": json.loads(p.masking_json),
        "logging": json.loads(p.logging_json),
        "tokens": json.loads(p.honeytokens_json),
    }


def create_profile(db: Session, data: dict, actor: str) -> TrapProfile:
    p = TrapProfile(
        name=data["name"], description=data.get("description", ""), level=data["level"],
        services_json=json.dumps(data.get("services", []), ensure_ascii=False),
        credentials_json=json.dumps(data.get("credentials", []), ensure_ascii=False),
        logging_json=json.dumps(data.get("logging", {}), ensure_ascii=False),
        masking_json=json.dumps(data.get("masking", {}), ensure_ascii=False),
        honeytokens_json=json.dumps(data.get("honeytokens", []), ensure_ascii=False),
    )
    db.add(p); db.flush()
    for t in data.get("honeytokens", []):
        val = str(t.get("value", ""))
        db.add(HoneyToken(
            token_uid=t.get("uid") or str(uuidlib.uuid4()),
            profile_id=p.id, kind=t.get("kind", "cred"), label=t.get("label", ""),
            value_digest=hashlib.sha256(val.encode()).hexdigest(),
        ))
    audit(db, actor, "profile.create", p.name)
    db.commit(); db.refresh(p)
    return p


def update_profile(db: Session, pid: int, data: dict, actor: str) -> Optional[TrapProfile]:
    p = db.get(TrapProfile, pid)
    if not p:
        return None
    p.name = data.get("name", p.name)
    p.description = data.get("description", p.description)
    p.level = data.get("level", p.level)
    if "services" in data:
        p.services_json = json.dumps(data["services"], ensure_ascii=False)
    if "credentials" in data:
        p.credentials_json = json.dumps(data["credentials"], ensure_ascii=False)
    if "logging" in data:
        p.logging_json = json.dumps(data["logging"], ensure_ascii=False)
    if "masking" in data:
        p.masking_json = json.dumps(data["masking"], ensure_ascii=False)
    if "honeytokens" in data:
        p.honeytokens_json = json.dumps(data["honeytokens"], ensure_ascii=False)
        existing = {t.value_digest for t in db.query(HoneyToken).filter_by(profile_id=p.id)}
        for t in data["honeytokens"]:
            d = hashlib.sha256(str(t.get("value", "")).encode()).hexdigest()
            if d not in existing:
                db.add(HoneyToken(token_uid=t.get("uid") or str(uuidlib.uuid4()),
                                  profile_id=p.id, kind=t.get("kind", "cred"),
                                  label=t.get("label", ""), value_digest=d))
    p.version += 1  # агенты получат новый конфиг по beacon
    audit(db, actor, "profile.update", f"{p.name}@v{p.version}")
    db.commit(); db.refresh(p)
    return p


def delete_profile(db: Session, pid: int, actor: str) -> bool:
    p = db.get(TrapProfile, pid)
    if not p:
        return False
    bound = db.query(Honeypot).filter(Honeypot.profile_id == pid).count()
    if bound:
        raise ValueError(f"Профиль привязан к {bound} ловушкам — сначала отвязать")
    db.query(HoneyToken).filter(HoneyToken.profile_id == pid).delete()
    db.delete(p)
    audit(db, actor, "profile.delete", p.name)
    db.commit()
    return True


# ---------------- Ловушки ----------------
def register_honeypot(db: Session, name: str, host_addr: str, mgmt_iface: str,
                      profile_id: Optional[int], actor: str) -> Honeypot:
    h = Honeypot(
        uuid=str(uuidlib.uuid4()), name=name, host_addr=host_addr,
        mgmt_iface=mgmt_iface or "mgmt0",
        agent_secret=secrets.token_hex(16),
        profile_id=profile_id, status="pending",
    )
    db.add(h)
    audit(db, actor, "honeypot.register", name, {"uuid": h.uuid})
    db.commit(); db.refresh(h)
    return h


def patch_honeypot(db: Session, hid: int, fields: dict, actor: str) -> Optional[Honeypot]:
    h = db.get(Honeypot, hid)
    if not h:
        return None
    if fields.get("profile_id") is not None:
        if not db.get(TrapProfile, fields["profile_id"]):
            raise ValueError("Профиль не найден")
        h.profile_id = fields["profile_id"]
    if "desired_state" in fields and fields["desired_state"]:
        h.desired_state = fields["desired_state"]
    if fields.get("name"):
        h.name = fields["name"]
    if fields.get("host_addr") is not None and fields["host_addr"] != "":
        h.host_addr = fields["host_addr"]
    audit(db, actor, "honeypot.update", h.name, fields)
    db.commit(); db.refresh(h)
    return h


def rotate_agent_secret(db: Session, hid: int, actor: str) -> Optional[str]:
    h = db.get(Honeypot, hid)
    if not h:
        return None
    h.agent_secret = secrets.token_hex(16)
    audit(db, actor, "honeypot.rotate_secret", h.name)
    db.commit()
    return h.agent_secret


def mark_stale_offline(db: Session) -> int:
    """Периодическая проверка last_seen → offline (FR-C2 статусы)."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=settings.HONEYPOT_OFFLINE_AFTER)
    q = db.query(Honeypot).filter(Honeypot.status == "online")
    n = 0
    for h in q:
        ls = h.last_seen
        if ls is None:
            continue
        if ls.tzinfo is None:
            ls = ls.replace(tzinfo=dt.timezone.utc)
        if ls < cutoff:
            h.status = "offline"; n += 1
    if n:
        db.commit()
    return n


# ---------------- Приём телеметрии (коллектор) ----------------
def ingest_beacon(db: Session, payload: dict) -> dict:
    """Обработка beacon'а от агента: досылка событий, обновление статуса, выдача конфига.

    Идемпотентно по event_uid — повторная досылка из локального буфера не создаёт дублей.
    """
    h = db.query(Honeypot).filter(Honeypot.uuid == payload["uuid"]).first()
    if not h:
        return {"ok": False, "error": "unknown_trap"}

    now = dt.datetime.now(dt.timezone.utc)
    h.last_seen = now
    h.status = "online"

    inserted = 0
    trig_tokens: list[str] = []
    for ev in payload.get("events", []):
        uid = ev.get("event_uid") or str(uuidlib.uuid4())
        exists = db.query(AttackEvent).filter(AttackEvent.event_uid == uid).first()
        if exists:
            continue
        e = AttackEvent(
            event_uid=uid, honeypot_id=h.id,
            ts_client=ev.get("ts_client"), etype=ev["etype"], proto=ev.get("proto", "tcp"),
            src_ip=ev.get("src_ip", ""), src_port=ev.get("src_port"), dst_port=ev.get("dst_port"),
            username=ev.get("username", ""), password=ev.get("password", ""),
            payload=ev.get("payload", ""), session_uid=ev.get("session_uid", ""),
            extra_json=json.dumps(ev.get("extra", {}), ensure_ascii=False),
        )
        db.add(e); inserted += 1

        # Сессии: собираем transcript по session_uid
        su = e.session_uid
        if su and e.etype in ("session", "command", "auth"):
            s = db.query(TrapSession).filter(TrapSession.uid == su).first()
            if not s:
                s = TrapSession(uid=su, honeypot_id=h.id, src_ip=e.src_ip,
                                proto=e.proto, started_at=e.ts_client or now)
                db.add(s)
                db.flush()
            line = f"$ {e.payload}" if e.etype == "command" else f"[{e.etype}] {e.username}:{e.password} {e.payload}"
            if e.payload or e.username:
                s.transcript = (s.transcript + "\n" + line).strip()
                s.commands_count += 1
            if e.etype == "session":
                try:
                    ex = ev.get("extra", {})
                    s.duration_sec = float(ex.get("duration_sec", s.duration_sec or 0))
                    s.ended_at = now
                except (TypeError, ValueError):
                    pass

        # Honeytoken сработал (FR-A6): агент прислал digest приманки
        if e.etype == "honeytoken":
            digest = (ev.get("extra") or {}).get("digest", "")
            tok = db.query(HoneyToken).filter(HoneyToken.value_digest == digest).first()
            if tok and not tok.triggered:
                tok.triggered = True
                tok.triggered_at = now
                tok.triggered_by_ip = e.src_ip
                trig_tokens.append(tok.label or tok.token_uid)

        # Файлы-артефакты (base64 в payload при capture_files)
        if e.etype == "file":
            ex = ev.get("extra", {})
            content_b64 = ex.get("content_b64", "")
            sha = ex.get("sha256") or hashlib.sha256(e.payload.encode()).hexdigest()
            if content_b64 and not db.query(Artifact).filter(Artifact.sha256 == sha).first():
                import base64
                blob = base64.b64decode(content_b64)
                db.add(Artifact(sha256=sha, filename=ex.get("filename", "upload.bin"),
                                honeypot_id=h.id, size_bytes=len(blob), content=blob))

    _run_alert_rules(db, h, payload.get("events", []), now)
    db.commit()

    # Формируем ответ агенту
    profile_cfg = None
    if h.profile:
        profile_cfg = _profile_to_dict(h.profile)
    masking = json.loads(h.profile.masking_json) if h.profile and h.profile.masking_json else {}
    commands: list[str] = []
    if h.desired_state == "stopped":
        commands.append("stop")
    else:
        commands.append("start")
    if h.profile and h.profile.version != h.applied_profile_version:
        commands.append("reload")
    interval = float(masking.get("beacon_interval_sec", 45))
    jitter_pct = float(masking.get("beacon_jitter_pct", 35))
    import random
    delay = max(5.0, interval * (1 + random.uniform(-jitter_pct, jitter_pct) / 100.0))

    cfg_hash = hashlib.sha256(
        json.dumps(profile_cfg, sort_keys=True).encode() if profile_cfg else b""
    ).hexdigest()[:16]

    return {
        "ok": True,
        "config_version": (h.profile.version if h.profile else 0),
        "config_hash": cfg_hash,
        "profile": profile_cfg,
        "commands": commands,
        "next_beacon_delay_sec": round(delay, 2),
        "_inserted": inserted,
        "_triggers": trig_tokens,
    }


def finalize_applied_version(db: Session, trap_uuid: str, version: int) -> None:
    h = db.query(Honeypot).filter(Honeypot.uuid == trap_uuid).first()
    if h:
        h.applied_profile_version = version
        db.commit()


# ---------------- Правила алертов (FR-C7 bonus) ----------------
def _run_alert_rules(db: Session, h: Honeypot, events: list[dict], now: dt.datetime) -> None:
    window_start = now - dt.timedelta(seconds=settings.ALERT_WINDOW_SECONDS)
    by_src: dict[str, int] = {}
    for ev in events:
        if ev.get("etype") == "auth" and (ev.get("extra") or {}).get("success") is False:
            by_src.setdefault(ev.get("src_ip", "?"), 0)
            by_src[ev["src_ip"]] += 1
    for ip, cnt in by_src.items():
        recent = db.query(AttackEvent).filter(
            AttackEvent.honeypot_id == h.id,
            AttackEvent.etype == "auth",
            AttackEvent.src_ip == ip,
            AttackEvent.ts_received >= window_start,
        ).count()
        if recent >= settings.ALERT_AUTH_FAIL_THRESHOLD:
            dup = db.query(Alert).filter(
                Alert.rule == "brute_force", Alert.src_ip == ip,
                Alert.honeypot_id == h.id, Alert.created_at >= window_start,
            ).first()
            if not dup:
                db.add(Alert(rule="brute_force", honeypot_id=h.id, src_ip=ip, severity="high",
                             detail=f"{recent} неудачных попыток аутентификации за "
                                    f"{settings.ALERT_WINDOW_SECONDS}s на {h.name}"))
    scan_ports = {ev.get("dst_port") for ev in events if ev.get("etype") in ("connect", "scan")}
    if len(scan_ports) >= 15:
        db.add(Alert(rule="portscan", honeypot_id=h.id,
                     src_ip=events[0].get("src_ip", "?"), severity="medium",
                     detail=f"Сканирование {len(scan_ports)} портов на {h.name}"))


# ---------------- Экспорт IoC (CSV / STIX) ----------------
def export_iocs(db: Session, fmt: str = "csv", since: Optional[dt.datetime] = None) -> str:
    q = db.query(AttackEvent)
    if since:
        q = q.filter(AttackEvent.ts_received >= since)
    rows = q.order_by(AttackEvent.ts_received.desc()).limit(10000).all()
    ips = sorted({r.src_ip for r in rows if r.src_ip})
    creds = sorted({f"{r.username}:{r.password}" for r in rows if r.username})
    hashes = [a.sha256 for a in db.query(Artifact).all()]
    if fmt == "stix":
        import time
        bundle = {
            "type": "bundle", "id": f"bundle--{uuidlib.uuid4()}",
            "objects": [
                {"type": "indicator", "id": f"indicator--{uuidlib.uuid4()}",
                 "spec_version": "2.1", "created": "2026-01-01T00:00:00Z",
                 "pattern": f"[ipv4-addr:value = '{ip}']", "pattern_type": "stix",
                 "valid_from": "2026-01-01T00:00:00Z"} for ip in ips
            ] + [
                {"type": "indicator", "id": f"indicator--{uuidlib.uuid4()}",
                 "spec_version": "2.1", "created": "2026-01-01T00:00:00Z",
                 "pattern": f"[file:hashes.'SHA-256' = '{h}']", "pattern_type": "stix",
                 "valid_from": "2026-01-01T00:00:00Z"} for h in hashes
            ],
        }
        return json.dumps(bundle, indent=2)
    lines = ["type,value"]
    lines += [f"ipv4,{ip}" for ip in ips]
    lines += [f"credential,{c}" for c in creds]
    lines += [f"sha256,{h}" for h in hashes]
    return "\n".join(lines)
