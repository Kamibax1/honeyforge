"""Control API: профили, ловушки, события, алерты, оркестратор, экспорт."""
from __future__ import annotations

import datetime as dt
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.models.db import (Alert, Artifact, AuditLog, Honeypot, HoneyToken, Operator,
                           Session as TrapSession, TrapProfile)
from app.schemas.api import (AuditOut, EventOut, HoneypotCreate, HoneypotPatch,
                             HoneypotOut, ProfileIn, ProfileOut)
from app.services import orchestrator
from app.services import core_services as svc

router = APIRouter(tags=["control"])


def _hp_out(h: Honeypot) -> HoneypotOut:
    return HoneypotOut(
        id=h.id, uuid=h.uuid, name=h.name, host_addr=h.host_addr, mgmt_iface=h.mgmt_iface,
        status=h.status, last_seen=h.last_seen, profile_id=h.profile_id,
        profile_name=h.profile.name if h.profile else None,
        desired_state=h.desired_state, applied_profile_version=h.applied_profile_version,
        registered_at=h.registered_at,
    )


# ---------------- Профили (FR-C1) ----------------
@router.get("/profiles", response_model=list[ProfileOut])
def list_profiles(db: Session = Depends(get_db), _: Operator = Depends(get_current_user)):
    return db.query(TrapProfile).order_by(TrapProfile.name).all()


@router.post("/profiles", response_model=ProfileOut, status_code=201)
def create_profile(body: ProfileIn, db: Session = Depends(get_db),
                   op: Operator = Depends(require_role("operator"))):
    try:
        p = svc.create_profile(db, body.model_dump(), op.login)
    except Exception as e:  # unique violation и т.п.
        db.rollback()
        raise HTTPException(409, f"Не удалось создать профиль: {e}")
    return p


@router.get("/profiles/{pid}", response_model=ProfileOut)
def get_profile(pid: int, db: Session = Depends(get_db), _: Operator = Depends(get_current_user)):
    p = db.get(TrapProfile, pid)
    if not p:
        raise HTTPException(404, "Профиль не найден")
    return p


@router.put("/profiles/{pid}", response_model=ProfileOut)
def update_profile(pid: int, body: ProfileIn, db: Session = Depends(get_db),
                   op: Operator = Depends(require_role("operator"))):
    p = svc.update_profile(db, pid, body.model_dump(), op.login)
    if not p:
        raise HTTPException(404, "Профиль не найден")
    return p


@router.delete("/profiles/{pid}", status_code=204)
def delete_profile(pid: int, db: Session = Depends(get_db),
                   op: Operator = Depends(require_role("admin"))):
    try:
        if not svc.delete_profile(db, pid, op.login):
            raise HTTPException(404, "Профиль не найден")
    except ValueError as e:
        raise HTTPException(409, str(e))


# ---------------- Ловушки (FR-C2) ----------------
@router.get("/honeypots", response_model=list[HoneypotOut])
def list_honeypots(db: Session = Depends(get_db), _: Operator = Depends(get_current_user)):
    svc.mark_stale_offline(db)
    return [_hp_out(h) for h in db.query(Honeypot).order_by(Honeypot.name).all()]


@router.post("/honeypots", status_code=201)
def register_honeypot(body: HoneypotCreate, db: Session = Depends(get_db),
                      op: Operator = Depends(require_role("operator"))):
    if body.profile_id is not None and not db.get(TrapProfile, body.profile_id):
        raise HTTPException(404, "Профиль не найден")
    h = svc.register_honeypot(db, body.name, body.host_addr, body.mgmt_iface,
                              body.profile_id, op.login)
    out = _hp_out(h)
    # секреты показываем один раз при регистрации — оператор кладёт их в env на хосте
    payload = out.model_dump()
    payload["agent_secret"] = h.agent_secret
    return Response(json.dumps(payload, default=str, ensure_ascii=False),
                    media_type="application/json", status_code=201)


@router.patch("/honeypots/{hid}", response_model=HoneypotOut)
def patch_honeypot(hid: int, body: HoneypotPatch, db: Session = Depends(get_db),
                   op: Operator = Depends(require_role("operator"))):
    try:
        h = svc.patch_honeypot(db, hid, body.model_dump(exclude_unset=True), op.login)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not h:
        raise HTTPException(404, "Ловушка не найдена")
    return _hp_out(h)


@router.post("/honeypots/{hid}/rotate-secret")
def rotate_secret(hid: int, db: Session = Depends(get_db),
                  op: Operator = Depends(require_role("admin"))):
    s = svc.rotate_agent_secret(db, hid, op.login)
    if not s:
        raise HTTPException(404, "Ловушка не найдена")
    return {"ok": True, "agent_secret": s}


# ---------------- Оркестратор (FR-C6 bonus) ----------------
@router.get("/honeypots/{hid}/deploy-bundle")
def deploy_bundle(hid: int, center_url: str = Query("https://cdn.example-assets.net"),
                  db: Session = Depends(get_db), op: Operator = Depends(require_role("operator"))):
    """Одна кнопка: сгенерировать артефакт развёртывания (compose + Dockerfile + install.sh)."""
    h = db.get(Honeypot, hid)
    if not h:
        raise HTTPException(404, "Ловушка не найдена")
    if not h.profile:
        raise HTTPException(400, "К ловушке не привязан профиль")
    prof = svc._profile_to_dict(h.profile)
    files = orchestrator.render_compose_bundle(h.name, h.uuid, center_url, prof)
    files["honeyd.py"] = _read_agent_source()
    svc.audit(db, op.login, "orchestrator.bundle", h.name)
    db.commit()
    tar = _make_tar(files)
    return Response(tar, media_type="application/x-tar",
                    headers={"Content-Disposition": f'attachment; filename="deploy-{hid}.tar"'})


def _read_agent_source() -> str:
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[3] / "agent" / "honeyd" / "honeyd.py"
    try:
        return p.read_text()
    except OSError:
        return "# agent source not bundled in this build\n"


def _make_tar(files: dict[str, str]) -> bytes:
    import io, tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


# ---------------- События / аналитика (FR-C4) ----------------
@router.get("/events", response_model=list[EventOut])
def list_events(
    honeypot_id: Optional[int] = None,
    src_ip: Optional[str] = None,
    etype: Optional[str] = None,
    since: Optional[dt.datetime] = None,
    until: Optional[dt.datetime] = None,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db), _: Operator = Depends(get_current_user),
):
    q = db.query(AttackEvent)
    if honeypot_id:
        q = q.filter(AttackEvent.honeypot_id == honeypot_id)
    if src_ip:
        q = q.filter(AttackEvent.src_ip == src_ip)
    if etype:
        q = q.filter(AttackEvent.etype == etype)
    if since:
        q = q.filter(AttackEvent.ts_received >= since)
    if until:
        q = q.filter(AttackEvent.ts_received <= until)
    rows = q.order_by(AttackEvent.ts_received.desc()).limit(limit).all()
    names = {h.id: h.name for h in db.query(Honeypot).all()}
    out = []
    for r in rows:
        o = EventOut.model_validate(r)
        o.honeypot_name = names.get(r.honeypot_id)
        out.append(o)
    return out


@router.get("/sessions")
def list_sessions(honeypot_id: Optional[int] = None, db: Session = Depends(get_db),
                  _: Operator = Depends(get_current_user)):
    q = db.query(TrapSession)
    if honeypot_id:
        q = q.filter(TrapSession.honeypot_id == honeypot_id)
    return [{
        "uid": s.uid, "honeypot_id": s.honeypot_id, "src_ip": s.src_ip, "proto": s.proto,
        "started_at": s.started_at, "ended_at": s.ended_at, "duration_sec": s.duration_sec,
        "commands_count": s.commands_count,
        "transcript_preview": s.transcript[:400],
    } for s in q.order_by(TrapSession.started_at.desc()).limit(200)]


@router.get("/artifacts")
def list_artifacts(db: Session = Depends(get_db), _: Operator = Depends(get_current_user)):
    return [{"sha256": a.sha256, "filename": a.filename, "size_bytes": a.size_bytes,
             "honeypot_id": a.honeypot_id, "stored_at": a.stored_at}
            for a in db.query(Artifact).order_by(Artifact.stored_at.desc())]


@router.get("/alerts")
def list_alerts(db: Session = Depends(get_db), _: Operator = Depends(get_current_user)):
    return [{
        "id": a.id, "rule": a.rule, "honeypot_id": a.honeypot_id, "src_ip": a.src_ip,
        "severity": a.severity, "detail": a.detail, "created_at": a.created_at,
    } for a in db.query(Alert).order_by(Alert.created_at.desc()).limit(200)]


@router.get("/honeytokens")
def list_honeytokens(db: Session = Depends(get_db), _: Operator = Depends(get_current_user)):
    return [{
        "token_uid": t.token_uid, "kind": t.kind, "label": t.label, "profile_id": t.profile_id,
        "triggered": t.triggered, "triggered_at": t.triggered_at, "triggered_by_ip": t.triggered_by_ip,
    } for t in db.query(HoneyToken).order_by(HoneyToken.triggered.desc())]


@router.get("/stats")
def stats(db: Session = Depends(get_db), _: Operator = Depends(get_current_user)):
    day_ago = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    ev_today = db.query(AttackEvent).filter(AttackEvent.ts_received >= day_ago).count()
    top_src = {}
    for r in db.query(AttackEvent).filter(AttackEvent.ts_received >= day_ago).limit(2000):
        top_src[r.src_ip] = top_src.get(r.src_ip, 0) + 1
    by_type = {}
    for r in db.query(AttackEvent).filter(AttackEvent.ts_received >= day_ago).limit(2000):
        by_type[r.etype] = by_type.get(r.etype, 0) + 1
    return {
        "honeypots_total": db.query(Honeypot).count(),
        "honeypots_online": db.query(Honeypot).filter(Honeypot.status == "online").count(),
        "profiles_total": db.query(TrapProfile).count(),
        "events_last_24h": ev_today,
        "top_sources": sorted(top_src.items(), key=lambda x: -x[1])[:10],
        "events_by_type": by_type,
        "alerts_open": db.query(Alert).filter(Alert.created_at >= day_ago).count(),
        "honeytokens_triggered": db.query(HoneyToken).filter(HoneyToken.triggered.is_(True)).count(),
    }


@router.get("/audit", response_model=list[AuditOut])
def audit_log(limit: int = Query(default=200, le=1000), db: Session = Depends(get_db),
              op: Operator = Depends(require_role("admin"))):
    return db.query(AuditLog).order_by(AuditLog.ts.desc()).limit(limit).all()


@router.get("/export/iocs")
def export_iocs(fmt: str = Query("csv", pattern="^(csv|stix)$"),
                days: int = Query(7, ge=1, le=365),
                db: Session = Depends(get_db), op: Operator = Depends(require_role("operator"))):
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    body = svc.export_iocs(db, fmt, since)
    svc.audit(db, op.login, "export.iocs", fmt, {"days": days})
    db.commit()
    media = "application/json" if fmt == "stix" else "text/csv"
    return Response(body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="ioc.{fmt}"'})
