"""Pydantic-схемы запросов/ответов Control API."""
from __future__ import annotations

import datetime as dt
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------- Профили (FR-C1) ----------
class ServiceSpec(BaseModel):
    model_config = ConfigDict(extra="ignore")

    proto: Literal["tcp", "udp", "http"] = "tcp"
    port: int = Field(ge=1, le=65535)
    kind: str = ""            # ftp/telnet/smtp/http/ssh/… — подсказка оператору
    banner: str = ""
    # для medium-эмуляций
    fake_fs: bool = False
    accept_any_cred: bool = True
    realistic_delay_ms: int = 120


class BaitCredential(BaseModel):
    username: str
    password: str
    note: str = ""


class MaskingParams(BaseModel):
    beacon_interval_sec: int = 45
    beacon_jitter_pct: int = 35          # MASK-5
    cover_path: str = "/static/js/analytics.js"   # MASK-2 — выглядит как легитимный ресурс
    cover_host_header: str = "cdn.example-assets.net"
    pad_min_bytes: int = 256              # выравнивание размера тела по границе блока
    process_name: str = "kworker/0:2-events_unbound"  # MASK-4
    tls_verify: bool = True               # MASK-7 (pinning CA-fingerprint)
    ca_pin_sha256: str = ""


class LoggingParams(BaseModel):
    capture_commands: bool = True
    capture_files: bool = True
    record_transcripts: bool = True
    local_buffer_max_events: int = 5000   # FR-A4


class ProfileIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = ""
    level: Literal["low", "medium", "high"]
    services: list[ServiceSpec] = []
    credentials: list[BaitCredential] = []
    masking: MaskingParams = MaskingParams()
    logging: LoggingParams = LoggingParams()
    honeytokens: list[dict[str, Any]] = []

    @field_validator("services")
    @classmethod
    def _uniq_ports(cls, v: list[ServiceSpec]) -> list[ServiceSpec]:
        seen = set()
        for s in v:
            key = (s.proto, s.port)
            if key in seen:
                raise ValueError(f"Дублирующийся порт {key}")
            seen.add(key)
        return v


class ProfileOut(ProfileIn):
    id: int
    version: int
    created_at: dt.datetime
    updated_at: dt.datetime

    model_config = {"from_attributes": True}


# ---------- Ловушки (FR-C2) ----------
class HoneypotCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    host_addr: str = ""
    mgmt_iface: str = "mgmt0"
    profile_id: Optional[int] = None


class HoneypotPatch(BaseModel):
    profile_id: Optional[int] = None
    desired_state: Optional[Literal["running", "stopped"]] = None
    name: Optional[str] = None
    host_addr: Optional[str] = None


class HoneypotOut(BaseModel):
    id: int
    uuid: str
    name: str
    host_addr: str
    mgmt_iface: str
    status: str
    last_seen: Optional[dt.datetime]
    profile_id: Optional[int]
    profile_name: Optional[str] = None
    desired_state: str
    applied_profile_version: int
    registered_at: dt.datetime


# ---------- Телеметрия от агента (FR-C3) ----------
class EventIn(BaseModel):
    event_uid: str
    ts_client: Optional[dt.datetime] = None
    etype: Literal["connect", "auth", "command", "request", "file", "honeytoken", "session", "scan"]
    proto: str = "tcp"
    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: str = ""
    password: str = ""
    payload: str = ""
    session_uid: str = ""
    extra: dict[str, Any] = {}


class BeaconIn(BaseModel):
    uuid: str
    applied_profile_version: int = 0
    stats: dict[str, Any] = {}
    events: list[EventIn] = []


class BeaconOut(BaseModel):
    """Ответ центра агенту: обновлённый профиль + команды (выходные данные центр→ловушка)."""
    ok: bool = True
    config_version: int = 0
    profile: Optional[dict[str, Any]] = None
    commands: list[str] = []
    next_beacon_delay_sec: float = 45.0


# ---------- Оператор / события ----------
class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    login: str


class EventOut(BaseModel):
    id: int
    event_uid: str
    honeypot_id: int
    honeypot_name: Optional[str] = None
    ts_client: Optional[dt.datetime]
    ts_received: dt.datetime
    etype: str
    proto: str
    src_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    username: str
    password: str
    payload: str
    session_uid: str

    model_config = {"from_attributes": True}


class OperatorIn(BaseModel):
    login: str
    password: str
    role: Literal["admin", "operator", "viewer"] = "operator"


class AuditOut(BaseModel):
    id: int
    ts: dt.datetime
    actor: str
    action: str
    object_ref: str
    meta: str

    model_config = {"from_attributes": True}
