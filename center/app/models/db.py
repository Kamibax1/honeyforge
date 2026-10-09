"""Слой данных (SQLAlchemy). Единая модель для SQLite (dev) и PostgreSQL (compose).

Таблицы: operators, profiles, honeypots, events, sessions, artifacts,
honeytokens, alerts, audit_log. Схема БД описана в docs/db.schema.md.
"""
from __future__ import annotations

import datetime as dt
from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, LargeBinary, String, Text, Index
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class Operator(Base):
    """Учётная запись оператора центра (FR-C5)."""
    __tablename__ = "operators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    login: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | operator | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrapProfile(Base):
    """Профиль ловушки (FR-C1): уровень, сервисы, баннеры, креды-приманки, маскировка."""
    __tablename__ = "profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    level: Mapped[str] = mapped_column(String(8), default="low")  # low | medium | high
    services_json: Mapped[str] = mapped_column(Text, default="[]")   # [{proto,port,banner,...}]
    credentials_json: Mapped[str] = mapped_column(Text, default="[]")  # bait creds
    logging_json: Mapped[str] = mapped_column(Text, default="{}")
    masking_json: Mapped[str] = mapped_column(Text, default="{}")     # jitter, path, UA...
    honeytokens_json: Mapped[str] = mapped_column(Text, default="[]")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    honeypots: Mapped[list["Honeypot"]] = relationship(back_populates="profile")


class Honeypot(Base):
    """Зарегистрированная ловушка (FR-C2) со статусом и last-seen."""
    __tablename__ = "honeypots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    host_addr: Mapped[str] = mapped_column(String(120), default="")
    mgmt_iface: Mapped[str] = mapped_column(String(64), default="mgmt0")  # MASK-3
    agent_secret: Mapped[str] = mapped_column(String(128), default="")    # аутентификация агента
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id"), nullable=True)
    desired_state: Mapped[str] = mapped_column(String(16), default="running")  # running|stopped
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|online|offline
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_profile_version: Mapped[int] = mapped_column(Integer, default=0)
    registered_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    profile: Mapped[TrapProfile | None] = relationship(back_populates="honeypots")
    events: Mapped[list["AttackEvent"]] = relationship(back_populates="honeypot")


class AttackEvent(Base):
    """Событие атаки (FR-A2, FR-C4). Фильтрация по trap/time/src/type — см. индексы."""
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_uid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    honeypot_id: Mapped[int] = mapped_column(ForeignKey("honeypots.id"), index=True)
    ts_client: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ts_received: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    etype: Mapped[str] = mapped_column(String(32), index=True)  # connect|auth|command|request|file|honeytoken|session
    proto: Mapped[str] = mapped_column(String(16), default="tcp")
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(128), default="")
    password: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[str] = mapped_column(Text, default="")
    session_uid: Mapped[str] = mapped_column(String(36), default="", index=True)
    extra_json: Mapped[str] = mapped_column(Text, default="{}")

    honeypot: Mapped[Honeypot] = relationship(back_populates="events")

    __table_args__ = (
        Index("ix_events_trap_time", "honeypot_id", "ts_received"),
        Index("ix_events_src", "src_ip", "ts_received"),
    )


class Session(Base):
    """Сессия взаимодействия атакующего с ловушкой (для medium/high)."""
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    uid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    honeypot_id: Mapped[int] = mapped_column(ForeignKey("honeypots.id"), index=True)
    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    proto: Mapped[str] = mapped_column(String(16), default="ssh")
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_sec: Mapped[float] = mapped_column(Float, default=0.0)
    transcript: Mapped[str] = mapped_column(Text, default="")
    commands_count: Mapped[int] = mapped_column(Integer, default=0)


class Artifact(Base):
    """Загруженный/извлечённый артефакт: хэш + содержимое (FR: данные на входе)."""
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(255), default="")
    honeypot_id: Mapped[int | None] = mapped_column(ForeignKey("honeypots.id"), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    stored_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HoneyToken(Base):
    """Honeytoken-приманка (FR-A6 bonus) и фиксация срабатывания."""
    __tablename__ = "honeytokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_uid: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(32), default="ssh_key")  # ssh_key|aws_key|file|url|cred
    label: Mapped[str] = mapped_column(String(120), default="")
    value_digest: Mapped[str] = mapped_column(String(64), default="")  # sha256 значения
    triggered: Mapped[bool] = mapped_column(Boolean, default=False)
    triggered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triggered_by_ip: Mapped[str] = mapped_column(String(64), default="")


class Alert(Base):
    """Автоматический алерт по правилам (FR-C7 bonus)."""
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule: Mapped[str] = mapped_column(String(64))
    honeypot_id: Mapped[int | None] = mapped_column(ForeignKey("honeypots.id"), nullable=True)
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AuditLog(Base):
    """Журнал аудита действий оператора (NFR наблюдаемость)."""
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    object_ref: Mapped[str] = mapped_column(String(255), default="")
    meta: Mapped[str] = mapped_column(Text, default="{}")
