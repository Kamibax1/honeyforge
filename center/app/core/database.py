"""Инициализация БД и сессий. Поддерживает SQLite (dev) и PostgreSQL (compose)."""
from __future__ import annotations

import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.db import Base

url = settings.DATABASE_URL
connect_args = {}
if url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    path = url.replace("sqlite:///", "")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)

if url.startswith("sqlite"):
    # WAL + включение FK для SQLite — приближаем поведение к production-настройкам
    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Создаёт таблицы и bootstrap-оператора при первом старте."""
    from app.core.security import hash_password
    from app.models.db import Operator

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if not db.query(Operator).first():
            db.add(Operator(
                login=settings.INITIAL_ADMIN_LOGIN,
                password_hash=hash_password(settings.INITIAL_ADMIN_PASSWORD),
                role="admin",
            ))
            db.commit()
    finally:
        db.close()
