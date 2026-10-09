"""HoneyForge Control Center — точка входа FastAPI.

Запуск dev:  uvicorn app.main:app --host 0.0.0.0 --port 8000
В проде за nginx (TLS-терминация, маскировка путей).
"""
from __future__ import annotations

import asyncio
import contextlib

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db, SessionLocal
from app.api import auth, control, ingest


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    stop = asyncio.Event()

    async def _janitor():
        """Перевод зависших ловушек в offline + периодический health."""
        while not stop.is_set():
            try:
                db = SessionLocal()
                try:
                    from app.services.core_services import mark_stale_offline
                    mark_stale_offline(db)
                finally:
                    db.close()
            except Exception:
                pass
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=30)

    task = asyncio.create_task(_janitor())
    yield
    stop.set()
    task.cancel()


app = FastAPI(title=settings.APP_NAME, version="1.0", lifespan=lifespan)

# CORS только для локального UI/realtime (в проде всё за одним nginx-origin)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "http://localhost:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(control.router)
app.include_router(ingest.router)


@app.get("/")
def root():
    # Корень выглядит как обычный сервисный endpoint, без «honeypot» в описании
    return {"service": "assets-metrics-api", "version": 2}
