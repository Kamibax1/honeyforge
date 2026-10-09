"""HoneyForge Control Center — конфигурация.

Все секреты берутся из переменных окружения (env), а не из кода.
По умолчанию используется SQLite, чтобы систему можно было поднять без
внешних зависимостей; в docker-compose поднимается PostgreSQL и
DATABASE_URL переопределяется на postgresql+psycopg2://...
"""
from __future__ import annotations

import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "HoneyForge Control Center"
    ENV: str = "dev"

    # Хранилище. В compose: postgresql+psycopg2://hf_center:hf_center@db:5432/honeyforge
    DATABASE_URL: str = Field(
        default="sqlite:///./data/honeyforge.db"
    )

    # Секрет подписи JWT-токенов оператора (обязательно сменить через env)
    JWT_SECRET: str = os.environ.get("HF_JWT_SECRET", "change-me-in-env")
    JWT_ALG: str = "HS256"
    ACCESS_TOKEN_TTL_MIN: int = 720

    # Ключ проксирующего слоя (X-HF-Key). Агент и realtime-слой знают его.
    AGGREGATOR_KEY: str = os.environ.get("HF_AGGREGATOR_KEY", "change-me-aggregator-key")

    # Пароль bootstrap-оператора при первом старте (если операторов ещё нет)
    INITIAL_ADMIN_LOGIN: str = os.environ.get("HF_ADMIN_LOGIN", "operator")
    INITIAL_ADMIN_PASSWORD: str = os.environ.get("HF_ADMIN_PASSWORD", "honeyforge")

    # Пороги алертов по умолчанию
    ALERT_AUTH_FAIL_THRESHOLD: int = int(os.environ.get("HF_ALERT_THRESHOLD", "5"))
    ALERT_WINDOW_SECONDS: int = int(os.environ.get("HF_ALERT_WINDOW", "60"))

    # Таймаут перевода ловушки в offline (секунд без beacon)
    HONEYPOT_OFFLINE_AFTER: int = int(os.environ.get("HF_OFFLINE_AFTER", "90"))

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.DATABASE_URL.startswith("sqlite"):
        os.makedirs("data", exist_ok=True)
    return s


settings = get_settings()
