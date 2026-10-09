"""Безопасность: хэширование паролей (bcrypt), JWT-токены, RBAC-зависимости."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.db import Operator

# passlib 1.7.4 несовместим с bcrypt >= 4.1 (самопроверка бэкенда падает с
# ValueError "password cannot be longer than 72 bytes"), поэтому фиксируем
# bcrypt==4.0.* в requirements.txt и дополнительно ограничиваем пароль длиной
# 72 байта — жёсткий лимит алгоритма bcrypt (иначе хэш/verify упадут на runtime).
_BCRYPT_MAX_BYTES = 72

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def _bcrypt_safe(p: str) -> str:
    """Обрезка пароля до 72 байт UTF-8 без разрыва многобайтовых символов."""
    raw = p.encode("utf-8")[:_BCRYPT_MAX_BYTES]
    return raw.decode("utf-8", errors="ignore")


def hash_password(p: str) -> str:
    return pwd_ctx.hash(_bcrypt_safe(p))


def verify_password(p: str, h: str) -> bool:
    try:
        return pwd_ctx.verify(_bcrypt_safe(p), h)
    except ValueError:
        # некорректный/битый хэш или несовместимость бэкенда — считаем неудачей
        return False


def create_access_token(login: str, role: str) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": login,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(minutes=settings.ACCESS_TOKEN_TTL_MIN)).timestamp()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def _current_user_optional(token: Optional[str], db: Session) -> Optional[Operator]:
    if not token:
        return None
    try:
        data = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Некорректный токен")
    op = db.query(Operator).filter(Operator.login == data.get("sub")).first()
    if not op or not op.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Оператор не найден/отключён")
    return op


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Operator:
    op = _current_user_optional(token, db)
    if op is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Требуется аутентификация",
                            headers={"WWW-Authenticate": "Bearer"})
    return op


ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def require_role(min_role: str):
    """Зависимость разграничения доступа (FR-C5)."""
    def checker(op: Operator = Depends(get_current_user)) -> Operator:
        if ROLE_RANK.get(op.role, 0) < ROLE_RANK[min_role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Нужна роль не ниже '{min_role}'")
        return op
    return checker
