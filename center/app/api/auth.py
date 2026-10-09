"""API аутентификации оператора (FR-C5)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import create_access_token, get_current_user, require_role, verify_password
from app.models.db import Operator
from app.schemas.api import TokenOut, OperatorIn
from app.services.core_services import audit

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    op = db.query(Operator).filter(Operator.login == form.username).first()
    if not op or not op.is_active or not verify_password(form.password, op.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")
    audit(db, op.login, "auth.login", op.login)
    db.commit()
    return TokenOut(access_token=create_access_token(op.login, op.role),
                    role=op.role, login=op.login)


@router.get("/auth/me")
def me(op: Operator = Depends(get_current_user)):
    return {"login": op.login, "role": op.role}


@router.post("/auth/operators", status_code=201)
def create_operator(body: OperatorIn, db: Session = Depends(get_db),
                    op: Operator = Depends(require_role("admin"))):
    """Управление учётками доступно только admin (разграничение доступа)."""
    from app.core.security import hash_password
    if db.query(Operator).filter(Operator.login == body.login).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Логин уже существует")
    new = Operator(login=body.login, password_hash=hash_password(body.password), role=body.role)
    db.add(new)
    audit(db, op.login, "auth.create_operator", body.login, {"role": body.role})
    db.commit()
    return {"ok": True, "login": new.login, "role": new.role}
