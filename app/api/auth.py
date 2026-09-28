"""
Authentication API routes.

POST /api/auth/login uses OAuth2PasswordRequestForm — the standard
FastAPI/OAuth2 convention of accepting `username`/`password` as form
fields rather than JSON, which is what makes it compatible with the
"Authorize" button in the auto-generated Swagger UI at /docs.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.auth import Token, UserCreate, UserRead
from app.security.auth import create_access_token, hash_password, verify_password
from app.security.deps import get_current_user, require_admin

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger("netsentinel.api.auth")


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
) -> Token:
    user = db.query(User).filter(User.username == form_data.username).first()

    if user is None or not verify_password(form_data.password, user.hashed_password):
        # Deliberately identical error for "no such user" and "wrong
        # password" — distinguishing them lets an attacker enumerate
        # valid usernames.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is disabled")

    token = create_access_token(subject=user.username, role=user.role.value)
    db.add(AuditLog(username=user.username, action="LOGIN", details="Successful login"))
    db.commit()

    return Token(access_token=token)


@router.post("/register", response_model=UserRead, status_code=201, dependencies=[Depends(require_admin)])
async def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    """
    Create a new user. Restricted to ADMIN so an unauthenticated caller
    can't self-provision an account — the very first admin account is
    created via the `scripts/create_admin.py` bootstrap script instead.
    """
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/me", response_model=UserRead)
async def get_me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
