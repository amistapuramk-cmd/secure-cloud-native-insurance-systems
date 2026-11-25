import time

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..config import settings
from ..database import get_db
from ..deps import audit, current_user, require_roles
from ..security import create_access_token, hash_password, verify_password

router = APIRouter(tags=["auth"])
_failures: dict[str, list[float]] = {}  # in-memory; use Redis in multi-replica production


def _locked(email: str) -> bool:
    cutoff = time.time() - settings.LOCKOUT_SECONDS
    _failures[email] = [t for t in _failures.get(email, []) if t > cutoff]
    return len(_failures[email]) >= settings.MAX_LOGIN_ATTEMPTS


@router.post("/auth/register", response_model=schemas.UserOut, status_code=201)
def register(data: schemas.RegisterIn, db: Session = Depends(get_db)):
    if db.scalar(select(models.User).where(models.User.email == data.email.lower())):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = models.User(email=data.email.lower(), full_name=data.full_name,
                       password_hash=hash_password(data.password), role="customer")
    db.add(user); db.commit(); db.refresh(user)
    audit(db, user.id, "user.register")
    return user


@router.post("/auth/login", response_model=schemas.TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = form.username.lower()
    if _locked(email):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts, try later")
    user = db.scalar(select(models.User).where(models.User.email == email))
    if not user or not user.is_active or not verify_password(form.password, user.password_hash):
        _failures.setdefault(email, []).append(time.time())
        audit(db, user.id if user else None, "auth.login_failed", email)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    _failures.pop(email, None)
    audit(db, user.id, "auth.login")
    return schemas.TokenOut(access_token=create_access_token(user.id, user.role))


@router.get("/users/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(current_user)):
    return user


@router.post("/users", response_model=schemas.UserOut, status_code=201)
def create_staff(data: schemas.StaffCreateIn, db: Session = Depends(get_db),
                 admin: models.User = Depends(require_roles("admin"))):
    if db.scalar(select(models.User).where(models.User.email == data.email.lower())):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = models.User(email=data.email.lower(), full_name=data.full_name,
                       password_hash=hash_password(data.password), role=data.role)
    db.add(user); db.commit(); db.refresh(user)
    audit(db, admin.id, "user.create_staff", f"{user.email}:{user.role}")
    return user
