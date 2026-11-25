import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from . import models
from .database import get_db
from .security import decode_token

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def audit(db: Session, user_id: int | None, action: str, detail: str = ""):
    db.add(models.AuditLog(user_id=user_id, action=action, detail=detail[:500]))
    db.commit()


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> models.User:
    try:
        payload = decode_token(token)
        user = db.get(models.User, int(payload["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Inactive or unknown user")
    return user


def require_roles(*roles: str):
    def checker(user: models.User = Depends(current_user)) -> models.User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user
    return checker
