import hashlib
import hmac
import os
import re
from datetime import datetime, timedelta, timezone

import jwt

from .config import settings

ALGORITHM = "HS256"
_ITERATIONS = 310_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"{_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        iters, salt, dk = stored.split("$")
        new = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(new.hex(), dk)
    except Exception:
        return False


def validate_password_strength(password: str) -> None:
    if (len(password) < 12 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password)
            or not re.search(r"\d", password)):
        raise ValueError("Password must be 12+ chars with upper, lower and a digit")


def create_access_token(user_id: int, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": str(user_id), "role": role, "exp": exp}, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
