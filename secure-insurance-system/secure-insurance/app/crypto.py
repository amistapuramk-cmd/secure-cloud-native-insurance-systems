"""Field-level encryption for sensitive data at rest (Fernet / AES-128-CBC + HMAC)."""
import base64
import hashlib

from cryptography.fernet import Fernet

from .config import settings


def _fernet() -> Fernet:
    key = settings.DATA_ENCRYPTION_KEY
    if not key:  # dev fallback only; use a real key + secrets manager in production
        key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode()).digest()).decode()
    return Fernet(key.encode())


def encrypt(text: str) -> str:
    return _fernet().encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()
