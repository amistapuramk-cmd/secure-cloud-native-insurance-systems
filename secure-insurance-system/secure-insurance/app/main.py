from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import select

from . import models
from .config import settings
from .database import Base, SessionLocal, engine
from .routers import audit, auth, claims, policies
from .security import hash_password


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)  # use Alembic migrations in production
    with SessionLocal() as db:
        if not db.scalar(select(models.User).where(models.User.email == settings.ADMIN_EMAIL.lower())):
            db.add(models.User(email=settings.ADMIN_EMAIL.lower(), full_name="System Admin",
                               password_hash=hash_password(settings.ADMIN_PASSWORD), role="admin"))
            db.commit()
    yield


app = FastAPI(title="Secure Cloud-Native Insurance System", version="1.0.0", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


@app.get("/health", tags=["ops"])
def health():  # liveness/readiness probe
    return {"status": "ok"}


for r in (auth.router, policies.router, claims.router, audit.router):
    app.include_router(r)
