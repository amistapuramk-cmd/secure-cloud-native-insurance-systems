from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="customer")  # customer|agent|adjuster|admin
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_number: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    type: Mapped[str] = mapped_column(String(20))  # health|auto|home|life
    coverage_amount: Mapped[float] = mapped_column(Float)
    premium: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|active|cancelled
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    claims: Mapped[list["Claim"]] = relationship(back_populates="policy")


class Claim(Base):
    __tablename__ = "claims"
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id"), index=True)
    claimant_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    amount: Mapped[float] = mapped_column(Float)
    description_enc: Mapped[str] = mapped_column(Text)  # encrypted at rest
    status: Mapped[str] = mapped_column(String(20), default="submitted")  # submitted|approved|rejected
    reviewer_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    policy: Mapped[Policy] = relationship(back_populates="claims")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
