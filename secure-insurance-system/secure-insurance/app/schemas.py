from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .security import validate_password_strength

Role = Literal["customer", "agent", "adjuster", "admin"]


class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=255)
    password: str

    @field_validator("password")
    @classmethod
    def strong(cls, v):
        validate_password_strength(v)
        return v


class StaffCreateIn(RegisterIn):
    role: Role


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PolicyCreate(BaseModel):
    type: Literal["health", "auto", "home", "life"]
    coverage_amount: float = Field(gt=0, le=10_000_000)


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    policy_number: str
    owner_id: int
    type: str
    coverage_amount: float
    premium: float
    status: str
    created_at: datetime


class ClaimCreate(BaseModel):
    policy_id: int
    amount: float = Field(gt=0)
    description: str = Field(min_length=3, max_length=5000)


class ClaimReview(BaseModel):
    decision: Literal["approved", "rejected"]
    note: str | None = Field(default=None, max_length=1000)


class ClaimOut(BaseModel):
    id: int
    policy_id: int
    claimant_id: int
    amount: float
    description: str
    status: str
    reviewer_note: str | None
    created_at: datetime
