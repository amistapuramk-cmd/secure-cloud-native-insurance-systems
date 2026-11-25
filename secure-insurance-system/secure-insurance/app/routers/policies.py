import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db
from ..deps import audit, current_user, require_roles

router = APIRouter(prefix="/policies", tags=["policies"])
BASE_RATE = {"health": 0.02, "auto": 0.03, "home": 0.01, "life": 0.015}


@router.post("", response_model=schemas.PolicyOut, status_code=201)
def request_policy(data: schemas.PolicyCreate, db: Session = Depends(get_db),
                   user: models.User = Depends(require_roles("customer"))):
    policy = models.Policy(policy_number="POL-" + secrets.token_hex(5).upper(), owner_id=user.id,
                           type=data.type, coverage_amount=data.coverage_amount,
                           premium=round(data.coverage_amount * BASE_RATE[data.type], 2))
    db.add(policy); db.commit(); db.refresh(policy)
    audit(db, user.id, "policy.request", policy.policy_number)
    return policy


@router.get("", response_model=list[schemas.PolicyOut])
def list_policies(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    q = select(models.Policy)
    if user.role == "customer":  # object-level access control
        q = q.where(models.Policy.owner_id == user.id)
    return db.scalars(q.order_by(models.Policy.id)).all()


@router.get("/{policy_id}", response_model=schemas.PolicyOut)
def get_policy(policy_id: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    p = db.get(models.Policy, policy_id)
    if not p or (user.role == "customer" and p.owner_id != user.id):
        raise HTTPException(404, "Policy not found")  # 404 avoids leaking existence
    return p


@router.post("/{policy_id}/approve", response_model=schemas.PolicyOut)
def approve(policy_id: int, db: Session = Depends(get_db),
            user: models.User = Depends(require_roles("agent", "admin"))):
    p = db.get(models.Policy, policy_id)
    if not p:
        raise HTTPException(404, "Policy not found")
    if p.status != "pending":
        raise HTTPException(409, f"Policy is {p.status}")
    p.status = "active"; db.commit(); db.refresh(p)
    audit(db, user.id, "policy.approve", p.policy_number)
    return p


@router.post("/{policy_id}/cancel", response_model=schemas.PolicyOut)
def cancel(policy_id: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    p = db.get(models.Policy, policy_id)
    if not p or (user.role == "customer" and p.owner_id != user.id):
        raise HTTPException(404, "Policy not found")
    if user.role == "adjuster":
        raise HTTPException(403, "Insufficient permissions")
    p.status = "cancelled"; db.commit(); db.refresh(p)
    audit(db, user.id, "policy.cancel", p.policy_number)
    return p
