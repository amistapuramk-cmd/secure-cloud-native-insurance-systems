from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..crypto import decrypt, encrypt
from ..database import get_db
from ..deps import audit, current_user, require_roles

router = APIRouter(prefix="/claims", tags=["claims"])


def to_out(c: models.Claim) -> schemas.ClaimOut:
    return schemas.ClaimOut(id=c.id, policy_id=c.policy_id, claimant_id=c.claimant_id, amount=c.amount,
                            description=decrypt(c.description_enc), status=c.status,
                            reviewer_note=c.reviewer_note, created_at=c.created_at)


@router.post("", response_model=schemas.ClaimOut, status_code=201)
def file_claim(data: schemas.ClaimCreate, db: Session = Depends(get_db),
               user: models.User = Depends(require_roles("customer"))):
    policy = db.get(models.Policy, data.policy_id)
    if not policy or policy.owner_id != user.id:
        raise HTTPException(404, "Policy not found")
    if policy.status != "active":
        raise HTTPException(409, "Claims can only be filed on active policies")
    if data.amount > policy.coverage_amount:
        raise HTTPException(422, "Claim exceeds coverage amount")
    claim = models.Claim(policy_id=policy.id, claimant_id=user.id, amount=data.amount,
                         description_enc=encrypt(data.description))
    db.add(claim); db.commit(); db.refresh(claim)
    audit(db, user.id, "claim.file", f"claim={claim.id}")
    return to_out(claim)


@router.get("", response_model=list[schemas.ClaimOut])
def list_claims(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    if user.role == "agent":
        raise HTTPException(403, "Insufficient permissions")
    q = select(models.Claim)
    if user.role == "customer":
        q = q.where(models.Claim.claimant_id == user.id)
    return [to_out(c) for c in db.scalars(q.order_by(models.Claim.id)).all()]


@router.post("/{claim_id}/review", response_model=schemas.ClaimOut)
def review(claim_id: int, data: schemas.ClaimReview, db: Session = Depends(get_db),
           user: models.User = Depends(require_roles("adjuster", "admin"))):
    c = db.get(models.Claim, claim_id)
    if not c:
        raise HTTPException(404, "Claim not found")
    if c.status != "submitted":
        raise HTTPException(409, f"Claim already {c.status}")
    c.status, c.reviewer_note = data.decision, data.note
    db.commit(); db.refresh(c)
    audit(db, user.id, f"claim.{data.decision}", f"claim={c.id}")
    return to_out(c)
