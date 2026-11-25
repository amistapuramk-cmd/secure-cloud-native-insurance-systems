from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..deps import require_roles

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit(limit: int = 100, db: Session = Depends(get_db),
               _: models.User = Depends(require_roles("admin"))):
    rows = db.scalars(select(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(min(limit, 500))).all()
    return [{"id": r.id, "user_id": r.user_id, "action": r.action, "detail": r.detail,
             "created_at": r.created_at} for r in rows]
