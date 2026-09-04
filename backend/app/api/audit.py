from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_roles
from app.db.session import get_db
from app.models.user import User
from app.schemas import AuditVerifyResponse
from app.services.events import verify_chain

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/verify", response_model=AuditVerifyResponse)
def verify(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("administrator", "supervisor")),
) -> AuditVerifyResponse:
    valid, count, head_hash, detail = verify_chain(db)
    return AuditVerifyResponse(
        valid=valid,
        event_count=count,
        head_hash=head_hash,
        detail=detail,
    )
