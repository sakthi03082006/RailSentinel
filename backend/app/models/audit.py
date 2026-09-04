from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditChainHead(Base):
    __tablename__ = "audit_chain_head"
    __table_args__ = (CheckConstraint("id = 1", name="ck_audit_chain_head_singleton"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    head_event_id: Mapped[UUID | None] = mapped_column(ForeignKey("security_events.id"), nullable=True)
