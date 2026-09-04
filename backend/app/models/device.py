from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    device_uid: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    device_type: Mapped[str] = mapped_column(String(32), nullable=False)
    station_id: Mapped[UUID] = mapped_column(ForeignKey("stations.id"), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    station: Mapped["Station"] = relationship(back_populates="devices")
