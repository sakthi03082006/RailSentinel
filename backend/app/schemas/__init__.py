from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EventStatus, EventType, SeverityBand


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserMe(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    full_name: str
    role: str
    is_active: bool


class EventCreate(BaseModel):
    id: UUID | None = None
    device_id: UUID
    station_id: UUID | None = None
    zone_id: UUID | None = None
    officer_id: UUID | None = None
    event_type: EventType
    threat_score: Decimal = Field(ge=0, le=100)
    confidence: Decimal | None = Field(default=None, ge=0, le=1)
    occurred_at: datetime
    lat: Decimal | None = Field(default=None, ge=-90, le=90)
    lon: Decimal | None = Field(default=None, ge=-180, le=180)
    local_seq: int | None = Field(default=None, ge=0)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID
    station_id: UUID
    zone_id: UUID | None
    officer_id: UUID | None
    event_type: str
    status: EventStatus
    severity_band: SeverityBand
    threat_score: Decimal
    confidence: Decimal | None
    occurred_at: datetime
    received_at: datetime
    lat: Decimal | None
    lon: Decimal | None
    local_seq: int | None


class EventDetail(EventSummary):
    payload: dict[str, Any]
    content_hash: str
    prev_event_hash: str
    event_hash: str
    chain_seq: int
    created_at: datetime


class EventListResponse(BaseModel):
    items: list[EventSummary]
    total: int
    limit: int
    offset: int


class AuditVerifyResponse(BaseModel):
    valid: bool
    event_count: int
    head_hash: str
    detail: str


class HealthResponse(BaseModel):
    status: str
