from enum import Enum
from datetime import datetime, UTC
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from uuid import UUID, uuid4

class SyncStatus(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    SYNCING = "SYNCING"
    SYNCED = "SYNCED"
    RETRY_WAIT = "RETRY_WAIT"

class EdgeSecurityEvent(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: UUID = Field(default_factory=uuid4)
    device_id: UUID
    station_id: UUID
    zone_id: Optional[UUID] = None
    event_type: str
    threat_score: float
    confidence: Optional[float] = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    lat: Optional[float] = None
    lon: Optional[float] = None
    payload: Dict[str, Any] = {}
    local_seq: int = 0
    sync_status: SyncStatus = SyncStatus.CREATED
    retry_count: int = 0
    last_error: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_backend_payload(self) -> Dict[str, Any]:
        """Maps strictly to the exact backend schema without modifying chain logic."""
        return {
            "id": str(self.event_id),
            "device_id": str(self.device_id),
            "station_id": str(self.station_id),
            "zone_id": str(self.zone_id) if self.zone_id else None,
            "event_type": self.event_type,
            "threat_score": self.threat_score,
            "confidence": self.confidence,
            "occurred_at": self.occurred_at.isoformat(),
            "lat": self.lat,
            "lon": self.lon,
            "local_seq": self.local_seq,
            "payload": self.payload
        }
