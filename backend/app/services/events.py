from datetime import UTC, datetime
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.audit import AuditChainHead
from app.models.device import Device
from app.models.enums import DeviceStatus, EventStatus
from app.models.event import SecurityEvent
from app.models.station import Station, Zone
from app.models.user import User
from app.schemas import EventCreate
from app.services.hash_chain import (
    GENESIS_HASH,
    canonical_event_fields,
    hashes_for_event,
)
from app.services.scoring import severity_band_for_score


def _get_or_404(db: Session, model, id_: UUID, label: str):
    row = db.get(model, id_)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"{label} not found")
    return row


def ingest_event(db: Session, body: EventCreate) -> tuple[SecurityEvent, bool]:
    """Persist a security event. Returns (event, created)."""
    event_id = body.id or uuid4()
    existing = db.get(SecurityEvent, event_id)
    if existing is not None:
        return existing, False

    device = _get_or_404(db, Device, body.device_id, "device")
    if device.status != DeviceStatus.ACTIVE.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="device is not active")

    station_id = body.station_id or device.station_id
    station = _get_or_404(db, Station, station_id, "station")
    if not station.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="station is not active")

    if body.zone_id is not None:
        zone = _get_or_404(db, Zone, body.zone_id, "zone")
        if zone.station_id != station_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="zone does not belong to station")

    if body.officer_id is not None:
        _get_or_404(db, User, body.officer_id, "officer")

    occurred_at = body.occurred_at
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)

    settings = get_settings()
    band = severity_band_for_score(body.threat_score, settings)

    head = db.execute(
        select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()
    ).scalar_one()

    raced = db.get(SecurityEvent, event_id)
    if raced is not None:
        return raced, False

    fields = canonical_event_fields(
        event_id=event_id,
        device_id=device.id,
        station_id=station_id,
        zone_id=body.zone_id,
        officer_id=body.officer_id,
        event_type=body.event_type.value,
        threat_score=body.threat_score,
        confidence=body.confidence,
        occurred_at=occurred_at,
        lat=body.lat,
        lon=body.lon,
        local_seq=body.local_seq,
        payload=body.payload,
    )
    prev_hash = head.head_hash or GENESIS_HASH
    content_hash, event_hash = hashes_for_event(fields, prev_hash)

    max_seq = db.scalar(select(func.coalesce(func.max(SecurityEvent.chain_seq), 0)))
    event = SecurityEvent(
        id=event_id,
        device_id=device.id,
        station_id=station_id,
        zone_id=body.zone_id,
        officer_id=body.officer_id,
        event_type=body.event_type.value,
        status=EventStatus.NEW.value,
        severity_band=band.value,
        threat_score=body.threat_score,
        confidence=body.confidence,
        occurred_at=occurred_at,
        received_at=datetime.now(UTC),
        lat=body.lat,
        lon=body.lon,
        local_seq=body.local_seq,
        payload=body.payload,
        content_hash=content_hash,
        prev_event_hash=prev_hash,
        event_hash=event_hash,
        chain_seq=max_seq + 1,
    )
    db.add(event)
    db.flush()
    head.head_hash = event_hash
    head.head_event_id = event.id
    db.commit()
    db.refresh(event)
    return event, True


def verify_chain(db: Session) -> tuple[bool, int, str, str]:
    head = db.get(AuditChainHead, 1)
    events = db.scalars(select(SecurityEvent).order_by(SecurityEvent.chain_seq.asc())).all()
    prev = GENESIS_HASH
    for event in events:
        fields = canonical_event_fields(
            event_id=event.id,
            device_id=event.device_id,
            station_id=event.station_id,
            zone_id=event.zone_id,
            officer_id=event.officer_id,
            event_type=event.event_type,
            threat_score=event.threat_score,
            confidence=event.confidence,
            occurred_at=event.occurred_at,
            lat=event.lat,
            lon=event.lon,
            local_seq=event.local_seq,
            payload=event.payload or {},
        )
        content, linked = hashes_for_event(fields, prev)
        if event.prev_event_hash != prev:
            return False, len(events), head.head_hash, f"prev hash mismatch at chain_seq={event.chain_seq}"
        if event.content_hash != content:
            return False, len(events), head.head_hash, f"content hash mismatch at chain_seq={event.chain_seq}"
        if event.event_hash != linked:
            return False, len(events), head.head_hash, f"event hash mismatch at chain_seq={event.chain_seq}"
        prev = event.event_hash
    expected_head = prev if events else GENESIS_HASH
    if head is None or head.head_hash != expected_head:
        return False, len(events), head.head_hash if head else "", "chain head does not match last event"
    return True, len(events), expected_head, "ok"
