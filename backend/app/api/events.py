from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models.enums import EventStatus, SeverityBand
from app.models.event import SecurityEvent
from app.models.user import User
from app.schemas import (
    EventCreate,
    EventDetail,
    EventListResponse,
    EventSummary,
)
from app.services.events import ingest_event
from app.services.websocket import manager


router = APIRouter(
    prefix="/api/v1/events",
    tags=["events"],
)


@router.post(
    "",
    response_model=EventDetail,
    status_code=status.HTTP_201_CREATED,
)
async def create_event(
    body: EventCreate,
    response: Response,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> SecurityEvent:
    event, created = ingest_event(db, body)

    if not created:
        response.status_code = status.HTTP_200_OK
        return event

    event_data = EventDetail.model_validate(event).model_dump(mode="json")

    await manager.broadcast(
        {
            "type": "security_event",
            "event": event_data,
        }
    )

    return event


@router.get(
    "",
    response_model=EventListResponse,
)
def list_events(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
    status_filter: EventStatus | None = Query(
        default=None,
        alias="status",
    ),
    severity_band: SeverityBand | None = None,
    station_id: UUID | None = None,
    device_id: UUID | None = None,
    since: datetime | None = None,
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
) -> EventListResponse:
    query = select(SecurityEvent)
    count_query = select(func.count()).select_from(SecurityEvent)

    if status_filter is not None:
        query = query.where(
            SecurityEvent.status == status_filter.value
        )
        count_query = count_query.where(
            SecurityEvent.status == status_filter.value
        )

    if severity_band is not None:
        query = query.where(
            SecurityEvent.severity_band == severity_band.value
        )
        count_query = count_query.where(
            SecurityEvent.severity_band == severity_band.value
        )

    if station_id is not None:
        query = query.where(
            SecurityEvent.station_id == station_id
        )
        count_query = count_query.where(
            SecurityEvent.station_id == station_id
        )

    if device_id is not None:
        query = query.where(
            SecurityEvent.device_id == device_id
        )
        count_query = count_query.where(
            SecurityEvent.device_id == device_id
        )

    if since is not None:
        query = query.where(
            SecurityEvent.received_at >= since
        )
        count_query = count_query.where(
            SecurityEvent.received_at >= since
        )

    total = db.scalar(count_query) or 0

    rows = db.scalars(
        query
        .order_by(SecurityEvent.received_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()

    return EventListResponse(
        items=[
            EventSummary.model_validate(row)
            for row in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{event_id}",
    response_model=EventDetail,
)
def get_event(
    event_id: UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> SecurityEvent:
    event = db.get(SecurityEvent, event_id)

    if event is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="event not found",
        )

    return event