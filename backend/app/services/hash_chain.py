from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

GENESIS_HASH = "0" * 64


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _dec(value: Decimal | None, places: int) -> str | None:
    if value is None:
        return None
    quantized = Decimal(value).quantize(Decimal("1").scaleb(-places))
    return format(quantized, "f")


def canonical_event_fields(
    *,
    event_id: UUID,
    device_id: UUID,
    station_id: UUID,
    zone_id: UUID | None,
    officer_id: UUID | None,
    event_type: str,
    threat_score: Decimal,
    confidence: Decimal | None,
    occurred_at: datetime,
    lat: Decimal | None,
    lon: Decimal | None,
    local_seq: int | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return {
        "confidence": _dec(confidence, 4),
        "device_id": str(device_id),
        "event_type": event_type,
        "id": str(event_id),
        "lat": _dec(lat, 6),
        "local_seq": local_seq,
        "lon": _dec(lon, 6),
        "occurred_at": _iso_utc(occurred_at),
        "officer_id": str(officer_id) if officer_id else None,
        "payload": payload,
        "station_id": str(station_id),
        "threat_score": _dec(threat_score, 2),
        "zone_id": str(zone_id) if zone_id else None,
    }


def canonical_json(fields: dict[str, Any]) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def content_hash_from_fields(fields: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(fields))


def link_event_hash(content_hash: str, prev_event_hash: str) -> str:
    return sha256_hex(f"{content_hash}|{prev_event_hash}")


def hashes_for_event(fields: dict[str, Any], prev_event_hash: str) -> tuple[str, str]:
    content = content_hash_from_fields(fields)
    return content, link_event_hash(content, prev_event_hash)
