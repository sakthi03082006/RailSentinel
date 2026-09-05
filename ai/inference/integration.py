from datetime import datetime, UTC
from uuid import UUID, uuid4
from typing import Dict, Any

from .models import ThreatAnalysis

# Hardcoded demo identifiers from backend/app/db/ids.py
DEMO_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000003")
DEMO_STATION_ID = UUID("00000000-0000-4000-8000-000000000001")
DEMO_ZONE_ID = UUID("00000000-0000-4000-8000-000000000002")

def map_analysis_to_event_payload(
    analysis: ThreatAnalysis,
    device_id: UUID = DEMO_DEVICE_ID,
    lat: float | None = 28.6142,
    lon: float | None = 77.2090,
) -> dict:
    """
    Converts a ThreatAnalysis into a valid RailSentinel Security Event API payload.
    Preserves exactly the threat_score and evidence structure.
    """
    evidence = analysis.evidence
    
    # Map AI objects and behaviors to the backend EventType
    if "person" in evidence.object_type.lower() and not evidence.person_left_object:
        event_type = "anomaly"
    elif evidence.person_left_object or evidence.object_type.lower() in (
        "luggage", "backpack", "bag", "package", "handbag", "suitcase"
    ):
        event_type = "unattended_object"
    else:
        event_type = "detection"
        
    payload = {
        "id": str(uuid4()),
        "device_id": str(device_id),
        "station_id": str(DEMO_STATION_ID),
        "zone_id": str(DEMO_ZONE_ID),
        "event_type": event_type,
        "threat_score": analysis.threat_score,  # Preserved exact risk score
        "confidence": evidence.confidence,
        "occurred_at": datetime.now(UTC).isoformat(),
        "payload": {
            "evidence": {
                "object_type": evidence.object_type,
                "dwell_seconds": evidence.dwell_seconds,
                "person_left_object": evidence.person_left_object,
                "detection_source": evidence.detection_source
            },
            "scientific_boundary_notice": "RGB/thermal CV threat screening. No chemical identification.",
            "explanation": analysis.explanation
        }
    }
    if lat is not None:
        payload["lat"] = lat
    if lon is not None:
        payload["lon"] = lon
    return payload
