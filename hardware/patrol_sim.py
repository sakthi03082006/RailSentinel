from datetime import datetime, UTC
from uuid import UUID
from typing import Dict, Any, List, Optional

from edge.app.schemas import EdgeSecurityEvent, SyncStatus
from edge.app.db import EdgeDatabase
from ai.inference.models import DetectionEvidence
from ai.inference.scoring import calculate_threat

PATROL_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000004")
STATION_ID = UUID("00000000-0000-4000-8000-000000000001")

class Waypoint:
    def __init__(self, lat: float, lon: float, name: str):
        self.lat = lat
        self.lon = lon
        self.name = name

class WheeledPatrolSimulator:
    def __init__(self, edge_db: EdgeDatabase):
        self.db = edge_db
        self.local_seq = 0
        self.route = [
            Waypoint(28.6139, 77.2090, "North Gate"),
            Waypoint(28.6140, 77.2095, "Platform 1"),
            Waypoint(28.6145, 77.2100, "Waiting Area B"),
        ]
        self.current_wp_idx = 0

    def move_to_next_waypoint(self):
        self.current_wp_idx = (self.current_wp_idx + 1) % len(self.route)

    def get_current_waypoint(self) -> Waypoint:
        return self.route[self.current_wp_idx]

    def _create_event(self, event_type: str, evidence: Optional[DetectionEvidence] = None) -> EdgeSecurityEvent:
        wp = self.get_current_waypoint()
        
        threat_score = 0.0
        severity = "GREEN"
        explanation = "Routine patrol waypoint reached."
        evidence_dict = {}

        if evidence:
            analysis = calculate_threat(evidence)
            threat_score = analysis.threat_score
            severity = analysis.severity.value
            explanation = analysis.explanation
            evidence_dict = analysis.evidence.model_dump()
            event_type = "unattended_object" if "luggage" in evidence.object_type.lower() else "anomaly"

        payload = {
            "route_information": {
                "waypoint_name": wp.name,
                "route_progress": f"{self.current_wp_idx + 1}/{len(self.route)}",
                "simulated_data": True
            }
        }
        
        if evidence:
            payload["evidence"] = evidence_dict
            payload["explanation"] = explanation
            payload["scientific_boundary_notice"] = "RGB/thermal CV threat screening. No chemical identification."
            
        self.local_seq += 1

        return EdgeSecurityEvent(
            device_id=PATROL_DEVICE_ID,
            station_id=STATION_ID,
            event_type=event_type,
            threat_score=threat_score,
            confidence=evidence.confidence if evidence else None,
            occurred_at=datetime.now(UTC),
            lat=wp.lat,
            lon=wp.lon,
            payload=payload,
            local_seq=self.local_seq,
            sync_status=SyncStatus.QUEUED
        )

    def emit_routine_observation(self):
        event = self._create_event(event_type="patrol")
        self.db.insert_event(event) # Add to SQLite offline Outbox
        return event

    def emit_threat_observation(self, evidence: DetectionEvidence):
        event = self._create_event(event_type="anomaly", evidence=evidence)
        self.db.insert_event(event) # Add to SQLite offline Outbox
        return event
