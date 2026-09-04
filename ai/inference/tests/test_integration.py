import pytest
from uuid import UUID
from copy import deepcopy

from ai.inference.models import ThreatAnalysis, DetectionEvidence, Severity
from ai.inference.integration import map_analysis_to_event_payload, DEMO_DEVICE_ID, DEMO_STATION_ID

def test_map_analysis_to_event_payload():
    evidence = DetectionEvidence(
        object_type="luggage",
        confidence=0.85,
        dwell_seconds=90.0,
        person_left_object=True,
        detection_source="SIM-1"
    )
    analysis = ThreatAnalysis(
        evidence=evidence,
        threat_score=85.5,
        severity=Severity.RED,
        explanation="High threat detected based on abandoned luggage."
    )
    
    payload = map_analysis_to_event_payload(analysis)
    
    assert payload["device_id"] == str(DEMO_DEVICE_ID)
    assert payload["station_id"] == str(DEMO_STATION_ID)
    assert payload["event_type"] == "unattended_object"  # luggage + person_left_object
    assert payload["threat_score"] == 85.5
    assert payload["confidence"] == 0.85
    
    assert "payload" in payload
    assert "evidence" in payload["payload"]
    assert payload["payload"]["evidence"]["object_type"] == "luggage"
    assert "scientific_boundary_notice" in payload["payload"]
    assert payload["payload"]["scientific_boundary_notice"] == "RGB/thermal CV threat screening. No chemical identification."
    assert payload["payload"]["explanation"] == "High threat detected based on abandoned luggage."

def test_map_person_anomaly():
    evidence = DetectionEvidence(
        object_type="person",
        confidence=0.9,
        dwell_seconds=120.0,
        person_left_object=False,
        detection_source="SIM-2"
    )
    analysis = ThreatAnalysis(
        evidence=evidence,
        threat_score=65.0,
        severity=Severity.RED,
        explanation="Person lingering."
    )
    
    payload = map_analysis_to_event_payload(analysis)
    
    assert payload["event_type"] == "anomaly"
    assert payload["threat_score"] == 65.0
