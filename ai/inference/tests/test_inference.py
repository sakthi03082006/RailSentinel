import pytest
from ai.inference.models import DetectionEvidence, ThreatAnalysis, Severity
from ai.inference.scoring import calculate_threat
from ai.inference.simulator import InferenceSimulator

def test_evidence_model():
    evidence = DetectionEvidence(
        object_type="luggage",
        confidence=0.9,
        dwell_seconds=30.0,
        person_left_object=True,
        detection_source="CAM_1"
    )
    assert evidence.object_type == "luggage"
    assert evidence.confidence == 0.9

def test_scoring_high_threat():
    evidence = DetectionEvidence(
        object_type="luggage",
        confidence=0.95,
        dwell_seconds=70.0,
        person_left_object=True,
        detection_source="CAM_1"
    )
    analysis = calculate_threat(evidence)
    
    # 10 for conf, 40 for left object, 20 for 70s dwell = 70 score -> RED
    assert analysis.threat_score >= 60.0
    assert analysis.severity == Severity.RED

def test_scoring_low_threat():
    evidence = DetectionEvidence(
        object_type="person",
        confidence=0.6,
        dwell_seconds=5.0,
        person_left_object=False,
        detection_source="CAM_2"
    )
    analysis = calculate_threat(evidence)
    assert analysis.threat_score < 30.0
    assert analysis.severity == Severity.GREEN

def test_simulator():
    sim = InferenceSimulator(sources=["CAM_1", "CAM_2"])
    results = sim.run_cycle(count=5)
    assert len(results) == 5
    for r in results:
        assert isinstance(r, ThreatAnalysis)
