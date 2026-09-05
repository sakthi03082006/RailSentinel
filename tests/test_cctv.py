import time
import pytest
from ai.cctv.detector import DetectedObject
from ai.cctv.tracker import SecurityObjectTracker
from ai.cctv.alert_manager import AlertManager
from ai.inference.models import Severity, ThreatAnalysis, DetectionEvidence
from ai.inference.scoring import calculate_threat


def test_tracker_initial_detection():
    tracker = SecurityObjectTracker(source_name="TEST-CAM")
    
    # Simulate a backpack detected
    det = DetectedObject(
        class_id=24,
        class_name="backpack",
        confidence=0.88,
        bbox=(100, 100, 200, 200),
        center=(150, 150),
        is_luggage=True,
    )
    
    tracks, evidences = tracker.update([det])
    assert len(tracks) == 1
    assert tracks[0].track_id == 1
    assert tracks[0].class_name == "backpack"
    assert len(evidences) == 1
    assert evidences[0].object_type == "backpack"
    assert evidences[0].confidence == 0.88
    # Initial frame has not confirmed separation
    assert tracks[0].person_left_object is False


def test_person_holding_bag_never_alerts():
    """
    CRITICAL FALSE-POSITIVE TEST:
    A person standing near or holding a bag must NEVER trigger an unattended alert,
    even if tracked for an extended duration.
    """
    tracker = SecurityObjectTracker(source_name="TEST-CAM", owner_proximity_px=150.0)
    alert_mgr = AlertManager()

    base_time = 1000.0

    # Person holding handbag (overlapping bounding boxes)
    handbag = DetectedObject(
        class_id=26,
        class_name="handbag",
        confidence=0.85,
        bbox=(120, 120, 180, 180),
        center=(150, 150),
        is_luggage=True,
    )
    person = DetectedObject(
        class_id=0,
        class_name="person",
        confidence=0.92,
        bbox=(100, 80, 240, 300),
        center=(170, 190),
        is_luggage=False,
    )

    # Simulate 30 seconds of person holding/wearing handbag
    for step in range(30):
        t = base_time + step
        tracks, evidences = tracker.update([handbag, person], current_time=t)
        bag_track = [tr for tr in tracks if tr.is_luggage][0]
        bag_evidence = [ev for ev in evidences if ev.object_type == "handbag"][0]

        # Must strictly remain attended
        assert bag_track.is_attended is True
        assert bag_track.person_left_object is False
        assert bag_track.unattended_seconds == 0.0
        assert bag_evidence.person_left_object is False
        assert bag_evidence.dwell_seconds == 0.0

        # Threat evaluation must remain GREEN
        analysis = calculate_threat(bag_evidence)
        assert analysis.severity == Severity.GREEN
        assert analysis.threat_score <= 10.0

        # AlertManager must NOT dispatch
        assert alert_mgr.should_dispatch("track_1", analysis) is False


def test_brief_person_flicker_resets_and_holds():
    """
    TEMPORARY FLICKER TEST:
    Brief detection dropouts or person temporarily stepping away (<3.0s)
    must hold the separation timer and reset upon return without alerting.
    """
    tracker = SecurityObjectTracker(
        source_name="TEST-CAM",
        owner_proximity_px=100.0,
        separation_confirm_seconds=3.0,
    )

    handbag = DetectedObject(
        class_id=26,
        class_name="handbag",
        confidence=0.9,
        bbox=(100, 100, 150, 150),
        center=(125, 125),
        is_luggage=True,
    )
    person = DetectedObject(
        class_id=0,
        class_name="person",
        confidence=0.9,
        bbox=(120, 80, 200, 250),
        center=(160, 165),
        is_luggage=False,
    )

    t0 = 2000.0
    # t0: Person standing next to handbag
    tracker.update([handbag, person], current_time=t0)

    # t0 + 1.0s: Person detection flickers off (first absent frame initializes timer)
    tracker.update([handbag], current_time=t0 + 1.0)

    # t0 + 2.0s: 1.0s into flicker (separation 1.0s < 3.0s threshold)
    tracks, evidences = tracker.update([handbag], current_time=t0 + 2.0)
    bag = tracks[0]
    # Separation time is only 1.0s < 3.0s threshold -> hold state
    assert bag.person_left_object is False
    assert bag.unattended_seconds == 1.0
    ev = evidences[0]
    assert ev.person_left_object is False

    # t0 + 2.5s: Person returns (flicker ends)
    tracks, evidences = tracker.update([handbag, person], current_time=t0 + 2.5)
    bag = tracks[0]
    # Timer must immediately reset to 0
    assert bag.is_attended is True
    assert bag.person_left_object is False
    assert bag.unattended_seconds == 0.0


def test_moving_bag_prevents_unattended_alert():
    """
    STATIONARY PERSISTENCE TEST:
    If a bag is moving across frames (e.g. being carried or rolling),
    drift > max_stationary_drift_px resets unattended timer.
    """
    tracker = SecurityObjectTracker(
        source_name="TEST-CAM",
        separation_confirm_seconds=3.0,
        max_stationary_drift_px=30.0,
    )

    t0 = 3000.0
    # Bag moves significantly between frames (drift = 50px each step)
    for i in range(5):
        bag_moving = DetectedObject(
            class_id=24,
            class_name="backpack",
            confidence=0.9,
            bbox=(100 + i * 50, 100, 150 + i * 50, 150),
            center=(125 + i * 50, 125),
            is_luggage=True,
        )
        tracks, evidences = tracker.update([bag_moving], current_time=t0 + i * 1.0)

    # Because drift occurred repeatedly, separation never confirmed
    bag = tracks[0]
    assert bag.person_left_object is False


def test_genuine_unattended_luggage_triggers_alert():
    """
    GENUINE DETECTION TEST:
    A bag that remains stationary after person confirmed left (>3.0s)
    must escalate from YELLOW to RED as unattended dwell increases.
    """
    tracker = SecurityObjectTracker(
        source_name="TEST-CAM",
        owner_proximity_px=100.0,
        separation_confirm_seconds=3.0,
    )
    alert_mgr = AlertManager(cooldown_seconds=5.0)

    backpack = DetectedObject(
        class_id=24,
        class_name="backpack",
        confidence=0.88,
        bbox=(100, 100, 150, 150),
        center=(125, 125),
        is_luggage=True,
    )
    person = DetectedObject(
        class_id=0,
        class_name="person",
        confidence=0.92,
        bbox=(120, 80, 200, 250),
        center=(160, 165),
        is_luggage=False,
    )
    person_away = DetectedObject(
        class_id=0,
        class_name="person",
        confidence=0.90,
        bbox=(500, 80, 580, 250),
        center=(540, 165),
        is_luggage=False,
    )

    t0 = 4000.0
    # Frame 1: Person next to backpack
    tracker.update([backpack, person], current_time=t0)

    # Frame 2: Person walks away at t0 + 1.0s (only 1s separation: debounce hold)
    tracks, evidences = tracker.update([backpack, person_away], current_time=t0 + 1.0)
    assert tracks[0].person_left_object is False

    # Frame 3: At t0 + 4.0s (3.0s continuous separation reached)
    tracks, evidences = tracker.update([backpack, person_away], current_time=t0 + 4.0)
    bag = tracks[0]
    assert bag.person_left_object is True
    assert bag.unattended_seconds == 3.0

    ev = evidences[0]
    assert ev.person_left_object is True
    assert ev.dwell_seconds == 3.0

    analysis = calculate_threat(ev)
    # 10 (conf>0.8) + 40 (left) = 50.0 -> YELLOW
    assert analysis.threat_score == 50.0
    assert analysis.severity == Severity.YELLOW
    assert alert_mgr.should_dispatch("track_1", analysis) is True

    # Frame 4: At t0 + 35.0s (dwell > 30s)
    tracks, evidences = tracker.update([backpack, person_away], current_time=t0 + 35.0)
    bag = tracks[0]
    ev = evidences[0]
    assert ev.dwell_seconds == 34.0

    analysis_high = calculate_threat(ev)
    # 10 (conf) + 40 (left) + 10 (dwell>30) = 60.0 -> RED
    assert analysis_high.threat_score == 60.0
    assert analysis_high.severity == Severity.RED


def test_alert_manager_debounce_logic():
    alert_manager = AlertManager(cooldown_seconds=5.0)
    
    evidence = DetectionEvidence(
        object_type="backpack",
        confidence=0.9,
        dwell_seconds=65.0,
        person_left_object=True,
        detection_source="TEST-CAM"
    )
    analysis = calculate_threat(evidence)
    assert analysis.severity == Severity.RED
    
    # First dispatch allowed
    assert alert_manager.should_dispatch("track_1", analysis) is True
    
    # Record mock dispatch
    alert_manager.dispatched_states["track_1"] = {
        "last_sent_time": time.time(),
        "last_severity": analysis.severity,
        "last_score": analysis.threat_score,
    }
    
    # Second immediate dispatch should be blocked by cooldown
    assert alert_manager.should_dispatch("track_1", analysis) is False


def test_handbag_and_suitcase_threat_scoring():
    """
    Focused test verifying that handbag and suitcase YOLO classes are recognized
    as luggage and produce appropriate non-zero YELLOW/RED threat scores and allow dispatch.
    """
    # 1. Handbag with 41s dwell and person left object
    handbag_evidence = DetectionEvidence(
        object_type="handbag",
        confidence=0.75,
        dwell_seconds=41.0,
        person_left_object=True,
        detection_source="CCTV-GATE-1",
    )
    analysis = calculate_threat(handbag_evidence)

    # 40 for person left + 10 for dwell > 30s = 50.0 -> YELLOW
    assert analysis.threat_score == 50.0
    assert analysis.severity == Severity.YELLOW
    assert "Person observed leaving the object" in analysis.explanation
    assert "Object dwelling for 41.0 seconds" in analysis.explanation

    # AlertManager must allow dispatch for YELLOW
    alert_mgr = AlertManager()
    assert alert_mgr.should_dispatch("track_handbag_1", analysis) is True

    # 2. Handbag with >60s dwell, high confidence -> RED
    handbag_critical = DetectionEvidence(
        object_type="handbag",
        confidence=0.85,
        dwell_seconds=65.0,
        person_left_object=True,
        detection_source="CCTV-GATE-1",
    )
    analysis_critical = calculate_threat(handbag_critical)
    # 10 (conf) + 40 (left) + 20 (dwell>60) = 70.0 -> RED
    assert analysis_critical.threat_score == 70.0
    assert analysis_critical.severity == Severity.RED

    # 3. Suitcase unattended -> non-zero score
    suitcase_evidence = DetectionEvidence(
        object_type="suitcase",
        confidence=0.80,
        dwell_seconds=35.0,
        person_left_object=True,
        detection_source="CCTV-GATE-1",
    )
    analysis_suitcase = calculate_threat(suitcase_evidence)
    assert analysis_suitcase.threat_score == 50.0
    assert analysis_suitcase.severity == Severity.YELLOW
