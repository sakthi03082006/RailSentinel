import pytest
import os
from uuid import UUID

from hardware.patrol_sim import WheeledPatrolSimulator, PATROL_DEVICE_ID
from ai.inference.models import DetectionEvidence
from edge.app.db import EdgeDatabase
from edge.app.schemas import SyncStatus

TEST_DB = "test_patrol_queue.db"

@pytest.fixture(autouse=True)
def clean_db():
    if os.path.exists(TEST_DB):
        try: os.remove(TEST_DB)
        except: pass
    yield
    if os.path.exists(TEST_DB):
        try: os.remove(TEST_DB)
        except: pass

def test_patrol_identity():
    assert PATROL_DEVICE_ID == UUID("00000000-0000-4000-8000-000000000004")

def test_patrol_routing():
    db = EdgeDatabase(TEST_DB)
    patrol = WheeledPatrolSimulator(db)
    
    # Check start
    wp1 = patrol.get_current_waypoint()
    assert wp1.name == "North Gate"
    
    # Move
    patrol.move_to_next_waypoint()
    wp2 = patrol.get_current_waypoint()
    assert wp2.name == "Platform 1"
    assert wp2.lat == 28.6140

def test_green_event_creation():
    db = EdgeDatabase(TEST_DB)
    patrol = WheeledPatrolSimulator(db)
    
    evt = patrol.emit_routine_observation()
    
    assert evt.threat_score == 0.0
    assert evt.event_type == "patrol"
    assert evt.device_id == PATROL_DEVICE_ID
    assert evt.payload["route_information"]["simulated_data"] is True
    assert evt.lat == 28.6139  # First waypoint
    
    # Check DB
    pending = db.get_pending_events()
    assert len(pending) == 1
    assert pending[0].event_id == evt.event_id

def test_red_threat_event():
    db = EdgeDatabase(TEST_DB)
    patrol = WheeledPatrolSimulator(db)
    
    ev = DetectionEvidence(
        camera_id="cam_01",
        detection_source="thermal",
        object_type="luggage",
        confidence=0.99,
        bbox={"x": 50, "y": 100, "w": 20, "h": 20},
        dwell_seconds=600,
        person_left_object=True,
        temperature_celsius=25.0
    )
    
    evt = patrol.emit_threat_observation(ev)
    
    assert evt.threat_score > 50.0  # it should be 80.0 usually
    assert evt.event_type == "unattended_object" 
    assert evt.lat == 28.6139
    assert evt.payload["scientific_boundary_notice"] is not None
    assert "luggage" in evt.payload["evidence"]["object_type"]
    
    pending = db.get_pending_events()
    assert len(pending) == 1
    assert pending[0].threat_score == evt.threat_score
