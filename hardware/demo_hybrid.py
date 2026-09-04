import time
import httpx
from edge.app.db import EdgeDatabase
from edge.app.schemas import SyncStatus
from edge.app.sync import EdgeSyncWorker
from hardware.patrol import WheeledPatrolSimulator, PATROL_DEVICE_ID
from ai.inference.models import DetectionEvidence

DB_PATH = "demo_patrol_edge.db"
API_BASE_URL = "http://localhost:8000/api/v1"
USERNAME = "admin"
PASSWORD = "admin"

def run_patrol_demo():
    print("=== MOBILE PATROL UNIT SIMULATION ===")
    print(f"Device ID: {PATROL_DEVICE_ID}")
    
    # Initialize Edge Offline Database
    db = EdgeDatabase(DB_PATH)
    db.clear() # clear for demo
    
    patrol = WheeledPatrolSimulator(edge_db=db)
    
    # 1. Observation 1: Normal Green
    print("\n--- Event 1: Normal Routine Patrol ---")
    wp = patrol.get_current_waypoint()
    print(f"Location: {wp.name} ({wp.lat}, {wp.lon}) [SIMULATED]")
    ev1 = patrol.emit_routine_observation()
    print(f"Generated UUID: {ev1.event_id}")
    print(f"Score: {ev1.threat_score}, Type: {ev1.event_type}, Status: {ev1.sync_status.value}")
    
    patrol.move_to_next_waypoint()
    
    # 2. Observation 2: RED Threat Event
    print("\n--- Event 2: Scanning Threat Zone ---")
    wp = patrol.get_current_waypoint()
    print(f"Location: {wp.name} ({wp.lat}, {wp.lon}) [SIMULATED]")
    
    # Simulate Unattended Luggage detection
    suspicious_evidence = DetectionEvidence(
        camera_id="cam_thermal_01",
        detection_source="thermal",
        object_type="luggage",
        confidence=0.98,
        bbox={"x": 50, "y": 100, "w": 20, "h": 20},
        dwell_seconds=600,  # 10 minutes (triggers RED)
        person_left_object=True,
        temperature_celsius=25.0
    )
    
    ev2 = patrol.emit_threat_observation(evidence=suspicious_evidence)
    print(f"Detected: {ev2.payload['explanation']}")
    print(f"Generated UUID: {ev2.event_id}")
    print(f"Score: {ev2.threat_score}, Type: {ev2.event_type}, Status: {ev2.sync_status.value}")
    
    # 3. Observation 3: Moving Forward (Normal)
    patrol.move_to_next_waypoint()
    print("\n--- Event 3: Proceeding on Route ---")
    wp = patrol.get_current_waypoint()
    print(f"Location: {wp.name} ({wp.lat}, {wp.lon}) [SIMULATED]")
    ev3 = patrol.emit_routine_observation()
    print(f"Score: {ev3.threat_score}, Type: {ev3.event_type}, Status: {ev3.sync_status.value}")
    
    print("\n=== NETWORK DISCONNECTED (TUNNEL) ===")
    worker = EdgeSyncWorker(db, "http://offline-network.local/broken", USERNAME, PASSWORD)
    worker.sync_batch()
    
    pending = db.get_pending_events()
    print(f"Pending queue size: {len(pending)}")
    for ev in pending:
        print(f"  - {ev.event_id} -> {ev.sync_status.value} (Retries: {ev.retry_count})")
    
    print("\n=== NETWORK RESTORED ===")
    worker.api_base_url = API_BASE_URL
    synced_qty = worker.sync_batch()
    print(f"Successfully pushed {synced_qty} events to Central API.")
    
    pending_now = db.get_pending_events()
    print(f"Pending queue size: {len(pending_now)}")
    
    import sqlite3
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        saved = conn.execute("SELECT sync_status FROM edge_events WHERE event_id = ?", (str(ev2.event_id),)).fetchone()
        print(f"Final local status of RED event: {saved['sync_status']}")
        
    print("\n=== DEMO COMPLETE ===")

if __name__ == "__main__":
    run_patrol_demo()
