import time
import httpx
from uuid import UUID

from edge.app.db import EdgeDatabase
from edge.app.schemas import EdgeSecurityEvent, SyncStatus
from edge.app.sync import EdgeSyncWorker

# From backend IDs
DEMO_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000003")
DEMO_STATION_ID = UUID("00000000-0000-4000-8000-000000000001")
API_BASE_URL = "http://localhost:8000/api/v1"
USERNAME = "admin"
PASSWORD = "admin"
DB_PATH = "demo_offline_edge.db"

def run_demo():
    print("--- [EDGE] OFFLINE-FIRST EVENT PIPELINE DEMO ---")
    
    # 1. Initialize local Edge DB
    print("\n[EDGE] Initializing localized SQLite Queue...")
    db = EdgeDatabase(DB_PATH)
    
    # 2. Simulate AI execution WHILE OFFLINE
    print("[EDGE] Network physically disconnected. Detecting threat...")
    off_event = EdgeSecurityEvent(
        device_id=DEMO_DEVICE_ID,
        station_id=DEMO_STATION_ID,
        event_type="unattended_object",
        threat_score=80.0,
        confidence=0.99,
        sync_status=SyncStatus.QUEUED,
        payload={"note": "Offline generation test"}
    )
    db.insert_event(off_event)
    print(f"[EDGE] Generated local UUID: {off_event.event_id}")
    print("[EDGE] Event stored to persistent local queue > PENDING.")
    
    pending = db.get_pending_events()
    print(f"[EDGE] Checking DB rows... Found {len(pending)} pending event(s).")
    
    # 3. Try to sync over bad network 
    print("\n[EDGE] Sync Daemon initializing. Forcing network failure scenario...")
    worker = EdgeSyncWorker(db, "http://localhost:9999/broken/path", USERNAME, PASSWORD)
    worker.sync_batch()
    
    pending_after_fail = db.get_pending_events()
    event_status = pending_after_fail[0].sync_status
    retry_ct = pending_after_fail[0].retry_count
    
    print(f"[EDGE] Network Failed. Status: {event_status.value} (Retries: {retry_ct})")
    
    # 4. Network Restored!
    print("\n[EDGE] Network RESTORED. Restarting sync loop against genuine API...")
    worker.api_base_url = API_BASE_URL
    synced_qty = worker.sync_batch()
    
    print(f"[EDGE] Sync Batch complete. Successfully pushed {synced_qty} event(s).")
    
    # 5. Check API confirmation
    import sqlite3
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        saved = conn.execute("SELECT * FROM edge_events WHERE event_id = ?", (str(off_event.event_id),)).fetchone()
        print(f"[EDGE] Final Local State => Status: {saved['sync_status']}, Error: {saved['last_error']}")
        
    print("\n--- [EDGE] DEMO COMPLETE ---")
    
if __name__ == "__main__":
    run_demo()
