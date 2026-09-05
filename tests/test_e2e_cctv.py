import asyncio
import json
import sys
from pathlib import Path
import websockets
import psycopg

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai.cctv.alert_manager import AlertManager
from ai.inference.models import DetectionEvidence
from ai.inference.scoring import calculate_threat


async def run_e2e_test():
    print("--- [E2E] Testing AlertManager -> Backend -> WebSocket -> DB Pipeline ---")
    
    # 1. Connect to WebSocket
    ws_url = "ws://localhost:8000/ws/events"
    print(f"[1] Connecting to WebSocket: {ws_url} ...")
    async with websockets.connect(ws_url) as ws:
        print("[1] WebSocket connected successfully!")

        # 2. Formulate threat
        evidence = DetectionEvidence(
            object_type="backpack",
            confidence=0.92,
            dwell_seconds=70.0,
            person_left_object=True,
            detection_source="CCTV-GATE-1"
        )
        analysis = calculate_threat(evidence)
        print(f"[2] Evaluated Threat: Score={analysis.threat_score} ({analysis.severity.value})")

        # 3. Dispatch via AlertManager
        alert_mgr = AlertManager()
        print("[3] Dispatching alert via AlertManager...")
        event_record = alert_mgr.dispatch("test_track_e2e", analysis)
        assert event_record is not None, "Dispatch failed!"
        event_id = event_record["id"]
        print(f"[3] Event successfully accepted by backend! ID: {event_id}")

        # 4. Await WebSocket broadcast
        print("[4] Listening for broadcast on WebSocket...")
        raw_msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
        ws_msg = json.loads(raw_msg)
        print(f"[4] Received WebSocket message type: '{ws_msg.get('type')}'")
        assert ws_msg.get("type") == "security_event"
        received_event = ws_msg.get("event", {})
        assert received_event.get("id") == event_id
        print(f"[4] Successfully verified broadcast for event ID: {event_id}")

        # 5. Verify storage in PostgreSQL
        print("[5] Querying PostgreSQL for persisted event & hash chain...")
        conn_str = "postgresql://railsentinel:railsentinel@localhost:5432/railsentinel"
        with psycopg.connect(conn_str) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, device_id, event_type, severity_band, threat_score, chain_seq, event_hash "
                    "FROM security_events WHERE id = %s",
                    (event_id,)
                )
                row = cur.fetchone()
                assert row is not None, "Event not found in database!"
                print(f"[5] DB Record Verified:")
                print(f"    - ID: {row[0]}")
                print(f"    - Device: {row[1]}")
                print(f"    - Type: {row[2]}")
                print(f"    - Severity: {row[3]}")
                print(f"    - Score: {row[4]}")
                print(f"    - Chain Seq: {row[5]}")
                print(f"    - Hash: {row[6][:16]}...")

    print("\n--- [E2E TEST PASSED] Full CCTV Pipeline Operational ---")


if __name__ == "__main__":
    asyncio.run(run_e2e_test())
