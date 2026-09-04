import sys
import httpx
from argparse import ArgumentParser

from .models import DetectionEvidence
from .scoring import calculate_threat
from .integration import map_analysis_to_event_payload

API_BASE_URL = "http://localhost:8000/api/v1"
USERNAME = "admin"
PASSWORD = "admin"

def run_demo(target_url: str = API_BASE_URL):
    print("Generating Deterministic High-Risk Demo Event...")
    
    # Generate deterministic high-risk event
    evidence = DetectionEvidence(
        object_type="luggage",
        confidence=0.9,
        dwell_seconds=95.0,
        person_left_object=True,
        detection_source="SIM-DEMO-CAM-1"
    )
    analysis = calculate_threat(evidence)
    print(f"Generated Event: {analysis.evidence.object_type} | Score: {analysis.threat_score} ({analysis.severity})")
    print(f"Explanation: {analysis.explanation}")
    
    payload = map_analysis_to_event_payload(analysis)
    
    print(f"\nAuthenticating with backend at {target_url}...")
    try:
        login_res = httpx.post(
            f"{target_url}/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=5.0
        )
        login_res.raise_for_status()
        token = login_res.json()["access_token"]
    except Exception as e:
        print(f"Failed to authenticate with backend: {e}")
        print("Falling back to local dry-run (simulation payload):")
        print(payload)
        return

    print("Posting security event to pipeline...")
    try:
        event_res = httpx.post(
            f"{target_url}/events",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0
        )
        event_res.raise_for_status()
        print("\nSuccess! Subsystem pipeline integrated successfully. Event posted:")
        print(event_res.json())
    except Exception as e:
        print(f"Failed to post event: {e}")
        try:
            print(event_res.json())
        except:
            pass

if __name__ == "__main__":
    parser = ArgumentParser(description="RailSentinel AI Simulator Demo")
    parser.add_argument("--url", default=API_BASE_URL, help="Base API URL")
    args = parser.parse_args()
    
    run_demo(args.url)
