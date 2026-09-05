import time
from typing import Dict, Optional
from uuid import UUID, uuid4
import httpx

from ai.inference.models import ThreatAnalysis, Severity
from ai.inference.integration import map_analysis_to_event_payload

# CCTV device registered in DB (from scripts/register_cctv.py & backend/app/db/ids.py)
CCTV_DEVICE_ID = UUID("00000000-0000-4000-8000-000000000005")


class AlertManager:
    """
    Manages stateful alert dispatching, authentication token renewal,
    and debouncing/cooldown to prevent event flooding into the backend.
    Enforces one physical tracked object = one active incident with in-place
    escalations from YELLOW to RED.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000/api/v1",
        username: str = "admin",
        password: str = "admin",
        device_id: UUID = CCTV_DEVICE_ID,
        cooldown_seconds: float = 8.0,
        min_report_severity: Severity = Severity.YELLOW,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.device_id = device_id
        self.cooldown_seconds = cooldown_seconds
        self.min_report_severity = min_report_severity

        self.access_token: Optional[str] = None
        self.token_expiry_time: float = 0.0

        # State tracking: track_id -> dict(incident_id, first_event_id, last_event_id, last_sent_time, last_severity, last_score, escalated)
        self.dispatched_states: Dict[str, dict] = {}

    def _ensure_authenticated(self) -> bool:
        """Ensures a valid JWT access token is available."""
        if self.access_token and time.time() < (self.token_expiry_time - 60):
            return True

        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.post(
                    f"{self.base_url}/auth/login",
                    json={"username": self.username, "password": self.password},
                )
                if res.status_code == 200:
                    data = res.json()
                    self.access_token = data["access_token"]
                    self.token_expiry_time = time.time() + 3600  # Default 60 mins
                    return True
                else:
                    print(f"[AlertManager] Login failed: {res.status_code} {res.text}")
                    return False
        except Exception as e:
            print(f"[AlertManager] Backend connection error during login: {e}")
            return False

    def should_dispatch(self, track_key: str, analysis: ThreatAnalysis) -> bool:
        """
        Determines whether an alert should be sent to the backend based on:
        - Severity threshold (YELLOW or RED by default)
        - Debounce cooldown per tracked object
        - Immediate escalation if severity changes (e.g. YELLOW -> RED)
        - Strict suppression of repeated detections for the same active incident
        """
        # Skip low-risk green events from flooding incident queue
        if self.min_report_severity == Severity.YELLOW and analysis.severity == Severity.GREEN:
            return False

        now = time.time()
        state = self.dispatched_states.get(track_key)

        if state is None:
            # First time this track triggers an alert
            return True

        last_sent = state["last_sent_time"]
        last_severity = state["last_severity"]

        # Escalate if severity upgraded from YELLOW to RED
        if last_severity == Severity.YELLOW and analysis.severity == Severity.RED:
            # Minimal debounce to avoid rapid fluttering
            if (now - last_sent) >= min(self.cooldown_seconds, 1.0):
                return True

        # Repeated frames for the same track without escalation must NOT create duplicate events
        return False

    def dispatch(self, track_key: str, analysis: ThreatAnalysis) -> Optional[dict]:
        """
        Dispatches a security event payload to POST /api/v1/events.
        Binds explicit incident_id and track_id so the dashboard updates the existing incident.
        """
        if not self.should_dispatch(track_key, analysis):
            return None

        if not self._ensure_authenticated():
            print("[AlertManager] Cannot dispatch: Backend authentication failed.")
            return None

        state = self.dispatched_states.get(track_key)
        if state is None:
            incident_id = f"inc-{uuid4()}"
            is_escalation = False
        else:
            incident_id = state["incident_id"]
            is_escalation = True

        payload = map_analysis_to_event_payload(
            analysis=analysis,
            device_id=self.device_id,
            lat=28.6142,
            lon=77.2090,
            track_id=track_key,
            incident_id=incident_id,
            is_escalation=is_escalation,
        )

        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.post(f"{self.base_url}/events", json=payload, headers=headers)
                # Fallback to default demo simulator device if specific CCTV device not yet registered
                if res.status_code == 404 and "device" in res.text:
                    fallback_id = UUID("00000000-0000-4000-8000-000000000003")
                    if self.device_id != fallback_id:
                        print(f"[AlertManager] Device {self.device_id} not in DB, falling back to default device {fallback_id}")
                        self.device_id = fallback_id
                        payload["device_id"] = str(fallback_id)
                        res = client.post(f"{self.base_url}/events", json=payload, headers=headers)

                if res.status_code in (200, 201):
                    event_data = res.json()
                    now = time.time()
                    self.dispatched_states[track_key] = {
                        "incident_id": incident_id,
                        "first_event_id": state["first_event_id"] if state else event_data.get("id"),
                        "last_event_id": event_data.get("id"),
                        "last_sent_time": now,
                        "last_severity": analysis.severity,
                        "last_score": analysis.threat_score,
                        "escalated": is_escalation or (state.get("escalated", False) if state else False),
                    }
                    action_tag = "ESCALATED TO RED" if is_escalation else "NEW INCIDENT"
                    print(
                        f"[AlertManager] DISPATCHED ALERT [{action_tag}]: {analysis.evidence.object_type.upper()} "
                        f"| Score: {analysis.threat_score:.1f} ({analysis.severity.value}) "
                        f"| Incident: {incident_id} | Event ID: {event_data.get('id', 'ok')}"
                    )
                    return event_data
                else:
                    print(f"[AlertManager] Event dispatch failed: {res.status_code} {res.text}")
                    return None
        except Exception as e:
            print(f"[AlertManager] Network error dispatching event: {e}")
            return None

    def retire_track(self, track_key: str) -> None:
        """
        Cleans up track state when the physical object leaves the camera view.
        Allows future detections of a new object to create a fresh incident.
        """
        self.dispatched_states.pop(track_key, None)
