import time
import httpx
from typing import Optional

from .db import EdgeDatabase
from .schemas import SyncStatus, EdgeSecurityEvent

class EdgeSyncWorker:
    def __init__(self, db: EdgeDatabase, api_base_url: str, username: str, password: str):
        self.db = db
        self.api_base_url = api_base_url
        self.username = username
        self.password = password
        self.token: Optional[str] = None

    def login(self) -> bool:
        """Attempts to obtain a fresh JWT from the backend."""
        try:
            res = httpx.post(
                f"{self.api_base_url}/auth/login",
                json={"username": self.username, "password": self.password},
                timeout=5.0
            )
            res.raise_for_status()
            self.token = res.json()["access_token"]
            return True
        except httpx.RequestError as e:
            # Network issue, will retry later
            return False
        except httpx.HTTPStatusError as e:
            # Auth failed permanently or temporally
            return False

    def sync_batch(self, limit: int = 50) -> int:
        """Pushes events from SQLite to backend. Tolerates failures natively."""
        events = self.db.get_pending_events(limit=limit)
        if not events:
            return 0
        
        synced_count = 0
        for event in events:
            self.db.update_event_status(event.event_id, SyncStatus.SYNCING)
            
            # Auth token expired or missing
            if not self.token:
                if not self.login():
                    self._mark_retry(event.event_id, "Cannot authenticate")
                    continue
            
            # Idempotent push
            success, error = self._post_event(event)

            if success:
                self.db.update_event_status(event.event_id, SyncStatus.SYNCED)
                synced_count += 1
            else:
                if error == "401":
                    # JWT likely expired, drop token to trigger refresh next loop
                    self.token = None 
                    self._mark_retry(event.event_id, "401 Unauthorized - Need Refresh")
                else:
                    self._mark_retry(event.event_id, error)
        
        return synced_count

    def _post_event(self, event: EdgeSecurityEvent) -> tuple[bool, Optional[str]]:
        try:
            res = httpx.post(
                f"{self.api_base_url}/events",
                json=event.to_backend_payload(),
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=10.0
            )
            # Idempotent design: either 200 or 201 is functionally "Synced"
            if res.status_code in [200, 201]:
                return True, None
            
            return False, str(res.status_code)
        
        except httpx.RequestError as e:
            return False, f"NetworkError: {str(e)}"
        
    def _mark_retry(self, event_id, err_str):
        self.db.update_event_status(event_id, SyncStatus.RETRY_WAIT, last_error=err_str)

    def compute_backoff(self, retry_count: int) -> float:
        """Exponential backoff maxing at ~60s."""
        return min(60.0, (2 ** retry_count) + 1.0)
