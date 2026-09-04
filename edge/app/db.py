import json
import sqlite3
from typing import Optional, List, Dict, Any
from datetime import datetime, UTC
from uuid import UUID

from .schemas import EdgeSecurityEvent, SyncStatus

class EdgeDatabase:
    def __init__(self, db_path: str = "edge_events.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS edge_events (
                        event_id TEXT PRIMARY KEY,
                        device_id TEXT NOT NULL,
                        station_id TEXT NOT NULL,
                        zone_id TEXT,
                        event_type TEXT NOT NULL,
                        threat_score REAL NOT NULL,
                        confidence REAL,
                        occurred_at TEXT NOT NULL,
                        lat REAL,
                        lon REAL,
                        payload TEXT NOT NULL,
                        local_seq INTEGER,
                        sync_status TEXT NOT NULL,
                        retry_count INTEGER DEFAULT 0,
                        last_error TEXT,
                        created_at TEXT NOT NULL
                    )
                ''')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_sync_status ON edge_events (sync_status, local_seq)')
        finally:
            conn.close()

    def insert_event(self, event: EdgeSecurityEvent) -> None:
        """Saves a new event to the exact exact event_id across retries rule."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute('''
                    INSERT OR IGNORE INTO edge_events 
                    (event_id, device_id, station_id, zone_id, event_type, threat_score, confidence, occurred_at, lat, lon, payload, local_seq, sync_status, retry_count, last_error, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(event.event_id), str(event.device_id), str(event.station_id),
                    str(event.zone_id) if event.zone_id else None,
                    event.event_type, event.threat_score, event.confidence,
                    event.occurred_at.isoformat(), event.lat, event.lon,
                    json.dumps(event.payload), event.local_seq, event.sync_status.value,
                    event.retry_count, event.last_error, event.created_at.isoformat()
                ))
        finally:
            conn.close()

    def get_pending_events(self, limit: int = 50) -> List[EdgeSecurityEvent]:
        """Tolerates temporal boundaries; fetches queued items ascending by local_seq."""
        status_in = (SyncStatus.QUEUED.value, SyncStatus.RETRY_WAIT.value)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM edge_events 
                WHERE sync_status IN (?, ?)
                ORDER BY local_seq ASC
                LIMIT ?
            ''', (status_in[0], status_in[1], limit))
            
            rows = cursor.fetchall()
            return [self._row_to_event(row) for row in rows]
        finally:
            conn.close()

    def update_event_status(self, event_id: UUID, status: SyncStatus, last_error: Optional[str] = None):
        """Never deletes a local event. Marks SYNCED or RETRY_WAIT safely."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                if status == SyncStatus.RETRY_WAIT:
                    conn.execute('''
                        UPDATE edge_events 
                        SET sync_status = ?, retry_count = retry_count + 1, last_error = ?
                        WHERE event_id = ?
                    ''', (status.value, last_error, str(event_id)))
                else:
                    conn.execute('''
                        UPDATE edge_events 
                        SET sync_status = ?, last_error = ?
                        WHERE event_id = ?
                    ''', (status.value, last_error, str(event_id)))
        finally:
            conn.close()

    def clear(self):
        """Only used for tests."""
        conn = sqlite3.connect(self.db_path)
        try:
            with conn:
                conn.execute('DELETE FROM edge_events')
        finally:
            conn.close()

    def _row_to_event(self, row: sqlite3.Row) -> EdgeSecurityEvent:
        return EdgeSecurityEvent(
            event_id=UUID(row['event_id']),
            device_id=UUID(row['device_id']),
            station_id=UUID(row['station_id']),
            zone_id=UUID(row['zone_id']) if row['zone_id'] else None,
            event_type=row['event_type'],
            threat_score=float(row['threat_score']),
            confidence=float(row['confidence']) if row['confidence'] is not None else None,
            occurred_at=datetime.fromisoformat(row['occurred_at']),
            lat=row['lat'],
            lon=row['lon'],
            payload=json.loads(row['payload']),
            local_seq=row['local_seq'],
            sync_status=SyncStatus(row['sync_status']),
            retry_count=row['retry_count'],
            last_error=row['last_error'],
            created_at=datetime.fromisoformat(row['created_at'])
        )
