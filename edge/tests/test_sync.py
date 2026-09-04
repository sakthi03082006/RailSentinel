import pytest
import os
from uuid import uuid4
from unittest.mock import Mock, patch

from edge.app.db import EdgeDatabase
from edge.app.schemas import EdgeSecurityEvent, SyncStatus
from edge.app.sync import EdgeSyncWorker

TEST_DB = "test_edge.db"

@pytest.fixture(autouse=True)
def setup_teardown():
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    yield
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

def test_persistence_and_reload():
    db = EdgeDatabase(TEST_DB)
    ev = EdgeSecurityEvent(
        device_id=uuid4(),
        station_id=uuid4(),
        event_type="test",
        threat_score=50.0,
        sync_status=SyncStatus.QUEUED
    )
    db.insert_event(ev)
    pending = db.get_pending_events()
    assert len(pending) == 1
    assert pending[0].event_id == ev.event_id
    assert pending[0].sync_status == SyncStatus.QUEUED

def test_no_duplicate_overwrite():
    db = EdgeDatabase(TEST_DB)
    ev = EdgeSecurityEvent(
        device_id=uuid4(),
        station_id=uuid4(),
        event_type="test",
        threat_score=50.0,
        sync_status=SyncStatus.QUEUED
    )
    db.insert_event(ev)
    
    # Try inserting exactly the same UUID again
    ev.threat_score = 100.0  # modified payload
    db.insert_event(ev)
    
    pending = db.get_pending_events()
    assert len(pending) == 1
    # It should not have been overwritten (IGNORE rule in SQL)
    assert pending[0].threat_score == 50.0

@patch('edge.app.sync.httpx.post')
def test_sync_successful(mock_post):
    db = EdgeDatabase(TEST_DB)
    worker = EdgeSyncWorker(db, "http://test", "u", "p")
    worker.token = "fake"
    
    ev = EdgeSecurityEvent(
        device_id=uuid4(),
        station_id=uuid4(),
        event_type="test",
        threat_score=50.0,
        sync_status=SyncStatus.QUEUED
    )
    db.insert_event(ev)
    
    # Mock backend response (201 Created)
    mock_res = Mock()
    mock_res.status_code = 201
    mock_post.return_value = mock_res
    
    synced = worker.sync_batch()
    assert synced == 1
    assert mock_post.called
    
    # Fetch from db to verify update
    pending = db.get_pending_events()
    assert len(pending) == 0

@patch('edge.app.sync.httpx.post')
def test_sync_fail_retry_state(mock_post):
    db = EdgeDatabase(TEST_DB)
    worker = EdgeSyncWorker(db, "http://test", "u", "p")
    worker.token = "fake"
    
    ev = EdgeSecurityEvent(
        device_id=uuid4(),
        station_id=uuid4(),
        event_type="test",
        threat_score=50.0,
        sync_status=SyncStatus.QUEUED
    )
    db.insert_event(ev)
    
    import httpx
    mock_post.side_effect = httpx.RequestError("Network Down", request=Mock())
    
    worker.sync_batch()
    
    pending = db.get_pending_events()
    assert len(pending) == 1
    assert pending[0].sync_status == SyncStatus.RETRY_WAIT
    assert pending[0].retry_count == 1
    assert "NetworkError" in pending[0].last_error

@patch('edge.app.sync.httpx.post')
def test_jwt_refresh(mock_post):
    from edge.app.sync import EdgeSyncWorker
    db = EdgeDatabase(TEST_DB)
    worker = EdgeSyncWorker(db, "http://test", "u", "p")

    ev = EdgeSecurityEvent(
        device_id=uuid4(),
        station_id=uuid4(),
        event_type="test",
        threat_score=50.0,
        sync_status=SyncStatus.QUEUED
    )
    db.insert_event(ev)
    
    # Needs two mock returns, one for auth, one for event POST
    mock_res_auth = Mock()
    mock_res_auth.status_code = 200
    mock_res_auth.json.return_value = {"access_token": "new_token"}
    
    mock_res_evt = Mock()
    mock_res_evt.status_code = 200
    
    mock_post.side_effect = [mock_res_auth, mock_res_evt]
    
    worker.sync_batch()
    
    assert worker.token == "new_token"
    pending = db.get_pending_events()
    assert len(pending) == 0  # synced
