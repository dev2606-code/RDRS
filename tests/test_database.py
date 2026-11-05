
from app.database.db import EventDatabase


def test_event_is_saved_and_retrieved(tmp_path):
    database = EventDatabase(str(tmp_path / "test.db"))

    event = {
        "path": "/sandbox/sample.txt",
        "action": "created",
        "entropy": 3.5,
        "risk_score": 5,
        "severity": "low",
        "status": "needs_review",
        "reasons": ["File created observed"],
    }

    event_id = database.add_event(event)
    results = database.list_events()

    assert event_id == 1
    assert len(results) == 1
    assert results[0]["path"] == "/sandbox/sample.txt"
    assert results[0]["reasons"] == ["File created observed"]


def test_database_limits_results(tmp_path):
    database = EventDatabase(str(tmp_path / "test.db"))

    for index in range(3):
        database.add_event({
            "path": f"/sandbox/{index}.txt",
            "action": "created",
            "entropy": 2.0,
            "risk_score": 5,
            "severity": "low",
            "status": "needs_review",
            "reasons": [],
        })

    assert len(database.list_events(limit=2)) == 2
def test_process_metadata_is_saved_and_retrieved(tmp_path):
    database = EventDatabase(str(tmp_path / "metadata.db"))

    event = {
        "path": "/sandbox/sample.txt",
        "action": "created",
        "entropy": 3.5,
        "risk_score": 5,
        "severity": "low",
        "status": "needs_review",
        "reasons": [],
        "process_id": 1234,
        "process_name": "example.exe",
        "process_path": "C:/Program Files/example.exe",
        "username": "test-user",
    }

    database.add_event(event)
    result = database.list_events()[0]

    assert result["process_id"] == 1234
    assert result["process_name"] == "example.exe"
    assert result["process_path"] == "C:/Program Files/example.exe"
    assert result["username"] == "test-user"


def test_process_metadata_defaults_to_none(tmp_path):
    database = EventDatabase(str(tmp_path / "metadata_none.db"))

    database.add_event({
        "path": "/sandbox/sample.txt",
        "action": "created",
        "entropy": 2.0,
        "risk_score": 5,
        "severity": "low",
        "status": "needs_review",
        "reasons": [],
    })

    result = database.list_events()[0]

    assert result["process_id"] is None
    assert result["process_name"] is None
    assert result["process_path"] is None
    assert result["username"] is None


def test_process_metadata_is_included_in_incidents(tmp_path):
    database = EventDatabase(str(tmp_path / "incident_metadata.db"))

    event_id = database.add_event({
        "path": "/sandbox/sample.locked",
        "action": "created",
        "entropy": 2.0,
        "risk_score": 40,
        "severity": "high",
        "status": "needs_review",
        "reasons": ["Suspicious file extension"],
        "process_id": 4321,
        "process_name": "sample.exe",
        "process_path": "C:/sample.exe",
        "username": "test-user",
    })

    incidents = database.list_incidents()

    assert len(incidents) == 1
    assert incidents[0]["event_id"] == event_id
    assert incidents[0]["process_id"] == 4321
    assert incidents[0]["process_name"] == "sample.exe"
    assert incidents[0]["process_path"] == "C:/sample.exe"
    assert incidents[0]["username"] == "test-user"
