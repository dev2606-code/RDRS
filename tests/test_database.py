
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
