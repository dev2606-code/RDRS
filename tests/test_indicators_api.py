
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import routes
from app.database.db import EventDatabase

client = TestClient(app)


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    database = EventDatabase(str(tmp_path / "indicators_api.db"))
    monkeypatch.setattr(routes.service, "database", database)
    return database


def create_test_event(database):
    database.add_event({
        "path": "/sandbox/test_file.locked",
        "action": "modified",
        "entropy": 7.8,
        "risk_score": 55,
        "severity": "high",
        "status": "detected",
        "reasons": ["Suspicious file activity"],
        "indicators": [
            "FILE_EXTENSION_SUSPICIOUS",
            "ENTROPY_HIGH",
        ],
        "confidence_score": 85,
        "confidence_level": "high",
    })


def test_events_api_returns_structured_indicators(test_database):
    create_test_event(test_database)

    response = client.get("/api/events")

    assert response.status_code == 200
    events = response.json()["events"]
    assert events[0]["indicators"] == [
        "FILE_EXTENSION_SUSPICIOUS",
        "ENTROPY_HIGH",
    ]


def test_alerts_api_preserves_indicators(test_database):
    create_test_event(test_database)

    response = client.get("/api/alerts")

    assert response.status_code == 200
    alerts = response.json()["alerts"]
    assert alerts[0]["indicators"] == [
        "FILE_EXTENSION_SUSPICIOUS",
        "ENTROPY_HIGH",
    ]


def test_incidents_api_returns_indicators(test_database):
    create_test_event(test_database)

    response = client.get("/api/incidents")

    assert response.status_code == 200
    incidents = response.json()["incidents"]
    assert incidents[0]["indicators"] == [
        "FILE_EXTENSION_SUSPICIOUS",
        "ENTROPY_HIGH",
    ]
