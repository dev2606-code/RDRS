
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api import routes
from app.api.routes import sysmon_provider
from app.database.db import EventDatabase


client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_sysmon_database(tmp_path, monkeypatch):
    """Use a fresh database for every API test."""
    database = EventDatabase(
        str(tmp_path / "sysmon_test.db")
    )
    monkeypatch.setattr(
        routes.service,
        "database",
        database,
    )
@pytest.fixture(autouse=True)
def authenticated_test_client(monkeypatch):
    monkeypatch.setenv(
        "RDRS_SESSION_SECRET",
        "test-secret-key-for-rdrs-authentication-123456789",
    )

    from app.core.auth import create_session

    token = create_session("test-user")
    client.cookies.set("rdrs_session", token)

def make_sysmon_xml(
    event_id,
    process_guid=None,
    extra_data="",
    record_id=1001,
    computer="DESKTOP-TEST",
    channel="Microsoft-Windows-Sysmon/Operational",
    include_identity=True,
):
    guid = process_guid or (
        f"{{11111111-1111-1111-1111-{record_id:012d}}}"
    )

    identity = ""

    if include_identity:
        identity = f"""
            <Computer>{computer}</Computer>
            <Channel>{channel}</Channel>
            <EventRecordID>{record_id}</EventRecordID>
        """

    return f"""<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime="2026-11-17T10:00:00.000Z"/>
        {identity}
    </System>
    <EventData>
        {extra_data}
        <Data Name="ProcessGuid">{guid}</Data>
        <Data Name="ProcessId">1234</Data>
        <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
        <Data Name="User">TEST\\User</Data>
    </EventData>
</Event>"""


def test_sysmon_process_create_event():
    xml = make_sysmon_xml(
        1,
        record_id=1001,
        extra_data='<Data Name="CommandLine">cmd.exe</Data>',
    )

    response = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["duplicate"] is False
    assert response.json()["event_id"] == 1


def test_sysmon_file_create_event():
    xml = make_sysmon_xml(
        11,
        record_id=1002,
        extra_data=(
            '<Data Name="TargetFilename">'
            'C:\\Temp\\test.txt'
            '</Data>'
        ),
    )

    response = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["duplicate"] is False
    assert response.json()["event_id"] == 11


def test_sysmon_unsupported_event():
    xml = make_sysmon_xml(3, record_id=1003)

    response = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is False


def test_sysmon_invalid_xml():
    response = client.post(
        "/api/sysmon/events",
        json={"xml_event": "<invalid"},
    )

    assert response.status_code == 422


def test_sysmon_missing_xml_field():
    response = client.post(
        "/api/sysmon/events",
        json={},
    )

    assert response.status_code == 422


def test_sysmon_process_file_correlation():
    guid = "{22222222-2222-2222-2222-222222222222}"

    process_xml = make_sysmon_xml(
        1,
        process_guid=guid,
        record_id=2001,
    )

    file_xml = make_sysmon_xml(
        11,
        process_guid=guid,
        record_id=2002,
        extra_data=(
            '<Data Name="TargetFilename">'
            'C:\\Temp\\correlation.txt'
            '</Data>'
        ),
    )

    process_response = client.post(
        "/api/sysmon/events",
        json={"xml_event": process_xml},
    )

    file_response = client.post(
        "/api/sysmon/events",
        json={"xml_event": file_xml},
    )

    assert process_response.status_code == 200
    assert file_response.status_code == 200

    metadata = file_response.json()["correlated_metadata"]

    assert metadata["process_id"] == 1234
    assert metadata["process_name"] == "cmd.exe"
    assert metadata["username"] == "TEST\\User"


def test_duplicate_sysmon_event_is_not_processed_twice(monkeypatch):
    xml = make_sysmon_xml(
        1,
        record_id=3001,
    )

    original_ingest = sysmon_provider.ingest_sysmon_event
    calls = []

    def tracked_ingest(xml_event):
        calls.append(xml_event)
        return original_ingest(xml_event)

    monkeypatch.setattr(
        sysmon_provider,
        "ingest_sysmon_event",
        tracked_ingest,
    )

    first = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    second = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert first.status_code == 200
    assert first.json()["accepted"] is True
    assert first.json()["duplicate"] is False

    assert second.status_code == 200
    assert second.json()["accepted"] is True
    assert second.json()["duplicate"] is True

    assert len(calls) == 1


def test_sysmon_event_missing_identity_is_rejected():
    xml = make_sysmon_xml(
        1,
        record_id=4001,
        include_identity=False,
    )

    response = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert response.status_code == 422
    assert "identity fields" in response.json()["detail"]


def test_same_record_id_on_different_computers_is_accepted():
    first_xml = make_sysmon_xml(
        1,
        record_id=5001,
        computer="DESKTOP-ONE",
    )

    second_xml = make_sysmon_xml(
        1,
        record_id=5001,
        computer="DESKTOP-TWO",
    )

    first = client.post(
        "/api/sysmon/events",
        json={"xml_event": first_xml},
    )

    second = client.post(
        "/api/sysmon/events",
        json={"xml_event": second_xml},
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert first.json()["duplicate"] is False
    assert second.json()["duplicate"] is False

def test_sysmon_provider_failure_does_not_record_receipt(monkeypatch):
    xml = make_sysmon_xml(
        1,
        record_id=6001,
    )

    def failing_ingest(xml_event):
        raise ValueError("Simulated provider failure")

    monkeypatch.setattr(
        sysmon_provider,
        "ingest_sysmon_event",
        failing_ingest,
    )

    first = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert first.status_code == 422
    assert first.json()["detail"] == "Simulated provider failure"

    # Restore provider and retry the same event.
    monkeypatch.undo()

    second = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert second.status_code == 200
    assert second.json()["accepted"] is True
    assert second.json()["duplicate"] is False

def test_sysmon_receipt_failure_returns_server_error(monkeypatch):
    xml = make_sysmon_xml(
        1,
        record_id=6002,
    )

    def failing_record(**kwargs):
        raise RuntimeError("Simulated database failure")

    monkeypatch.setattr(
        routes.service.database,
        "record_sysmon_event",
        failing_record,
    )

    response = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert response.status_code == 500

def test_sysmon_provider_failure_does_not_record_receipt(monkeypatch):
    xml = make_sysmon_xml(
        1,
        record_id=6001,
    )

    original_ingest = sysmon_provider.ingest_sysmon_event

    def failing_ingest(xml_event):
        raise ValueError("Simulated provider failure")

    monkeypatch.setattr(
        sysmon_provider,
        "ingest_sysmon_event",
        failing_ingest,
    )

    first = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert first.status_code == 422
    assert first.json()["detail"] == "Simulated provider failure"

    # Restore only the provider method, not the database fixture.
    monkeypatch.setattr(
        sysmon_provider,
        "ingest_sysmon_event",
        original_ingest,
    )

    second = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert second.status_code == 200
    assert second.json()["accepted"] is True
    assert second.json()["duplicate"] is False


def test_sysmon_event_can_retry_after_provider_failure(monkeypatch):
    xml = make_sysmon_xml(
        1,
        record_id=6001,
        computer="DESKTOP-RETRY",
    )

    original_ingest = sysmon_provider.ingest_sysmon_event
    calls = []

    def failing_ingest(xml_event):
        calls.append("failed")
        raise RuntimeError("Simulated temporary provider failure")

    monkeypatch.setattr(
        sysmon_provider,
        "ingest_sysmon_event",
        failing_ingest,
    )

    with pytest.raises(RuntimeError, match="temporary provider failure"):
        client.post(
            "/api/sysmon/events",
            json={"xml_event": xml},
        )

    # The failed attempt must not create a processed-event receipt.
    assert routes.service.database.has_sysmon_event(
        "DESKTOP-RETRY",
        "Microsoft-Windows-Sysmon/Operational",
        6001,
    ) is False

    # Restore the provider and retry the same event.
    monkeypatch.setattr(
        sysmon_provider,
        "ingest_sysmon_event",
        original_ingest,
    )

    retry = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert retry.status_code == 200
    assert retry.json()["accepted"] is True
    assert retry.json()["duplicate"] is False
    assert retry.json()["event_id"] == 1

    assert routes.service.database.has_sysmon_event(
        "DESKTOP-RETRY",
        "Microsoft-Windows-Sysmon/Operational",
        6001,
    ) is True

    assert len(calls) == 1