
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import sysmon_provider


client = TestClient(app)


def make_sysmon_xml(event_id, process_guid=None, extra_data=""):
    guid = process_guid or "{11111111-1111-1111-1111-111111111111}"

    return f"""<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime="2026-11-17T10:00:00.000Z"/>
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
        extra_data='<Data Name="CommandLine">cmd.exe</Data>',
    )

    response = client.post(
        "/api/sysmon/events",
        json={"xml_event": xml},
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["event_id"] == 1


def test_sysmon_file_create_event():
    xml = make_sysmon_xml(
        11,
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
    assert response.json()["event_id"] == 11


def test_sysmon_unsupported_event():
    xml = make_sysmon_xml(3)

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
    )

    file_xml = make_sysmon_xml(
        11,
        process_guid=guid,
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
