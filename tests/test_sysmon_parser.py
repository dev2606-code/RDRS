
import pytest

from app.attribution.sysmon_parser import parse_sysmon_event


def make_sysmon_event(
    event_id,
    fields,
    record_id="12345",
    computer="DESKTOP-TEST",
    channel="Microsoft-Windows-Sysmon/Operational",
):
    data = "".join(
        f'<Data Name="{name}">{value}</Data>'
        for name, value in fields.items()
    )

    return f"""
    <Event>
        <System>
            <Provider Name="Microsoft-Windows-Sysmon"/>
            <EventID>{event_id}</EventID>
            <TimeCreated SystemTime="2026-11-05T10:00:00.000Z"/>
            <EventRecordID>{record_id}</EventRecordID>
            <Channel>{channel}</Channel>
            <Computer>{computer}</Computer>
        </System>
        <EventData>
            {data}
        </EventData>
    </Event>
    """


def test_parse_process_create_event():
    xml = make_sysmon_event(1, {
        "ProcessGuid": "{ABC-123}",
        "ProcessId": "1234",
        "Image": r"C:\Windows\System32\cmd.exe",
        "User": "TEST-PC\\tester",
        "CommandLine": "cmd.exe",
    })

    result = parse_sysmon_event(xml)

    assert result["event_id"] == 1
    assert result["process_id"] == 1234
    assert result["process_name"] == "cmd.exe"
    assert result["process_path"] == r"C:\Windows\System32\cmd.exe"
    assert result["username"] == "TEST-PC\\tester"
    assert result["process_guid"] == "{ABC-123}"

    assert result["computer"] == "DESKTOP-TEST"
    assert result["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert result["record_id"] == 12345


def test_parse_file_create_event():
    xml = make_sysmon_event(11, {
        "ProcessGuid": "{FILE-123}",
        "ProcessId": "0x4D2",
        "Image": r"C:\Windows\System32\notepad.exe",
        "User": "TEST-PC\\tester",
        "TargetFilename": r"C:\Users\tester\sample.txt",
    })

    result = parse_sysmon_event(xml)

    assert result["event_id"] == 11
    assert result["process_id"] == 1234
    assert result["process_name"] == "notepad.exe"
    assert result["target_filename"] == (
        r"C:\Users\tester\sample.txt"
    )


def test_unsupported_event_returns_none():
    xml = make_sysmon_event(3, {
        "Image": r"C:\Windows\System32\cmd.exe",
    })

    assert parse_sysmon_event(xml) is None


def test_invalid_xml_raises_value_error():
    with pytest.raises(ValueError, match="Invalid Sysmon XML"):
        parse_sysmon_event("<Event>")


def test_missing_process_metadata_returns_none():
    xml = make_sysmon_event(11, {
        "TargetFilename": r"C:\Temp\sample.txt",
    })

    result = parse_sysmon_event(xml)

    assert result["process_id"] is None
    assert result["process_name"] is None
    assert result["process_path"] is None
    assert result["username"] is None


def test_missing_sysmon_identity_fields_return_none():
    xml = """
    <Event>
        <System>
            <EventID>11</EventID>
        </System>
        <EventData>
            <Data Name="TargetFilename">C:\\Temp\\sample.txt</Data>
        </EventData>
    </Event>
    """

    result = parse_sysmon_event(xml)

    assert result["computer"] is None
    assert result["channel"] is None
    assert result["record_id"] is None


def test_invalid_record_id_raises_value_error():
    xml = make_sysmon_event(
        11,
        {},
        record_id="invalid",
    )

    with pytest.raises(
        ValueError,
        match="Invalid Sysmon EventRecordID",
    ):
        parse_sysmon_event(xml)


def test_negative_record_id_raises_value_error():
    xml = make_sysmon_event(
        11,
        {},
        record_id="-1",
    )

    with pytest.raises(
        ValueError,
        match="cannot be negative",
    ):
        parse_sysmon_event(xml)
