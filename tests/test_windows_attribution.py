
from datetime import datetime, timezone, timedelta

from app.attribution.windows import WindowsProcessAttributionProvider


def make_sysmon_event(
    event_id=11,
    timestamp=None,
    process_guid="{ABC-123}",
    process_id="1234",
    image=r"C:\Windows\System32\test.exe",
    username="TEST\\user",
    target_filename=r"C:\RDRS\sample.txt",
):
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    if isinstance(timestamp, datetime):
        timestamp = timestamp.isoformat()

    fields = {
        "ProcessGuid": process_guid,
        "ProcessId": process_id,
        "Image": image,
        "User": username,
        "TargetFilename": target_filename,
    }

    data = "".join(
        f'<Data Name="{name}">{value}</Data>'
        for name, value in fields.items()
        if value is not None
    )

    return f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <EventID>{event_id}</EventID>
            <TimeCreated SystemTime="{timestamp}" />
        </System>
        <EventData>{data}</EventData>
    </Event>
    """


def test_provider_attributes_exact_matching_file():
    provider = WindowsProcessAttributionProvider()

    timestamp = datetime.now(timezone.utc)

    provider.ingest_sysmon_event(
        make_sysmon_event(timestamp=timestamp)
    )

    result = provider.get_process_metadata({
        "path": r"c:\rdrs\SAMPLE.txt",
        "timestamp": timestamp.timestamp(),
    })

    assert result["process_id"] == 1234
    assert result["process_name"] == "test.exe"
    assert result["process_path"] == r"C:\Windows\System32\test.exe"
    assert result["username"] == "TEST\\user"


def test_provider_does_not_match_different_file():
    provider = WindowsProcessAttributionProvider()

    timestamp = datetime.now(timezone.utc)

    provider.ingest_sysmon_event(
        make_sysmon_event(timestamp=timestamp)
    )

    result = provider.get_process_metadata({
        "path": r"C:\RDRS\another.txt",
        "timestamp": timestamp.timestamp(),
    })

    assert all(value is None for value in result.values())


def test_provider_does_not_match_by_basename_only():
    provider = WindowsProcessAttributionProvider()

    timestamp = datetime.now(timezone.utc)

    provider.ingest_sysmon_event(
        make_sysmon_event(
            timestamp=timestamp,
            target_filename=r"C:\RDRS\sample.txt",
        )
    )

    result = provider.get_process_metadata({
        "path": r"D:\OTHER\sample.txt",
        "timestamp": timestamp.timestamp(),
    })

    assert all(value is None for value in result.values())


def test_provider_rejects_timestamp_outside_window():
    provider = WindowsProcessAttributionProvider(
        max_age_seconds=5
    )

    timestamp = datetime.now(timezone.utc)

    provider.ingest_sysmon_event(
        make_sysmon_event(timestamp=timestamp)
    )

    result = provider.get_process_metadata({
        "path": r"C:\RDRS\sample.txt",
        "timestamp": (
            timestamp + timedelta(seconds=10)
        ).timestamp(),
    })

    assert all(value is None for value in result.values())


def test_provider_does_not_attribute_without_watchdog_timestamp():
    provider = WindowsProcessAttributionProvider()

    timestamp = datetime.now(timezone.utc)

    provider.ingest_sysmon_event(
        make_sysmon_event(timestamp=timestamp)
    )

    result = provider.get_process_metadata({
        "path": r"C:\RDRS\sample.txt",
    })

    assert all(value is None for value in result.values())


def test_provider_consumes_matching_event_once():
    provider = WindowsProcessAttributionProvider()

    timestamp = datetime.now(timezone.utc)

    provider.ingest_sysmon_event(
        make_sysmon_event(timestamp=timestamp)
    )

    event = {
        "path": r"C:\RDRS\sample.txt",
        "timestamp": timestamp.timestamp(),
    }

    first_result = provider.get_process_metadata(event)
    second_result = provider.get_process_metadata(event)

    assert first_result["process_id"] == 1234
    assert all(value is None for value in second_result.values())


def test_provider_limits_pending_events():
    provider = WindowsProcessAttributionProvider(
        max_pending_events=2
    )

    now = datetime.now(timezone.utc)

    for offset in range(3):
        provider.ingest_sysmon_event(
            make_sysmon_event(
                timestamp=now + timedelta(seconds=offset),
                target_filename=rf"C:\RDRS\file{offset}.txt",
            )
        )

    assert len(provider._pending) == 2


def test_provider_rejects_invalid_sysmon_xml():
    provider = WindowsProcessAttributionProvider()

    try:
        provider.ingest_sysmon_event("<invalid")
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid XML should raise ValueError")
