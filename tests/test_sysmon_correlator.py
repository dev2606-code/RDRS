from app.attribution.sysmon_correlator import SysmonEventCorrelator


PROCESS_TIME = "2026-11-05T10:00:00.000Z"
FILE_TIME = "2026-11-05T10:00:05.000Z"


def make_event(
    event_id,
    process_guid=None,
    process_id=None,
    process_name=None,
    process_path=None,
    username=None,
    target_filename=None,
    timestamp=FILE_TIME,
):
    return {
        "event_id": event_id,
        "process_guid": process_guid,
        "process_id": process_id,
        "process_name": process_name,
        "process_path": process_path,
        "username": username,
        "target_filename": target_filename,
        "timestamp": timestamp,
    }


def test_correlates_file_event_using_process_guid():
    correlator = SysmonEventCorrelator()

    correlator.add_event(make_event(
        1,
        process_guid="{GUID-123}",
        process_id=1234,
        process_name="cmd.exe",
        process_path=r"C:\Windows\System32\cmd.exe",
        username="TEST-PC\\tester",
        timestamp=PROCESS_TIME,
    ))

    result = correlator.add_event(make_event(
        11,
        process_guid="{GUID-123}",
        process_id=1234,
        target_filename=r"C:\Temp\sample.txt",
    ))

    assert result == {
        "process_id": 1234,
        "process_name": "cmd.exe",
        "process_path": r"C:\Windows\System32\cmd.exe",
        "username": "TEST-PC\\tester",
    }


def test_does_not_correlate_using_pid_alone():
    correlator = SysmonEventCorrelator()

    correlator.add_event(make_event(
        1,
        process_guid="{GUID-123}",
        process_id=1234,
        process_name="cmd.exe",
        timestamp=PROCESS_TIME,
    ))

    result = correlator.add_event(make_event(
        11,
        process_guid=None,
        process_id=1234,
    ))

    assert result is None
def test_does_not_match_different_process_guids():
    correlator = SysmonEventCorrelator()

    correlator.add_event(make_event(
        1,
        process_guid="{GUID-OLD}",
        process_id=1234,
        process_name="old.exe",
        timestamp=PROCESS_TIME,
    ))

    result = correlator.add_event(make_event(
        11,
        process_guid="{GUID-NEW}",
        process_id=1234,
    ))

    assert result == {
        "process_id": 1234,
        "process_name": None,
        "process_path": None,
        "username": None,
    }

def test_file_event_metadata_takes_priority():
    correlator = SysmonEventCorrelator()

    correlator.add_event(make_event(
        1,
        process_guid="{GUID-123}",
        process_id=1234,
        process_name="old.exe",
        username="OLD-USER",
        timestamp=PROCESS_TIME,
    ))

    result = correlator.add_event(make_event(
        11,
        process_guid="{GUID-123}",
        process_id=5678,
        process_name="new.exe",
        username="NEW-USER",
    ))

    assert result == {
        "process_id": 5678,
        "process_name": "new.exe",
        "process_path": None,
        "username": "NEW-USER",
    }


def test_unrelated_event_returns_none():
    correlator = SysmonEventCorrelator()

    result = correlator.add_event(make_event(
        3,
        process_guid="{GUID-123}",
        process_id=1234,
    ))

    assert result is None


def test_does_not_correlate_when_process_event_is_later():
    correlator = SysmonEventCorrelator()

    correlator.add_event(make_event(
        1,
        process_guid="{GUID-123}",
        process_name="cmd.exe",
        timestamp=FILE_TIME,
    ))

    result = correlator.add_event(make_event(
        11,
        process_guid="{GUID-123}",
        timestamp=PROCESS_TIME,
    ))

    assert result["process_name"] is None


def test_rejects_invalid_timestamp_for_correlation():
    correlator = SysmonEventCorrelator()

    correlator.add_event(make_event(
        1,
        process_guid="{GUID-123}",
        process_name="cmd.exe",
        timestamp="invalid",
    ))

    result = correlator.add_event(make_event(
        11,
        process_guid="{GUID-123}",
    ))

    assert result["process_name"] is None
