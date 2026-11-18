from app.attribution.sysmon_correlator import SysmonEventCorrelator
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
def test_rejects_boolean_event_id():
    correlator = SysmonEventCorrelator()
    assert correlator.add_event(
        make_event(True, process_guid="{GUID-123}")
    ) is None


def test_rejects_non_dictionary_event():
    correlator = SysmonEventCorrelator()
    assert correlator.add_event(None) is None


def test_rejects_empty_process_guid():
    correlator = SysmonEventCorrelator()
    result = correlator.add_event(make_event(11, process_guid="   "))
    assert result is None


def test_process_guid_matching_is_case_insensitive():
    correlator = SysmonEventCorrelator()
    correlator.add_event(make_event(
        1,
        process_guid="{GUID-123}",
        process_name="cmd.exe",
        timestamp=PROCESS_TIME,
    ))
    result = correlator.add_event(make_event(
        11,
        process_guid="{guid-123}",
        timestamp=FILE_TIME,
    ))
    assert result["process_name"] == "cmd.exe"


def test_process_event_without_timezone_is_not_cached():
    correlator = SysmonEventCorrelator()
    correlator.add_event(make_event(
        1,
        process_guid="{GUID-123}",
        process_name="cmd.exe",
        timestamp="2026-11-05T10:00:00",
    ))
    result = correlator.add_event(make_event(
        11,
        process_guid="{GUID-123}",
        timestamp=FILE_TIME,
    ))
    assert result["process_name"] is None


def test_correlator_evicts_oldest_process_when_cache_is_full():
    correlator = SysmonEventCorrelator(max_processes=2)

    for guid in ("{GUID-1}", "{GUID-2}", "{GUID-3}"):
        correlator.add_event(make_event(
            1,
            process_guid=guid,
            process_name=f"{guid}.exe",
            timestamp=PROCESS_TIME,
        ))

    assert len(correlator._processes) == 2
    assert "{guid-1}" not in correlator._processes
    assert "{guid-2}" in correlator._processes
    assert "{guid-3}" in correlator._processes


def test_rejects_invalid_cache_capacity():
    for value in (0, -1, True, 1.5):
        try:
            SysmonEventCorrelator(max_processes=value)
        except ValueError:
            continue
        raise AssertionError(f"Expected ValueError for {value!r}")