import json
import subprocess
from types import SimpleNamespace

import pytest

from app.attribution import windows_event_log
from app.attribution.windows_event_log import WindowsSysmonEventSource


def make_source(**kwargs):
    return WindowsSysmonEventSource(**kwargs)


def mock_windows(monkeypatch):
    monkeypatch.setattr(
        windows_event_log,
        "os",
        SimpleNamespace(name="nt"),
    )


def mock_run(monkeypatch, stdout="[]", stderr="", returncode=0):
    result = subprocess.CompletedProcess(
        args=["powershell.exe"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )

    monkeypatch.setattr(
        windows_event_log.subprocess,
        "run",
        lambda *args, **kwargs: result,
    )


def test_source_rejects_invalid_timeout():
    for timeout in [True, False, 0, -1, 1.5, "30", None]:
        with pytest.raises(ValueError):
            WindowsSysmonEventSource(timeout=timeout)


@pytest.mark.parametrize(
    "executable",
    ["", " ", None, 123],
)
def test_source_rejects_invalid_powershell_executable(executable):
    with pytest.raises(ValueError):
        WindowsSysmonEventSource(
            powershell_executable=executable
        )


@pytest.mark.parametrize(
    "after_record_id",
    [True, False, -1, 1.5, "0", None],
)
def test_read_rejects_invalid_after_record_id(after_record_id):
    source = make_source()

    with pytest.raises(ValueError):
        source.read_events(after_record_id=after_record_id)


@pytest.mark.parametrize(
    "limit",
    [True, False, 0, -1, 1.5, "100", 1001, None],
)
def test_read_rejects_invalid_limit(limit):
    source = make_source()

    with pytest.raises(ValueError):
        source.read_events(limit=limit)


def test_read_events_rejects_non_windows(monkeypatch):
    monkeypatch.setattr(
        windows_event_log,
        "os",
        SimpleNamespace(name="darwin"),
    )

    with pytest.raises(RuntimeError, match="requires Windows"):
        make_source().read_events()


def test_read_events_success_and_command_arguments(monkeypatch):
    mock_windows(monkeypatch)

    payload = [
        {"record_id": 12, "xml": "<Event>12</Event>"},
        {"record_id": 11, "xml": "<Event>11</Event>"},
    ]

    captured = {}

    def fake_run(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs

        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(
        windows_event_log.subprocess,
        "run",
        fake_run,
    )

    source = WindowsSysmonEventSource(
        powershell_executable="powershell-test",
        timeout=15,
    )

    records = source.read_events(
        after_record_id=10,
        limit=25,
    )

    assert records == [
        {"record_id": 11, "xml": "<Event>11</Event>"},
        {"record_id": 12, "xml": "<Event>12</Event>"},
    ]

    assert captured["args"][0][0] == "powershell-test"
    assert captured["kwargs"]["timeout"] == 15
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["check"] is False


def test_read_events_normalizes_single_json_record(monkeypatch):
    mock_windows(monkeypatch)

    payload = {
        "record_id": 5,
        "xml": "<Event>5</Event>",
    }

    mock_run(monkeypatch, stdout=json.dumps(payload))

    records = make_source().read_events(after_record_id=4)

    assert records == [payload]


def test_read_events_empty_output_returns_empty_list(monkeypatch):
    mock_windows(monkeypatch)
    mock_run(monkeypatch, stdout="")

    assert make_source().read_events() == []


def test_read_events_invalid_json_raises_value_error(monkeypatch):
    mock_windows(monkeypatch)
    mock_run(monkeypatch, stdout="not-json")

    with pytest.raises(ValueError, match="Invalid response"):
        make_source().read_events()


def test_read_events_nonzero_exit_raises_runtime_error(monkeypatch):
    mock_windows(monkeypatch)

    mock_run(
        monkeypatch,
        returncode=1,
        stderr="Access denied",
    )

    with pytest.raises(RuntimeError, match="Access denied"):
        make_source().read_events()


def test_read_events_timeout_is_wrapped(monkeypatch):
    mock_windows(monkeypatch)

    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd="powershell.exe",
            timeout=30,
        )

    monkeypatch.setattr(
        windows_event_log.subprocess,
        "run",
        raise_timeout,
    )

    with pytest.raises(RuntimeError, match="timed out"):
        make_source().read_events()


def test_read_events_powershell_missing_is_wrapped(monkeypatch):
    mock_windows(monkeypatch)

    def raise_os_error(*args, **kwargs):
        raise FileNotFoundError("PowerShell executable not found")

    monkeypatch.setattr(
        windows_event_log.subprocess,
        "run",
        raise_os_error,
    )

    with pytest.raises(RuntimeError, match="PowerShell"):
        make_source().read_events()


@pytest.mark.parametrize(
    "payload",
    [
        [{"record_id": True, "xml": "<Event/>"}],
        [{"record_id": 0, "xml": "<Event/>"}],
        [{"record_id": 5, "xml": ""}],
        [{"record_id": 5, "xml": None}],
        ["invalid-record"],
    ],
)
def test_read_events_rejects_invalid_records(monkeypatch, payload):
    mock_windows(monkeypatch)
    mock_run(monkeypatch, stdout=json.dumps(payload))

    with pytest.raises(ValueError):
        make_source().read_events(after_record_id=1)


def test_read_events_rejects_non_list_json(monkeypatch):
    mock_windows(monkeypatch)
    mock_run(monkeypatch, stdout=json.dumps("unexpected"))

    with pytest.raises(ValueError, match="Expected a list"):
        make_source().read_events()