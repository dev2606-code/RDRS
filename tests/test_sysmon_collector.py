import json
from io import BytesIO
from urllib.error import HTTPError
import pytest

from app.attribution.sysmon_collector import (
    PermanentSendError,
    RetryableSendError,
    SysmonApiSender,
    SysmonBookmarkStore,
    SysmonEventCollector,
)

from app.attribution.windows_event_log import (
    WindowsSysmonEventSource,
)

class FakeEventSource:
    def __init__(self, records):
        self.records = records
        self.calls = []

    def read_events(self, after_record_id=0, limit=100):
        self.calls.append((after_record_id, limit))

        return [
            record
            for record in self.records
            if (
                not isinstance(record, dict)
                or isinstance(record.get("record_id"), bool)
                or not isinstance(record.get("record_id"), int)
                or record.get("record_id") <= 0
                or record.get("record_id") > after_record_id
            )
        ][:limit]


class FakeSender:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, xml):
        if self.fail:
            raise RuntimeError("API unavailable")

        self.sent.append(xml)
        return {"accepted": True}


def test_collector_forwards_events(tmp_path):
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(
        source, sender, bookmark_path=tmp_path / "bookmark.json"
    )

    result = collector.poll_once()

    assert result == {
        "read": 2,
        "sent": 2,
        "last_record_id": 2,
    }
    assert len(sender.sent) == 2


def test_collector_advances_record_cursor(tmp_path):
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(
        source, sender, bookmark_path=tmp_path / "bookmark.json"
    )

    collector.poll_once()
    collector.poll_once()

    assert source.calls[-1] == (2, 100)
    assert len(sender.sent) == 2


def test_collector_does_not_advance_after_send_failure(tmp_path):
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
    ])
    sender = FakeSender(fail=True)

    collector = SysmonEventCollector(
        source, sender, bookmark_path=tmp_path / "bookmark.json"
    )

    with pytest.raises(RuntimeError):
        collector.poll_once()

    assert collector.last_record_id == 0
    assert not (tmp_path / "bookmark.json").exists()


def test_collector_sorts_records(tmp_path):
    source = FakeEventSource([
        {"record_id": 3, "xml": "<Event>three</Event>"},
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(
        source, sender, bookmark_path=tmp_path / "bookmark.json"
    )

    collector.poll_once()

    assert sender.sent == [
        "<Event>one</Event>",
        "<Event>two</Event>",
        "<Event>three</Event>",
    ]


def test_collector_rejects_invalid_batch_size(tmp_path):
    with pytest.raises(ValueError):
        SysmonEventCollector(
            FakeEventSource([]),
            FakeSender(),
            batch_size=0,
            bookmark_path=tmp_path / "bookmark.json",
        )


def test_sender_rejects_invalid_endpoint():
    with pytest.raises(ValueError):
        SysmonApiSender("ftp://localhost/events")


def test_windows_source_rejects_non_windows():
    import os

    if os.name == "nt":
        pytest.skip("This test is for non-Windows systems")

    source = WindowsSysmonEventSource()

    with pytest.raises(RuntimeError):
        source.read_events()


def test_bookmark_store_returns_zero_when_missing(tmp_path):
    store = SysmonBookmarkStore(tmp_path / "bookmark.json")

    assert store.load() == 0


def test_bookmark_store_saves_and_loads_record_id(tmp_path):
    path = tmp_path / "bookmark.json"
    store = SysmonBookmarkStore(path)

    store.save(125)

    assert store.load() == 125
    assert json.loads(path.read_text()) == {"last_record_id": 125}


def test_collector_resumes_after_restart(tmp_path):
    path = tmp_path / "bookmark.json"

    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
        {"record_id": 3, "xml": "<Event>three</Event>"},
    ])

    first_sender = FakeSender()
    first_collector = SysmonEventCollector(
        source, first_sender, bookmark_path=path
    )
    first_collector.poll_once()

    second_sender = FakeSender()
    second_collector = SysmonEventCollector(
        source, second_sender, bookmark_path=path
    )

    result = second_collector.poll_once()

    assert source.calls[-1] == (3, 100)
    assert result["sent"] == 0
    assert second_collector.last_record_id == 3


def test_collector_resumes_after_partial_batch(tmp_path):
    path = tmp_path / "bookmark.json"

    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])

    sender = FakeSender()
    collector = SysmonEventCollector(
        source, sender, bookmark_path=path
    )

    collector.poll_once()

    restarted = SysmonEventCollector(
        source, FakeSender(), bookmark_path=path
    )

    assert restarted.last_record_id == 2


def test_corrupt_bookmark_is_rejected(tmp_path):
    path = tmp_path / "bookmark.json"
    path.write_text("{invalid json")

    with pytest.raises(ValueError, match="Could not read"):
        SysmonBookmarkStore(path).load()


def test_bookmark_rejects_invalid_record_id(tmp_path):
    store = SysmonBookmarkStore(tmp_path / "bookmark.json")

    for value in (-1, True, "12"):
        with pytest.raises(ValueError):
            store.save(value)


def test_collector_does_not_advance_bookmark_after_send_failure(tmp_path):
    path = tmp_path / "bookmark.json"
    store = SysmonBookmarkStore(path)
    store.save(5)

    source = FakeEventSource([
        {"record_id": 6, "xml": "<Event>six</Event>"},
    ])

    collector = SysmonEventCollector(
        source,
        FakeSender(fail=True),
        bookmark_path=path,
    )

    with pytest.raises(RuntimeError):
        collector.poll_once()

    assert collector.last_record_id == 5
    assert store.load() == 5


def test_collector_does_not_advance_memory_if_bookmark_save_fails(
    tmp_path, monkeypatch
):
    path = tmp_path / "bookmark.json"
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
    ])

    collector = SysmonEventCollector(
        source, FakeSender(), bookmark_path=path
    )

    def fail_save(record_id):
        raise OSError("Disk unavailable")

    monkeypatch.setattr(collector.bookmark_store, "save", fail_save)

    with pytest.raises(OSError, match="Disk unavailable"):
        collector.poll_once()

    assert collector.last_record_id == 0
def test_collector_retries_temporary_failure_then_succeeds(tmp_path):
    class FlakySender:
        def __init__(self):
            self.attempts = 0

        def send(self, xml):
            self.attempts += 1
            if self.attempts == 1:
                raise RetryableSendError("Temporary failure")
            return {"accepted": True}

    sender = FlakySender()
    delays = []

    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event/>"},
    ])

    collector = SysmonEventCollector(
        source,
        sender,
        bookmark_path=tmp_path / "bookmark.json",
        max_retries=3,
        initial_backoff=0.5,
        sleep=delays.append,
    )

    result = collector.poll_once()

    assert sender.attempts == 2
    assert delays == [0.5]
    assert result["sent"] == 1
    assert result["last_record_id"] == 1


def test_collector_stops_after_retry_limit(tmp_path):
    class AlwaysFailSender:
        def __init__(self):
            self.attempts = 0

        def send(self, xml):
            self.attempts += 1
            raise RetryableSendError("API unavailable")

    sender = AlwaysFailSender()
    delays = []
    bookmark = tmp_path / "bookmark.json"

    source = FakeEventSource([
        {"record_id": 5, "xml": "<Event/>"},
    ])

    collector = SysmonEventCollector(
        source,
        sender,
        bookmark_path=bookmark,
        max_retries=2,
        initial_backoff=0.5,
        sleep=delays.append,
    )

    with pytest.raises(RetryableSendError):
        collector.poll_once()

    assert sender.attempts == 3
    assert delays == [0.5, 1.0]
    assert collector.last_record_id == 0
    assert SysmonBookmarkStore(bookmark).load() == 0


def test_collector_does_not_retry_permanent_failure(tmp_path):
    class PermanentFailSender:
        def __init__(self):
            self.attempts = 0

        def send(self, xml):
            self.attempts += 1
            raise PermanentSendError("Invalid request")

    sender = PermanentFailSender()
    delays = []
    bookmark = tmp_path / "bookmark.json"

    source = FakeEventSource([
        {"record_id": 3, "xml": "<Event/>"},
    ])

    collector = SysmonEventCollector(
        source,
        sender,
        bookmark_path=bookmark,
        max_retries=3,
        sleep=delays.append,
    )

    with pytest.raises(PermanentSendError):
        collector.poll_once()

    assert sender.attempts == 1
    assert delays == []
    assert collector.last_record_id == 0
    assert SysmonBookmarkStore(bookmark).load() == 0


def test_collector_with_zero_retries_attempts_once(tmp_path):
    class AlwaysFailSender:
        def __init__(self):
            self.attempts = 0

        def send(self, xml):
            self.attempts += 1
            raise RetryableSendError("Temporary failure")

    sender = AlwaysFailSender()
    delays = []

    source = FakeEventSource([
        {"record_id": 2, "xml": "<Event/>"},
    ])

    collector = SysmonEventCollector(
        source,
        sender,
        bookmark_path=tmp_path / "bookmark.json",
        max_retries=0,
        sleep=delays.append,
    )

    with pytest.raises(RetryableSendError):
        collector.poll_once()

    assert sender.attempts == 1
    assert delays == []
    assert collector.last_record_id == 0


def test_sender_classifies_http_503_as_retryable(monkeypatch):
    error = HTTPError(
        "http://localhost",
        503,
        "Service unavailable",
        {},
        BytesIO(b""),
    )

    def fake_urlopen(*args, **kwargs):
        raise error

    monkeypatch.setattr(
        "app.attribution.sysmon_collector.urlopen",
        fake_urlopen,
    )

    sender = SysmonApiSender("http://localhost")

    with pytest.raises(RetryableSendError):
        sender.send("<Event/>")


def test_sender_classifies_http_422_as_permanent(monkeypatch):
    error = HTTPError(
        "http://localhost",
        422,
        "Unprocessable Entity",
        {},
        BytesIO(b""),
    )

    def fake_urlopen(*args, **kwargs):
        raise error

    monkeypatch.setattr(
        "app.attribution.sysmon_collector.urlopen",
        fake_urlopen,
    )

    sender = SysmonApiSender("http://localhost")

    with pytest.raises(PermanentSendError):
        sender.send("<Event/>")

@pytest.mark.parametrize(
    "batch_size",
    [True, False, 1.5, "10", -1, 1001],
)
def test_collector_rejects_invalid_batch_size_values(tmp_path, batch_size):
    with pytest.raises(ValueError):
        SysmonEventCollector(
            FakeEventSource([]),
            FakeSender(),
            batch_size=batch_size,
            bookmark_path=tmp_path / "bookmark.json",
        )


@pytest.mark.parametrize("max_retries", [True, False, 1.5, -1, "3"])
def test_collector_rejects_invalid_retry_values(tmp_path, max_retries):
    with pytest.raises(ValueError):
        SysmonEventCollector(
            FakeEventSource([]),
            FakeSender(),
            max_retries=max_retries,
            bookmark_path=tmp_path / "bookmark.json",
        )


@pytest.mark.parametrize(
    "initial,max_backoff",
    [
        (float("nan"), 1),
        (1, float("nan")),
        (float("inf"), 2),
        (1, float("inf")),
        (True, 2),
        (1, False),
        (-1, 2),
        (2, 1),
    ],
)
def test_collector_rejects_invalid_backoff_values(
    tmp_path, initial, max_backoff
):
    with pytest.raises(ValueError):
        SysmonEventCollector(
            FakeEventSource([]),
            FakeSender(),
            initial_backoff=initial,
            max_backoff=max_backoff,
            bookmark_path=tmp_path / "bookmark.json",
        )


@pytest.mark.parametrize(
    "record",
    [
        {"record_id": True, "xml": "<Event/>"},
        {"record_id": -1, "xml": "<Event/>"},
        {"record_id": 0, "xml": "<Event/>"},
        {"record_id": 1.5, "xml": "<Event/>"},
        {"record_id": 1, "xml": ""},
        {"record_id": 1, "xml": "   "},
        {"record_id": 1},
        None,
    ],
)
def test_collector_rejects_malformed_records_before_sending(
    tmp_path, record
):
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>valid</Event>"},
        record,
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(
        source,
        sender,
        bookmark_path=tmp_path / "bookmark.json",
    )

    with pytest.raises(ValueError):
        collector.poll_once()

    assert sender.sent == []
    assert collector.last_record_id == 0


def test_collector_rejects_duplicate_record_ids(tmp_path):
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 1, "xml": "<Event>duplicate</Event>"},
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(
        source,
        sender,
        bookmark_path=tmp_path / "bookmark.json",
    )

    with pytest.raises(ValueError, match="Duplicate"):
        collector.poll_once()

    assert sender.sent == []
    assert collector.last_record_id == 0


def test_collector_rejects_invalid_event_source_result(tmp_path):
    class InvalidSource:
        def read_events(self, after_record_id=0, limit=100):
            return None

    collector = SysmonEventCollector(
        InvalidSource(),
        FakeSender(),
        bookmark_path=tmp_path / "bookmark.json",
    )

    with pytest.raises(ValueError, match="list or tuple"):
        collector.poll_once()


def test_collector_rejects_sender_without_acceptance(tmp_path):
    class UnconfirmedSender:
        def send(self, xml):
            return {"accepted": False}

    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event/>"},
    ])

    collector = SysmonEventCollector(
        source,
        UnconfirmedSender(),
        bookmark_path=tmp_path / "bookmark.json",
    )

    with pytest.raises(PermanentSendError):
        collector.poll_once()

    assert collector.last_record_id == 0


@pytest.mark.parametrize(
    "timeout",
    [True, False, 0, 0.5, float("nan"), float("inf"), "10"],
)
def test_sender_rejects_invalid_timeout(timeout):
    with pytest.raises(ValueError):
        SysmonApiSender("http://localhost", timeout=timeout)


def test_sender_rejects_empty_xml():
    sender = SysmonApiSender("http://localhost")

    with pytest.raises(PermanentSendError):
        sender.send("   ")
def test_collector_recovers_after_partial_batch_failure(tmp_path):
    path = tmp_path / "bookmark.json"

    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])

    class FailOnSecondEventSender:
        def __init__(self):
            self.sent = []

        def send(self, xml):
            if xml == "<Event>two</Event>":
                raise PermanentSendError("Second event rejected")

            self.sent.append(xml)
            return {"accepted": True}

    first_sender = FailOnSecondEventSender()

    collector = SysmonEventCollector(
        source,
        first_sender,
        bookmark_path=path,
    )

    with pytest.raises(PermanentSendError):
        collector.poll_once()

    assert first_sender.sent == ["<Event>one</Event>"]
    assert collector.last_record_id == 1
    assert SysmonBookmarkStore(path).load() == 1

    # Simulate restart after partial batch failure.
    retry_sender = FakeSender()

    restarted = SysmonEventCollector(
        source,
        retry_sender,
        bookmark_path=path,
    )

    result = restarted.poll_once()

    assert retry_sender.sent == ["<Event>two</Event>"]
    assert result["sent"] == 1
    assert result["last_record_id"] == 2
    assert SysmonBookmarkStore(path).load() == 2