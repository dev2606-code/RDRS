
import pytest

from app.attribution.sysmon_collector import (
    SysmonApiSender,
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
            if record["record_id"] > after_record_id
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


def test_collector_forwards_events():
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(source, sender)

    result = collector.poll_once()

    assert result == {
        "read": 2,
        "sent": 2,
        "last_record_id": 2,
    }
    assert len(sender.sent) == 2


def test_collector_advances_record_cursor():
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(source, sender)

    collector.poll_once()
    collector.poll_once()

    assert source.calls[-1] == (2, 100)
    assert len(sender.sent) == 2


def test_collector_does_not_advance_after_send_failure():
    source = FakeEventSource([
        {"record_id": 1, "xml": "<Event>one</Event>"},
    ])
    sender = FakeSender(fail=True)

    collector = SysmonEventCollector(source, sender)

    with pytest.raises(RuntimeError):
        collector.poll_once()

    assert collector.last_record_id == 0


def test_collector_sorts_records():
    source = FakeEventSource([
        {"record_id": 3, "xml": "<Event>three</Event>"},
        {"record_id": 1, "xml": "<Event>one</Event>"},
        {"record_id": 2, "xml": "<Event>two</Event>"},
    ])
    sender = FakeSender()

    collector = SysmonEventCollector(source, sender)

    collector.poll_once()

    assert sender.sent == [
        "<Event>one</Event>",
        "<Event>two</Event>",
        "<Event>three</Event>",
    ]


def test_collector_rejects_invalid_batch_size():
    with pytest.raises(ValueError):
        SysmonEventCollector(
            FakeEventSource([]),
            FakeSender(),
            batch_size=0,
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
