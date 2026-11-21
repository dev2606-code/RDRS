import time

from watchdog.events import FileCreatedEvent, FileMovedEvent

from app.detectors.file_monitor import SandboxFileMonitor, SandboxEventHandler


def test_monitor_detects_file_creation(tmp_path):
    events = []

    monitor = SandboxFileMonitor(str(tmp_path), events.append)
    monitor.start()

    try:
        test_file = tmp_path / "harmless.txt"
        test_file.write_text("Safe RDRS test data.", encoding="utf-8")

        deadline = time.time() + 3

        while time.time() < deadline:
            if any(event["action"] == "created" for event in events):
                break
            time.sleep(0.05)

        assert any(
            event["action"] == "created"
            and event["path"].endswith("harmless.txt")
            for event in events
        )
    finally:
        monitor.stop()
def test_monitor_detects_suspicious_file_rename(tmp_path):
    events = []

    monitor = SandboxFileMonitor(str(tmp_path), events.append)
    monitor.start()

    try:
        original_file = tmp_path / "report.pdf"
        renamed_file = tmp_path / "report.pdf.locked"

        original_file.write_text(
            "Safe RDRS test data.",
            encoding="utf-8",
        )

        time.sleep(0.3)

        original_file.rename(renamed_file)

        deadline = time.time() + 3

        while time.time() < deadline:
            if any(
                event["action"] == "moved"
                and event["path"].endswith("report.pdf.locked")
                for event in events
            ):
                break

            time.sleep(0.05)

        rename_event = next(
            (
                event for event in events
                if event["action"] == "moved"
                and event["path"].endswith("report.pdf.locked")
            ),
            None,
        )

        assert rename_event is not None
        assert rename_event["source_path"].endswith("report.pdf")
        assert rename_event["destination_path"].endswith(
            "report.pdf.locked"
        )

    finally:
        monitor.stop()
def test_monitor_rejects_file_event_outside_sandbox(tmp_path):
    sandbox = tmp_path / "sandbox"
    outside_file = tmp_path / "outside.txt"
    sandbox.mkdir()

    events = []
    handler = SandboxEventHandler(events.append, str(sandbox))

    handler.on_created(FileCreatedEvent(str(outside_file)))

    assert events == []


def test_monitor_rejects_move_from_inside_to_outside(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    source = sandbox / "safe.txt"
    destination = tmp_path / "outside.txt"

    events = []
    handler = SandboxEventHandler(events.append, str(sandbox))

    handler.on_moved(FileMovedEvent(str(source), str(destination)))

    assert events == []


def test_monitor_rejects_move_from_outside_to_inside(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    source = tmp_path / "outside.txt"
    destination = sandbox / "safe.txt"

    events = []
    handler = SandboxEventHandler(events.append, str(sandbox))

    handler.on_moved(FileMovedEvent(str(source), str(destination)))

    assert events == []