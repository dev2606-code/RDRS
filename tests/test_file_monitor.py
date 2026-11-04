
import time

from app.detectors.file_monitor import SandboxFileMonitor


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