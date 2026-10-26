
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
