
from pathlib import Path
from threading import Lock
from typing import Any

from app.database.db import EventDatabase
from app.detectors.detection_engine import DetectionEngine
from app.detectors.file_monitor import SandboxFileMonitor


class RDRSService:
    """Connect sandbox monitoring, detection, and event storage."""

    def __init__(
        self,
        sandbox_directory: str = "data/sandbox",
        database_path: str = "data/rdrs.db",
    ):
        self.sandbox = Path(sandbox_directory).resolve()
        self.sandbox.mkdir(parents=True, exist_ok=True)

        self.database = EventDatabase(database_path)
        self.engine = DetectionEngine(str(self.sandbox))
        self.monitor = SandboxFileMonitor(
            str(self.sandbox),
            self.process_event,
        )

        self._lock = Lock()
        self._running = False

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        result = self.engine.analyze_event(event)
        event_id = self.database.add_event(result)

        return {
            "event_id": event_id,
            **result,
        }

    def start(self) -> None:
        with self._lock:
            if self._running:
                return

            self.monitor.start()
            self._running = True

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return

            self.monitor.stop()
            self._running = False

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.database.list_events(limit)
