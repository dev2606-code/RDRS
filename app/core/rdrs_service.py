import logging

from pathlib import Path
from threading import Lock
from typing import Any

from app.attribution.base import (
    PROCESS_METADATA_FIELDS,
    ProcessAttributionProvider,
)
from app.attribution.null_provider import NullProcessAttributionProvider
from app.database.db import EventDatabase
from app.detectors.detection_engine import DetectionEngine
from app.detectors.file_monitor import SandboxFileMonitor

logger = logging.getLogger("rdrs")


class RDRSService:
    """Connect sandbox monitoring, detection, and event storage."""

    def __init__(
        self,
        sandbox_directory: str = "data/sandbox",
        database_path: str = "data/rdrs.db",
        attribution_provider: ProcessAttributionProvider | None = None,
    ):
        self.sandbox = Path(sandbox_directory).resolve()
        self.sandbox.mkdir(parents=True, exist_ok=True)

        self.database = EventDatabase(database_path)
        self.engine = DetectionEngine(str(self.sandbox))

        self.attribution_provider = (
            attribution_provider
            if attribution_provider is not None
            else NullProcessAttributionProvider()
        )

        self.monitor = SandboxFileMonitor(
            str(self.sandbox),
            self.process_event,
        )

        self._lock = Lock()
        self._running = False

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        logger.info("Sandbox file event received: %s", event)

        try:
            enriched_event = dict(event)

            try:
                metadata = (
                    self.attribution_provider.get_process_metadata(event)
                )

                if not isinstance(metadata, dict):
                    raise TypeError(
                        "Attribution provider must return a dictionary"
                    )

                for field in PROCESS_METADATA_FIELDS:
                    if enriched_event.get(field) is None:
                        enriched_event[field] = metadata.get(field)

            except Exception:
                logger.exception(
                    "Process attribution failed; continuing without "
                    "additional metadata"
                )

            recent_events = self.database.list_events(limit=50)

            result = self.engine.analyze_event(
                enriched_event,
                recent_events=recent_events,
            )

            logger.info("Detection result: %s", result)

            event_id = self.database.add_event(result)

            logger.info("Event saved to database with ID: %s", event_id)

            return {
                "event_id": event_id,
                **result,
            }

        except Exception:
            logger.exception("Failed to process or save sandbox event")
            raise

    def start(self) -> None:
        with self._lock:
            if self._running:
                logger.info("RDRS monitor is already running")
                return

            logger.info(
                "Starting RDRS monitor for sandbox: %s",
                self.sandbox,
            )

            try:
                self.monitor.start()
                self._running = True
                logger.info("RDRS monitor started successfully")

            except Exception:
                logger.exception("RDRS monitor failed to start")
                raise

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return

            self.monitor.stop()
            self._running = False

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.database.list_events(limit)
