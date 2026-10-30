
import logging
import time

from pathlib import Path
from threading import Lock
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


logger = logging.getLogger("rdrs")


class SandboxEventHandler(FileSystemEventHandler):
    """Record file-system events without modifying monitored files."""

    def __init__(self, callback: Callable[[dict], None]):
        super().__init__()
        self.callback = callback

    def on_created(self, event: FileSystemEvent) -> None:
        self._record(event, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        self._record(event, "modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._record(event, "deleted")

    def on_moved(self, event: FileSystemEvent) -> None:
        self._record(event, "moved")

    def _record(self, event: FileSystemEvent, action: str) -> None:
        if event.is_directory:
            return

        logger.info(
            "Watchdog detected file event: action=%s path=%s",
            action,
            event.src_path,
        )

        event_data = {
            "action": action,
            "path": str(event.src_path),
            "timestamp": time.time(),
        }

        try:
            self.callback(event_data)
        except Exception:
            logger.exception(
                "Failed to process watchdog event: %s",
                event_data,
            )


class SandboxFileMonitor:
    """Monitor a dedicated sandbox directory without modifying files."""

    def __init__(
        self,
        directory: str,
        callback: Callable[[dict], None],
    ):
        self.directory = Path(directory).resolve()
        self.callback = callback
        self.observer = None
        self._lock = Lock()
        self._running = False

    def start(self) -> None:
        with self._lock:
            if self._running:
                logger.info("Sandbox file monitor is already running")
                return

            self.directory.mkdir(parents=True, exist_ok=True)

            handler = SandboxEventHandler(self.callback)
            observer = Observer()

            observer.schedule(
                handler,
                str(self.directory),
                recursive=True,
            )

            try:
                observer.start()
            except Exception:
                observer.stop()
                raise

            self.observer = observer
            self._running = True

            logger.info(
                "Watchdog observer alive: %s",
                observer.is_alive(),
            )
            logger.info(
                "Watchdog monitoring directory: %s",
                self.directory,
            )
            logger.info(
                "Sandbox file monitor started: %s",
                self.directory,
            )

    def stop(self) -> None:
        with self._lock:
            if not self._running or self.observer is None:
                return

            observer = self.observer
            observer.stop()
            observer.join(timeout=5)

            if observer.is_alive():
                logger.error("Watchdog observer did not stop within 5 seconds")
                return

            self.observer = None
            self._running = False

            logger.info("Sandbox file monitor stopped")
