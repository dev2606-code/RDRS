
import logging
import time
from pathlib import Path
from threading import Lock
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


logger = logging.getLogger("rdrs")


class SandboxEventHandler(FileSystemEventHandler):
    """Record file-system events confined to the sandbox."""

    def __init__(
        self,
        callback: Callable[[dict], None],
        sandbox_directory: str,
    ):
        super().__init__()
        self.callback = callback
        self.sandbox = Path(sandbox_directory).resolve()

    def _is_inside_sandbox(self, path: str) -> bool:
        try:
            resolved = Path(path).resolve()
            return resolved.is_relative_to(self.sandbox)
        except (ValueError, TypeError, OSError, RuntimeError):
            return False

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

        source_path = str(event.src_path)
        destination_path = None

        if action == "moved":
            destination_path = str(event.dest_path)

            # Reject moves crossing the sandbox boundary.
            if not self._is_inside_sandbox(source_path):
                return

            if not self._is_inside_sandbox(destination_path):
                return

        elif not self._is_inside_sandbox(source_path):
            return

        monitored_path = destination_path or source_path

        logger.info(
            "Watchdog detected file event: action=%s",
            action,
        )

        event_data = {
            "action": action,
            "path": monitored_path,
            "timestamp": time.time(),
        }

        if action == "moved":
            event_data["source_path"] = source_path
            event_data["destination_path"] = destination_path

        try:
            self.callback(event_data)
        except Exception:
            logger.exception("Failed to process watchdog event")


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

            handler = SandboxEventHandler(
                self.callback,
                str(self.directory),
            )

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
            logger.info("Sandbox file monitor started")

    def stop(self) -> None:
        with self._lock:
            if not self._running or self.observer is None:
                return

            observer = self.observer
            observer.stop()
            observer.join(timeout=5)

            if observer.is_alive():
                logger.error(
                    "Watchdog observer did not stop within 5 seconds"
                )
                return

            self.observer = None
            self._running = False

            logger.info("Sandbox file monitor stopped")
