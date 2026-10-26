
import time
from pathlib import Path
from threading import Event
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


class SandboxEventHandler(FileSystemEventHandler):
    """Record file-system events without modifying monitored files."""

    def __init__(self, callback: Callable[[dict], None]):
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

        self.callback({
            "action": action,
            "path": str(event.src_path),
            "timestamp": time.time(),
        })


class SandboxFileMonitor:
    """Monitor a dedicated directory; never modify monitored files."""

    def __init__(self, directory: str, callback: Callable[[dict], None]):
        self.directory = Path(directory).resolve()
        self.callback = callback
        self.observer = Observer()

    def start(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)

        handler = SandboxEventHandler(self.callback)
        self.observer.schedule(handler, str(self.directory), recursive=True)
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)
