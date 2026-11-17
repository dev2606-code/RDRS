
"""Forward collected Sysmon XML events to the RDRS API."""

import json
import os

from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "http://127.0.0.1:8000/api/sysmon/events"
DEFAULT_BOOKMARK_PATH = Path("data/sysmon_bookmark.json")


class SysmonBookmarkStore:
    """Persist the last successfully processed Sysmon record ID."""

    def __init__(self, path: str | Path = DEFAULT_BOOKMARK_PATH):
        self.path = Path(path)

    def load(self) -> int:
        """Load the saved record ID, or return zero if missing."""

        if not self.path.exists():
            return 0

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Could not read Sysmon bookmark") from exc

        if not isinstance(data, dict):
            raise ValueError("Invalid Sysmon bookmark format")

        record_id = data.get("last_record_id")

        if (
            not isinstance(record_id, int)
            or isinstance(record_id, bool)
            or record_id < 0
        ):
            raise ValueError("Invalid Sysmon bookmark record ID")

        return record_id

    def save(self, record_id: int) -> None:
        """Atomically save the last processed record ID."""

        if (
            not isinstance(record_id, int)
            or isinstance(record_id, bool)
            or record_id < 0
        ):
            raise ValueError("record_id must be a non-negative integer")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        temporary_path = self.path.with_name(
            self.path.name + ".tmp"
        )

        try:
            temporary_path.write_text(
                json.dumps({"last_record_id": record_id}),
                encoding="utf-8",
            )
            os.replace(temporary_path, self.path)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()


class SysmonApiSender:
    """Send original Sysmon XML to the RDRS API."""

    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: int = 10,
    ):
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError("Endpoint must use HTTP or HTTPS")

        if timeout < 1:
            raise ValueError("timeout must be positive")

        self.endpoint = endpoint
        self.timeout = timeout

    def send(self, xml_event: str) -> dict[str, Any]:
        payload = json.dumps({
            "xml_event": xml_event,
        }).encode("utf-8")

        request = Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.loads(
                    response.read().decode("utf-8")
                )
        except HTTPError as exc:
            raise RuntimeError(
                f"RDRS API returned HTTP {exc.code}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(
                "Could not connect to RDRS API"
            ) from exc

        if not isinstance(result, dict):
            raise ValueError("Invalid RDRS API response")

        if result.get("accepted") is not True:
            raise ValueError("RDRS did not accept the Sysmon event")

        return result


class SysmonEventCollector:
    """Collect Sysmon records and forward them to RDRS."""

    def __init__(
        self,
        event_source,
        sender,
        batch_size: int = 100,
        bookmark_path: str | Path = DEFAULT_BOOKMARK_PATH,
    ):
        if not 1 <= batch_size <= 1000:
            raise ValueError("batch_size must be between 1 and 1000")

        self.event_source = event_source
        self.sender = sender
        self.batch_size = batch_size

        self.bookmark_store = SysmonBookmarkStore(bookmark_path)
        self.last_record_id = self.bookmark_store.load()

    def poll_once(self) -> dict[str, int]:
        """Read and forward one batch of events."""

        records = self.event_source.read_events(
            after_record_id=self.last_record_id,
            limit=self.batch_size,
        )

        sent = 0

        for record in sorted(
            records,
            key=lambda item: item["record_id"],
        ):
            record_id = record["record_id"]

            if record_id <= self.last_record_id:
                continue

            self.sender.send(record["xml"])

            # Persist only after successful API acceptance.
            self.bookmark_store.save(record_id)
            self.last_record_id = record_id
            sent += 1

        return {
            "read": len(records),
            "sent": sent,
            "last_record_id": self.last_record_id,
        }
