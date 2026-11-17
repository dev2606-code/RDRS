
"""Forward collected Sysmon XML events to the RDRS API."""

import json
import os
import socket
import time

from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "http://127.0.0.1:8000/api/sysmon/events"
DEFAULT_BOOKMARK_PATH = Path("data/sysmon_bookmark.json")

RETRYABLE_HTTP_CODES = {408, 429, 500, 502, 503, 504}


class RetryableSendError(RuntimeError):
    """A temporary failure that may succeed on retry."""


class PermanentSendError(RuntimeError):
    """A failure that should not be retried."""


class SysmonBookmarkStore:
    """Persist the last successfully processed Sysmon record ID."""

    def __init__(self, path: str | Path = DEFAULT_BOOKMARK_PATH):
        self.path = Path(path)

    def load(self) -> int:
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
        if (
            not isinstance(record_id, int)
            or isinstance(record_id, bool)
            or record_id < 0
        ):
            raise ValueError("record_id must be a non-negative integer")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        temporary_path = self.path.with_name(self.path.name + ".tmp")

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
        payload = json.dumps({"xml_event": xml_event}).encode("utf-8")

        request = Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))

        except HTTPError as exc:
            if exc.code in RETRYABLE_HTTP_CODES:
                raise RetryableSendError(
                    f"Temporary RDRS API error: HTTP {exc.code}"
                ) from exc

            raise PermanentSendError(
                f"RDRS API rejected request: HTTP {exc.code}"
            ) from exc

        except (URLError, TimeoutError, socket.timeout, ConnectionError) as exc:
            raise RetryableSendError(
                "Could not temporarily connect to RDRS API"
            ) from exc

        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PermanentSendError(
                "Invalid response from RDRS API"
            ) from exc

        if not isinstance(result, dict):
            raise PermanentSendError("Invalid RDRS API response")

        if result.get("accepted") is not True:
            raise PermanentSendError(
                "RDRS did not accept the Sysmon event"
            )

        return result


class SysmonEventCollector:
    """Collect Sysmon records and forward them to RDRS."""

    def __init__(
        self,
        event_source,
        sender,
        batch_size: int = 100,
        bookmark_path: str | Path = DEFAULT_BOOKMARK_PATH,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
        max_backoff: float = 8.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if not 1 <= batch_size <= 1000:
            raise ValueError("batch_size must be between 1 and 1000")

        if max_retries < 0:
            raise ValueError("max_retries cannot be negative")

        if initial_backoff < 0:
            raise ValueError("initial_backoff cannot be negative")

        if max_backoff < initial_backoff:
            raise ValueError("max_backoff cannot be less than initial_backoff")

        self.event_source = event_source
        self.sender = sender
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self.sleep = sleep

        self.bookmark_store = SysmonBookmarkStore(bookmark_path)
        self.last_record_id = self.bookmark_store.load()

    def _send_with_retry(self, xml_event: str) -> None:
        """Retry temporary send failures with bounded exponential backoff."""

        for attempt in range(self.max_retries + 1):
            try:
                self.sender.send(xml_event)
                return
            except RetryableSendError:
                if attempt >= self.max_retries:
                    raise

                delay = min(
                    self.initial_backoff * (2 ** attempt),
                    self.max_backoff,
                )
                self.sleep(delay)

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

            self._send_with_retry(record["xml"])

            # Persist only after successful API acceptance.
            self.bookmark_store.save(record_id)
            self.last_record_id = record_id
            sent += 1

        return {
            "read": len(records),
            "sent": sent,
            "last_record_id": self.last_record_id,
        }
