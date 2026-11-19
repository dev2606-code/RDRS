
"""Reliable, bookmark-based Sysmon event collection and forwarding."""

import json
import math
import os
import socket
import time

from numbers import Real
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "http://127.0.0.1:8000/api/sysmon/events"
DEFAULT_BOOKMARK_PATH = Path("data/sysmon_bookmark.json")


class RetryableSendError(Exception):
    """Raised when sending an event may succeed if retried."""


class PermanentSendError(Exception):
    """Raised when an event cannot be sent without correcting the request."""


class SysmonBookmarkStore:
    """Persist the last successfully processed Sysmon record ID."""

    def __init__(self, path: str | Path = DEFAULT_BOOKMARK_PATH):
        self.path = Path(path)

    def load(self) -> int:
        """Load the bookmark, or return zero if it does not exist."""
        if not self.path.exists():
            return 0

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Could not read Sysmon bookmark: corrupted or invalid") from exc

        if not isinstance(data, dict):
            raise ValueError("Could not read Sysmon bookmark: corrupted or invalid")

        record_id = data.get("last_record_id", data.get("record_id"))

        if (
            isinstance(record_id, bool)
            or not isinstance(record_id, int)
            or record_id < 0
        ):
            raise ValueError("Could not read Sysmon bookmark: corrupted or invalid")

        return record_id

    def save(self, record_id: int) -> None:
        """Atomically save the latest successfully processed record ID."""
        if (
            isinstance(record_id, bool)
            or not isinstance(record_id, int)
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
        except OSError:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise


class SysmonApiSender:
    """Send Sysmon XML events to the RDRS API."""

    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        timeout: float = 5.0,
    ):
        if not isinstance(endpoint, str) or not endpoint.strip():
            raise ValueError("endpoint must be a non-empty string")

        if not endpoint.startswith(("http://", "https://")):
            raise ValueError("endpoint must use HTTP or HTTPS")

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, Real)
            or not math.isfinite(timeout)
            or timeout < 1
        ):
            raise ValueError("timeout must be a finite number >= 1")

        self.endpoint = endpoint
        self.timeout = float(timeout)

    def send(self, event_xml: str) -> dict[str, Any]:
        """Send XML and require a confirmed acceptance response."""
        if not isinstance(event_xml, str) or not event_xml.strip():
            raise PermanentSendError("Sysmon event XML cannot be empty")

        payload = json.dumps({"event_xml": event_xml}).encode("utf-8")

        request = Request(
            self.endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=self.timeout) as response:
                response_body = response.read().decode("utf-8")

        except HTTPError as exc:
            if 400 <= exc.code < 500 and exc.code != 429:
                raise PermanentSendError(
                    f"RDRS API rejected the event: HTTP {exc.code}"
                ) from exc

            raise RetryableSendError(
                f"RDRS API temporarily unavailable: HTTP {exc.code}"
            ) from exc

        except (URLError, TimeoutError, socket.timeout, ConnectionError) as exc:
            raise RetryableSendError(
                f"Unable to connect to RDRS API: {exc}"
            ) from exc

        try:
            result = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise RetryableSendError(
                "RDRS API returned invalid JSON"
            ) from exc

        if not isinstance(result, dict):
            raise RetryableSendError(
                "RDRS API response must be a JSON object"
            )

        if result.get("accepted") is not True:
            raise RetryableSendError(
                "RDRS API did not confirm event acceptance"
            )

        return result


class SysmonEventCollector:
    """Collect, validate, forward, and bookmark Sysmon events."""

    def __init__(
        self,
        event_source: Any,
        sender: Any,
        bookmark_path: str | Path = DEFAULT_BOOKMARK_PATH,
        batch_size: int = 100,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
        max_backoff: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        bookmark_store: SysmonBookmarkStore | None = None,
    ):
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or not 1 <= batch_size <= 1000
        ):
            raise ValueError("batch_size must be an integer between 1 and 1000")

        if (
            isinstance(max_retries, bool)
            or not isinstance(max_retries, int)
            or max_retries < 0
        ):
            raise ValueError("max_retries must be a non-negative integer")

        if (
            isinstance(initial_backoff, bool)
            or not isinstance(initial_backoff, Real)
            or not math.isfinite(initial_backoff)
            or initial_backoff < 0
        ):
            raise ValueError("initial_backoff must be finite and non-negative")

        if (
            isinstance(max_backoff, bool)
            or not isinstance(max_backoff, Real)
            or not math.isfinite(max_backoff)
            or max_backoff < 0
        ):
            raise ValueError("max_backoff must be finite and non-negative")

        if max_backoff < initial_backoff:
            raise ValueError("max_backoff cannot be smaller than initial_backoff")

        if not callable(sleep):
            raise ValueError("sleep must be callable")

        if bookmark_store is not None and bookmark_path != DEFAULT_BOOKMARK_PATH:
            raise ValueError("Provide bookmark_path or bookmark_store, not both")

        self.event_source = event_source
        self.sender = sender

        self.bookmark_store = (
            bookmark_store
            if bookmark_store is not None
            else SysmonBookmarkStore(bookmark_path)
        )

        self.batch_size = batch_size
        self.max_retries = max_retries
        self.initial_backoff = float(initial_backoff)
        self.max_backoff = float(max_backoff)
        self.sleep = sleep

        self.last_record_id = self.bookmark_store.load()

    @staticmethod
    def _validate_records(records: Any) -> list[dict[str, Any]]:
        """Validate the complete batch before forwarding any event."""
        if not isinstance(records, (list, tuple)):
            raise ValueError("Event source must return a list or tuple")

        validated = []
        seen_ids = set()

        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Every Sysmon record must be a dictionary")

            record_id = record.get("record_id")
            event_xml = record.get("xml")

            if (
                isinstance(record_id, bool)
                or not isinstance(record_id, int)
                or record_id <= 0
            ):
                raise ValueError("record_id must be a positive integer")

            if not isinstance(event_xml, str) or not event_xml.strip():
                raise ValueError("event_xml must be a non-empty string")

            if record_id in seen_ids:
                raise ValueError(f"Duplicate record_id: {record_id}")

            seen_ids.add(record_id)
            validated.append(record)

        return sorted(validated, key=lambda record: record["record_id"])

    def _send_with_retry(self, event_xml: str) -> dict[str, Any]:
        """Retry temporary errors with bounded exponential backoff."""
        for attempt in range(self.max_retries + 1):
            try:
                result = self.sender.send(event_xml)

                if not isinstance(result, dict):
                    raise RetryableSendError(
                        "Sender response must be a dictionary"
                    )

                if result.get("accepted") is not True:
                  raise PermanentSendError(
        "Sender did not confirm event acceptance"
    )

                return result

            except PermanentSendError:
                raise

            except RetryableSendError:
                if attempt >= self.max_retries:
                    raise

                delay = min(
                    self.initial_backoff * (2 ** attempt),
                    self.max_backoff,
                )
                self.sleep(delay)

        raise RetryableSendError("Event sending failed")

    def poll_once(self) -> dict[str, Any]:
        """Read, validate, send, and bookmark a batch."""
        records = self.event_source.read_events(
            after_record_id=self.last_record_id,
            limit=self.batch_size,
        )
        records = self._validate_records(records)

        sent = 0

        for record in records:
            record_id = record["record_id"]

            if record_id <= self.last_record_id:
                continue

            self._send_with_retry(record["xml"])

            # Advance the cursor only after successful bookmark persistence.
            self.bookmark_store.save(record_id)
            self.last_record_id = record_id
            sent += 1

        return {
            "read": len(records),
            "sent": sent,
            "last_record_id": self.last_record_id,
        }
