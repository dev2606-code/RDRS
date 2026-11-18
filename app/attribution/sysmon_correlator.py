
"""Correlate Sysmon process and file events safely."""

from datetime import datetime, timezone
from typing import Any


METADATA_FIELDS = (
    "process_id",
    "process_name",
    "process_path",
    "username",
)


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO timestamp and normalize it to UTC."""

    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )

        # Reject timestamps without timezone information.
        if parsed.tzinfo is None:
            return None

        return parsed.astimezone(timezone.utc)

    except (TypeError, ValueError, OverflowError):
        return None


def _normalize_guid(value: Any) -> str | None:
    """Normalize a Sysmon ProcessGuid without guessing its identity."""

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    if not normalized:
        return None

    return normalized.casefold()


class SysmonEventCorrelator:
    """Correlate file events with process creation events by ProcessGuid."""

    def __init__(self, max_processes: int = 10000):
        if (
            not isinstance(max_processes, int)
            or isinstance(max_processes, bool)
            or max_processes < 1
        ):
            raise ValueError("max_processes must be a positive integer")

        self.max_processes = max_processes
        self._processes: dict[str, dict[str, Any]] = {}

    def add_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Cache valid process events and attribute file events."""

        if not isinstance(event, dict):
            return None

        event_id = event.get("event_id")

        if (
            not isinstance(event_id, int)
            or isinstance(event_id, bool)
        ):
            return None

        process_guid = _normalize_guid(event.get("process_guid"))

        if event_id == 1:
            if process_guid is None:
                return None

            # Only cache process events with valid timestamps.
            if _parse_timestamp(event.get("timestamp")) is None:
                return None

            self._processes.pop(process_guid, None)
            self._processes[process_guid] = dict(event)

            # Bound memory usage using least-recently-added eviction.
            while len(self._processes) > self.max_processes:
                oldest_guid = next(iter(self._processes))
                del self._processes[oldest_guid]

            return None

        if event_id != 11:
            return None

        if process_guid is None:
            return None

        result = {
            field: event.get(field)
            for field in METADATA_FIELDS
        }

        process_event = self._processes.get(process_guid)

        if process_event is None:
            return result

        process_time = _parse_timestamp(
            process_event.get("timestamp")
        )
        file_time = _parse_timestamp(event.get("timestamp"))

        # Never attribute using missing, invalid, or future timestamps.
        if (
            process_time is None
            or file_time is None
            or process_time > file_time
        ):
            return result

        # Preserve metadata supplied directly by the file event.
        for field in METADATA_FIELDS:
            if result[field] is None:
                result[field] = process_event.get(field)

        return result
