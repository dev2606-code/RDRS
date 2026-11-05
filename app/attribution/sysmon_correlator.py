"""Correlate Sysmon process and file events safely."""

from datetime import datetime
from typing import Any


METADATA_FIELDS = (
    "process_id",
    "process_name",
    "process_path",
    "username",
)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


class SysmonEventCorrelator:
    """Correlate file events with process creation events by ProcessGuid."""

    def __init__(self, max_processes: int = 10000):
        if max_processes < 1:
            raise ValueError("max_processes must be at least 1")

        self.max_processes = max_processes
        self._processes: dict[str, dict[str, Any]] = {}

    def add_event(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Cache process events and attribute file events."""

        event_id = event.get("event_id")
        process_guid = event.get("process_guid")

        if event_id == 1:
            if not process_guid:
                return None

            self._processes.pop(process_guid, None)
            self._processes[process_guid] = dict(event)

            while len(self._processes) > self.max_processes:
                oldest_guid = next(iter(self._processes))
                del self._processes[oldest_guid]

            return None

        if event_id != 11:
            return None

        if not process_guid:
            return None

        result = {
            field: event.get(field)
            for field in METADATA_FIELDS
        }

        process_event = self._processes.get(process_guid)

        if not process_event:
            return result

        process_time = _parse_timestamp(
            process_event.get("timestamp")
        )
        file_time = _parse_timestamp(event.get("timestamp"))

        if (
            process_time is None
            or file_time is None
            or process_time > file_time
        ):
            return result

        for field in METADATA_FIELDS:
            if result[field] is None:
                result[field] = process_event.get(field)

        return result