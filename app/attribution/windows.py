import logging
import ntpath
import os
import time

from collections import OrderedDict
from datetime import datetime, timezone
from threading import Lock
from typing import Any

from app.attribution.base import PROCESS_METADATA_FIELDS
from app.attribution.null_provider import NullProcessAttributionProvider
from app.attribution.sysmon_correlator import SysmonEventCorrelator
from app.attribution.sysmon_parser import parse_sysmon_event


logger = logging.getLogger("rdrs")


class WindowsProcessAttributionProvider(NullProcessAttributionProvider):
    """Attribute file events using explicitly ingested Sysmon events."""

    def __init__(
        self,
        max_pending_events: int = 10000,
        max_age_seconds: float = 30.0,
    ):
        if max_pending_events < 1:
            raise ValueError("max_pending_events must be at least 1")

        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")

        self.max_pending_events = max_pending_events
        self.max_age_seconds = max_age_seconds

        self.correlator = SysmonEventCorrelator()
        self._pending: OrderedDict[
            tuple[str, float], dict[str, Any]
        ] = OrderedDict()

        self._lock = Lock()

    @staticmethod
    def _normalize_path(value: str | None) -> str | None:
        if not value:
            return None

        value = str(value).strip()

        if not value:
            return None

        # Sysmon paths are Windows paths. Watchdog paths on Windows
        # are also normalized using Windows path rules.
        return ntpath.normcase(ntpath.normpath(value))

    @staticmethod
    def _timestamp(value: Any) -> float | None:
        if isinstance(value, (int, float)):
            return float(value)

        if not isinstance(value, str) or not value:
            return None

        try:
            parsed = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                return None

            return parsed.timestamp()

        except (TypeError, ValueError, OverflowError):
            return None

    def ingest_sysmon_event(
        self,
        xml_event: str,
    ) -> dict[str, Any] | None:
        """Parse and correlate one Sysmon XML event."""

        parsed = parse_sysmon_event(xml_event)

        if parsed is None:
            return None

        with self._lock:
            correlated = self.correlator.add_event(parsed)

            if parsed["event_id"] != 11 or correlated is None:
                return correlated

            path = self._normalize_path(
                parsed.get("target_filename")
            )

            event_time = self._timestamp(
                parsed.get("timestamp")
            )

            if path is None or event_time is None:
                return None

            if not any(
                correlated.get(field) is not None
                for field in PROCESS_METADATA_FIELDS
            ):
                return None

            key = (path, event_time)

            self._pending.pop(key, None)
            self._pending[key] = dict(correlated)

            while len(self._pending) > self.max_pending_events:
                self._pending.popitem(last=False)

            return dict(correlated)

    def get_process_metadata(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """Return metadata only for an exact path and timestamp match."""

        result = super().get_process_metadata(event)

        path = self._normalize_path(event.get("path"))
        event_time = self._timestamp(event.get("timestamp"))

        if path is None or event_time is None:
            return result

        with self._lock:
            # Remove expired records.
            now = time.time()

            expired = [
                key
                for key in self._pending
                if now - key[1] > self.max_age_seconds
            ]

            for key in expired:
                self._pending.pop(key, None)

            # Require the Sysmon and Watchdog timestamps to be close.
            for key, metadata in list(self._pending.items()):
                pending_path, pending_time = key

                if pending_path != path:
                    continue

                if abs(pending_time - event_time) > self.max_age_seconds:
                    continue

                self._pending.pop(key, None)

                return {
                    field: metadata.get(field)
                    for field in PROCESS_METADATA_FIELDS
                }

        return result