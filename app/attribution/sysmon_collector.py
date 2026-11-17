
"""Forward collected Sysmon XML events to the RDRS API."""

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "http://127.0.0.1:8000/api/sysmon/events"


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
    ):
        if not 1 <= batch_size <= 1000:
            raise ValueError("batch_size must be between 1 and 1000")

        self.event_source = event_source
        self.sender = sender
        self.batch_size = batch_size
        self.last_record_id = 0

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

            # Advance only after successful API acceptance.
            self.last_record_id = record_id
            sent += 1

        return {
            "read": len(records),
            "sent": sent,
            "last_record_id": self.last_record_id,
        }
