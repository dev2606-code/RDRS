"""Common interface for process attribution providers."""

from typing import Any, Protocol


PROCESS_METADATA_FIELDS = (
    "process_id",
    "process_name",
    "process_path",
    "username",
)


class ProcessAttributionProvider(Protocol):
    """Interface implemented by process attribution providers."""

    def get_process_metadata(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """Return verified process metadata for an event."""
        ...
