"""Safe fallback when process attribution is unavailable."""

from typing import Any

from app.attribution.base import PROCESS_METADATA_FIELDS


class NullProcessAttributionProvider:
    """Return unavailable metadata without making assumptions."""

    def get_process_metadata(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            field: None
            for field in PROCESS_METADATA_FIELDS
        }
