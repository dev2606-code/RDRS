"""Windows process attribution provider foundation."""

from typing import Any

from app.attribution.null_provider import NullProcessAttributionProvider


class WindowsProcessAttributionProvider(
    NullProcessAttributionProvider
):
    """Windows provider placeholder.

    Reliable process-to-filesystem-event correlation is not yet
    implemented. Therefore, this provider deliberately returns
    unavailable metadata instead of guessing.
    """

    def get_process_metadata(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        return super().get_process_metadata(event)
