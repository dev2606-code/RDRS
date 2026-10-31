from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.entropy import calculate_entropy


class DetectionEngine:
    """Generate explainable, preliminary file-risk alerts."""

    def __init__(self, sandbox_directory: str):
     self.sandbox = Path(sandbox_directory).resolve()

     self.suspicious_extensions = {
        ".locked",
        ".encrypted",
        ".crypt",
        ".crypto",
        ".enc",
        ".ransom",
    }

    def _count_recent_file_changes(
        self,
        recent_events: list[dict[str, Any]],
        current_time: datetime,
    ) -> int:
        """Count distinct files changed within the last 60 seconds."""

        cutoff = current_time - timedelta(seconds=60)
        changed_paths = set()

        for item in recent_events:
            if item.get("action") not in {"created", "modified"}:
                continue

            timestamp = item.get("timestamp")
            if not timestamp:
                continue

            try:
                if isinstance(timestamp, (int, float)):
                    event_time = datetime.fromtimestamp(
                        timestamp,
                        tz=timezone.utc,
                    )
                else:
                    event_time = datetime.fromisoformat(
                        str(timestamp).replace("Z", "+00:00")
                    )

                    if event_time.tzinfo is None:
                        event_time = event_time.replace(tzinfo=timezone.utc)

                if cutoff <= event_time <= current_time:
                    event_path = Path(item["path"]).resolve()
                    if event_path.is_relative_to(self.sandbox):
                        changed_paths.add(str(event_path))

            except (ValueError, TypeError, KeyError, OSError):
                continue

        return len(changed_paths)

    def analyze_event(
        self,
        event: dict[str, Any],
        recent_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        file_path = Path(event["path"]).resolve()

        # Only analyze files inside the configured sandbox.
        if not file_path.is_relative_to(self.sandbox):
            raise ValueError("File is outside the configured sandbox")

        action = event.get("action")
        entropy = None
        reasons = []
        score = 0
        if file_path.suffix.lower() in self.suspicious_extensions:
            score += 25
            reasons.append(
                f"Suspicious file extension detected: {file_path.suffix}"
            )

        current_time = datetime.now(timezone.utc)
        recent_change_count = self._count_recent_file_changes(
            [*(recent_events or []), event],
            current_time,
        )
        if action in {"created", "modified"} and file_path.is_file():
            entropy = calculate_entropy(str(file_path))

            if entropy >= 7.2:
                score += 40
                reasons.append("High file entropy")

        if action == "deleted":
            score += 10
            reasons.append("File deletion observed")

        if action == "moved":
            score += 10
            reasons.append("File move observed")

        if action in {"created", "modified"}:
            score += 5
            reasons.append(f"File {action} observed")

        if recent_change_count >= 10:
            score += 30
            reasons.append(
                f"High file-change activity ({recent_change_count} distinct files in 60 seconds)"
            )
        elif recent_change_count >= 5:
            score += 15
            reasons.append(
                f"Elevated file-change activity ({recent_change_count} distinct files in 60 seconds)"
            )

        # Higher scores require multiple indicators, not just one event.
        if action == "deleted" and entropy is None:
            reasons.append("File content unavailable for entropy analysis")

        score = min(score, 100)

        if score >= 70:
            severity = "critical"
        elif score >= 40:
            severity = "high"
        elif score >= 20:
            severity = "medium"
        else:
            severity = "low"

        return {
            "path": str(file_path),
            "action": action,
            "entropy": entropy,
            "risk_score": score,
            "severity": severity,
            "status": "needs_review",
            "reasons": reasons or [
                "No configured risk indicators matched"
            ],
        }
