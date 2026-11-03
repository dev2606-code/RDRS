
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
        """Count distinct modified files within the last 60 seconds."""

        cutoff = current_time - timedelta(seconds=60)
        changed_paths = set()

        for item in recent_events:
            if item.get("action") != "modified":
                continue

            timestamp = item.get("timestamp")
            if not timestamp:
                continue

            try:
                if isinstance(timestamp, (int, float)):
                    event_time = datetime.fromtimestamp(
                        timestamp, tz=timezone.utc
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

    def _count_recent_file_moves(
        self,
        recent_events: list[dict[str, Any]],
        current_time: datetime,
    ) -> int:
        """Count distinct files moved within the last 60 seconds."""

        cutoff = current_time - timedelta(seconds=60)
        moved_paths = set()

        for item in recent_events:
            if item.get("action") != "moved":
                continue

            timestamp = item.get("timestamp")
            if not timestamp:
                continue

            try:
                if isinstance(timestamp, (int, float)):
                    event_time = datetime.fromtimestamp(
                        timestamp, tz=timezone.utc
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
                        moved_paths.add(str(event_path))

            except (ValueError, TypeError, KeyError, OSError):
                continue

        return len(moved_paths)

    def _count_recent_suspicious_extensions(
        self,
        recent_events: list[dict[str, Any]],
        current_time: datetime,
    ) -> int:
        """Count distinct suspicious-extension files changed within 60 seconds."""

        cutoff = current_time - timedelta(seconds=60)
        suspicious_paths = set()

        for item in recent_events:
            if item.get("action") not in {"created", "modified", "moved"}:
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

                if not cutoff <= event_time <= current_time:
                    continue

                event_path = Path(item["path"]).resolve()

                if not event_path.is_relative_to(self.sandbox):
                    continue

                if event_path.suffix.lower() in self.suspicious_extensions:
                    suspicious_paths.add(str(event_path))

            except (ValueError, TypeError, KeyError, OSError):
                continue

        return len(suspicious_paths)

    def _count_correlated_indicators(
        self,
        recent_events: list[dict[str, Any]],
        current_reasons: list[str],
        current_time: datetime,
    ) -> int:
        """Count distinct ransomware-risk indicator categories."""

        cutoff = current_time - timedelta(seconds=60)

        indicator_keywords = {
            "entropy": ("high file entropy",),
            "renaming": ("rapid file-rename activity",),
            "extension": (
                "suspicious file extension",
                "suspicious extension burst",
                "multiple suspicious file extensions",
            ),
            "file_changes": (
                "file-change activity",
                "file change activity",
            ),
        }

        found_indicators = set()

        for reason in current_reasons:
            reason_lower = reason.lower()

            for category, keywords in indicator_keywords.items():
                if any(keyword in reason_lower for keyword in keywords):
                    found_indicators.add(category)

        for item in recent_events:
            timestamp = item.get("timestamp")
            if not timestamp:
                continue

            try:
                if isinstance(timestamp, (int, float)):
                    event_time = datetime.fromtimestamp(
                        timestamp, tz=timezone.utc
                    )
                else:
                    event_time = datetime.fromisoformat(
                        str(timestamp).replace("Z", "+00:00")
                    )
                    if event_time.tzinfo is None:
                        event_time = event_time.replace(tzinfo=timezone.utc)

                if not cutoff <= event_time <= current_time:
                    continue

                event_path = Path(item["path"]).resolve()
                if not event_path.is_relative_to(self.sandbox):
                    continue

                for reason in item.get("reasons") or []:
                    reason_lower = str(reason).lower()

                    for category, keywords in indicator_keywords.items():
                        if any(keyword in reason_lower for keyword in keywords):
                            found_indicators.add(category)

            except (ValueError, TypeError, KeyError, OSError):
                continue

        return len(found_indicators)

    def analyze_event(
        self,
        event: dict[str, Any],
        recent_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:

        file_path = Path(event["path"]).resolve()

        if not file_path.is_relative_to(self.sandbox):
            raise ValueError("File is outside the configured sandbox")

        action = event.get("action")
        entropy = None
        reasons = []
        score = 0

        current_time = datetime.now(timezone.utc)
        all_events = [*(recent_events or []), event]

        recent_change_count = self._count_recent_file_changes(
            all_events, current_time
        )
        recent_move_count = self._count_recent_file_moves(
            all_events, current_time
        )
        recent_suspicious_extension_count = (
            self._count_recent_suspicious_extensions(
                all_events,
                current_time,
            )
        )

        if file_path.suffix.lower() in self.suspicious_extensions:
            score += 25
            reasons.append(
                f"Suspicious file extension detected: {file_path.suffix}"
            )

        if action in {"created", "modified"} and file_path.is_file():
            entropy = calculate_entropy(str(file_path))

            is_compressed_file = file_path.suffix.lower() in {
                ".gz", ".zip", ".rar", ".7z", ".bz2", ".xz"
            }

            if entropy >= 7.2 and not is_compressed_file:
                score += 10
                reasons.append("High file entropy")

        if action == "deleted":
            score += 10
            reasons.append("File deletion observed")

        if action == "moved":
            score += 10
            reasons.append("File move observed")

        if recent_move_count >= 5:
            score += 15
            reasons.append(
                f"Rapid file-rename activity "
                f"({recent_move_count} distinct files in 60 seconds)"
            )

        if recent_suspicious_extension_count >= 5:
            score += 20
            reasons.append(
                "Suspicious extension burst detected "
                f"({recent_suspicious_extension_count} distinct files in 60 seconds)"
            )

        if action in {"created", "modified"}:
            score += 5
            reasons.append(f"File {action} observed")

        if recent_change_count >= 10:
            score += 30
            reasons.append(
                f"High file-change activity "
                f"({recent_change_count} distinct files in 60 seconds)"
            )
        elif recent_change_count >= 5:
            score += 15
            reasons.append(
                f"Elevated file-change activity "
                f"({recent_change_count} distinct files in 60 seconds)"
            )

        if action == "deleted" and entropy is None:
            reasons.append("File content unavailable for entropy analysis")
        correlated_indicator_count = self._count_correlated_indicators(
            recent_events or [],
            reasons,
            current_time,
        )

        if correlated_indicator_count >= 3:
            score += 15
            reasons.append(
                "Correlated ransomware indicators detected "
                f"({correlated_indicator_count} distinct indicators in 60 seconds)"
            )
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
