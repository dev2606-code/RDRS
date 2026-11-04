from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.entropy import calculate_entropy


class DetectionEngine:
    """Generate explainable, preliminary file-risk alerts."""

    WINDOW_SECONDS = 60

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

        self.compressed_extensions = {
            ".gz",
            ".zip",
            ".rar",
            ".7z",
            ".bz2",
            ".xz",
        }

        self.indicator_keywords = {
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

    @staticmethod
    def _parse_timestamp(timestamp: Any) -> datetime | None:
        """Convert supported timestamps into timezone-aware UTC datetimes."""

        if timestamp is None or timestamp == "":
            return None

        try:
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(
                    timestamp,
                    tz=timezone.utc,
                )

            parsed = datetime.fromisoformat(
                str(timestamp).replace("Z", "+00:00")
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.astimezone(timezone.utc)

        except (ValueError, TypeError, OverflowError, OSError):
            return None

    def _is_sandbox_path(self, path: str) -> bool:
        """Check whether a resolved path belongs to the configured sandbox."""

        try:
            resolved = Path(path).resolve()
            return resolved.is_relative_to(self.sandbox)
        except (ValueError, TypeError, OSError):
            return False

    def _event_path(self, event: dict[str, Any]) -> Path | None:
        """Return the primary event path when it is inside the sandbox."""

        path = event.get("path")

        if not path:
            return None

        try:
            resolved = Path(path).resolve()

            if resolved.is_relative_to(self.sandbox):
                return resolved

        except (ValueError, TypeError, OSError):
            pass

        return None

    def _count_recent_file_changes(
        self,
        recent_events: list[dict[str, Any]],
        current_time: datetime,
    ) -> int:
        """Count distinct modified files within the last 60 seconds."""

        cutoff = current_time - timedelta(
            seconds=self.WINDOW_SECONDS
        )

        changed_paths = set()

        for item in recent_events:
            if item.get("action") != "modified":
                continue

            event_time = self._parse_timestamp(
                item.get("timestamp")
            )

            if event_time is None:
                continue

            if not cutoff <= event_time <= current_time:
                continue

            event_path = self._event_path(item)

            if event_path is not None:
                changed_paths.add(str(event_path))

        return len(changed_paths)

    def _count_recent_file_moves(
        self,
        recent_events: list[dict[str, Any]],
        current_time: datetime,
    ) -> int:
        """Count distinct files moved within the last 60 seconds."""

        cutoff = current_time - timedelta(
            seconds=self.WINDOW_SECONDS
        )

        moved_paths = set()

        for item in recent_events:
            if item.get("action") != "moved":
                continue

            event_time = self._parse_timestamp(
                item.get("timestamp")
            )

            if event_time is None:
                continue

            if not cutoff <= event_time <= current_time:
                continue

            event_path = self._event_path(item)

            if event_path is not None:
                moved_paths.add(str(event_path))

        return len(moved_paths)

    def _count_recent_suspicious_extensions(
        self,
        recent_events: list[dict[str, Any]],
        current_time: datetime,
    ) -> int:
        """Count distinct suspicious-extension files changed in 60 seconds."""

        cutoff = current_time - timedelta(
            seconds=self.WINDOW_SECONDS
        )

        suspicious_paths = set()

        for item in recent_events:
            if item.get("action") not in {
                "created",
                "modified",
                "moved",
            }:
                continue

            event_time = self._parse_timestamp(
                item.get("timestamp")
            )

            if event_time is None:
                continue

            if not cutoff <= event_time <= current_time:
                continue

            event_path = self._event_path(item)

            if event_path is None:
                continue

            if event_path.suffix.lower() in self.suspicious_extensions:
                suspicious_paths.add(str(event_path))

        return len(suspicious_paths)

    def _count_correlated_indicators(
        self,
        recent_events: list[dict[str, Any]],
        current_reasons: list[str],
        current_time: datetime,
    ) -> int:
        """Count distinct ransomware-risk indicator categories."""

        cutoff = current_time - timedelta(
            seconds=self.WINDOW_SECONDS
        )

        found_indicators = set()

        def collect_indicators(reasons: list[str]) -> None:
            for reason in reasons:
                reason_lower = str(reason).lower()

                for category, keywords in self.indicator_keywords.items():
                    if any(
                        keyword in reason_lower
                        for keyword in keywords
                    ):
                        found_indicators.add(category)

        collect_indicators(current_reasons)

        for item in recent_events:
            event_time = self._parse_timestamp(
                item.get("timestamp")
            )

            if event_time is None:
                continue

            if not cutoff <= event_time <= current_time:
                continue

            if self._event_path(item) is None:
                continue

            reasons = item.get("reasons") or []

            if isinstance(reasons, str):
                reasons = [reasons]

            if isinstance(reasons, list):
                collect_indicators(reasons)

        return len(found_indicators)

    def _calculate_confidence(
        self,
        indicator_count: int,
        risk_score: int,
    ) -> tuple[int, str]:
        """Estimate evidence strength, not ransomware probability."""

        if indicator_count >= 3 and risk_score >= 40:
            return 90, "high"

        if indicator_count >= 2:
            return 65, "medium"

        if indicator_count == 1:
            return 35, "low"

        return 10, "low"

    def analyze_event(
        self,
        event: dict[str, Any],
        recent_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Analyze one sandbox event using recent historical activity."""

        file_path = self._event_path(event)

        if file_path is None:
            raise ValueError(
                "File is outside the configured sandbox"
            )

        action = event.get("action")
        entropy = None
        reasons = []
        score = 0

        # Prefer the incoming event timestamp. Fall back to UTC now
        # when the timestamp is missing or invalid.
        current_time = (
            self._parse_timestamp(event.get("timestamp"))
            or datetime.now(timezone.utc)
        )

        historical_events = recent_events or []
        current_event = {
            **event,
            "timestamp": current_time.isoformat(),
        }

        all_events = [
            *historical_events,
            current_event,
        ]

        recent_change_count = self._count_recent_file_changes(
            all_events,
            current_time,
        )

        recent_move_count = self._count_recent_file_moves(
            all_events,
            current_time,
        )

        recent_suspicious_extension_count = (
            self._count_recent_suspicious_extensions(
                all_events,
                current_time,
            )
        )

        # Suspicious file extension.
        if file_path.suffix.lower() in self.suspicious_extensions:
            score += 25

            reasons.append(
                f"Suspicious file extension detected: {file_path.suffix}"
            )

        # File entropy.
        if action in {"created", "modified"}:
            try:
                if file_path.is_file():
                    entropy = calculate_entropy(str(file_path))

                    is_compressed_file = (
                        file_path.suffix.lower()
                        in self.compressed_extensions
                    )

                    if entropy >= 7.2 and not is_compressed_file:
                        score += 10
                        reasons.append("High file entropy")
                else:
                    reasons.append(
                        "File content unavailable for entropy analysis"
                    )

            except OSError:
                entropy = None
                reasons.append(
                    "File content unavailable for entropy analysis"
                )
        # Suspicious extension burst.
        if recent_suspicious_extension_count >= 5:
            score += 20

            reasons.append(
                "Suspicious extension burst detected "
                f"({recent_suspicious_extension_count} "
                "distinct files in 60 seconds)"
            )

        # Normal creation and modification activity.
        if action in {"created", "modified"}:
            score += 5
            reasons.append(f"File {action} observed")

        # File deletion activity.
        elif action == "deleted":
            score += 10
            reasons.append("File deletion observed")

        # File rename activity.
        elif action == "moved":
            score += 10
            reasons.append("File rename observed")

        # Rapid file renaming.
        if recent_move_count >= 5:
            score += 15

            reasons.append(
                "Rapid file-rename activity "
                f"({recent_move_count} distinct files in 60 seconds)"
            )

        # Rapid file modification.
        if recent_change_count >= 10:
            score += 30

            reasons.append(
                "High file-change activity "
                f"({recent_change_count} distinct files in 60 seconds)"
            )

        elif recent_change_count >= 5:
            score += 15

            reasons.append(
                "Elevated file-change activity "
                f"({recent_change_count} distinct files in 60 seconds)"
            )

        if action == "deleted" and entropy is None:
            reasons.append(
                "File content unavailable for entropy analysis"
            )

        # Correlation of independent indicator categories.
        correlated_indicator_count = (
            self._count_correlated_indicators(
                historical_events,
                reasons,
                current_time,
            )
        )

        if correlated_indicator_count >= 3:
            score += 15

            reasons.append(
                "Correlated ransomware indicators detected "
                f"({correlated_indicator_count} "
                "distinct indicators in 60 seconds)"
            )

        score = min(score, 100)

        confidence_score, confidence_level = (
            self._calculate_confidence(
                correlated_indicator_count,
                score,
            )
        )

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
            "confidence_score": confidence_score,
            "confidence_level": confidence_level,
            "reasons": reasons or [
                "No configured risk indicators matched"
            ],
        }