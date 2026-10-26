
from pathlib import Path
from typing import Any

from app.core.entropy import calculate_entropy


class DetectionEngine:
    """Generate explainable, preliminary file-risk alerts."""

    def __init__(self, sandbox_directory: str):
        self.sandbox = Path(sandbox_directory).resolve()

    def analyze_event(self, event: dict[str, Any]) -> dict[str, Any]:
        file_path = Path(event["path"]).resolve()

        # Only analyze files inside the configured sandbox.
        if not file_path.is_relative_to(self.sandbox):
            raise ValueError("File is outside the configured sandbox")

        action = event.get("action", "unknown")
        entropy = None
        reasons = []
        score = 0

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
