
from datetime import datetime, timezone
import gzip
import random

from app.detectors.detection_engine import DetectionEngine


def test_normal_text_file_does_not_raise_high_risk(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "notes.txt"
    sample.write_text("These are normal study notes.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))

    result = engine.analyze_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["risk_score"] < 20
    assert result["severity"] == "low"
    assert result["status"] == "needs_review"


def test_legitimate_zip_file_does_not_raise_entropy_alert(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "backup.gz"
    content = random.Random(42).randbytes(4096)

    with gzip.open(sample, "wb") as compressed:
        compressed.write(content)

    engine = DetectionEngine(str(sandbox))

    result = engine.analyze_event({
        "path": str(sample),
        "action": "created",
    })

    assert "High file entropy" not in result["reasons"]
    assert result["risk_score"] < 20


def test_bulk_file_creation_alone_does_not_raise_change_burst(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    recent_events = [
        {
            "path": str(sandbox / f"copy_{i}.txt"),
            "action": "created",
            "timestamp": now,
        }
        for i in range(15)
    ]

    sample = sandbox / "current.txt"
    sample.write_text("Normal file.", encoding="utf-8")

    result = engine.analyze_event(
        {
            "path": str(sample),
            "action": "created",
            "timestamp": now,
        },
        recent_events=recent_events,
    )

    assert not any(
        "file-change activity" in reason.lower()
        for reason in result["reasons"]
    )


def test_single_file_rename_does_not_raise_rename_burst(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    result = engine.analyze_event(
        {
            "path": str(sandbox / "renamed.txt"),
            "action": "moved",
            "timestamp": now,
        },
        recent_events=[],
    )

    assert not any(
        "rapid file-rename activity" in reason.lower()
        for reason in result["reasons"]
    )
    assert result["status"] == "needs_review"
