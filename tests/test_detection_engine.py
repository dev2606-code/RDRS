
from datetime import datetime, timedelta, timezone
import gzip
import random

import pytest

from app.detectors.detection_engine import DetectionEngine


def test_normal_file_generates_reviewable_result(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "normal.txt"
    sample.write_text("Harmless RDRS test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))
    result = engine.analyze_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["status"] == "needs_review"
    assert result["risk_score"] >= 0
    assert result["severity"] in {"low", "medium", "high"}


def test_file_outside_sandbox_is_rejected(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("Safe test.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))

    with pytest.raises(ValueError):
        engine.analyze_event({
            "path": str(outside_file),
            "action": "created",
        })


def test_deleted_file_generates_low_risk_review(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    engine = DetectionEngine(str(sandbox))
    result = engine.analyze_event({
        "path": str(sandbox / "deleted.txt"),
        "action": "deleted",
    })

    assert result["risk_score"] == 10
    assert result["status"] == "needs_review"


def test_duplicate_events_for_same_file_count_once(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "duplicate.txt"
    sample.write_text("Safe test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    recent_events = [
        {"path": str(sample), "action": "created", "timestamp": now},
        {"path": str(sample), "action": "modified", "timestamp": now},
    ]

    result = engine.analyze_event(
        {"path": str(sample), "action": "modified", "timestamp": now},
        recent_events=recent_events,
    )

    assert result["risk_score"] == 5
    assert not any("file-change activity" in reason for reason in result["reasons"])


def test_old_events_do_not_increase_risk(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "old-events.txt"
    sample.write_text("Safe test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))
    old_time = (
        datetime.now(timezone.utc) - timedelta(minutes=5)
    ).isoformat()

    recent_events = [
        {
            "path": str(sandbox / f"old_{i}.txt"),
            "action": "modified",
            "timestamp": old_time,
        }
        for i in range(12)
    ]

    result = engine.analyze_event(
        {"path": str(sample), "action": "modified"},
        recent_events=recent_events,
    )

    assert result["risk_score"] == 5
    assert not any("file-change activity" in reason for reason in result["reasons"])


def test_invalid_timestamps_are_ignored(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "invalid-time.txt"
    sample.write_text("Safe test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))

    recent_events = [
        {
            "path": str(sandbox / f"invalid_{i}.txt"),
            "action": "modified",
            "timestamp": "not-a-valid-timestamp",
        }
        for i in range(12)
    ]

    result = engine.analyze_event(
        {"path": str(sample), "action": "modified"},
        recent_events=recent_events,
    )

    assert result["risk_score"] == 5
    assert not any("file-change activity" in reason for reason in result["reasons"])


def test_high_entropy_file_is_flagged_for_review(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "high_entropy.txt"
    sample.write_bytes(bytes(range(256)) * 200)

    engine = DetectionEngine(str(sandbox))
    result = engine.analyze_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["entropy"] >= 7.2
    assert result["risk_score"] == 15
    assert result["severity"] == "low"
    assert "High file entropy" in result["reasons"]


def test_high_entropy_alone_is_not_confirmed_threat(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "random_data.bin"
    sample.write_bytes(bytes(range(256)) * 200)

    engine = DetectionEngine(str(sandbox))
    result = engine.analyze_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["entropy"] >= 7.2
    assert result["status"] == "needs_review"
    assert "High file entropy" in result["reasons"]


def test_suspicious_extension_generates_medium_risk(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "sample.locked"
    sample.write_text("Synthetic RDRS test file.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))
    result = engine.analyze_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["risk_score"] == 30
    assert result["severity"] == "medium"
    assert any(
        "Suspicious file extension" in reason
        for reason in result["reasons"]
    )


def test_rapid_file_changes_increase_risk(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "current.txt"
    sample.write_text("Safe test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    recent_events = [
        {
            "path": str(sandbox / f"file_{i}.txt"),
            "action": "modified",
            "timestamp": now,
        }
        for i in range(5)
    ]

    result = engine.analyze_event(
        {
            "path": str(sample),
            "action": "modified",
            "timestamp": now,
        },
        recent_events=recent_events,
    )

    assert result["risk_score"] == 20
    assert result["severity"] == "medium"
    assert any(
        "Elevated file-change activity" in reason
        for reason in result["reasons"]
    )


def test_legitimate_compressed_file_remains_low_risk(tmp_path):
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

    assert result["entropy"] >= 7.2
    assert result["risk_score"] == 5
    assert result["severity"] == "low"
    assert result["status"] == "needs_review"
    assert "High file entropy" not in result["reasons"]

def test_bulk_file_creation_does_not_trigger_rapid_modification_alert(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "current.txt"
    sample.write_text("Safe test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    recent_events = [
        {
            "path": str(sandbox / f"copy_{i}.txt"),
            "action": "created",
            "timestamp": now,
        }
        for i in range(8)
    ]

    result = engine.analyze_event(
        {
            "path": str(sample),
            "action": "modified",
            "timestamp": now,
        },
        recent_events=recent_events,
    )

    assert result["risk_score"] == 5
    assert result["severity"] == "low"
    assert not any(
        "file-change activity" in reason
        for reason in result["reasons"]
    )
def test_rapid_file_renaming_increases_risk(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "current.txt"
    sample.write_text("Safe test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    recent_events = [
        {
            "path": str(sandbox / f"renamed_{i}.txt"),
            "action": "moved",
            "timestamp": now,
        }
        for i in range(5)
    ]

    result = engine.analyze_event(
        {
            "path": str(sample),
            "action": "moved",
            "timestamp": now,
        },
        recent_events=recent_events,
    )

    assert result["risk_score"] == 25
    assert result["severity"] == "medium"
    assert any(
        "file-rename activity" in reason
        for reason in result["reasons"]
    )
def test_suspicious_extension_burst_increases_risk(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    recent_events = [
        {
            "path": str(sandbox / f"file_{i}.locked"),
            "action": "created",
            "timestamp": now,
        }
        for i in range(4)
    ]

    result = engine.analyze_event(
        {
            "path": str(sandbox / "current.locked"),
            "action": "created",
            "timestamp": now,
        },
        recent_events=recent_events,
    )

    assert result["risk_score"] == 50
    assert result["severity"] == "high"
    assert any(
        "suspicious extension burst" in reason.lower()
        for reason in result["reasons"]
    )
def test_correlated_ransomware_indicators_increase_risk(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    engine = DetectionEngine(str(sandbox))
    now = datetime.now(timezone.utc).isoformat()

    recent_events = [
        {
            "path": str(sandbox / "document.txt"),
            "action": "modified",
            "timestamp": now,
            "risk_score": 10,
            "reasons": ["High file entropy"],
        },
        {
            "path": str(sandbox / "photo.txt"),
            "action": "moved",
            "timestamp": now,
            "risk_score": 10,
            "reasons": ["Rapid file-rename activity"],
        },
    ]

    result = engine.analyze_event(
        {
            "path": str(sandbox / "current.locked"),
            "action": "created",
            "timestamp": now,
        },
        recent_events=recent_events,
    )

    assert result["risk_score"] == 45
    assert result["severity"] == "high"
    assert any(
        "correlated ransomware indicators" in reason.lower()
        for reason in result["reasons"]
    )
def test_confidence_high_with_multiple_indicators(tmp_path):
    engine = DetectionEngine(str(tmp_path))

    score, level = engine._calculate_confidence(3, 45)

    assert score == 90
    assert level == "high"


def test_confidence_medium_with_two_indicators(tmp_path):
    engine = DetectionEngine(str(tmp_path))

    score, level = engine._calculate_confidence(2, 30)

    assert score == 65
    assert level == "medium"


def test_confidence_low_with_one_indicator(tmp_path):
    engine = DetectionEngine(str(tmp_path))

    score, level = engine._calculate_confidence(1, 10)

    assert score == 35
    assert level == "low"
def test_event_timestamp_controls_recent_activity_window(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "current.txt"
    sample.write_text("Safe test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))

    event_time = datetime.now(timezone.utc) - timedelta(minutes=5)

    future_events = [
        {
            "path": str(sandbox / f"future_{i}.txt"),
            "action": "modified",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        for i in range(12)
    ]

    result = engine.analyze_event(
        {
            "path": str(sample),
            "action": "modified",
            "timestamp": event_time.isoformat(),
        },
        recent_events=future_events,
    )

    assert result["risk_score"] == 5
    assert not any(
        "file-change activity" in reason.lower()
        for reason in result["reasons"]
    )


def test_rename_destination_with_suspicious_extension_is_detected(
    tmp_path,
):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    renamed_file = sandbox / "report.pdf.locked"
    renamed_file.write_text(
        "Synthetic RDRS test data.",
        encoding="utf-8",
    )

    engine = DetectionEngine(str(sandbox))

    result = engine.analyze_event(
        {
            "path": str(renamed_file),
            "source_path": str(sandbox / "report.pdf"),
            "destination_path": str(renamed_file),
            "action": "moved",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        recent_events=[],
    )

    assert result["risk_score"] == 35
    assert result["action"] == "moved"
    assert any(
        "Suspicious file extension" in reason
        for reason in result["reasons"]
    )
@pytest.mark.parametrize(
    "error_type",
    [FileNotFoundError, PermissionError],
)
def test_entropy_errors_do_not_crash_detection(
    tmp_path, monkeypatch, error_type
):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "sample.txt"
    sample.write_text("Normal test content.", encoding="utf-8")

    engine = DetectionEngine(str(sandbox))

    def raise_file_error(_):
        raise error_type("Synthetic file access error")

    monkeypatch.setattr(
        "app.detectors.detection_engine.calculate_entropy",
        raise_file_error,
    )

    result = engine.analyze_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["entropy"] is None
    assert result["risk_score"] == 5
    assert result["status"] == "needs_review"
    assert any(
        "File content unavailable for entropy analysis" in reason
        for reason in result["reasons"]
    )