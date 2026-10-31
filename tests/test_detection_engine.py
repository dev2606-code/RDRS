from datetime import datetime, timedelta, timezone
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
    assert result["risk_score"] == 45
    assert result["severity"] == "high"
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