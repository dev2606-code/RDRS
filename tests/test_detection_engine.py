
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
