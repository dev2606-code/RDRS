
from pathlib import Path

from app.core.entropy import calculate_entropy


def test_empty_file_has_zero_entropy(tmp_path: Path):
    file_path = tmp_path / "empty.txt"
    file_path.write_bytes(b"")

    assert calculate_entropy(str(file_path)) == 0.0


def test_repeated_bytes_have_zero_entropy(tmp_path: Path):
    file_path = tmp_path / "repeated.txt"
    file_path.write_bytes(b"A" * 100)

    assert calculate_entropy(str(file_path)) == 0.0


def test_entropy_is_between_zero_and_eight(tmp_path: Path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("Harmless RDRS test content.", encoding="utf-8")

    result = calculate_entropy(str(file_path))

    assert 0.0 <= result <= 8.0
