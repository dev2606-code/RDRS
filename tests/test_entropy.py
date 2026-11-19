
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
def test_uniform_byte_distribution_has_maximum_entropy(tmp_path: Path):
    file_path = tmp_path / "uniform.bin"
    file_path.write_bytes(bytes(range(256)) * 10)

    assert calculate_entropy(str(file_path)) == 8.0


def test_entropy_uses_only_configured_sample_size(tmp_path: Path):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"A" * 100 + bytes(range(256)))

    result = calculate_entropy(str(file_path), sample_size=100)

    assert result == 0.0
import pytest

@pytest.mark.parametrize(
    "sample_size",
    [0, -1, True, False, 1.5, "65536", None],
)
def test_calculate_entropy_rejects_invalid_sample_size(
    tmp_path,
    sample_size,
):
    file_path = tmp_path / "sample.bin"
    file_path.write_bytes(b"test data")

    with pytest.raises(ValueError):
        calculate_entropy(
            str(file_path),
            sample_size=sample_size,
        )