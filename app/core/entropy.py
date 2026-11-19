import math
from collections import Counter
from pathlib import Path


def calculate_entropy(
    file_path: str,
    sample_size: int = 65536,
) -> float:
    """
    Calculate Shannon entropy for up to sample_size bytes.

    Returns a value between 0 and 8 bits per byte.
    Reads files only; does not modify them.
    """

    if (
        not isinstance(sample_size, int)
        or isinstance(sample_size, bool)
        or sample_size <= 0
    ):
        raise ValueError(
            "sample_size must be a positive integer"
        )

    path = Path(file_path)

    with path.open("rb") as file:
        data = file.read(sample_size)

    if not data:
        return 0.0

    total_bytes = len(data)
    counts = Counter(data)

    entropy = 0.0

    for count in counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)