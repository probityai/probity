"""The retained native packet, shared only as immutable test input."""

from pathlib import Path

import pytest

RETAINED = Path(__file__).resolve().parents[1] / "retained"


@pytest.fixture(scope="session")
def original_packet() -> Path:
    """Return the packet retained from the latest successful main run."""
    return RETAINED / "fresh-run" / "packet"
