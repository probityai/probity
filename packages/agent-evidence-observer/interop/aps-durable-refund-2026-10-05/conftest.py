"""Select the retained native captures that the public reader controls read."""
from __future__ import annotations

from pathlib import Path

import pytest

RETAINED = Path(__file__).resolve().parent / "retained"


@pytest.fixture(scope="session")
def capture() -> Path:
    """Return the committed native captures without copying them."""
    return RETAINED / "native"
