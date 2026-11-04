"""Select the retained authority reference run that the reader controls read."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

RETAINED = Path(__file__).resolve().parent / "retained"


@pytest.fixture(scope="session")
def retained() -> tuple[Path, dict[str, object]]:
    """Return the committed native population and its consumer pins without copying."""
    root = RETAINED / "native"
    return root, json.loads((root / "consumer-pins.json").read_text(encoding="ascii"))
