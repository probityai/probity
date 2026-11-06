"""The retained native population for joint reader and host gate controls."""
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from probity_observer.crypto import strict_loads

from joint_common import load, withheld_sources

RETAINED = Path(__file__).resolve().parents[1] / "retained"


class Retained(NamedTuple):
    """Retained packet root, its pins, the reader's retained report and withheld sources."""

    root: Path
    pins: dict[str, Any]
    report: dict[str, Any]
    withheld: dict[str, str]


@pytest.fixture(scope="session")
def retained() -> Retained:
    """Select the committed original packet and the reader output retained with it."""
    root = RETAINED / "fresh-run"
    return Retained(root, load(root, "consumer-pins.json"), strict_loads((RETAINED / "host-receipts/reader.stdout").read_bytes()), withheld_sources(RETAINED / "WITHHELD-SOURCES.json"))

