"""The retained native packet, shared only as immutable test input."""

from pathlib import Path

import pytest

from probity_adk.contract import withheld_for

RETAINED = Path(__file__).resolve().parents[1] / "retained"


@pytest.fixture(scope="session")
def packet() -> Path:
    return RETAINED / "fresh-run" / "packet"


@pytest.fixture(scope="session")
def withheld(packet: Path) -> dict[str, str]:
    return withheld_for(RETAINED / "WITHHELD-SOURCES.json", packet)
