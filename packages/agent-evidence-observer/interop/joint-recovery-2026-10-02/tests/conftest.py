"""One shared actual native population for joint reader and host gate controls."""
import os
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from probity_observer.crypto import strict_loads

from joint_common import load, withheld_sources
from joint_run import run

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


@pytest.fixture(scope="session")
def fresh(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Run the real population through a relative caller-selected output path.

    The workflow and CLI may supply a relative root. Every literal native
    launch path must still join the plan's selected absolute capture roots.
    """
    root = tmp_path_factory.mktemp("joint-native") / "packet"
    report = run(Path(os.path.relpath(root)), "0" * 40)
    return root, load(root, "consumer-pins.json"), report
