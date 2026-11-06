"""Select the committed original packet and the reader output retained with it."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any, NamedTuple

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from target_common import withheld_sources

RETAINED = Path(__file__).resolve().parents[1] / "retained"


class Retained(NamedTuple):
    """Retained packet root, its reader report and withheld-source record."""

    root: Path
    report: dict[str, Any]
    withheld: dict[str, str]
    withheld_file: Path


@pytest.fixture(scope="session")
def retained() -> Retained:
    """Return the committed packet without copying it."""
    root = RETAINED / "fresh-run"
    return Retained(root, json.loads((RETAINED / "host-receipts/reader.stdout").read_bytes()), withheld_sources(RETAINED / "WITHHELD-SOURCES.json"), RETAINED / "WITHHELD-SOURCES.json")


@pytest.fixture
def copied(retained: Retained, tmp_path: Path) -> Path:
    """Isolate one mutation while preserving every retained byte."""
    root = tmp_path / "packet"
    shutil.copytree(retained.root, root)
    return root
