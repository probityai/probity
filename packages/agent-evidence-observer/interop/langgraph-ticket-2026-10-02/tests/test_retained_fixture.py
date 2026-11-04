"""Replay the original durable-restart artifact after its CI retention expired."""
from __future__ import annotations

import zipfile
from pathlib import Path

from durable_reader import verify_saved
from lg_common import decode, sha, withheld_in

PROFILE_ROOT = Path(__file__).resolve().parents[1]
RETAINED = PROFILE_ROOT / "retained"
ARCHIVE = "durable-fixture.zip"
# Hash-only form of the archive from the original local run: embedded runtime
# sources are removed and listed with their digests in WITHHELD-SOURCES.json.
RETAINED_SHA256 = "d515984bc20d258bf2a261f3e18a6fcefaa6e816a1bd3b8e50408437b23c74c4"


def test_retained_original_durable_fixture(tmp_path: Path) -> None:
    raw = (RETAINED / ARCHIVE).read_bytes()
    assert sha(raw) == RETAINED_SHA256
    provenance = decode((PROFILE_ROOT / "durable-provenance.json").read_bytes())
    assert provenance["fixture"] == {"path": "retained/" + ARCHIVE, "sha256": RETAINED_SHA256, "bytes": len(raw), "files": 65}
    with zipfile.ZipFile(RETAINED / ARCHIVE) as retained:
        names = retained.namelist()
        assert len(names) == len(set(names)) == provenance["fixture"]["files"]
        assert all((tmp_path / name).resolve().is_relative_to(tmp_path.resolve()) for name in names)
        retained.extractall(tmp_path)
    withheld = withheld_in(RETAINED / "WITHHELD-SOURCES.json", ARCHIVE + "/")
    assert len(withheld) == 6
    report = verify_saved(tmp_path, decode((tmp_path / "consumer-pins.json").read_bytes()), withheld)
    assert report == decode((PROFILE_ROOT / "durable-recorded-report.json").read_bytes())
