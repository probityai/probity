"""Replay the original authenticated successful Ubuntu artifact after expiry."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from probity_adk.contract import decode, encode, withheld_in
from probity_adk.reader import verify_saved

RETAINED = Path(__file__).resolve().parents[1] / "retained"
ARCHIVE = "native-fixture-37058694970.zip"
# Hash-only form of the archive uploaded by CI run 37058694970: embedded runtime
# sources are removed and listed with their digests in WITHHELD-SOURCES.json.
RETAINED_SHA256 = "5e8e168f690714bab634a9a1d91cde600df5631e1b65d7af75d1667832a37a47"


def test_retained_original_native_ci_bytes(tmp_path: Path) -> None:
    archive = RETAINED / ARCHIVE
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == RETAINED_SHA256
    with zipfile.ZipFile(archive) as retained:
        names = retained.namelist()
        assert len(names) == len(set(names)) == 825
        assert all(
            not Path(name).is_absolute() and ".." not in Path(name).parts
            for name in names
        )
        retained.extractall(tmp_path)
    original = tmp_path / "fresh-run"
    packet = original / "packet"
    withheld = withheld_in(
        RETAINED / "WITHHELD-SOURCES.json", ARCHIVE + "/fresh-run/packet/"
    )
    assert len(withheld) == 13
    report = verify_saved(
        packet, decode((packet / "consumer-pins.json").read_bytes()), withheld
    )
    expected = (packet / "report.json").read_bytes()
    assert encode(report) == expected
    assert (original / "producer-stdout.json").read_bytes().rstrip(b"\n") == expected
    assert (original / "reader-stdout.json").read_bytes().rstrip(b"\n") == expected
