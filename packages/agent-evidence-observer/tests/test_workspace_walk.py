"""A workspace the verifier cannot read in full is never reported as verified."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from probity_observer.cli import main
from probity_observer.records import CoverageError, tree_manifest

PACKET = Path(__file__).resolve().parents[1] / "scripts" / "fixtures" / "broker-packet"
PINS = [
    "--observer-key", "a592976c199b8a4f3a80ca4412df916de591aa4a10f95e0b8030e1321bd2d9de",
    "--witness-key", "143f322c613549cf4da40ae09b0634f82b68d2d5a1017639bdde2e1eb15353f6",
]

root_only = pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 directory")


@root_only
def test_unreadable_directory_refuses_the_manifest(tmp_path: Path) -> None:
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    (hidden / "extra.txt").write_text("not committed\n")
    hidden.chmod(0)
    try:
        with pytest.raises(CoverageError, match="workspace walk is incomplete"):
            tree_manifest(tmp_path)
    finally:
        hidden.chmod(0o700)


@root_only
def test_hidden_extra_files_never_print_verified(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "packet"
    shutil.copytree(PACKET, root)
    hidden = root / "workspace" / "payload"
    hidden.mkdir()
    (hidden / "exfil.sh").write_text("echo extra\n")
    hidden.chmod(0)
    try:
        with pytest.raises(CoverageError):
            main(["verify", str(root), *PINS])
        assert "verified" not in capsys.readouterr().out
    finally:
        hidden.chmod(0o700)
