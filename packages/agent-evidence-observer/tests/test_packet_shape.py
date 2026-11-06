"""verify_packet refuses fields, line endings and workspaces it would not check."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest
from probity_observer.crypto import VerificationError, strict_loads
from probity_observer.verify import verify_packet

PACKET = Path(__file__).resolve().parents[1] / "scripts" / "fixtures" / "broker-packet"
OBSERVER_KEY = "a592976c199b8a4f3a80ca4412df916de591aa4a10f95e0b8030e1321bd2d9de"
WITNESS_KEY = "143f322c613549cf4da40ae09b0634f82b68d2d5a1017639bdde2e1eb15353f6"


def check(root: Path, packet: dict | None = None, workspace: Path | None = None) -> dict:
    packet = packet if packet is not None else strict_loads((root / "packet.json").read_bytes())
    return verify_packet(packet, root / "history.jsonl", OBSERVER_KEY, WITNESS_KEY, workspace)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    shutil.copytree(PACKET, tmp_path / "packet")
    return tmp_path / "packet"


def test_retained_packet_still_verifies(root: Path) -> None:
    assert check(root, workspace=root / "workspace")["afterRoot"]


def test_unexpected_top_level_field_refuses(root: Path) -> None:
    packet = strict_loads((root / "packet.json").read_bytes())
    packet["policyDecision"] = {"allow": True}
    with pytest.raises(VerificationError, match="packet fields are unsupported"):
        check(root, packet)


def test_missing_top_level_field_refuses(root: Path) -> None:
    packet = strict_loads((root / "packet.json").read_bytes())
    del packet["startCheckpoint"]
    with pytest.raises(VerificationError, match="packet fields are unsupported"):
        check(root, packet)


def test_crlf_history_refuses(root: Path) -> None:
    history = root / "history.jsonl"
    history.write_bytes(history.read_bytes().replace(b"\n", b"\r\n"))
    with pytest.raises(VerificationError, match="not LF"):
        check(root)


def test_bare_carriage_return_history_refuses(root: Path) -> None:
    history = root / "history.jsonl"
    lines = history.read_bytes().split(b"\n")
    history.write_bytes(lines[0] + b"\r" + b"\n".join(lines[1:]))
    with pytest.raises(VerificationError, match="not LF"):
        check(root)


def test_symlinked_workspace_refuses(root: Path, tmp_path: Path) -> None:
    link = tmp_path / "linked-workspace"
    os.symlink(root / "workspace", link)
    with pytest.raises(VerificationError, match="symbolic link"):
        check(root, workspace=link)

