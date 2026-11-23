"""The verify command answers every input with one typed verdict and never a bare traceback.

0 verified, 1 refused with a JSON reason, 3 the verifier failed on this input. Until this test,
a refusal was an uncaught VerificationError (exit 1, like any crash), and 50 of 318 one-field type
swaps of the broker-packet fixture crashed with TypeError or KeyError instead of being refused.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from probity_observer import cli
from probity_observer.cli import REFUSED, VERIFIED, VERIFIER_ERROR, main

PACKET = Path(__file__).resolve().parents[1] / "scripts" / "fixtures" / "broker-packet"
PINS = [
    "--observer-key", "a592976c199b8a4f3a80ca4412df916de591aa4a10f95e0b8030e1321bd2d9de",
    "--witness-key", "143f322c613549cf4da40ae09b0634f82b68d2d5a1017639bdde2e1eb15353f6",
]


def _copy(tmp_path: Path) -> Path:
    root = tmp_path / "packet"
    shutil.copytree(PACKET, root)
    return root


def _write_packet(root: Path, packet: dict[str, Any]) -> None:
    raw = json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    (root / "packet.json").write_bytes(raw.encode())


def _put(node: Any, path: tuple[str, ...], value: Any) -> None:
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value


def _answer(root: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    code = main(["verify", str(root), *PINS])
    return code, json.loads(capsys.readouterr().out)


def test_the_fixture_verifies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, answer = _answer(_copy(tmp_path), capsys)
    assert (code, answer["status"]) == (VERIFIED, "verified")


@pytest.mark.parametrize(
    ("name", "relative", "change"),
    [
        ("space after a colon", "packet.json", lambda b: b.replace(b'":', b'": ', 1)),
        ("trailing newline", "packet.json", lambda b: b + b"\n"),
        ("space in the history", "history.jsonl", lambda b: b.replace(b'":', b'": ', 1)),
        ("one letter of the scope", "packet.json", lambda b: b.replace(b'"/work"', b'"/worl"', 1)),
        ("one bit of the retained file", "workspace/result.txt", lambda b: bytes([b[0] ^ 1]) + b[1:]),
    ],
)
def test_one_changed_byte_is_refused(tmp_path, capsys, name, relative, change) -> None:
    root = _copy(tmp_path)
    target = root / relative
    target.write_bytes(change(target.read_bytes()))
    code, answer = _answer(root, capsys)
    assert code == REFUSED, name
    assert answer["status"] == "refused" and answer["reason"], name


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("claim",), None),
        (("claim", "coverage"), None),
        (("claim", "coverage"), {}),
        (("commitment", "preimage"), 7),
        (("commitment", "signature"), None),
        (("checkpoint", "signature"), []),
        (("authority",), {}),
        (("claimSignature",), 1),
    ],
)
def test_a_member_of_the_wrong_type_is_refused(tmp_path, capsys, path, value) -> None:
    root = _copy(tmp_path)
    packet = json.loads((root / "packet.json").read_bytes())
    _put(packet, path, value)
    _write_packet(root, packet)
    code, answer = _answer(root, capsys)
    assert code == REFUSED, (path, value, answer)
    assert answer["status"] == "refused"


def test_a_missing_packet_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _copy(tmp_path)
    (root / "packet.json").unlink()
    code, answer = _answer(root, capsys)
    assert (code, answer["refusal"]) == (REFUSED, "FileNotFoundError")


def test_a_verifier_failure_is_not_a_refusal(tmp_path, capsys, monkeypatch) -> None:
    def broken(_arguments: object) -> dict[str, str]:
        raise RuntimeError("verifier bug")

    monkeypatch.setattr(cli, "run_verify_command", broken)
    code = main(["verify", str(_copy(tmp_path)), *PINS])
    captured = capsys.readouterr()
    assert code == VERIFIER_ERROR
    assert json.loads(captured.out)["status"] == "verifier-error"
    assert "RuntimeError: verifier bug" in captured.err
