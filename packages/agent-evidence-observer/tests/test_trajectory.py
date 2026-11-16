"""A witnessed trajectory head catches each of the six edits to a closed trajectory."""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path
from typing import Any

import pytest
import rfc8785
from probity_observer import SigningKey, VerificationError
from probity_observer.history import GENESIS
from probity_observer.ledger import HEAD_DOMAIN
from probity_observer.trajectory import (
    CANONICALIZATION_TERM,
    HEAD_FORMAT,
    TrajectoryRecorder,
    entry_digest,
    genesis,
    verify_trajectory,
)

TID = "run-2026-11-15-a"

EVENTS = [
    {"type": "session.start", "agent": "planner"},
    {"type": "tool.call", "tool": "lookup", "status": "ok"},
    {"type": "tool.call", "tool": "write", "status": "ok"},
    {"type": "decision", "parent": 2, "outcome": "apply"},
    {"type": "session.end", "status": "ok"},
]


def _closed(tmp_path: Path) -> tuple[Path, dict[str, Any], SigningKey]:
    """Write the five-event session and close it under an ephemeral witness key."""
    witness = SigningKey.generate()
    path = tmp_path / "trajectory.jsonl"
    recorder = TrajectoryRecorder(path, trajectory_id=TID)
    for event in EVENTS:
        recorder.emit(event)
    return path, recorder.close(witness), witness


def _entries(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def _write(path: Path, entries: list[dict[str, Any]]) -> None:
    path.write_bytes(b"".join(rfc8785.dumps(entry) + b"\n" for entry in entries))


def _relink(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What a producer who edits its own storage does: renumber and re-hash every link."""
    previous = genesis(TID)
    out = []
    for number, entry in enumerate(entries, start=1):
        fixed = {"seq": number, "prev": previous, "event": entry["event"]}
        out.append(fixed)
        previous = entry_digest(fixed)
    return out


def test_clean_session_verifies(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    result = verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)
    assert result["count"] == 5
    assert result["canonicalization"] == "jcs_integer_only_v1"
    assert result["canonicalization_term"] == CANONICALIZATION_TERM
    assert set(head) == {"format", "trajectory", "count", "head", "keyid", "signature"}
    assert head["format"] == HEAD_FORMAT and head["trajectory"] == TID
    assert result["trajectory"] == TID


def test_prev_is_plain_sha256_over_rfc8785_bytes(tmp_path: Path) -> None:
    """A second party recomputes every link with any RFC 8785 library and no domain prefix."""
    path, head, _ = _closed(tmp_path)
    entries = _entries(path)
    assert entries[0]["prev"] == genesis(TID) == hashlib.sha256(
        rfc8785.dumps({"format": "probity-trajectory-genesis-v1", "trajectory": TID})).hexdigest()
    for earlier, later in itertools.pairwise(entries):
        assert later["prev"] == hashlib.sha256(rfc8785.dumps(earlier)).hexdigest()
    assert head["head"] == hashlib.sha256(rfc8785.dumps(entries[-1])).hexdigest()


def test_drop_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    _write(path, entries[:2] + entries[3:])
    with pytest.raises(VerificationError, match="seq is not contiguous"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_drop_relinked_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    _write(path, _relink(entries[:2] + entries[3:]))
    with pytest.raises(VerificationError, match="tail missing"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_swap_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    entries[1], entries[2] = entries[2], entries[1]
    _write(path, entries)
    with pytest.raises(VerificationError, match="seq is not contiguous"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_swap_relinked_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    entries[1], entries[2] = entries[2], entries[1]
    _write(path, _relink(entries))
    with pytest.raises(VerificationError, match="differs from the witnessed head"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_flip_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    entries[2]["event"]["status"] = "error"
    _write(path, entries)
    with pytest.raises(VerificationError, match="prev does not link"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_parent_rewrite_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    entries[3]["event"]["parent"] = 1
    _write(path, _relink(entries))
    with pytest.raises(VerificationError, match="differs from the witnessed head"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_link_rewrite_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    entries[2]["prev"] = "f" * 64
    _write(path, entries)
    with pytest.raises(VerificationError, match="prev does not link"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_tail_truncation_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    _write(path, _entries(path)[:-1])
    with pytest.raises(VerificationError, match="tail missing"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_entries_past_head_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    entries = _entries(path)
    extra = {"seq": 6, "prev": entry_digest(entries[-1]), "event": {"type": "late"}}
    _write(path, entries + [extra])
    with pytest.raises(VerificationError, match="past the witnessed head"):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_rewrite_resigned_with_another_key_refused(tmp_path: Path) -> None:
    """The producer rewrites the log and re-signs a head with a key it holds."""
    path, _, witness = _closed(tmp_path)
    entries = _entries(path)
    entries[1]["event"]["status"] = "error"
    _write(path, _relink(entries))
    impostor = SigningKey.generate()
    payload = {"format": HEAD_FORMAT, "trajectory": TID, "count": 5, "head": entry_digest(_entries(path)[-1])}
    forged = {**payload, "keyid": impostor.public_hex, "signature": impostor.sign(HEAD_FORMAT, payload)}
    with pytest.raises(VerificationError, match="differs from the pinned witness key"):
        verify_trajectory(path, forged, witness.public_hex, trajectory_id=TID)
    relabelled = {**forged, "keyid": witness.public_hex}
    with pytest.raises(VerificationError, match="does not verify"):
        verify_trajectory(path, relabelled, witness.public_hex, trajectory_id=TID)


def test_canonicalization_declarations(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    assert verify_trajectory(path, head, witness.public_hex, trajectory_id=TID, canonicalization="rfc8785")["count"] == 5
    for value in ("jcs_safe_integer_v1", "cbor_deterministic", "raw", "RFC8785", ""):
        with pytest.raises(VerificationError, match="canonicalization"):
            verify_trajectory(path, head, witness.public_hex, trajectory_id=TID, canonicalization=value)
    with pytest.raises(VerificationError, match="canonicalization"):
        TrajectoryRecorder(tmp_path / "other.jsonl", trajectory_id=TID, canonicalization="raw")


def test_empty_trajectory_has_genesis_head(tmp_path: Path) -> None:
    witness = SigningKey.generate()
    path = tmp_path / "empty.jsonl"
    head = TrajectoryRecorder(path, trajectory_id=TID).close(witness)
    assert head["count"] == 0 and head["head"] == genesis(TID)
    assert verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)["count"] == 0


def test_closed_recorder_refuses_events(tmp_path: Path) -> None:
    witness = SigningKey.generate()
    recorder = TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=TID)
    recorder.emit({"type": "a"})
    recorder.close(witness)
    with pytest.raises(VerificationError, match="closed"):
        recorder.emit({"type": "b"})


def test_profile_refusals(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=TID)
    with pytest.raises(VerificationError):
        recorder.emit({"value": 1.5})
    with pytest.raises(VerificationError):
        recorder.emit({"value": 2**53})
    with pytest.raises(VerificationError, match="JSON object"):
        recorder.emit(["not", "an", "object"])  # type: ignore[arg-type]
    assert recorder.count == 0


def test_duplicate_member_in_stored_entry_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    lines = path.read_bytes().splitlines()
    lines[0] = lines[0].replace(b'"event":{', b'"event":{"type":"x",', 1)
    path.write_bytes(b"\n".join(lines) + b"\n")
    with pytest.raises(VerificationError):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_existing_file_refused(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    path.write_bytes(b"{}\n")
    with pytest.raises(VerificationError, match="already holds entries"):
        TrajectoryRecorder(path, trajectory_id=TID)


def test_head_of_another_trajectory_refused(tmp_path: Path) -> None:
    """Counter-example: the producer hands over a quiet session's file and head in place of the session asked about."""
    witness = SigningKey.generate()
    quiet = TrajectoryRecorder(tmp_path / "quiet.jsonl", trajectory_id="run-quiet")
    quiet.emit({"type": "tool.call", "status": "ok"})
    quiet_head = quiet.close(witness)
    asked = TrajectoryRecorder(tmp_path / "asked.jsonl", trajectory_id=TID)
    asked.emit({"type": "tool.call", "status": "ok"})
    asked.emit({"type": "tool.call", "tool": "wire_funds", "status": "ok"})
    asked.close(witness)
    with pytest.raises(VerificationError, match="names another trajectory"):
        verify_trajectory(tmp_path / "quiet.jsonl", quiet_head, witness.public_hex, trajectory_id=TID)
    relabelled = {**quiet_head, "trajectory": TID}
    with pytest.raises(VerificationError, match="does not verify"):
        verify_trajectory(tmp_path / "quiet.jsonl", relabelled, witness.public_hex, trajectory_id=TID)


def test_entries_of_another_trajectory_do_not_link(tmp_path: Path) -> None:
    """The first link is bound to the id, so a renamed entry list fails at entry 1 even under an honest head."""
    path, head, witness = _closed(tmp_path)
    with pytest.raises(VerificationError):
        verify_trajectory(path, {**head, "trajectory": "run-other"}, witness.public_hex, trajectory_id="run-other")
    other = tmp_path / "other.jsonl"
    other.write_bytes(path.read_bytes())
    recorder = TrajectoryRecorder(tmp_path / "empty.jsonl", trajectory_id="run-other")
    other_head = {**recorder.head_payload(), "count": 5, "head": head["head"]}
    signed = {**other_head, "keyid": witness.public_hex, "signature": witness.sign(HEAD_FORMAT, other_head)}
    with pytest.raises(VerificationError, match="entry 1: prev does not link"):
        verify_trajectory(other, signed, witness.public_hex, trajectory_id="run-other")


def test_ledger_head_is_not_a_trajectory_head(tmp_path: Path) -> None:
    """Counter-example: a witness that also signs ledger heads; its count-0 ledger head must not close an empty trajectory."""
    witness = SigningKey.generate()
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")
    payload = {"format": HEAD_DOMAIN, "count": 0, "head": GENESIS}
    ledger_head = {**payload, "keyid": witness.public_hex, "signature": witness.sign(HEAD_DOMAIN, payload)}
    with pytest.raises(VerificationError, match="invalid fields"):
        verify_trajectory(path, ledger_head, witness.public_hex, trajectory_id=TID)
    cross = {"format": HEAD_DOMAIN, "trajectory": TID, "count": 0, "head": genesis(TID)}
    crossed = {**cross, "keyid": witness.public_hex, "signature": witness.sign(HEAD_DOMAIN, cross)}
    with pytest.raises(VerificationError, match="unsupported format"):
        verify_trajectory(path, crossed, witness.public_hex, trajectory_id=TID)
    domain_swap = {**crossed, "format": HEAD_FORMAT}
    with pytest.raises(VerificationError, match="does not verify"):
        verify_trajectory(path, domain_swap, witness.public_hex, trajectory_id=TID)


@pytest.mark.parametrize("value", ["", None, 7, "run\u00e9"])
def test_trajectory_id_refusals(tmp_path: Path, value: object) -> None:
    with pytest.raises(VerificationError, match="trajectory id"):
        TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=value)  # type: ignore[arg-type]
