"""A witnessed trajectory head catches each of the six edits to a closed trajectory,
and the witness signs only the count and head it saw itself."""

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
    TrajectoryWitness,
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


def _witness(tmp_path: Path, key: SigningKey | None = None) -> TrajectoryWitness:
    """A witness under an ephemeral key and its own registry; tests never commit a secret."""
    key = key or SigningKey.generate()
    return TrajectoryWitness(key, tmp_path / f"registry-{key.public_hex}")


def _closed(tmp_path: Path) -> tuple[Path, dict[str, Any], SigningKey]:
    """Write the five-event session and close it under an ephemeral witness key."""
    witness = SigningKey.generate()
    path = tmp_path / "trajectory.jsonl"
    recorder = TrajectoryRecorder(path, trajectory_id=TID, witness=_witness(tmp_path, witness))
    for event in EVENTS:
        recorder.emit(event)
    return path, recorder.close(), witness


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
        TrajectoryRecorder(tmp_path / "other.jsonl", trajectory_id=TID, witness=_witness(tmp_path), canonicalization="raw")


def test_empty_trajectory_has_genesis_head(tmp_path: Path) -> None:
    witness = SigningKey.generate()
    path = tmp_path / "empty.jsonl"
    head = TrajectoryRecorder(path, trajectory_id=TID, witness=_witness(tmp_path, witness)).close()
    assert head["count"] == 0 and head["head"] == genesis(TID)
    assert verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)["count"] == 0


def test_closed_recorder_refuses_events(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=TID, witness=_witness(tmp_path))
    recorder.emit({"type": "a"})
    recorder.close()
    with pytest.raises(VerificationError, match="closed"):
        recorder.emit({"type": "b"})


def test_profile_refusals(tmp_path: Path) -> None:
    recorder = TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=TID, witness=_witness(tmp_path))
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
        TrajectoryRecorder(path, trajectory_id=TID, witness=_witness(tmp_path))


def test_head_of_another_trajectory_refused(tmp_path: Path) -> None:
    """Counter-example: the producer hands over a quiet session's file and head in place of the session asked about."""
    witness = SigningKey.generate()
    counter = _witness(tmp_path, witness)
    quiet = TrajectoryRecorder(tmp_path / "quiet.jsonl", trajectory_id="run-quiet", witness=counter)
    quiet.emit({"type": "tool.call", "status": "ok"})
    quiet_head = quiet.close()
    asked = TrajectoryRecorder(tmp_path / "asked.jsonl", trajectory_id=TID, witness=counter)
    asked.emit({"type": "tool.call", "status": "ok"})
    asked.emit({"type": "tool.call", "tool": "wire_funds", "status": "ok"})
    asked.close()
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
    recorder = TrajectoryRecorder(tmp_path / "empty.jsonl", trajectory_id="run-other", witness=_witness(tmp_path))
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
        TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=value, witness=_witness(tmp_path))  # type: ignore[arg-type]


def _five(tmp_path: Path, witness: TrajectoryWitness) -> TrajectoryRecorder:
    recorder = TrajectoryRecorder(tmp_path / "trajectory.jsonl", trajectory_id=TID, witness=witness)
    for event in EVENTS:
        recorder.emit(event)
    return recorder


def test_witness_refuses_a_shortened_claim(tmp_path: Path) -> None:
    """Counter-example: the producer asks the witness to sign a head that stops before the last event."""
    witness = _witness(tmp_path)
    recorder = _five(tmp_path, witness)
    entries = _entries(recorder.path)
    short = {"format": HEAD_FORMAT, "trajectory": TID, "count": 4, "head": entry_digest(entries[3])}
    with pytest.raises(VerificationError, match="close refused: the witness counted 5 entries"):
        witness.close(TID, short)
    head = recorder.close()
    assert head["count"] == 5 and head["head"] == entry_digest(entries[4])
    assert verify_trajectory(recorder.path, head, witness.public_hex, trajectory_id=TID)["count"] == 5


def test_witness_refuses_a_producer_that_rewinds_its_own_state(tmp_path: Path) -> None:
    """Counter-example: the recorder's own count and head are rewound, as a producer that holds them would."""
    witness = _witness(tmp_path)
    recorder = _five(tmp_path, witness)
    entries = _entries(recorder.path)
    recorder._count, recorder._last = 4, entry_digest(entries[3])
    _write(recorder.path, entries[:4])
    with pytest.raises(VerificationError, match="close refused"):
        recorder.close()


def test_witness_never_reopens_an_identifier(tmp_path: Path) -> None:
    """Counter-example: start the trajectory again under the same id to drop what the witness already counted."""
    witness = _witness(tmp_path)
    _five(tmp_path, witness)
    with pytest.raises(VerificationError, match="already opened"):
        TrajectoryRecorder(tmp_path / "again.jsonl", trajectory_id=TID, witness=witness)
    witness.close(TID, witness.head_payload(TID))
    with pytest.raises(VerificationError, match="already opened"):
        witness.open(TID)


def test_witness_refuses_entries_that_do_not_follow(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    witness.open(TID)
    first = {"seq": 1, "prev": genesis(TID), "event": {"type": "a"}}
    witness.observe(TID, first)
    with pytest.raises(VerificationError, match="the witness expects 2"):
        witness.observe(TID, {**first, "event": {"type": "rewritten"}})
    with pytest.raises(VerificationError, match="the witness expects 2"):
        witness.observe(TID, {"seq": 3, "prev": entry_digest(first), "event": {"type": "c"}})
    with pytest.raises(VerificationError, match="prev does not link"):
        witness.observe(TID, {"seq": 2, "prev": "0" * 64, "event": {"type": "b"}})
    with pytest.raises(VerificationError, match="invalid fields"):
        witness.observe(TID, {"seq": 2, "prev": entry_digest(first), "event": {}, "extra": 1})
    with pytest.raises(VerificationError, match="not an integer"):
        witness.observe(TID, {"seq": True, "prev": entry_digest(first), "event": {}})
    assert witness.head_payload(TID)["count"] == 1


def test_witness_refuses_an_unopened_or_closed_trajectory(tmp_path: Path) -> None:
    witness = _witness(tmp_path)
    with pytest.raises(VerificationError, match="not open"):
        witness.observe(TID, {"seq": 1, "prev": genesis(TID), "event": {}})
    witness.open(TID)
    witness.close(TID, witness.head_payload(TID))
    with pytest.raises(VerificationError, match="not open"):
        witness.close(TID, {"format": HEAD_FORMAT, "trajectory": TID, "count": 0, "head": genesis(TID)})


def test_restarted_witness_never_reopens_an_identifier(tmp_path: Path) -> None:
    """Counter-example: a second witness instance under the same key (a restart, a second worker) opens the id again
    and signs a second, different head for it; both heads verified before the registry moved to disk."""
    key = SigningKey.generate()
    first = TrajectoryRecorder(tmp_path / "a.jsonl", trajectory_id=TID, witness=_witness(tmp_path, key))
    first.emit({"type": "tool.call", "status": "denied"})
    first.close()
    with pytest.raises(VerificationError, match="already opened"):
        TrajectoryRecorder(tmp_path / "b.jsonl", trajectory_id=TID, witness=_witness(tmp_path, key))
    assert not (tmp_path / "b.jsonl").exists()


def test_registry_belongs_to_one_witness_key(tmp_path: Path) -> None:
    registry = tmp_path / "registry"
    TrajectoryWitness(SigningKey.generate(), registry)
    with pytest.raises(VerificationError, match="another witness key"):
        TrajectoryWitness(SigningKey.generate(), registry)


@pytest.mark.parametrize("separator", [b"\r", b"\r\n"])
def test_only_lf_separates_entries(tmp_path: Path, separator: bytes) -> None:
    """Counter-example: entries separated by CR or CRLF verified, while a reader that splits on LF refuses them."""
    path, head, witness = _closed(tmp_path)
    raw = path.read_bytes()
    path.write_bytes(raw[:-1].replace(b"\n", separator) + b"\n")
    with pytest.raises(VerificationError):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_blank_line_refused(tmp_path: Path) -> None:
    path, head, witness = _closed(tmp_path)
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(VerificationError):
        verify_trajectory(path, head, witness.public_hex, trajectory_id=TID)


def test_entry_the_witness_refuses_never_reaches_the_file(tmp_path: Path) -> None:
    """Counter-example: emit raised because the witness refused, and the line was on disk anyway."""
    witness = _witness(tmp_path)
    recorder = TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=TID, witness=witness)
    recorder.emit({"type": "a"})
    witness.close(TID, witness.head_payload(TID))
    with pytest.raises(VerificationError, match="not open"):
        recorder.emit({"type": "b"})
    assert recorder.path.read_bytes().count(b"\n") == 1 and recorder.count == 1


def test_failed_write_breaks_the_recorder(tmp_path: Path) -> None:
    """An entry the witness counted and the file did not store leaves no way to close or continue."""
    witness = _witness(tmp_path)
    recorder = TrajectoryRecorder(tmp_path / "t.jsonl", trajectory_id=TID, witness=witness)
    recorder.emit({"type": "a"})
    recorder.path = tmp_path / "missing-dir" / "t.jsonl"
    with pytest.raises(VerificationError, match="counted by the witness and not stored"):
        recorder.emit({"type": "b"})
    with pytest.raises(VerificationError, match="broken"):
        recorder.emit({"type": "c"})
    with pytest.raises(VerificationError, match="close refused"):
        recorder.close()
