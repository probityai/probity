"""A hash-chained journal of DSSE-signed in-toto statements, its signed checkpoint, and the
offline verifier an outsider runs over both.

Each line is one envelope. Its statement's predicate carries ``seq`` (1, 2, ...), ``prev`` (SHA-256
of the previous line's bytes, 64 zeros for the first) and ``at``. A checkpoint is a signed statement
of the line count and the last line's hash: pinned by an outsider, it exposes a truncated or
rewritten journal.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import Signer, load_public, open_envelope, sign_envelope, statement
from .records import TOOL_CALL_RECORD, judge_approval_binding, judge_uncertain_effect

GENESIS = "0" * 64
CHECKPOINT_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/tool-call-journal-checkpoint"
JOURNAL_FILE = "journal.jsonl"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(base64.b64decode(envelope["payload"]))


class Journal:
    """Append-only signed journal in ``directory``. Appends are serialised by a file lock and
    fsynced, so a record that returned is on disk before the caller acts on it."""

    def __init__(self, directory: str | os.PathLike[str], signer: Signer) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / JOURNAL_FILE
        self.signer = signer

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = b""
        with self.path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    last = line.rstrip(b"\n")
        if not last:
            return 0, GENESIS
        return int(_payload(json.loads(last))["predicate"]["seq"]), _line_hash(last)

    def append(self, predicate_type: str, subject_name: str, subject_digest: str,
               predicate: Mapping[str, Any]) -> dict[str, Any]:
        """Sign and append one statement; returns the envelope written."""
        lock = self.directory / (JOURNAL_FILE + ".lock")
        with lock.open("w") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            seq, head = self._tail()
            body = statement(subject_name, subject_digest, predicate_type,
                             {**dict(predicate), "at": now(), "prev": head, "seq": seq + 1})
            envelope = sign_envelope(self.signer, json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
            line = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return envelope

    def statements(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [_payload(json.loads(line)) for line in self.path.read_text().splitlines() if line.strip()]

    def checkpoint(self) -> dict[str, Any]:
        """A signed statement of the line count and head, for an outsider to pin."""
        seq, head = self._tail()
        body = statement("tool-call-journal", head, CHECKPOINT_TYPE, {"at": now(), "count": seq, "head": head})
        return sign_envelope(self.signer, json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


def _keys(public_pems: Iterable[bytes]) -> list[Any]:
    keys = [load_public(pem) for pem in public_pems]
    if not keys:
        raise ValueError("verify_journal needs at least one trusted public key")
    return keys


def _check_approval(pred: dict[str, Any], problems: list[str], where: str) -> None:
    embedded = pred.get("approvalBinding")
    if not embedded:
        if pred.get("decision") == "allow":
            problems.append(f"{where}:allow_without_approval_binding")
        return
    payload = base64.b64decode(embedded["payloadB64"])
    if hashlib.sha256(payload).hexdigest() != pred.get("argsSha256"):
        problems.append(f"{where}:approval_payload_is_not_the_call_arguments")
    verdict = judge_approval_binding(embedded["record"], payload)
    if pred.get("decision") == "allow" and verdict["decision"] != "allow":
        problems.append(f"{where}:recorded_allow_but_reader_says_{verdict['reason']}")
    if pred.get("decision") == "deny" and verdict["decision"] == "deny" and verdict["reason"] != pred.get("reason"):
        problems.append(f"{where}:deny_reason_{pred.get('reason')}_but_reader_says_{verdict['reason']}")


def _check_effect(pred: dict[str, Any], problems: list[str], where: str) -> str | None:
    record = pred.get("uncertainEffect")
    if not record:
        problems.append(f"{where}:effect_without_uncertain_effect_record")
        return None
    verdict = judge_uncertain_effect(record)
    if verdict["decision"] != "supported":
        problems.append(f"{where}:uncertain_effect_{verdict['decision']}:{verdict['reason']}")
    if record.get("operation", {}).get("argsDigest") != "sha256:" + str(pred.get("argsSha256")):
        problems.append(f"{where}:effect_args_differ_from_call")
    if pred.get("outcome") != verdict.get("reported_outcome"):
        problems.append(f"{where}:outcome_field_differs_from_record")
    return verdict.get("reported_outcome")


def _check_line(i: int, line: str, keys: list[Any], prev: str) -> tuple[dict[str, Any] | None, list[str]]:
    problems: list[str] = []
    where = f"line_{i}"
    try:
        payload, _ = open_envelope(json.loads(line), keys)
        body = json.loads(payload)
    except (ValueError, KeyError, TypeError) as exc:
        return None, [f"{where}:{exc}"]
    pred = body.get("predicate", {})
    if pred.get("seq") != i:
        problems.append(f"{where}:seq_{pred.get('seq')}_not_{i}")
    if pred.get("prev") != prev:
        problems.append(f"{where}:chain_broken")
    if body.get("predicateType") == TOOL_CALL_RECORD:
        if pred.get("phase") == "authorize":
            _check_approval(pred, problems, where)
        elif pred.get("phase") == "effect":
            _check_effect(pred, problems, where)
    return body, problems


def _cross_checks(bodies: list[tuple[int, dict[str, Any]]]) -> list[str]:
    """Run-level rules: an effect needs an earlier allow for its permit; a permit has one effect
    record; an intent with no effect record is an open operation, reported, never read as success."""
    problems: list[str] = []
    allowed: set[str] = set()
    effects: dict[str, int] = {}
    intents: dict[str, int] = {}
    for i, body in bodies:
        if body.get("predicateType") != TOOL_CALL_RECORD:
            continue
        pred = body["predicate"]
        pid = pred.get("permitId")
        phase = pred.get("phase")
        if phase == "authorize" and pred.get("decision") == "allow":
            allowed.add(pid)
        elif phase == "intent":
            if pid not in allowed:
                problems.append(f"line_{i}:intent_without_permit")
            intents.setdefault(pid, i)
        elif phase == "effect":
            if pid not in allowed:
                problems.append(f"line_{i}:effect_without_permit")
            if pid in effects and pred.get("outcome") == "committed":
                problems.append(f"line_{i}:second_effect_record_for_permit")
            effects[pid] = i
    for pid, i in intents.items():
        if pid not in effects:
            problems.append(f"line_{i}:open_intent_no_effect_record:{pid[:12]}")
    return problems


def verify_journal(path: str | os.PathLike[str], public_pems: Iterable[bytes],
                   checkpoint_env: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Verify a journal offline: every signature, the chain, the checkpoint, and both published
    readers re-run on every embedded record. Reports the denominator (``verified`` of ``records``).

    ``path`` is the journal file or the directory holding ``journal.jsonl``.
    """
    keys = _keys(public_pems)
    p = Path(path)
    p = p / JOURNAL_FILE if p.is_dir() else p
    lines = [line for line in p.read_text().splitlines() if line.strip()] if p.exists() else []
    prev, failures, bodies, verified = GENESIS, [], [], 0
    outcomes: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        body, problems = _check_line(i, line, keys, prev)
        prev = _line_hash(line.encode())
        failures.extend(problems)
        if body is None:
            continue
        bodies.append((i, body))
        if not problems:
            verified += 1
        pred = body.get("predicate", {})
        if pred.get("phase") == "effect" and pred.get("outcome"):
            outcomes[pred["outcome"]] = outcomes.get(pred["outcome"], 0) + 1
    failures.extend(_cross_checks(bodies))
    checkpoint = "not_supplied"
    if checkpoint_env is not None:
        try:
            cp = json.loads(open_envelope(dict(checkpoint_env), keys)[0])["predicate"]
            if cp["count"] != len(lines):
                failures.append(f"checkpoint_count_{cp['count']}_journal_has_{len(lines)}")
                checkpoint = "mismatch"
            elif cp["head"] != prev:
                failures.append("checkpoint_head_mismatch")
                checkpoint = "mismatch"
            else:
                checkpoint = "matches"
        except (ValueError, KeyError, TypeError) as exc:
            failures.append(f"checkpoint:{exc}")
            checkpoint = "invalid"
    if failures:
        verdict = "FAIL"
    elif checkpoint != "matches":
        verdict = "NOT_ESTABLISHED"  # every line holds, but truncation cannot be ruled out
    else:
        verdict = "PASS"
    return {"verdict": verdict, "records": len(lines), "verified": verified, "failures": failures,
            "checkpoint": checkpoint, "outcomes": outcomes,
            "statements": [body for _, body in bodies]}
