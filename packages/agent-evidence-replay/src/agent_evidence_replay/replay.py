"""Recompute the digest chain of an action record and flag tamper or a gap.

The rules are in SPEC.md at the root of the repository; section numbers below
name its sections. Canonicalization comes from agent-evidence-vectors, the
reference implementation of the record format, and is not reimplemented here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from agent_evidence_vectors.auditrecord import Malformed, canonical_bytes

PIN_SCHEMA = "evaluator-replay-pin/v1"
GENESIS = "genesis"
TAMPER, GAP, UNRESOLVED, INVALID = "tamper", "gap", "unresolved", "invalid"
INTACT, TAMPERED, GAPPED, BROKEN = "intact", "tampered", "gap", "broken"


class PinError(ValueError):
    """The pin is not a pin this kit can read."""


@dataclass(frozen=True)
class Finding:
    """One thing a replay found wrong."""

    code: str
    cls: str
    index: int | None
    id: str | None
    detail: str


@dataclass(frozen=True)
class Pin:
    """What the evaluator holds outside the lab's reach (SPEC section 5)."""

    count: int | None = None
    head: str | None = None
    records: dict[str, str] | None = None

    @classmethod
    def from_json(cls, node: Any) -> Pin:
        """Read a decoded pin, refusing anything that is not one."""
        if not isinstance(node, dict) or node.get("schema") != PIN_SCHEMA:
            raise PinError(f"a pin is an object with schema {PIN_SCHEMA!r}")
        count, head, records = node.get("count"), node.get("head"), node.get("records")
        if count is not None and (not isinstance(count, int) or isinstance(count, bool) or count < 0):
            raise PinError("count must be a non-negative integer")
        if head is not None and not _is_digest(head):
            raise PinError("head must be a lowercase hex SHA-256")
        if records is not None and not (
            isinstance(records, dict) and all(isinstance(k, str) and _is_digest(v) for k, v in records.items())
        ):
            raise PinError("records must map each id to a lowercase hex SHA-256")
        return cls(count, head, records)


@dataclass
class Report:
    """The verdict on one record."""

    verdict: str
    findings: list[Finding] = field(default_factory=list)
    steps: int = 0
    end: str = "unproven"

    def to_json(self) -> dict[str, Any]:
        """The report as a JSON-ready dict."""
        found = [{**asdict(f), "class": f.cls} for f in self.findings]
        for item in found:
            del item["cls"]
        return {"verdict": self.verdict, "end": self.end, "steps": self.steps, "findings": found}


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def digest(line: bytes) -> str:
    """The line digest: SHA-256 of a step's bytes without its terminator."""
    return hashlib.sha256(line).hexdigest()


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Malformed("duplicate-member")
        out[key] = value
    return out


def _refuse_float(text: str) -> float:
    raise Malformed("non-integer-number")


def _split(data: bytes) -> list[bytes]:
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def _read(data: bytes) -> tuple[list[bytes], list[dict[str, Any]]] | Finding:
    """Section 4, check 1: parse every line or name the first that cannot be read."""
    lines = _split(data)
    if not lines:
        return Finding("record_unreadable", INVALID, None, None, "the record has no steps")
    parsed: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        try:
            node = json.loads(
                line.decode("utf-8"), object_pairs_hook=_refuse_duplicates, parse_float=_refuse_float
            )
            canonical_bytes(node)
        except (UnicodeDecodeError, ValueError, Malformed) as exc:
            return Finding("record_unreadable", INVALID, index, None, f"line {index}: {exc}")
        if not (isinstance(node, dict) and isinstance(node.get("id"), str)
                and isinstance(node.get("previousHash"), str)):
            return Finding("record_unreadable", INVALID, index, None,
                           f"line {index}: a step is an object with string id and previousHash")
        parsed.append(node)
    return lines, parsed


def make_pin(data: bytes) -> dict[str, Any]:
    """A pin describing a record, for the evaluator to keep elsewhere (SPEC section 5)."""
    read = _read(data)
    if isinstance(read, Finding):
        raise PinError(read.detail)
    lines, parsed = read
    digests = [digest(line) for line in lines]
    return {
        "schema": PIN_SCHEMA,
        "count": len(lines),
        "head": digests[-1],
        "records": {step["id"]: d for step, d in zip(parsed, digests, strict=True)},
    }


def _chain_findings(lines: list[bytes], parsed: list[dict[str, Any]]) -> tuple[list[Finding], list[str]]:
    digests = [digest(line) for line in lines]
    found: list[Finding] = []
    seen: dict[str, int] = {}
    for index, (line, step) in enumerate(zip(lines, parsed, strict=True)):
        if line != canonical_bytes(step):
            found.append(Finding("line_not_canonical", TAMPER, index, step["id"],
                                 "the line's bytes differ from the canonical form of its content"))
        if step["id"] in seen:
            found.append(Finding("id_duplicate", TAMPER, index, step["id"],
                                 f"id repeats the step at line {seen[step['id']]}"))
        seen.setdefault(step["id"], index)
        want = GENESIS if index == 0 else digests[index - 1]
        if step["previousHash"] != want:
            code = "genesis_missing" if index == 0 else "link_broken"
            found.append(Finding(code, UNRESOLVED, index, step["id"],
                                 f"previousHash is {step['previousHash']!r}, expected {want!r}"))
    return found, digests


def _pinned_findings(pin: Pin, parsed: list[dict[str, Any]], digests: list[str]) -> list[Finding]:
    if pin.records is None:
        return []
    found: list[Finding] = []
    present = {step["id"]: (i, d) for i, (step, d) in reversed(list(enumerate(zip(parsed, digests, strict=True))))}
    for wanted_id in pin.records:
        if wanted_id not in present:
            found.append(Finding("step_missing", GAP, None, wanted_id, "a pinned step is absent"))
    for step_id, (index, got) in present.items():
        if step_id not in pin.records:
            found.append(Finding("step_unpinned", TAMPER, index, step_id, "the pin does not list this step"))
        elif pin.records[step_id] != got:
            found.append(Finding("digest_mismatch", TAMPER, index, step_id,
                                 f"digest is {got}, pinned {pin.records[step_id]}"))
    return found


def _end_findings(pin: Pin, digests: list[str], pinned: list[Finding]) -> tuple[list[Finding], str]:
    found: list[Finding] = []
    named_missing = any(f.code == "step_missing" for f in pinned)
    if pin.count is not None and len(digests) < pin.count and not named_missing:
        found.append(Finding("steps_missing", GAP, None, None,
                             f"the record has {len(digests)} steps, the pin {pin.count}"))
    if pin.count is not None and len(digests) > pin.count:
        found.append(Finding("count_mismatch", TAMPER, None, None,
                             f"the record has {len(digests)} steps, the pin {pin.count}"))
    if pin.head is None:
        return found, "unproven"
    if pin.head == digests[-1]:
        return found, "proven"
    if pin.head in digests:
        found.append(Finding("tail_truncated", GAP, None, None,
                             f"the pinned head is step {digests.index(pin.head)}, not the last"))
    elif not _head_explained(pin, digests, pinned, bool(found)):
        cls = TAMPER if pin.count == len(digests) else UNRESOLVED
        found.append(Finding("head_mismatch", cls, None, None, "the pinned head matches no step"))
    return found, "unproven"


def _head_explained(pin: Pin, digests: list[str], pinned: list[Finding], reported: bool) -> bool:
    """Whether an earlier finding already accounts for the pinned head matching no step."""
    owner = {d: i for i, d in (pin.records or {}).items()}.get(pin.head or "")
    return owner is not None or reported or (
        pin.count is not None and len(digests) < pin.count) or any(f.code == "step_missing" for f in pinned)


def _classify_links(found: list[Finding], pin: Pin, parsed: list[dict[str, Any]],
                    digests: list[str]) -> list[Finding]:
    """Section 4, check 8: give a broken link the class of the cause the pin shows."""
    if pin.records is None:
        return found
    owner = {d: i for i, d in pin.records.items()}
    present = {step["id"]: d for step, d in zip(parsed, digests, strict=True)}
    out: list[Finding] = []
    for item in found:
        if item.cls == UNRESOLVED and item.index is not None:
            cause = owner.get(parsed[item.index]["previousHash"])
            if cause is not None:
                cls = GAP if cause not in present else TAMPER
                item = Finding(item.code, cls, item.index, item.id, f"{item.detail}; the pin names step {cause!r} here")
        out.append(item)
    return out


def replay_bytes(data: bytes, pin: Pin | None = None, require_end: bool = False) -> Report:
    """Replay a record's bytes against an optional pin (SPEC section 4)."""
    pin = pin or Pin()
    read = _read(data)
    if isinstance(read, Finding):
        return Report("invalid", [read])
    lines, parsed = read
    found, digests = _chain_findings(lines, parsed)
    pinned = _pinned_findings(pin, parsed, digests)
    found += pinned
    found = _classify_links(found, pin, parsed, digests)
    ending, end = _end_findings(pin, digests, pinned)
    found += ending
    if require_end and end != "proven":
        found.append(Finding("end_unproven", GAP, None, None, "no pinned head shows where the record ends"))
    classes = {f.cls for f in found}
    verdict = (TAMPERED if TAMPER in classes else GAPPED if GAP in classes
               else BROKEN if UNRESOLVED in classes else INTACT)
    return Report(verdict, found, len(lines), end)
