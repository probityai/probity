"""A hash-linked trajectory for ``emit()``-style telemetry, closed by a witnessed head.

Each emitted event is wrapped in an entry ``{"seq", "prev", "event"}``. ``seq``
counts from 1 per trajectory with no gaps, and ``prev`` is the SHA-256 of the
canonical bytes of the previous entry (the first entry names :data:`GENESIS`).
A second party can recompute every link with any RFC 8785 library: the entry
digest has no domain prefix, so the bytes hashed are exactly the canonical
entry.

The chain fixes the start and the middle of a trajectory and nothing about its
end: a producer that drops the last events still holds a chain that verifies.
Closing the trajectory therefore writes a head in the existing
``probity-witness-ledger-head-v0`` format (count and last digest), signed by a
witness key the caller supplies and the consumer pins. Only a head signed by a
key outside the producer's reach fixes the end; a head the producer signs with
its own key fixes it only against a third party who edits storage.

The canonical bytes are the observer's JSON profile: RFC 8785 restricted to
integers below 2^53, with floats refused. That is the
``jcs_integer_only_v1`` value of the agent-evidence vocabulary term
``canonicalization``; on that input the bytes equal plain ``rfc8785``, so the
short token is accepted as a declaration too. Any other declaration is
refused, because the verifier would hash different bytes from the producer.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from .crypto import SigningKey, VerificationError, canonical, strict_loads, verify_signature
from .history import GENESIS
from .ledger import HEAD_DOMAIN

CANONICALIZATION_TERM = "https://w3id.org/agent-evidence/vocab/v1/canonicalization"
CANONICALIZATIONS = frozenset({"jcs_integer_only_v1", "rfc8785"})
DEFAULT_CANONICALIZATION = "jcs_integer_only_v1"
HASH_ALG = "sha256"
ENTRY_FIELDS = frozenset({"seq", "prev", "event"})

__all__ = [
    "CANONICALIZATIONS",
    "CANONICALIZATION_TERM",
    "DEFAULT_CANONICALIZATION",
    "GENESIS",
    "TrajectoryRecorder",
    "entry_digest",
    "verify_trajectory",
]


def check_canonicalization(value: str) -> str:
    """Return a supported canonicalization declaration or refuse it.

    Args:
        value: A value of the vocabulary term ``canonicalization``.

    Raises:
        VerificationError: The value names bytes this module does not produce.
    """
    if value not in CANONICALIZATIONS:
        raise VerificationError(
            f"trajectory canonicalization {value!r} is not one of {sorted(CANONICALIZATIONS)}")
    return value


def entry_digest(entry: dict[str, Any]) -> str:
    """Return the SHA-256 of an entry's canonical bytes as lowercase hex."""
    return hashlib.sha256(canonical(entry)).hexdigest()


class TrajectoryRecorder:
    """Append hash-linked entries to a JSONL file and close it with a signed head.

    The recorder never holds the witness key. ``close`` takes the signer from
    the caller, so a deployment can keep the witness key in a separate process
    or account and hand only the head payload across.
    """

    def __init__(self, path: Path, *, canonicalization: str = DEFAULT_CANONICALIZATION) -> None:
        self.path = path
        self.canonicalization = check_canonicalization(canonicalization)
        self._count = 0
        self._last = GENESIS
        self._closed = False
        if path.exists() and path.stat().st_size:
            raise VerificationError("trajectory file already holds entries; start a new trajectory")

    @property
    def count(self) -> int:
        """Number of entries written so far."""
        return self._count

    @property
    def head(self) -> str:
        """Digest of the last entry, or :data:`GENESIS` before the first."""
        return self._last

    def emit(self, event: dict[str, Any]) -> dict[str, Any]:
        """Record one telemetry event and return the entry written.

        Args:
            event: A JSON object inside the canonical profile.

        Raises:
            VerificationError: The trajectory is closed, or the event is not a
                JSON object inside the profile.
        """
        if self._closed:
            raise VerificationError("trajectory is closed")
        if not isinstance(event, dict):
            raise VerificationError("a trajectory event must be a JSON object")
        entry = {"seq": self._count + 1, "prev": self._last, "event": event}
        line = canonical(entry) + b"\n"
        with self.path.open("ab") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        self._count += 1
        self._last = entry_digest(entry)
        return entry

    def head_payload(self) -> dict[str, Any]:
        """The unsigned head payload a separate witness signs."""
        return {"format": HEAD_DOMAIN, "count": self._count, "head": self._last}

    def close(self, witness: SigningKey) -> dict[str, Any]:
        """Close the trajectory and return its signed head.

        Args:
            witness: The witness signer. Its public half is what the consumer
                pins; tests use an ephemeral key, never a committed secret.

        Returns:
            A head with exactly the ledger-head fields ``format``, ``count``,
            ``head``, ``keyid`` and ``signature``.
        """
        payload = self.head_payload()
        self._closed = True
        return {**payload, "keyid": witness.public_hex,
                "signature": witness.sign(HEAD_DOMAIN, payload)}


def _read_entries(path: Path) -> list[dict[str, Any]]:
    raw = path.read_bytes() if path.exists() else b""
    if raw and not raw.endswith(b"\n"):
        raise VerificationError("trajectory ends with an incomplete line")
    entries: list[dict[str, Any]] = []
    previous = GENESIS
    for number, line in enumerate(raw.splitlines(), start=1):
        entry = strict_loads(line)
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            raise VerificationError(f"trajectory entry {number} has invalid fields")
        if type(entry["seq"]) is not int or entry["seq"] != number:
            raise VerificationError(f"trajectory entry {number}: seq is not contiguous from 1")
        if entry["prev"] != previous:
            raise VerificationError(f"trajectory entry {number}: prev does not link to entry {number - 1}")
        if not isinstance(entry["event"], dict):
            raise VerificationError(f"trajectory entry {number}: event is not a JSON object")
        entries.append(entry)
        previous = entry_digest(entry)
    return entries


def verify_trajectory(
    path: Path,
    retained_head: dict[str, Any],
    pinned_witness_key: str,
    *,
    canonicalization: str = DEFAULT_CANONICALIZATION,
) -> dict[str, Any]:
    """Verify a closed trajectory against a head retained outside it.

    Args:
        path: The trajectory JSONL file.
        retained_head: The signed head, kept apart from the trajectory.
        pinned_witness_key: The witness public key the consumer selected.
        canonicalization: The producer's declared ``canonicalization`` value.

    Returns:
        ``count``, ``head``, ``canonicalization``, ``hash_alg`` and the
        vocabulary term identifier of the canonicalization.

    Raises:
        VerificationError: A dropped, swapped, rewritten or edited entry, a
            truncated tail, entries past the head, a head under another key,
            or an unsupported canonicalization.

    A verified trajectory says the entries are the ones the witness saw counted
    at close. It does not say who produced the events or that they are true.
    """
    check_canonicalization(canonicalization)
    fields = {"format", "count", "head", "keyid", "signature"}
    if not isinstance(retained_head, dict) or set(retained_head) != fields:
        raise VerificationError("trajectory head has invalid fields")
    payload = {key: retained_head[key] for key in ("format", "count", "head")}
    if payload["format"] != HEAD_DOMAIN:
        raise VerificationError("trajectory head has an unsupported format")
    if type(payload["count"]) is not int or payload["count"] < 0:
        raise VerificationError("trajectory head has an invalid count")
    if retained_head["keyid"] != pinned_witness_key:
        raise VerificationError("trajectory head key differs from the pinned witness key")
    if not isinstance(retained_head["signature"], str):
        raise VerificationError("trajectory head has an invalid signature")
    verify_signature(pinned_witness_key, HEAD_DOMAIN, payload, retained_head["signature"])
    entries = _read_entries(path)
    if len(entries) < payload["count"]:
        raise VerificationError(
            f"trajectory holds {len(entries)} entries and the witnessed head counts {payload['count']}: tail missing")
    if len(entries) > payload["count"]:
        raise VerificationError(
            f"trajectory holds {len(entries) - payload['count']} entries past the witnessed head")
    last = entry_digest(entries[-1]) if entries else GENESIS
    if last != payload["head"]:
        raise VerificationError("trajectory's last entry differs from the witnessed head")
    return {"count": len(entries), "head": last, "canonicalization": canonicalization,
            "canonicalization_term": CANONICALIZATION_TERM, "hash_alg": HASH_ALG}
