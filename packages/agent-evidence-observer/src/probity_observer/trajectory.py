"""A hash-linked trajectory for ``emit()``-style telemetry, closed by a witnessed head.

Each trajectory has an identifier the consumer knows in advance (a session or
run id). Each emitted event is wrapped in an entry ``{"seq", "prev", "event"}``.
``seq`` counts from 1 per trajectory with no gaps, and ``prev`` is the SHA-256
of the canonical bytes of the previous entry; the first entry names
:func:`genesis` of the identifier, the SHA-256 of the canonical object
``{"format": "probity-trajectory-genesis-v1", "trajectory": <id>}``. A second
party can recompute every link with any RFC 8785 library: no digest has a
domain prefix, so the bytes hashed are exactly the canonical object.

The chain fixes the start and the middle of a trajectory and nothing about its
end: a producer that drops the last events still holds a chain that verifies.
Closing the trajectory therefore writes a head in the
``probity-trajectory-head-v1`` format (identifier, count and last digest),
signed by a :class:`TrajectoryWitness` whose public key the consumer pins. The
witness never signs a head the producer composed: it registers the identifier
once at open, receives every entry as it is written, checks each link itself,
and at close signs only its own count and last digest, refusing a close whose
claim differs. A producer that drops, swaps or rewrites entries after the
witness saw them, or reopens an identifier to start again, cannot get a head
for that. The record of opened identifiers is a directory on disk, not process
memory, so a restarted witness, or a second witness instance under the same key
and directory, refuses an identifier the first one opened. The head has its own signing domain, so a witness that also signs
ledger heads cannot have one read as the other, and it names the identifier, so
the head of one trajectory never verifies another. A witness in the producer's
own process fixes the end only against a third party who edits storage; it
fixes it against the producer when it runs in a process or account the
producer cannot reach.

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

from .crypto import (
    SigningKey,
    VerificationError,
    canonical,
    strict_loads,
    verify_signature,
)

CANONICALIZATION_TERM = "https://w3id.org/agent-evidence/vocab/v1/canonicalization"
CANONICALIZATIONS = frozenset({"jcs_integer_only_v1", "rfc8785"})
DEFAULT_CANONICALIZATION = "jcs_integer_only_v1"
HASH_ALG = "sha256"
ENTRY_FIELDS = frozenset({"seq", "prev", "event"})
GENESIS_FORMAT = "probity-trajectory-genesis-v1"
HEAD_FORMAT = "probity-trajectory-head-v1"
HEAD_FIELDS = frozenset({"format", "trajectory", "count", "head", "keyid", "signature"})
REGISTRY_KEY_FILE = "witness-key"

__all__ = [
    "CANONICALIZATIONS",
    "CANONICALIZATION_TERM",
    "DEFAULT_CANONICALIZATION",
    "GENESIS_FORMAT",
    "HEAD_FORMAT",
    "TrajectoryRecorder",
    "TrajectoryWitness",
    "entry_digest",
    "genesis",
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


def check_trajectory_id(value: Any) -> str:
    """Return a trajectory identifier or refuse it.

    Raises:
        VerificationError: The identifier is not a non-empty ASCII string.
    """
    if not isinstance(value, str) or not value or not value.isascii():
        raise VerificationError("trajectory id must be a non-empty ASCII string")
    return value


def entry_digest(entry: dict[str, Any]) -> str:
    """Return the SHA-256 of an entry's canonical bytes as lowercase hex."""
    return hashlib.sha256(canonical(entry)).hexdigest()


def genesis(trajectory_id: str) -> str:
    """Return the ``prev`` the first entry of a trajectory names.

    It is the SHA-256 of the canonical object ``{"format", "trajectory"}``, so
    an entry list is bound to its trajectory from the first link on.
    """
    return hashlib.sha256(canonical(
        {"format": GENESIS_FORMAT, "trajectory": check_trajectory_id(trajectory_id)})).hexdigest()


def _create_exclusive(path: Path, data: bytes) -> bool:
    """Create ``path`` holding ``data`` durably, or return False when it exists."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return True


def _check_entry(entry: Any, label: str) -> dict[str, Any]:
    """Return an entry with exactly the entry fields, an integer ``seq`` and an object event."""
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        raise VerificationError(f"{label} has invalid fields")
    if type(entry["seq"]) is not int:
        raise VerificationError(f"{label}: seq is not an integer")
    if not isinstance(entry["event"], dict):
        raise VerificationError(f"{label}: event is not a JSON object")
    return entry


class TrajectoryWitness:
    """Count trajectories as their entries arrive and sign only what was counted.

    The witness holds the signing key and a registry directory. ``open``
    registers an identifier once by creating its file in the registry with an
    exclusive create, so the refusal survives a restart and holds across every
    witness instance that shares the directory; a registry records the public
    key it belongs to and refuses a witness under another key. ``open`` registers an identifier once,
    ``observe`` takes each entry as it is written and checks ``seq`` and
    ``prev`` against the witness's own count and last digest, and ``close``
    signs the witness's own head payload. A producer's claim is compared, never
    signed: a close whose identifier, count or last digest differs from what the
    witness counted is refused, and an identifier is never opened twice.
    Run it in a process or account the producer cannot reach for the head to
    bind the producer; in the same process it binds only storage edits.
    """

    def __init__(self, key: SigningKey, registry: Path) -> None:
        """Bind the witness key to a registry of opened identifiers.

        Args:
            key: The witness signing key.
            registry: The directory that records every identifier this key has
                opened. Every instance and restart of the witness under this key
                must use the same directory; a second directory under the same
                key would let an identifier open twice.

        Raises:
            VerificationError: The registry belongs to another witness key.
        """
        self._key = key
        self._registry = registry
        self._open: dict[str, tuple[int, str]] = {}
        registry.mkdir(parents=True, exist_ok=True)
        owner = registry / REGISTRY_KEY_FILE
        public = key.public_hex.encode("ascii")
        if not _create_exclusive(owner, public) and owner.read_bytes() != public:
            raise VerificationError("trajectory witness registry belongs to another witness key")

    @property
    def public_hex(self) -> str:
        """The public key a consumer pins for this witness's heads."""
        return self._key.public_hex

    def open(self, trajectory_id: str) -> str:
        """Register a new trajectory and return its identifier.

        Raises:
            VerificationError: The identifier is invalid or was opened before.
        """
        check_trajectory_id(trajectory_id)
        name = hashlib.sha256(trajectory_id.encode("ascii")).hexdigest() + ".opened"
        if not _create_exclusive(self._registry / name, canonical({"trajectory": trajectory_id})):
            raise VerificationError(f"trajectory {trajectory_id!r} was already opened at this witness")
        self._open[trajectory_id] = (0, genesis(trajectory_id))
        return trajectory_id

    def _state(self, trajectory_id: str) -> tuple[int, str]:
        if trajectory_id not in self._open:
            raise VerificationError(f"trajectory {trajectory_id!r} is not open at this witness")
        return self._open[trajectory_id]

    def observe(self, trajectory_id: str, entry: dict[str, Any]) -> str:
        """Count one entry of an open trajectory and return its digest.

        Raises:
            VerificationError: The trajectory is not open, or the entry does not
                follow the last entry this witness counted.
        """
        count, last = self._state(trajectory_id)
        _check_entry(entry, "observed entry")
        if entry["seq"] != count + 1:
            raise VerificationError(f"observed entry seq {entry['seq']}: the witness expects {count + 1}")
        if entry["prev"] != last:
            raise VerificationError(f"observed entry {entry['seq']}: prev does not link to the last counted entry")
        digest = entry_digest(entry)
        self._open[trajectory_id] = (count + 1, digest)
        return digest

    def head_payload(self, trajectory_id: str) -> dict[str, Any]:
        """The witness's own unsigned head for an open trajectory."""
        count, last = self._state(trajectory_id)
        return {"format": HEAD_FORMAT, "trajectory": trajectory_id, "count": count, "head": last}

    def close(self, trajectory_id: str, claimed: dict[str, Any]) -> dict[str, Any]:
        """Close a trajectory and sign the head the witness counted.

        Args:
            trajectory_id: The trajectory to close.
            claimed: The head payload the producer asks for.

        Returns:
            The signed head: ``format``, ``trajectory``, ``count``, ``head``,
            ``keyid`` and ``signature``.

        Raises:
            VerificationError: The claim differs from what the witness counted;
                the trajectory stays open, so a correct claim can still close it.
        """
        own = self.head_payload(trajectory_id)
        if claimed != own:
            raise VerificationError(
                f"close refused: the witness counted {own['count']} entries of {trajectory_id!r} ending at "
                f"{own['head']}, and the claim differs")
        signature = self._key.sign(HEAD_FORMAT, own)
        del self._open[trajectory_id]
        return {**own, "keyid": self._key.public_hex, "signature": signature}


class TrajectoryRecorder:
    """Append hash-linked entries to a JSONL file and close it with a witnessed head.

    The recorder never holds the witness key. It hands each entry to the
    witness before writing it, so the witness counts the trajectory itself and
    an entry the witness refuses never reaches the file; ``close`` asks the
    witness to sign the head it counted. A write that fails after the witness
    counted the entry leaves the recorder broken: it refuses further events and
    the witness refuses its close, because the file can no longer match.
    """

    def __init__(self, path: Path, *, trajectory_id: str, witness: TrajectoryWitness,
                 canonicalization: str = DEFAULT_CANONICALIZATION) -> None:
        self.path = path
        self.trajectory_id = check_trajectory_id(trajectory_id)
        self.canonicalization = check_canonicalization(canonicalization)
        if path.exists() and path.stat().st_size:
            raise VerificationError("trajectory file already holds entries; start a new trajectory")
        self.witness = witness
        witness.open(trajectory_id)
        self._count = 0
        self._last = genesis(trajectory_id)
        self._closed = False
        self._broken: str | None = None

    @property
    def count(self) -> int:
        """Number of entries written so far."""
        return self._count

    @property
    def head(self) -> str:
        """Digest of the last entry, or :func:`genesis` of the id before the first."""
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
        if self._broken is not None:
            raise VerificationError(f"trajectory is broken: {self._broken}")
        if not isinstance(event, dict):
            raise VerificationError("a trajectory event must be a JSON object")
        entry = {"seq": self._count + 1, "prev": self._last, "event": event}
        line = canonical(entry) + b"\n"
        digest = self.witness.observe(self.trajectory_id, entry)
        try:
            with self.path.open("ab") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            self._broken = f"entry {entry['seq']} was counted by the witness and not stored ({exc})"
            raise VerificationError(f"trajectory is broken: {self._broken}") from exc
        self._last = digest
        self._count += 1
        return entry

    def head_payload(self) -> dict[str, Any]:
        """The head payload this recorder claims at close."""
        return {"format": HEAD_FORMAT, "trajectory": self.trajectory_id,
                "count": self._count, "head": self._last}

    def close(self) -> dict[str, Any]:
        """Close the trajectory and return the head the witness counted and signed.

        Returns:
            A head with exactly the fields ``format``, ``trajectory``,
            ``count``, ``head``, ``keyid`` and ``signature``, signed in the
            ``probity-trajectory-head-v1`` domain.

        Raises:
            VerificationError: The witness counted something other than this
                recorder claims.
        """
        head = self.witness.close(self.trajectory_id, self.head_payload())
        self._closed = True
        return head


def _read_entries(path: Path, trajectory_id: str) -> list[dict[str, Any]]:
    raw = path.read_bytes() if path.exists() else b""
    if raw and not raw.endswith(b"\n"):
        raise VerificationError("trajectory ends with an incomplete line")
    entries: list[dict[str, Any]] = []
    previous = genesis(trajectory_id)
    lines = raw[:-1].split(b"\n") if raw else []
    for number, line in enumerate(lines, start=1):
        entry = _check_entry(strict_loads(line), f"trajectory entry {number}")
        if entry["seq"] != number:
            raise VerificationError(f"trajectory entry {number}: seq is not contiguous from 1")
        if entry["prev"] != previous:
            raise VerificationError(f"trajectory entry {number}: prev does not link to entry {number - 1}")
        entries.append(entry)
        previous = entry_digest(entry)
    return entries


def verify_trajectory(
    path: Path,
    retained_head: dict[str, Any],
    pinned_witness_key: str,
    *,
    trajectory_id: str,
    canonicalization: str = DEFAULT_CANONICALIZATION,
) -> dict[str, Any]:
    """Verify a closed trajectory against a head retained outside it.

    Args:
        path: The trajectory JSONL file.
        retained_head: The signed head, kept apart from the trajectory.
        pinned_witness_key: The witness public key the consumer selected.
        trajectory_id: The identifier the consumer expects (its session or
            run id), never one read from the producer's files.
        canonicalization: The producer's declared ``canonicalization`` value.

    Returns:
        ``count``, ``head``, ``canonicalization``, ``hash_alg`` and the
        vocabulary term identifier of the canonicalization.

    Raises:
        VerificationError: A dropped, swapped, rewritten or edited entry, a
            truncated tail, entries past the head, a head under another key,
            a head of another trajectory or another format, or an
            unsupported canonicalization.

    A verified trajectory says the entries are the ones the witness saw counted
    at close. It does not say who produced the events or that they are true.
    """
    check_canonicalization(canonicalization)
    check_trajectory_id(trajectory_id)
    if not isinstance(retained_head, dict) or set(retained_head) != HEAD_FIELDS:
        raise VerificationError("trajectory head has invalid fields")
    payload = {key: retained_head[key] for key in ("format", "trajectory", "count", "head")}
    if payload["format"] != HEAD_FORMAT:
        raise VerificationError("trajectory head has an unsupported format")
    if payload["trajectory"] != trajectory_id:
        raise VerificationError("trajectory head names another trajectory")
    if type(payload["count"]) is not int or payload["count"] < 0:
        raise VerificationError("trajectory head has an invalid count")
    if retained_head["keyid"] != pinned_witness_key:
        raise VerificationError("trajectory head key differs from the pinned witness key")
    if not isinstance(retained_head["signature"], str):
        raise VerificationError("trajectory head has an invalid signature")
    verify_signature(pinned_witness_key, HEAD_FORMAT, payload, retained_head["signature"])
    entries = _read_entries(path, trajectory_id)
    if len(entries) < payload["count"]:
        raise VerificationError(
            f"trajectory holds {len(entries)} entries and the witnessed head counts {payload['count']}: tail missing")
    if len(entries) > payload["count"]:
        raise VerificationError(
            f"trajectory holds {len(entries) - payload['count']} entries past the witnessed head")
    last = entry_digest(entries[-1]) if entries else genesis(trajectory_id)
    if last != payload["head"]:
        raise VerificationError("trajectory's last entry differs from the witnessed head")
    return {"trajectory": trajectory_id, "count": len(entries), "head": last,
            "canonicalization": canonicalization,
            "canonicalization_term": CANONICALIZATION_TERM, "hash_alg": HASH_ALG}
