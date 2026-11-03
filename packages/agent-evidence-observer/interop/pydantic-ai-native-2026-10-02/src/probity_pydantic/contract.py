"""Shared finite plan and byte framing; no framework or network import."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from probity_observer.crypto import VerificationError, canonical, strict_loads

LOGGER = logging.getLogger(__name__)
LEGACY_PROFILE = "probity-pydantic-ai-ticket-v0"
PROFILE = "probity-pydantic-ai-ticket-v1"
VERSION = "1.107.7"
PROMPT = "Execute the selected ticket update."
CONTENT = "DONE"
RETRY = "selected transient pre-dispatch retry"
ERROR = "selected producer failure before HTTP dispatch"
LEGACY_CASES = ("permit", "deny", "changed-arguments", "retry", "producer-error")
CASES = LEGACY_CASES + ("retry-exhausted", "committed-effect-error")
COMMITTED_ERROR = "selected producer failure after committed HTTP effect"
EXHAUSTED_ERROR = "Tool 'dispatch_ticket' exceeded max retries count of 1"
MAX_FILE = 2 * 1024 * 1024


def require(condition: bool, reason: str) -> None:
    """Raise and log one bounded refusal without including candidate content.

    Parameters
    ----------
    condition : bool
        Relation that must hold before consumer admission continues.
    reason : str
        Stable public reason used in tests and the CLI's refusal result.

    Raises
    ------
    VerificationError
        If ``condition`` is false. See :func:`read` for byte-level checks.
    """
    if not condition:
        LOGGER.warning("pydantic consumer refused: %s", reason)
        raise VerificationError(reason)


def sha(raw: bytes) -> str:
    """Return the SHA-256 of exact bytes, without JSON normalization."""
    return hashlib.sha256(raw).hexdigest()


def decode(raw: bytes) -> Any:
    """Decode Observer's duplicate-refusing restricted JSON representation."""
    return strict_loads(raw)


def encode(value: Any) -> bytes:
    """Encode profile JSON in Observer's unchanged canonical byte format."""
    return canonical(value)


def read(root: Path, name: str) -> bytes:
    """Read a bounded literal file from an already selected packet directory.

    Parameters
    ----------
    root : Path
        Selected packet directory. Symlinks are refused by the outer reader.
    name : str
        Profile-owned relative path; never a candidate-selected arbitrary path.

    Returns
    -------
    bytes
        Exact file content, limited to :data:`MAX_FILE` bytes.
    """
    path = root / name
    require(path.is_file() and not path.is_symlink(), "packet file missing or linked")
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE, "packet file exceeds bound")
    return raw


def write(path: Path, raw: bytes) -> None:
    """Create exact retained bytes once, refusing an existing artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)


def script(case: str) -> list[str]:
    """Return the frozen native tool argument sequence for one declared case."""
    require(case in CASES, "unknown declared case")
    if case in {"retry", "retry-exhausted"}:
        return [CONTENT, CONTENT]
    return ["CHANGED" if case == "changed-arguments" else CONTENT]


def expected_outcome(case: str, index: int) -> str:
    """Select the frozen dispatch outcome; a trace cannot choose its own branch."""
    if case == "producer-error":
        return "error"
    if case == "retry-exhausted":
        return "retry"
    if case == "committed-effect-error":
        return "committed-error"
    if case == "retry" and index == 0:
        return "retry"
    return "return"


def cases_for(profile: str) -> tuple[str, ...]:
    """Select a versioned population while retaining historical v0 packets."""
    require(profile in {LEGACY_PROFILE, PROFILE}, "unknown packet profile")
    return LEGACY_CASES if profile == LEGACY_PROFILE else CASES


def withheld_in(file: Path, prefix: str) -> dict[str, str]:
    """Digests of embedded sources a retained record omits, keyed inside ``prefix``."""
    value = decode(read(file.parent, file.name))
    require(isinstance(value, dict) and list(value) == sorted(value), "withheld form")
    require(
        all(isinstance(d, str) and len(d) == 64 for d in value.values())
        and all(c in "0123456789abcdef" for d in value.values() for c in d),
        "withheld digest",
    )
    return {k[len(prefix) :]: d for k, d in value.items() if k.startswith(prefix)}


def withheld_for(file: Path, packet: Path) -> dict[str, str]:
    """Omitted-source digests for a packet stored under the list's own directory."""
    base = file.resolve().parent
    require(packet.resolve().is_relative_to(base), "withheld location")
    return withheld_in(file, packet.resolve().relative_to(base).as_posix() + "/")
