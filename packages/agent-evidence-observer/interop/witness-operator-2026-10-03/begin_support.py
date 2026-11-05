"""Signed begin histories for operator tests, built with public primitives only."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from probity_observer.crypto import SigningKey, digest
from probity_observer.history import append_history
from probity_observer.ledger import LedgerWitness

DOMAIN = "probity-prior-commitment-v0"
RETAINED = Path(__file__).resolve().parent / "retained" / "native"


def write_begin(path: Path, observer: SigningKey, interval: str, **overrides: Any) -> bytes:
    """Append one signed begin event, optionally with a replaced preimage field."""
    authority = {"intervalId": interval, "scope": "/work", "operation": "write-file"}
    preimage = {"authorityDigest": digest("probity-authority-v0", authority), "beforeRoot": "b" * 64,
                "intervalId": interval, "witnessNonce": secrets.token_hex(32), **overrides}
    payload = {"preimage": preimage, "committedAt": "2026-10-03T00:00:00Z"}
    commitment = {**payload, "keyid": observer.public_hex, "signature": observer.sign(DOMAIN, payload)}
    append_history(path, {"kind": "begin", "commitmentDigest": digest(DOMAIN, payload), "commitment": commitment})
    return path.read_bytes()


def register_begin(witness: LedgerWitness, observer: SigningKey, path: Path, interval: str) -> dict[str, Any]:
    """Register a signed begin with the ledger witness, as an observer does before an effect."""
    write_begin(path, observer, interval)
    return witness.checkpoint(path)


def retained_histories(case: str = "permit") -> tuple[bytes, bytes]:
    """Return the begin-only and the complete history of one retained native case."""
    raw = (RETAINED / "packet" / case / "history.jsonl").read_bytes()
    return raw.splitlines(keepends=True)[0], raw
