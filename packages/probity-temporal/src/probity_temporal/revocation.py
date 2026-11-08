"""Revocation: approver keys and approvals (permit ids) withdrawn after they were issued.

A list is a signed, versioned document. The authority holds the last list it accepted as one immutable
snapshot; a refresh replaces the snapshot only with a list that verifies under the revocation key and
does not roll back (a lower version, or the same version with different contents, is refused and the
last good snapshot stays). When the snapshot is older than ``max_staleness`` seconds the authority
refuses with a retryable code: a call is never allowed on revocation state it cannot vouch for.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from probity_records import Signer, canonical, load_public, sha256_hex
from probity_records.core import _b64, _unb64

REVOCATION_DOMAIN = b"probity-revocation-v1\x00"


def sign_revocations(signer: Signer, version: int, approver_key_ids: list[str], approval_ids: list[str],
                     issued_at: str) -> dict[str, Any]:
    body = {"approvalIds": sorted(set(approval_ids)), "approverKeyIds": sorted(set(approver_key_ids)),
            "issuedAt": issued_at, "version": version}
    return {"body": body, "sig": _b64(signer.sign(REVOCATION_DOMAIN + canonical(body)))}


def verify_revocations(signed: Any, pem: bytes) -> dict[str, Any] | None:
    if not isinstance(signed, dict) or not isinstance(signed.get("body"), dict):
        return None
    try:
        load_public(pem).verify(_unb64(signed.get("sig")), REVOCATION_DOMAIN + canonical(signed["body"]))
    except Exception:  # noqa: BLE001 - any failure to verify is a refusal of the list
        return None
    body = signed["body"]
    if not isinstance(body.get("version"), int):
        return None
    return body


@dataclass(frozen=True)
class Snapshot:
    version: int
    digest: str
    approver_key_ids: frozenset[str]
    approval_ids: frozenset[str]
    fetched_at: float


@dataclass
class Revocations:
    """``provider()`` returns the current signed list; ``key`` is the PEM that signs lists."""

    provider: Callable[[], Any]
    key: bytes
    refresh_seconds: float = 30.0
    max_staleness: float = 300.0
    monotonic: Callable[[], float] = time.monotonic
    _snapshot: Snapshot | None = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    rejected: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if not self.refresh():  # the first fetch must succeed, or the worker does not start
            raise RuntimeError(f"revocation list unavailable at start: {self.rejected[-1:]}")

    def refresh(self) -> bool:
        """Fetch, verify and accept a newer list; True when the snapshot now holds a fresh list."""
        try:
            signed = self.provider()
        except Exception as exc:  # noqa: BLE001 - a failed fetch keeps the last good snapshot
            self.rejected.append(f"fetch_failed:{type(exc).__name__}")
            return False
        body = verify_revocations(signed, self.key)
        if body is None:
            self.rejected.append("signature_invalid")
            return False
        digest = sha256_hex(canonical(body))
        with self._lock:
            current = self._snapshot
            if current is not None:
                if body["version"] < current.version:
                    self.rejected.append(f"rollback_{body['version']}_below_{current.version}")
                    return False
                if body["version"] == current.version and digest != current.digest:
                    self.rejected.append(f"same_version_{body['version']}_different_contents")
                    return False
            self._snapshot = Snapshot(body["version"], digest, frozenset(body.get("approverKeyIds", [])),
                                      frozenset(body.get("approvalIds", [])), self.monotonic())
        return True

    def current(self) -> Snapshot | None:
        """The snapshot to judge with, refreshed when due; None when it is too stale to trust."""
        snap = self._snapshot
        now = self.monotonic()
        if snap is None or now - snap.fetched_at >= self.refresh_seconds:
            self.refresh()
            snap = self._snapshot
        if snap is None or self.monotonic() - snap.fetched_at > self.max_staleness:
            return None
        return snap
