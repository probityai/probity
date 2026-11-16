"""Record what discovery declared and where each call went, at call time.

A discovery record (an SVCB RRset with its ``sig`` parameter, the JWKS it
names, the DNSSEC chain that signs it) says where an agent may be reached and
under which key. It does not say where the agent's calls actually went. This
module writes both sides into one witnessed trajectory
(:mod:`probity_observer.trajectory`):

- a ``resolution`` event: the queried name, the SVCB answer in presentation
  format, the ``sig`` value as received, the JWKS fetch URL with the SHA-256 of
  the bytes fetched, the SHA-256 of the DNSSEC chain as received (or ``null``
  when no chain was fetched), and the observer's clock;
- a ``call`` event: the endpoint the request was sent to, the resolution it
  relied on (by ``seq``), and the observer's clock.

The raw JWKS and chain bytes stay with the caller; the event binds them by
digest so a verifier given the bytes can check them. A joining verifier
(``declared_versus_acted/v1`` in agent-evidence-verify) compares each call to
a verified binding. A call the observer did not record is missing, never clean:
the trajectory's witnessed head fixes how many events exist.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .crypto import VerificationError
from .trajectory import DEFAULT_CANONICALIZATION, TrajectoryRecorder

RESOLUTION_KIND = "resolution"
CALL_KIND = "call"
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")

__all__ = ["CALL_KIND", "RESOLUTION_KIND", "ResolutionObserver"]


def _instant(value: str) -> str:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise VerificationError("observer time must be RFC 3339 UTC ending in Z")
    datetime.fromisoformat(value)
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise VerificationError(f"{label} must be a non-empty ASCII string")
    return value


def _sha256(data: bytes | None, label: str) -> str | None:
    if data is None:
        return None
    if not isinstance(data, bytes):
        raise VerificationError(f"{label} must be the bytes as received")
    return hashlib.sha256(data).hexdigest()


class ResolutionObserver:
    """Record discovery answers and the calls that relied on them.

    Args:
        path: The trajectory file (a new, empty file).
        canonicalization: The trajectory's declared canonicalization.
    """

    def __init__(self, path: Path, *, canonicalization: str = DEFAULT_CANONICALIZATION) -> None:
        self.trajectory = TrajectoryRecorder(path, canonicalization=canonicalization)
        self._resolutions: set[int] = set()

    def resolved(
        self,
        *,
        name: str,
        svcb: list[str],
        at: str,
        sig: str | None = None,
        jwks_url: str | None = None,
        jwks_bytes: bytes | None = None,
        dnssec_chain: bytes | None = None,
    ) -> int:
        """Record one discovery answer as received and return its ``seq``.

        Args:
            name: The owner name queried.
            svcb: The SVCB RRset in presentation format, one record per item.
            at: The observer's clock, RFC 3339 UTC.
            sig: The ``sig`` SvcParam as received, if any.
            jwks_url: The URL the JWKS was fetched from, if any.
            jwks_bytes: The JWKS bytes fetched; required with ``jwks_url``.
            dnssec_chain: The DNSSEC chain as received (wire bytes), if fetched.
        """
        if not isinstance(svcb, list) or not svcb:
            raise VerificationError("svcb must list at least one record")
        if (jwks_url is None) != (jwks_bytes is None):
            raise VerificationError("jwks_url and jwks_bytes go together")
        event = {
            "kind": RESOLUTION_KIND,
            "name": _text(name, "name"),
            "svcb": [_text(record, "svcb record") for record in svcb],
            "sig": None if sig is None else _text(sig, "sig"),
            "jwks": None if jwks_url is None else {
                "url": _text(jwks_url, "jwks_url"), "sha256": _sha256(jwks_bytes, "jwks_bytes")},
            "dnssec_chain_sha256": _sha256(dnssec_chain, "dnssec_chain"),
            "at": _instant(at),
        }
        seq = self.trajectory.emit(event)["seq"]
        self._resolutions.add(seq)
        return seq

    def called(self, *, endpoint: str, at: str, resolution: int | None) -> int:
        """Record the endpoint one call went to and return its ``seq``.

        Args:
            endpoint: The URL or host:port the request was sent to.
            at: The observer's clock, RFC 3339 UTC.
            resolution: The ``seq`` of the resolution the call relied on, or
                ``None`` when the caller used no discovery answer.
        """
        if resolution is not None and resolution not in self._resolutions:
            raise VerificationError("a call can only name a resolution recorded earlier")
        event = {"kind": CALL_KIND, "endpoint": _text(endpoint, "endpoint"),
                 "resolution": resolution, "at": _instant(at)}
        return self.trajectory.emit(event)["seq"]
