"""Status receipt binding: does a credential status receipt vouch for this exact credential.

An authority that keeps the standing of agent credentials signs a status receipt: this credential is
active, from this time, until that one. A relying party that holds the receipt and the credential
decides offline. The receipt is worth that much only if it names the credential by the digest of its
bytes. A receipt that names the credential by identifier alone, or signs the status and nothing else,
vouches for every credential that carries the identifier: a holder can swap the capability set, swap
or add a public key, sign the result with a key of their own and present it beside the authority's
genuine receipt, and the credential's own signature still verifies because the key that made it ships
inside the credential.

The verifying key of the receipt is the authority key the case supplies, never a key the receipt or
the credential names. The credential's own signatures are read only as the holder's proof over its
bytes; the binding is the receipt's digest of the credential payload. The reader checks in a fixed
order and names the first check that fails (see ``CHECKS``); a case that passes all of them is
``accept`` with reason ``credential_bound``. The rule code is a port of the corpus's own reader at
agent-evidence-vectors ``feat/receipt-binds-capabilities-1121`` (``statusreceipt.py``).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import strictb64
from ..common import CaseError
from ..dsse import pae
from ..json_input import parse_json

SUITE = "status-receipt-binding/v1"
ACCEPT, REJECT = "accept", "reject"
ACCEPTED = "credential_bound"
MAX_RECORD_BYTES = 1 << 20
CREDENTIAL_TYPE = "application/vnd.agent-evidence.agent-credential+json"
RECEIPT_TYPE = "application/vnd.agent-evidence.credential-status-receipt+json"
STATUSES = ("active", "revoked", "suspended")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "receipt_malformed",
    "receipt_signature_invalid",
    "receipt_unbound",
    "credential_malformed",
    "credential_signature_invalid",
    "credential_id_mismatch",
    "credential_digest_mismatch",
    "receipt_not_yet_valid",
    "receipt_expired",
    "credential_not_active",
)
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _when(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class _Envelope:
    """A DSSE envelope as read: the payload type, the payload bytes and the signatures, each
    None when that part does not parse."""

    payload_type: str | None
    payload: bytes | None
    signatures: list[tuple[str, bytes]] | None
    body: dict[str, Any] | None


def _signatures(entries: Any) -> list[tuple[str, bytes]] | None:
    """The ``(keyid, sig)`` pairs of a DSSE ``signatures`` member, or None when it is not a
    non-empty list of exactly those two members with a canonical base64 signature."""
    if not isinstance(entries, list) or not entries:
        return None
    out: list[tuple[str, bytes]] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"keyid", "sig"}:
            return None
        if not isinstance(entry["keyid"], str):
            return None
        try:
            out.append((entry["keyid"], strictb64.std(entry["sig"])))
        except (ValueError, TypeError):
            return None
    return out


def _object(payload: bytes | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    try:
        parsed = parse_json(payload, max_bytes=MAX_RECORD_BYTES, max_depth=32, max_nodes=32768)
    except (ValueError, UnicodeDecodeError, CaseError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _envelope(path: Path) -> _Envelope:
    try:
        raw = parse_json(path.read_bytes(), max_bytes=MAX_RECORD_BYTES, max_depth=32, max_nodes=32768)
    except (OSError, ValueError, UnicodeDecodeError, CaseError):
        return _Envelope(None, None, None, None)
    if not isinstance(raw, dict) or set(raw) != {"payload", "payloadType", "signatures"}:
        return _Envelope(None, None, None, None)
    payload_type = raw["payloadType"] if isinstance(raw["payloadType"], str) else None
    try:
        payload: bytes | None = strictb64.std(raw["payload"])
    except (ValueError, TypeError):
        payload = None
    return _Envelope(payload_type, payload, _signatures(raw["signatures"]), _object(payload))


@dataclass(frozen=True)
class _Case:
    now: datetime | None
    authority_key: bytes | None
    credential: _Envelope
    receipt: _Envelope


def _load(case_path: Path) -> _Case:
    case = parse_json(case_path.read_bytes(), max_bytes=MAX_RECORD_BYTES, max_depth=32, max_nodes=32768)
    base = case_path.parent
    now = case.get("now")
    try:
        key: bytes | None = strictb64.std(case.get("authorityKey"))
    except (ValueError, TypeError):
        key = None
    return _Case(
        _when(now) if isinstance(now, str) and _TIME.fullmatch(now) else None,
        key if key is not None and len(key) == 32 else None,
        _envelope(base / str(case.get("credential", ""))),
        _envelope(base / str(case.get("receipt", ""))),
    )


def _binding(body: dict[str, Any] | None) -> dict[str, Any] | None:
    credential = body.get("credential") if body else None
    return credential if isinstance(credential, dict) else None


def receipt_well_formed(receipt: _Envelope) -> bool:
    """Whether the receipt has the shape check 1 asks for. A receipt that names the credential
    by identifier only is well formed here: check 3 refuses it by name."""
    body = receipt.body
    if receipt.payload_type != RECEIPT_TYPE or receipt.signatures is None:
        return False
    if len(receipt.signatures) != 1 or body is None:
        return False
    if set(body) != {"credential", "issuedAt", "status", "validUntil"}:
        return False
    binding = _binding(body)
    if binding is None or not set(binding) <= {"digest", "id"} or "id" not in binding:
        return False
    if not isinstance(binding["id"], str) or not binding["id"]:
        return False
    if "digest" in binding:
        digest = binding["digest"]
        if (not isinstance(digest, dict) or set(digest) != {"sha256"}
                or not isinstance(digest["sha256"], str) or not _HEX64.fullmatch(digest["sha256"])):
            return False
    if body["status"] not in STATUSES:
        return False
    times = (body["issuedAt"], body["validUntil"])
    if not all(isinstance(t, str) and _TIME.fullmatch(t) for t in times):
        return False
    return _when(body["issuedAt"]) < _when(body["validUntil"])


def _ed25519(key: bytes, message: bytes, sig: bytes) -> bool:
    """One Ed25519 verification (RFC 8032, through OpenSSL); any refusal is False."""
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _dsse_verifies(key: bytes, envelope: _Envelope, sig: bytes) -> bool:
    if envelope.payload_type is None or envelope.payload is None:
        return False
    return _ed25519(key, pae(envelope.payload_type, envelope.payload), sig)


def receipt_signature_verifies(c: _Case) -> bool:
    """Whether the receipt's one signature verifies under the authority key."""
    sigs = c.receipt.signatures
    if c.authority_key is None or not sigs or len(sigs) != 1:
        return False
    return _dsse_verifies(c.authority_key, c.receipt, sigs[0][1])


def _key_bytes(jwk: Any) -> bytes | None:
    if not isinstance(jwk, dict) or set(jwk) != {"crv", "kid", "kty", "x"}:
        return None
    if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519" or not isinstance(jwk["kid"], str):
        return None
    try:
        raw = strictb64.url(jwk["x"])
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == 32 else None


def credential_keys(credential: _Envelope) -> dict[str, bytes] | None:
    """The credential's keys by ``kid``, or None when the list is not well formed."""
    keys = credential.body.get("keys") if credential.body else None
    if not isinstance(keys, list) or not keys:
        return None
    found: dict[str, bytes] = {}
    for jwk in keys:
        raw = _key_bytes(jwk)
        if raw is None or not jwk["kid"] or jwk["kid"] in found:
            return None
        found[jwk["kid"]] = raw
    return found


def credential_well_formed(credential: _Envelope) -> bool:
    """Whether the credential has the shape check 4 asks for."""
    body = credential.body
    if credential.payload_type != CREDENTIAL_TYPE or credential.signatures is None:
        return False
    if body is None or set(body) != {"capabilities", "id", "keys", "name"}:
        return False
    if not isinstance(body["id"], str) or not body["id"] or not isinstance(body["name"], str):
        return False
    caps = body["capabilities"]
    if (not isinstance(caps, list) or not caps or not all(isinstance(c, str) and c for c in caps)
            or caps != sorted(set(caps))):
        return False
    return credential_keys(credential) is not None


def credential_signature_verifies(c: _Case) -> bool:
    """Whether every credential signature verifies under the key its keyid names in the
    credential's own key list. This is the holder's proof over the bytes and nothing more:
    whoever writes the key list also holds a key that verifies."""
    keys = credential_keys(c.credential)
    sigs = c.credential.signatures
    if keys is None or not sigs:
        return False
    return all(kid in keys and _dsse_verifies(keys[kid], c.credential, sig) for kid, sig in sigs)


def _id_mismatch(c: _Case) -> bool:
    binding = _binding(c.receipt.body)
    body = c.credential.body
    return binding is None or body is None or binding.get("id") != body.get("id")


def _digest_mismatch(c: _Case) -> bool:
    binding = _binding(c.receipt.body)
    digest = binding.get("digest") if binding else None
    declared = digest.get("sha256") if isinstance(digest, dict) else None
    return c.credential.payload is None or declared != _sha(c.credential.payload)


def _window(c: _Case) -> tuple[datetime, datetime] | None:
    body = c.receipt.body
    if body is None or not all(isinstance(body.get(k), str) and _TIME.fullmatch(body[k])
                               for k in ("issuedAt", "validUntil")):
        return None
    return _when(body["issuedAt"]), _when(body["validUntil"])


def _first_failure(c: _Case) -> str | None:
    """Name the first check in ``CHECKS`` the case fails, or None.
    """
    window = _window(c)
    failures: dict[str, Callable[[], bool]] = {
        "receipt_malformed": lambda: not receipt_well_formed(c.receipt),
        "receipt_signature_invalid": lambda: not receipt_signature_verifies(c),
        "receipt_unbound": lambda: "digest" not in (_binding(c.receipt.body) or {}),
        "credential_malformed": lambda: not credential_well_formed(c.credential),
        "credential_signature_invalid": lambda: not credential_signature_verifies(c),
        "credential_id_mismatch": lambda: _id_mismatch(c),
        "credential_digest_mismatch": lambda: _digest_mismatch(c),
        "receipt_not_yet_valid": lambda: window is None or c.now is None or c.now < window[0],
        "receipt_expired": lambda: window is None or c.now is None or c.now >= window[1],
        "credential_not_active": lambda: (c.receipt.body or {}).get("status") != "active",
    }
    for name in CHECKS:
        if failures[name]():
            return name
    return None


def judge(case_path: Path) -> tuple[str, str]:
    """(decision, reason) for the ``case.json`` at ``case_path``."""
    failure = _first_failure(_load(case_path))
    return (ACCEPT, ACCEPTED) if failure is None else (REJECT, failure)
