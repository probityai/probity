"""Canonical bytes, digests, Ed25519 signers, DSSE envelopes and signed approvals.

Every digest a record carries is SHA-256 over RFC 8785 (JCS) bytes, so a verifier in any
language recomputes it from the JSON value alone.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

import jcs_admit
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
APPROVAL_DOMAIN = b"probity-approval-v1\x00"
PERMIT_DOMAIN = b"probity-permit-v1\x00"


#: JCS prints every number as an IEEE double, so an integer beyond this has no one-to-one form:
#: 2**53 and 2**53 + 1 print the same bytes, and an approval over one would hold for the other.
MAX_EXACT_INT = 2**53 - 1


def _refuse_inexact_ints(value: Any, depth: int = 0) -> None:
    if depth > 256:
        raise ValueError("value_too_deep")
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -MAX_EXACT_INT <= value <= MAX_EXACT_INT:
            raise ValueError(f"integer_beyond_exact_json_range:{value}")
    elif isinstance(value, dict):
        for item in value.values():
            _refuse_inexact_ints(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _refuse_inexact_ints(item, depth + 1)


def canonical(value: Any) -> bytes:
    """The RFC 8785 bytes of a JSON value; an integer JCS cannot print exactly is refused."""
    _refuse_inexact_ints(value)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return jcs_admit.admit(raw.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def args_sha256(args: Any) -> str:
    """SHA-256 (hex) of the JCS bytes of a call's arguments."""
    return sha256_hex(canonical(args))


def args_digest(tool: str, args: Any) -> str:
    """SHA-256 (hex) of the JCS bytes of ``{"tool": tool, "args": args}``: one call's identity."""
    return sha256_hex(canonical({"args": args, "tool": tool}))


def permit_id(pause_token: str, tool_call_id: str, args_sha256_hex: str) -> str:
    """The single-use permit identifier; it doubles as the Temporal Update id that carries the approval."""
    return sha256_hex(canonical({"argsSha256": args_sha256_hex, "pauseToken": pause_token,
                                 "toolCallId": tool_call_id}))


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding; lengths count bytes."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def key_id(key: Ed25519PublicKey) -> str:
    """SHA-256 of the raw public key, the identity agent-evidence-verify reports for a key."""
    return sha256_hex(key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def load_public(pem_or_raw: bytes) -> Ed25519PublicKey:
    if len(pem_or_raw) == 32:
        return Ed25519PublicKey.from_public_bytes(pem_or_raw)
    key = load_pem_public_key(pem_or_raw)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("only Ed25519 public keys are supported")
    return key


@dataclass(frozen=True)
class Signer:
    """An Ed25519 signing key. Keep it out of the agent's process in production."""

    key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes) -> Signer:
        key = load_pem_private_key(pem, None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("only Ed25519 private keys are supported")
        return cls(key)

    def private_pem(self) -> bytes:
        return self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    def public_pem(self) -> bytes:
        return self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    @property
    def public(self) -> Ed25519PublicKey:
        return self.key.public_key()

    @property
    def key_id(self) -> str:
        return key_id(self.public)

    @property
    def provenance(self) -> dict[str, Any]:
        """A key in this process's memory: run it in the separate-uid authority service, never the worker."""
        return {"backend": "local"}

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64 text")
    try:
        data = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise ValueError("expected canonical base64") from exc
    if _b64(data) != text:
        raise ValueError("expected canonical base64")
    return data


def sign_envelope(signer: Any, payload: bytes, payload_type: str = IN_TOTO_PAYLOAD_TYPE) -> dict[str, Any]:
    """One DSSE envelope with one Ed25519 signature."""
    sig = signer.sign(pae(payload_type, payload))
    return {"payload": _b64(payload), "payloadType": payload_type,
            "signatures": [{"keyid": signer.key_id, "sig": _b64(sig)}]}


def open_envelope(envelope: Any, keys: list[Ed25519PublicKey],
                  payload_type: str = IN_TOTO_PAYLOAD_TYPE) -> tuple[bytes, str]:
    """The payload and the accepting key's id; ValueError when no key accepts or the type differs.

    ``keyid`` is unsigned, so it is never read: every key is tried against every signature.
    """
    if not isinstance(envelope, dict) or not {"payload", "payloadType", "signatures"} <= envelope.keys():
        raise ValueError("envelope_shape")
    kind = envelope["payloadType"]
    payload = _unb64(envelope["payload"])
    entries = envelope["signatures"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("envelope_shape")
    pre = pae(kind, payload)
    for key in keys:
        for entry in entries:
            try:
                key.verify(_unb64(entry.get("sig") if isinstance(entry, dict) else None), pre)
            except (InvalidSignature, ValueError):
                continue
            if kind != payload_type:
                raise ValueError("payload_type_unexpected")
            return payload, key_id(key)
    raise ValueError("signature_unverified")


def statement(subject_name: str, subject_digest: str, predicate_type: str,
              predicate: dict[str, Any]) -> dict[str, Any]:
    return {"_type": STATEMENT_TYPE, "predicate": predicate, "predicateType": predicate_type,
            "subject": [{"digest": {"sha256": subject_digest}, "name": subject_name}]}


def sign_approval(signer: Any, body: dict[str, Any]) -> dict[str, Any]:
    """An approval signed by the approver's own key over a domain-separated JCS body."""
    data = canonical(body)
    return {"body": body, "sig": _b64(signer.sign(APPROVAL_DOMAIN + data))}


def verify_approval(signed: Any, approver_pems: dict[str, bytes]) -> dict[str, Any] | None:
    """The approval body when its signature verifies under the key pinned for its ``approver``.

    ``approver_pems`` maps an approver principal to that approver's public key. The
    approval-binding reader compares key identifiers by name only, so this check runs first.
    """
    if not isinstance(signed, dict) or not isinstance(signed.get("body"), dict):
        return None
    body = signed["body"]
    pem = approver_pems.get(str(body.get("approver", "")))
    if pem is None:
        return None
    try:
        load_public(pem).verify(_unb64(signed.get("sig")), APPROVAL_DOMAIN + canonical(body))
    except (InvalidSignature, ValueError):
        return None
    return body


def sign_permit(signer: Any, claims: dict[str, Any]) -> dict[str, Any]:
    """A permit: the authority's signature over the claims of one exact call.

    The claims name the signing key's custody (``keyProvenance``); a permit signed by a delegated
    session key carries the root's certificate for it, so the system of record pins the root only.
    """
    claims = {**claims, "keyProvenance": dict(getattr(signer, "provenance", {"backend": "unstated"}))}
    permit = {"claims": claims, "sig": _b64(signer.sign(PERMIT_DOMAIN + canonical(claims)))}
    certificate = getattr(signer, "certificate", None)
    if certificate is not None:
        permit["delegation"] = certificate
    return permit


def verify_permit(permit: Any, authority_pem: bytes) -> dict[str, Any] | None:
    """The claims when the pinned authority key, or a session key it certified for the permit's
    ``issuedAt``, signed them; ``None`` otherwise."""
    if not isinstance(permit, dict) or not isinstance(permit.get("claims"), dict):
        return None
    root = load_public(authority_pem)
    keys = [root]
    if permit.get("delegation") is not None:
        from .signing import verify_delegation  # noqa: PLC0415 - signing imports core

        try:
            delegation = verify_delegation(permit["delegation"], [root])
        except ValueError:
            return None
        if not delegation.covers(str(permit["claims"].get("issuedAt"))):
            return None
        keys.append(delegation.session)
    message = PERMIT_DOMAIN + canonical(permit["claims"])
    for key in keys:
        try:
            key.verify(_unb64(permit.get("sig")), message)
        except (InvalidSignature, ValueError):
            continue
        return permit["claims"]
    return None
