"""Verify a DSSE envelope, then check the claim its payload carries.

``probityai verify`` accepts a probity case or a DSSE envelope. For an envelope:

1. The envelope is parsed strictly. ``payload`` and every ``signatures[].sig``
   must be canonical padded base64 in the standard or the URL-safe alphabet;
   two encodings of one byte string are refused, so one signature cannot cover
   two envelopes. An envelope with no signatures, an empty ``payloadType`` or
   more than :data:`MAX_SIGNATURES` entries is malformed.
2. The pre-image is ``PAE(payloadType, payload)`` from DSSE protocol v1.
3. Each consumer key (Ed25519, raw 32 bytes or a PEM public key) is tried
   against every signature entry. ``keyid`` is unsigned, so it is never read.
   One accepting key is enough; each key counts once.
4. Only an authentic envelope has its ``payloadType`` compared with the
   expected type (in-toto Statement JSON by default).
5. The verified payload bytes are served to the claim adapters in place of the
   case artifact pinned to the same SHA-256. The consumer policy decides as
   for any case. The payload must be read by the check, or the input is refused.

A signature that does not verify under a supplied key, and a payload type that
differs from the expected one, are ``not_established``: the consumer's keys do
not establish the bundle, which says nothing either way about the claim inside.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

from .common import CaseError, supplied_artifacts
from .core import adjudicate

IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
ENVELOPE_FIELDS = frozenset({"payload", "payloadType", "signatures"})
MAX_SIGNATURES = 1024
_STANDARD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_URL_SAFE = re.compile(r"[A-Za-z0-9_-]*={0,2}")


def is_envelope(value: Any) -> bool:
    """Whether a parsed JSON input has the members of a DSSE envelope."""
    return isinstance(value, dict) and ENVELOPE_FIELDS <= value.keys()


def pae(payload_type: str, payload: bytes) -> bytes:
    """The DSSE v1 pre-authentication encoding; lengths count bytes."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def decode_b64(text: Any, label: str) -> bytes:
    """Decode canonical padded base64 in either RFC 4648 alphabet, or refuse."""
    if isinstance(text, str):
        for pattern, decode, encode in (
                (_STANDARD, base64.b64decode, base64.b64encode),
                (_URL_SAFE, base64.urlsafe_b64decode, base64.urlsafe_b64encode)):
            if len(text) % 4 == 0 and pattern.fullmatch(text):
                try:
                    data = decode(text)
                except (binascii.Error, ValueError):
                    continue
                if encode(data).decode("ascii") == text:
                    return data
    raise CaseError(f"{label}: expected canonical padded base64")


def load_key(data: bytes, label: str) -> Ed25519PublicKey:
    """An Ed25519 public key from 32 raw bytes or a PEM SubjectPublicKeyInfo."""
    if len(data) == 32:
        try:
            return Ed25519PublicKey.from_public_bytes(data)
        except ValueError as exc:
            raise CaseError(f"{label}: unusable Ed25519 public key") from exc
    try:
        key = load_pem_public_key(data)
    except (ValueError, TypeError) as exc:
        raise CaseError(f"{label}: expected a raw or PEM Ed25519 public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise CaseError(f"{label}: only Ed25519 keys are supported")
    return key


def key_id(key: Ed25519PublicKey) -> str:
    """SHA-256 of the raw public key: the identity reported for an accepting key."""
    return hashlib.sha256(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def parse(envelope: Any) -> tuple[str, bytes, list[bytes]]:
    """``(payloadType, payload, signatures)`` of a well-formed envelope."""
    if not is_envelope(envelope):
        raise CaseError("envelope: expected payload, payloadType and signatures")
    payload_type = envelope["payloadType"]
    if not isinstance(payload_type, str) or not payload_type:
        raise CaseError("envelope.payloadType: expected a nonempty string")
    payload = decode_b64(envelope["payload"], "envelope.payload")
    entries = envelope["signatures"]
    if not isinstance(entries, list) or not entries:
        raise CaseError("envelope.signatures: expected a nonempty list")
    if len(entries) > MAX_SIGNATURES:
        raise CaseError(f"envelope.signatures: more than {MAX_SIGNATURES} entries")
    signatures = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or "sig" not in entry:
            raise CaseError(f"envelope.signatures[{index}]: expected an object with sig")
        signatures.append(decode_b64(entry["sig"], f"envelope.signatures[{index}].sig"))
    return payload_type, payload, signatures


def accepting_keys(keys: Sequence[Ed25519PublicKey], pre_image: bytes,
                   signatures: list[bytes]) -> list[str]:
    """The distinct keys under which some signature entry verifies."""
    accepted = []
    for key in keys:
        for signature in signatures:
            try:
                key.verify(signature, pre_image)
            except InvalidSignature:
                continue
            identity = key_id(key)
            if identity not in accepted:
                accepted.append(identity)
            break
    return accepted


def _unestablished(case: dict, policy: dict, reason: str, check: dict) -> dict:
    case_id = case.get("case_id")
    assessments = policy.get("assessments")
    assessment = assessments.get(case_id) if isinstance(assessments, dict) else None
    if not isinstance(case_id, str) or not isinstance(assessment, dict) or not isinstance(
            assessment.get("claim_type"), str):
        raise CaseError("case_id has no consumer assessment")
    return {"schema_version": "probity-decision/v1", "case_id": case_id,
            "claim_type": assessment["claim_type"], "decision": "not_established",
            "reason": reason, "scope": {"envelope": check}, "checks": [check],
            "vantage": "unestablished"}


def adjudicate_envelope(envelope: Any, case: Any, policy: Any, artifact_root: Path,
                        keys: Sequence[Ed25519PublicKey], *,
                        payload_type: str = IN_TOTO_PAYLOAD_TYPE,
                        require_witness_scope: str = "PEER") -> dict:
    """Verify ``envelope`` under ``keys``, then decide the case on its payload."""
    if not keys:
        raise CaseError("a DSSE envelope needs at least one --key")
    if not isinstance(case, dict) or not isinstance(policy, dict):
        raise CaseError("case and policy must be JSON objects")
    kind, payload, signatures = parse(envelope)
    digest = hashlib.sha256(payload).hexdigest()
    accepted = accepting_keys(keys, pae(kind, payload), signatures)
    check = {"id": "dsse_envelope", "payload_type": kind, "payload_sha256": digest,
             "accepted_keys": accepted, "status": "met"}
    if not accepted:
        check["status"] = "unavailable"
        return _unestablished(case, policy, "dsse_signature_unverified", check)
    if kind != payload_type:
        check.update(status="unavailable", expected_payload_type=payload_type)
        return _unestablished(case, policy, "dsse_payload_type_unexpected", check)
    with supplied_artifacts({digest: payload}) as used:
        result = adjudicate(case, policy, artifact_root,
                            require_witness_scope=require_witness_scope)
    if digest not in used:
        raise CaseError("envelope payload is not an artifact the claim reads")
    result["checks"].insert(0, check)
    result["scope"]["envelope"] = check
    return result
