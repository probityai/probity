"""Admission-signer role for the bounded refund sandbox (contract review-2026-10-23).

The signer holds the admission-signer key and did not make the admission
decision. It signs only a committed admission record it was handed in full,
never a digest, and it recomputes every reference it signs. It emits:

* ``refund-sandbox-handoff/0.1`` envelopes (contract section 6), and
* ``refund-sandbox-resolution/0.1`` envelopes for a reissue that admission
  resolved to an existing operation (contract section 9).

Signature bytes are ``ASCII(type) || 0x00 || UTF8(JCS(payload))`` with Ed25519.
JCS and Ed25519 come from the pinned ``agent-evidence-vectors`` package. The
verifier selects the domain from the record type it expects, never from the
submitted ``payload.schema``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_evidence_vectors.run_vectors import (
    ed25519_public_key,
    ed25519_sign,
    ed25519_verify,
    jcs_dumps,
)

CONTRACT_REVISION = "review-2026-10-23"
ADMISSION = "refund-sandbox-admission/0.1"
HANDOFF = "refund-sandbox-handoff/0.1"
RESOLUTION = "refund-sandbox-resolution/0.1"
TRUST = "refund-sandbox-trust/0.1"
IDEMPOTENCY = "refund-sandbox-idempotency/0.1"
SIGNER_ROLE = "admission-signer"
HANDOFF_LIFETIME_CEILING = 600

ADMISSION_FIELDS = frozenset({
    "schema", "contract_revision", "workflow_id", "admission_issuer", "provider_namespace",
    "decision_id", "operation_id", "approval_ref", "pic_evidence_ref", "pic_verification_ref",
    "pic_trust_file_ref", "aps_evidence_ref", "aps_intent_file_ref", "aps_action_file_ref",
    "aps_payload_file_ref", "decision_evidence_ref", "aps_consumption_trust_ref", "tool",
    "arguments", "state", "committed_at", "valid_until",
})
INPUT_REFS = (
    "pic_evidence_ref", "pic_verification_ref", "pic_trust_file_ref", "aps_evidence_ref",
    "aps_intent_file_ref", "aps_action_file_ref", "aps_payload_file_ref",
    "decision_evidence_ref", "aps_consumption_trust_ref",
)
HANDOFF_FIELDS = frozenset({
    "schema", "contract_revision", "workflow_id", "admission_issuer", "provider_namespace",
    "operation_id", "admission_ref", "key_id", "trust_snapshot_ref", "issued_at",
    "not_before", "valid_until",
})
RESOLUTION_FIELDS = frozenset({
    "schema", "contract_revision", "workflow_id", "admission_issuer", "provider_namespace",
    "decision_id", "operation_id", "original_admission_ref", "original_approval_ref",
    "presented_approval_ref", "presented_inputs", "disposition", "dispatch_authorized",
    "key_id", "trust_snapshot_ref", "issued_at",
})
TRUST_FIELDS = frozenset({"schema", "workflow_id", "version", "provider_namespaces", "keys"})
KEY_FIELDS = frozenset({"key_id", "issuer", "role", "public_key_hex", "not_before", "not_after", "revoked_at"})
SCOPE = ("workflow_id", "admission_issuer", "provider_namespace")
REFUND_ARGS = frozenset({"payment_id", "amount_minor", "currency"})

_REF = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class SignerRefusal(ValueError):
    """A record, trust input or envelope the signer or verifier refuses, with a code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _require(cond: bool, code: str) -> None:
    if not cond:
        raise SignerRefusal(code)


def ref_of(obj: Any) -> str:
    """Return ``sha256:`` plus the SHA-256 of the object's JCS bytes."""
    return "sha256:" + hashlib.sha256(jcs_dumps(obj)).hexdigest()


def signing_bytes(record_type: str, payload: dict[str, Any]) -> bytes:
    """Return the contract's domain-separated signature input for one record type."""
    return record_type.encode("ascii") + b"\x00" + jcs_dumps(payload)


def parse_ts(value: Any) -> datetime:
    """Parse a whole-second UTC wrapper timestamp; refuse any other shape."""
    _require(isinstance(value, str) and bool(_TS.match(value)), "timestamp-format")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def fmt_ts(value: datetime) -> str:
    """Format a UTC instant as a whole-second wrapper timestamp, rounding up."""
    whole = value.replace(microsecond=0)
    if value.microsecond:
        whole += timedelta(seconds=1)
    return whole.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ascii_id(value: Any) -> bool:
    return isinstance(value, str) and value != "" and value.isascii() and value.isprintable()


def check_admission_record(record: Any) -> str:
    """Check a committed admission record's closed shape and return its admission_ref."""
    _require(isinstance(record, dict), "admission-not-object")
    _require(set(record) == ADMISSION_FIELDS, "admission-fields")
    _require(record["schema"] == ADMISSION, "admission-schema")
    _require(record["contract_revision"] == CONTRACT_REVISION, "admission-revision")
    _require(record["state"] == "committed", "admission-not-committed")
    for name in (*SCOPE, "decision_id", "operation_id", "approval_ref"):
        _require(_ascii_id(record[name]), f"admission-{name}")
    for name in INPUT_REFS:
        _require(isinstance(record[name], str) and bool(_REF.match(record[name])), f"admission-{name}")
    _require(record["tool"] == "refund", "admission-tool")
    args = record["arguments"]
    _require(isinstance(args, dict) and set(args) == REFUND_ARGS, "admission-arguments")
    _require(type(args["amount_minor"]) is int and 0 < args["amount_minor"] <= 2**53 - 1, "admission-amount")
    _require(_ascii_id(args["payment_id"]) and _ascii_id(args["currency"]), "admission-arguments")
    _require(parse_ts(record["committed_at"]) < parse_ts(record["valid_until"]), "admission-window")
    return ref_of(record)


def check_trust_snapshot(snapshot: Any) -> str:
    """Check an issuance trust snapshot's closed shape and return trust_snapshot_ref."""
    _require(isinstance(snapshot, dict) and set(snapshot) == TRUST_FIELDS, "trust-fields")
    _require(snapshot["schema"] == TRUST, "trust-schema")
    keys = snapshot["keys"]
    _require(isinstance(keys, list) and keys != [], "trust-keys")
    ids, pubs = set(), set()
    for key in keys:
        _require(isinstance(key, dict) and set(key) == KEY_FIELDS, "trust-key-fields")
        _require(isinstance(key["public_key_hex"], str) and bool(_HEX64.match(key["public_key_hex"])), "trust-key-hex")
        _require(key["key_id"] not in ids and key["public_key_hex"] not in pubs, "trust-key-duplicate")
        ids.add(key["key_id"])
        pubs.add(key["public_key_hex"])
        parse_ts(key["not_before"])
        parse_ts(key["not_after"])
        if key["revoked_at"] is not None:
            parse_ts(key["revoked_at"])
    return ref_of(snapshot)


def _signer_key(snapshot: dict[str, Any], key_id: str, scope: dict[str, Any], at: datetime) -> dict[str, Any]:
    matches = [k for k in snapshot["keys"] if k["key_id"] == key_id]
    _require(len(matches) == 1, "key-unknown")
    key = matches[0]
    _require(key["role"] == SIGNER_ROLE, "key-role")
    _require(key["issuer"] == scope["admission_issuer"], "key-issuer")
    _require(snapshot["workflow_id"] == scope["workflow_id"], "key-workflow")
    _require(scope["provider_namespace"] in snapshot["provider_namespaces"], "key-provider")
    _require(parse_ts(key["not_before"]) <= at < parse_ts(key["not_after"]), "key-validity")
    _require(key["revoked_at"] is None or at < parse_ts(key["revoked_at"]), "key-revoked")
    return key


def _envelope(record_type: str, payload: dict[str, Any], seed: bytes, key: dict[str, Any]) -> dict[str, Any]:
    _require(ed25519_public_key(seed).hex() == key["public_key_hex"], "key-material-mismatch")
    sig = ed25519_sign(seed, signing_bytes(record_type, payload))
    return {"payload": payload, "alg": "ed25519", "signature": base64.b64encode(sig).decode("ascii")}


def sign_handoff(record: dict[str, Any], snapshot: dict[str, Any], key_id: str, seed: bytes, now: datetime) -> dict[str, Any]:
    """Sign a handoff over a committed admission record handed over in full.

    valid_until is the earlier of the record's valid_until, the key's not_after
    and issued_at plus the 600-second ceiling, so re-signing the same operation
    cannot extend it.
    """
    admission_ref = check_admission_record(record)
    trust_ref = check_trust_snapshot(snapshot)
    issued = parse_ts(fmt_ts(now))
    key = _signer_key(snapshot, key_id, record, issued)
    until = min(parse_ts(record["valid_until"]), parse_ts(key["not_after"]),
                issued + timedelta(seconds=HANDOFF_LIFETIME_CEILING))
    _require(issued < until, "handoff-window-empty")
    payload = {
        "schema": HANDOFF, "contract_revision": CONTRACT_REVISION,
        **{k: record[k] for k in SCOPE}, "operation_id": record["operation_id"],
        "admission_ref": admission_ref, "key_id": key_id, "trust_snapshot_ref": trust_ref,
        "issued_at": fmt_ts(issued), "not_before": fmt_ts(issued), "valid_until": fmt_ts(until),
    }
    return _envelope(HANDOFF, payload, seed, key)


def sign_resolution(original: dict[str, Any], presented_approval_ref: str, presented_inputs: dict[str, Any],
                    snapshot: dict[str, Any], key_id: str, seed: bytes, now: datetime) -> dict[str, Any]:
    """Sign a resolved_existing record for a reissue admission already verified.

    The original admission is hashed as handed over, never rewritten, and the
    record carries dispatch_authorized false by construction.
    """
    original_ref = check_admission_record(original)
    _require(isinstance(presented_inputs, dict) and set(presented_inputs) == set(INPUT_REFS), "presented-inputs-fields")
    for name in INPUT_REFS:
        _require(isinstance(presented_inputs[name], str) and bool(_REF.match(presented_inputs[name])), f"presented-{name}")
    _require(_ascii_id(presented_approval_ref), "presented-approval-ref")
    _require(presented_approval_ref != original["approval_ref"], "resolution-same-receipt")
    trust_ref = check_trust_snapshot(snapshot)
    issued = parse_ts(fmt_ts(now))
    key = _signer_key(snapshot, key_id, original, issued)
    payload = {
        "schema": RESOLUTION, "contract_revision": CONTRACT_REVISION,
        **{k: original[k] for k in SCOPE}, "decision_id": original["decision_id"],
        "operation_id": original["operation_id"], "original_admission_ref": original_ref,
        "original_approval_ref": original["approval_ref"], "presented_approval_ref": presented_approval_ref,
        "presented_inputs": dict(presented_inputs), "disposition": "resolved_existing",
        "dispatch_authorized": False, "key_id": key_id, "trust_snapshot_ref": trust_ref,
        "issued_at": fmt_ts(issued),
    }
    return _envelope(RESOLUTION, payload, seed, key)


def verify_envelope(record_type: str, envelope: Any, record: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Verify a handoff or resolution envelope against the expected type, record and issuance trust.

    Returns the payload. Checks integrity and authorization at issuance only;
    current dispatch authorization (contract section 7) is the executor's check.
    """
    fields = {HANDOFF: HANDOFF_FIELDS, RESOLUTION: RESOLUTION_FIELDS}.get(record_type)
    _require(fields is not None, "unexpected-record-type")
    _require(isinstance(envelope, dict) and set(envelope) == {"payload", "alg", "signature"}, "envelope-fields")
    _require(envelope["alg"] == "ed25519", "envelope-alg")
    payload = envelope["payload"]
    _require(isinstance(payload, dict) and set(payload) == fields, "payload-fields")
    _require(payload["schema"] == record_type, "payload-schema")
    _require(payload["contract_revision"] == CONTRACT_REVISION, "payload-revision")
    record_ref = check_admission_record(record)
    _require(payload["trust_snapshot_ref"] == check_trust_snapshot(snapshot), "trust-snapshot-ref")
    for name in (*SCOPE, "operation_id"):
        _require(payload[name] == record[name], f"scope-{name}")
    if record_type == HANDOFF:
        _require(payload["admission_ref"] == record_ref, "admission-ref")
        _require(payload["not_before"] == payload["issued_at"], "handoff-not-before")
        _require(parse_ts(payload["valid_until"]) <= parse_ts(record["valid_until"]), "handoff-extends-record")
        _require(parse_ts(payload["issued_at"]) < parse_ts(payload["valid_until"]), "handoff-window-empty")
    else:
        _require(payload["original_admission_ref"] == record_ref, "original-admission-ref")
        _require(payload["original_approval_ref"] == record["approval_ref"], "original-approval-ref")
        _require(payload["decision_id"] == record["decision_id"], "decision-id")
        _require(payload["disposition"] == "resolved_existing", "disposition")
        _require(payload["dispatch_authorized"] is False, "dispatch-authorized")
    key = _signer_key(snapshot, payload["key_id"], record, parse_ts(payload["issued_at"]))
    try:
        sig = base64.b64decode(envelope["signature"], validate=True)
    except (binascii.Error, TypeError, ValueError):
        raise SignerRefusal("signature-encoding") from None
    _require(len(sig) == 64 and base64.b64encode(sig).decode("ascii") == envelope["signature"], "signature-encoding")
    _require(ed25519_verify(bytes.fromhex(key["public_key_hex"]), signing_bytes(record_type, payload), sig), "signature-invalid")
    return payload


def idempotency_key(scope: dict[str, Any]) -> str:
    """Return the executor's scoped idempotency key (contract section 10)."""
    body = {k: scope[k] for k in (*SCOPE, "operation_id")}
    return "sha256:" + hashlib.sha256(IDEMPOTENCY.encode("ascii") + b"\x00" + jcs_dumps(body)).hexdigest()
