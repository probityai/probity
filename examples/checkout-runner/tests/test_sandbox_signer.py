"""Admission-signer role: handoff and resolution signing under contract review-2026-10-23."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone

import pytest

from agent_evidence_vectors.run_vectors import ed25519_public_key
from checkout_runner import sandbox_signer as s

SEED = hashlib.sha256(b"refund-sandbox test-only admission signer").digest()
OTHER = hashlib.sha256(b"refund-sandbox test-only other key").digest()
NOW = datetime(2026, 10, 27, 12, 0, 0, 250000, tzinfo=timezone.utc)


def _ref(tag: str) -> str:
    return "sha256:" + hashlib.sha256(tag.encode()).hexdigest()


def record() -> dict:
    return {
        "schema": s.ADMISSION, "contract_revision": s.CONTRACT_REVISION,
        "workflow_id": "wf-refund-1", "admission_issuer": "admission-door", "provider_namespace": "sim",
        "decision_id": "dec-1", "operation_id": "op-1", "approval_ref": "rcpt-1",
        **{name: _ref(name) for name in s.INPUT_REFS},
        "tool": "refund", "arguments": {"payment_id": "pay_A", "amount_minor": 4000, "currency": "EUR"},
        "state": "committed", "committed_at": "2026-10-27T11:59:00Z", "valid_until": "2026-10-27T12:30:00Z",
    }


def key(seed: bytes = SEED, key_id: str = "k1", role: str = s.SIGNER_ROLE, revoked_at=None) -> dict:
    return {"key_id": key_id, "issuer": "admission-door", "role": role,
            "public_key_hex": ed25519_public_key(seed).hex(), "not_before": "2026-10-01T00:00:00Z",
            "not_after": "2026-11-01T00:00:00Z", "revoked_at": revoked_at}


def snapshot(*keys: dict) -> dict:
    return {"schema": s.TRUST, "workflow_id": "wf-refund-1", "version": 1,
            "provider_namespaces": ["sim"], "keys": list(keys) or [key()]}


def presented() -> dict:
    return {name: _ref("new-" + name) for name in s.INPUT_REFS}


def test_handoff_round_trip_binds_admission_ref_and_caps_lifetime() -> None:
    rec, snap = record(), snapshot()
    env = s.sign_handoff(rec, snap, "k1", SEED, NOW)
    payload = s.verify_envelope(s.HANDOFF, env, rec, snap)
    assert payload["admission_ref"] == s.ref_of(rec)
    assert payload["issued_at"] == "2026-10-27T12:00:01Z"  # .250 rounds up, never down
    assert payload["valid_until"] == "2026-10-27T12:10:01Z"  # 600 s ceiling, inside the record window


def test_signature_bytes_are_the_contract_domain() -> None:
    payload = {"b": 1, "a": "x"}
    assert s.signing_bytes(s.HANDOFF, payload) == b'refund-sandbox-handoff/0.1\x00{"a":"x","b":1}'


@pytest.mark.parametrize("mutate,code", [
    (lambda r: r.update(state="pending"), "admission-not-committed"),
    (lambda r: r.update(extra=1), "admission-fields"),
    (lambda r: r["arguments"].update(amount_minor=4000.0), "admission-amount"),
    (lambda r: r.update(pic_evidence_ref="sha256:abc"), "admission-pic_evidence_ref"),
])
def test_signer_refuses_a_record_that_is_not_a_closed_committed_record(mutate, code) -> None:
    rec = record()
    mutate(rec)
    with pytest.raises(s.SignerRefusal) as err:
        s.sign_handoff(rec, snapshot(), "k1", SEED, NOW)
    assert err.value.code == code


def test_signer_refuses_a_bare_digest() -> None:
    with pytest.raises(s.SignerRefusal) as err:
        s.sign_handoff(s.ref_of(record()), snapshot(), "k1", SEED, NOW)  # type: ignore[arg-type]
    assert err.value.code == "admission-not-object"


@pytest.mark.parametrize("snap,key_id,code", [
    (snapshot(), "k9", "key-unknown"),
    (snapshot(key(role="pic-merchant")), "k1", "key-role"),
    (snapshot(key(revoked_at="2026-10-20T00:00:00Z")), "k1", "key-revoked"),
])
def test_signer_refuses_a_key_the_trust_snapshot_does_not_give_the_role(snap, key_id, code) -> None:
    with pytest.raises(s.SignerRefusal) as err:
        s.sign_handoff(record(), snap, key_id, SEED, NOW)
    assert err.value.code == code


def test_seed_must_match_the_selected_key() -> None:
    with pytest.raises(s.SignerRefusal) as err:
        s.sign_handoff(record(), snapshot(), "k1", OTHER, NOW)
    assert err.value.code == "key-material-mismatch"


def test_changed_record_after_signing_is_refused() -> None:
    rec, snap = record(), snapshot()
    env = s.sign_handoff(rec, snap, "k1", SEED, NOW)
    changed = copy.deepcopy(rec)
    changed["arguments"]["amount_minor"] = 4100
    with pytest.raises(s.SignerRefusal) as err:
        s.verify_envelope(s.HANDOFF, env, changed, snap)
    assert err.value.code == "admission-ref"


def test_forged_signature_and_tampered_payload_are_refused() -> None:
    rec, snap = record(), snapshot(key(), key(OTHER, "k2"))
    env = s.sign_handoff(rec, snap, "k1", SEED, NOW)
    forged = copy.deepcopy(env)
    forged["payload"]["key_id"] = "k2"
    with pytest.raises(s.SignerRefusal) as err:
        s.verify_envelope(s.HANDOFF, forged, rec, snap)
    assert err.value.code == "signature-invalid"


def test_resolution_round_trip_never_authorizes_dispatch() -> None:
    rec, snap = record(), snapshot()
    env = s.sign_resolution(rec, "rcpt-2", presented(), snap, "k1", SEED, NOW)
    payload = s.verify_envelope(s.RESOLUTION, env, rec, snap)
    assert payload["dispatch_authorized"] is False
    assert payload["original_admission_ref"] == s.ref_of(rec)
    assert payload["presented_inputs"] == presented()


def test_resolution_and_handoff_domains_do_not_cross() -> None:
    rec, snap = record(), snapshot()
    res = s.sign_resolution(rec, "rcpt-2", presented(), snap, "k1", SEED, NOW)
    with pytest.raises(s.SignerRefusal) as err:
        s.verify_envelope(s.HANDOFF, res, rec, snap)
    assert err.value.code == "payload-fields"
    relabeled = copy.deepcopy(res)
    relabeled["payload"]["schema"] = s.HANDOFF
    with pytest.raises(s.SignerRefusal):
        s.verify_envelope(s.RESOLUTION, relabeled, rec, snap)


def test_resolution_refuses_the_original_receipt_and_open_inputs() -> None:
    with pytest.raises(s.SignerRefusal) as err:
        s.sign_resolution(record(), "rcpt-1", presented(), snapshot(), "k1", SEED, NOW)
    assert err.value.code == "resolution-same-receipt"
    with pytest.raises(s.SignerRefusal) as err:
        s.sign_resolution(record(), "rcpt-2", {**presented(), "x": _ref("x")}, snapshot(), "k1", SEED, NOW)
    assert err.value.code == "presented-inputs-fields"


def test_resigning_the_same_operation_cannot_extend_the_record_window() -> None:
    rec, snap = record(), snapshot()
    late = datetime(2026, 10, 27, 12, 25, 0, tzinfo=timezone.utc)
    payload = s.verify_envelope(s.HANDOFF, s.sign_handoff(rec, snap, "k1", SEED, late), rec, snap)
    assert payload["valid_until"] == rec["valid_until"]


def test_idempotency_key_ignores_key_rotation() -> None:
    assert s.idempotency_key(record()) == s.idempotency_key({**record(), "key_id": "k2"})
