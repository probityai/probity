"""One key-authority check: a signature proves a key signed, never that the key may speak.

The negatives are the classes the 15 Nov 2026 matrix break-it pass found in six verifiers: a key the
record supplies for itself, a key under a foreign key id, a key present in a DID document but not
listed for assertions, a revoked or expired binding, a binding of another subject, and a log
inclusion proof for another leaf. Each comes back unauthorized or unknown, beside a control that
comes back authorized.
"""

import base64
import datetime
import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters.proof_of_control import leaf_hash, node_hash
from agent_evidence_verify.common import CaseError
from agent_evidence_verify.key_authority import (
    AUTHORIZED,
    UNAUTHORIZED,
    UNKNOWN,
    authorize,
    jwk_key_bytes,
    key_set_fingerprint,
    key_sha256,
    kt_leaf,
    multibase_key_bytes,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DID = "did:web:issuer.example"


def _key() -> bytes:
    return Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


KEY, OTHER = _key(), _key()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwk(raw: bytes) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64(raw)}


def _did(asserting: bool = True, key: bytes = KEY, did: str = DID) -> bytes:
    method = {"id": f"{did}#k1", "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": _jwk(key)}
    doc = {"id": did, "verificationMethod": [method], "authentication": ["#k1"]}
    if asserting:
        doc["assertionMethod"] = ["#k1"]
    return json.dumps(doc).encode()


def _did_authority(document: bytes) -> dict:
    return {"kind": "did-web", "did": DID, "document": "did.json",
            "document_sha256": hashlib.sha256(document).hexdigest()}


def _t(text: str) -> datetime.datetime:
    return datetime.datetime.fromisoformat(text)


# ---- pin -----------------------------------------------------------------------------------------

def test_a_pinned_key_is_authorized_and_a_record_supplied_key_is_not() -> None:
    authority = {"kind": "pin", "keys": [{"public_key_sha256": key_sha256(KEY), "kid": "k1"}]}
    good = authorize(authority, KEY, kid="k1")
    assert (good.outcome, good.reason) == (AUTHORIZED, "key_pinned")
    assert good.key_set_sha256 == key_set_fingerprint([key_sha256(KEY)])
    forged = authorize(authority, OTHER, kid="k1")
    assert (forged.outcome, forged.reason) == (UNAUTHORIZED, "key_not_pinned")
    assert forged.key_set_sha256 == good.key_set_sha256


def test_a_pinned_key_under_a_foreign_key_id_is_refused() -> None:
    authority = {"kind": "pin", "keys": [{"public_key_sha256": key_sha256(KEY), "kid": "k1"}]}
    assert authorize(authority, KEY, kid="k2").reason == "key_id_mismatch"
    assert authorize({"kind": "pin", "keys": [{"public_key_sha256": key_sha256(KEY)}]},
                     KEY, kid="anything").outcome == AUTHORIZED


def test_no_authority_in_the_policy_decides_nothing() -> None:
    result = authorize(None, KEY)
    assert (result.outcome, result.reason) == (UNKNOWN, "no_key_authority_in_policy")


@pytest.mark.parametrize("authority", [{"kind": "trust-me"}, {"kind": "pin", "keys": []},
                                       {"kind": "pin", "keys": [{"public_key_sha256": "AB"}]},
                                       "pin"])
def test_a_malformed_authority_is_the_consumers_case_error(authority) -> None:
    with pytest.raises(CaseError):
        authorize(authority, KEY)


# ---- did:web -------------------------------------------------------------------------------------

def test_a_key_under_assertion_method_is_authorized() -> None:
    document = _did()
    result = authorize(_did_authority(document), KEY, kid=f"{DID}#k1", did_document=document)
    assert (result.outcome, result.reason) == (AUTHORIZED, "key_in_assertion_method")
    assert authorize(_did_authority(document), KEY, kid="#k1", did_document=document).outcome == AUTHORIZED


def test_a_key_only_for_authentication_may_not_make_assertions() -> None:
    document = _did(asserting=False)
    result = authorize(_did_authority(document), KEY, did_document=document)
    assert (result.outcome, result.reason) == (UNAUTHORIZED, "key_not_in_assertion_method")


@pytest.mark.parametrize("document,reason", [
    (_did(key=OTHER), "key_not_in_did_document"),
    (_did(did="did:web:attacker.example"), "did_document_id_mismatch"),
    (b'{"id":"did:web:issuer.example","id":"x"}', "did_document_malformed"),
])
def test_a_did_document_that_does_not_carry_the_key_for_this_did_refuses(document, reason) -> None:
    assert authorize(_did_authority(document), KEY, did_document=document).reason == reason


def test_a_did_document_other_than_the_pinned_bytes_is_refused() -> None:
    pinned, served = _did(), _did(key=OTHER)
    result = authorize(_did_authority(pinned), OTHER, did_document=served)
    assert (result.outcome, result.reason) == (UNAUTHORIZED, "did_document_not_pinned")
    assert authorize(_did_authority(pinned), KEY).reason == "did_document_unavailable"


def test_a_did_key_under_another_method_id_is_refused() -> None:
    document = _did()
    assert authorize(_did_authority(document), KEY, kid=f"{DID}#k9",
                     did_document=document).reason == "key_id_mismatch"


def test_multibase_and_jwk_name_the_same_key() -> None:
    raw = KEY
    number = int.from_bytes(b"\xed\x01" + raw, "big")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    text = ""
    while number:
        number, digit = divmod(number, 58)
        text = alphabet[digit] + text
    assert multibase_key_bytes("z" + text) == jwk_key_bytes(_jwk(raw)) == raw
    with pytest.raises(CaseError):
        jwk_key_bytes({**_jwk(raw), "d": "secret"})
    with pytest.raises(CaseError):
        jwk_key_bytes({"kty": "OKP", "crv": "Ed25519", "x": _b64(raw) + "="})


# ---- registry ------------------------------------------------------------------------------------

REGISTRY = {"kind": "registry", "bindings": [
    {"subject": "agent-a", "public_key_sha256": key_sha256(KEY), "not_before": "2026-01-01T00:00:00Z",
     "not_after": "2027-01-01T00:00:00Z", "revoked_at": "2026-06-01T00:00:00Z"},
    {"subject": "agent-b", "public_key_sha256": key_sha256(OTHER), "not_before": "2026-01-01T00:00:00Z"},
]}


@pytest.mark.parametrize("key,subject,at,outcome,reason", [
    (KEY, "agent-a", "2026-03-01T00:00:00+00:00", AUTHORIZED, "key_bound_at_time"),
    (KEY, "agent-a", "2026-07-01T00:00:00+00:00", UNAUTHORIZED, "key_revoked"),
    (KEY, "agent-a", "2025-12-31T00:00:00+00:00", UNAUTHORIZED, "key_outside_validity"),
    (OTHER, "agent-a", "2026-03-01T00:00:00+00:00", UNAUTHORIZED, "key_not_bound_to_subject"),
    (KEY, "agent-b", "2026-03-01T00:00:00+00:00", UNAUTHORIZED, "key_not_bound_to_subject"),
    (KEY, None, "2026-03-01T00:00:00+00:00", UNKNOWN, "record_subject_unknown"),
    (KEY, "agent-a", None, UNKNOWN, "record_time_unknown"),
])
def test_a_registry_binding_speaks_for_one_subject_inside_its_window(key, subject, at, outcome,
                                                                      reason) -> None:
    result = authorize(REGISTRY, key, subject=subject, at=_t(at) if at else None)
    assert (result.outcome, result.reason) == (outcome, reason)


# ---- key transparency ----------------------------------------------------------------------------

def _log(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """A two- or four-leaf RFC 6962 tree: its root and each leaf's audit path."""
    hashes = [leaf_hash(leaf) for leaf in leaves]
    if len(hashes) == 2:
        return node_hash(*hashes), [[hashes[1]], [hashes[0]]]
    left, right = node_hash(hashes[0], hashes[1]), node_hash(hashes[2], hashes[3])
    return node_hash(left, right), [[hashes[1], right], [hashes[0], right],
                                    [hashes[3], left], [hashes[2], left]]


def test_a_key_in_the_pinned_log_is_authorized_and_a_proof_for_another_leaf_is_not() -> None:
    leaves = [kt_leaf(KEY, "agent-a"), kt_leaf(OTHER, "agent-b"), b"x", b"y"]
    root, paths = _log(leaves)
    authority = {"kind": "kt-inclusion", "tree_size": 4, "root_sha256": root.hex()}
    proof = {"index": 0, "tree_size": 4, "path": [h.hex() for h in paths[0]]}
    assert authorize(authority, KEY, subject="agent-a", inclusion_proof=proof).outcome == AUTHORIZED
    assert authorize(authority, KEY, subject="agent-b", inclusion_proof=proof).reason == "key_not_in_log"
    assert authorize(authority, OTHER, subject="agent-a", inclusion_proof=proof).reason == "key_not_in_log"
    assert authorize(authority, KEY, subject="agent-a").reason == "inclusion_proof_unavailable"
    other_head = {**proof, "tree_size": 8}
    assert authorize(authority, KEY, subject="agent-a",
                     inclusion_proof=other_head).reason == "inclusion_proof_for_another_tree_head"


# ---- the first consumer: proof_of_control/v1 -----------------------------------------------------

def _poc(tmp_path: Path, key_authority) -> dict:
    from agent_evidence_verify.adapters import proof_of_control

    artifact = json.loads((Path(proof_of_control.__file__).parents[3]
                           / "examples/corpus-routes/proof-of-control/artifact.json").read_text())
    data = json.dumps(artifact).encode()
    (tmp_path / "artifact.json").write_bytes(data)
    assessment = {"claim_type": "proof_of_control/v1", "input": "artifact"}
    if key_authority is not None:
        assessment["key_authority"] = key_authority
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {"artifact": {
        "path": "artifact.json", "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return adjudicate(case, policy, tmp_path), bytes.fromhex(artifact["public_key"])


def test_a_signed_artifact_agrees_only_under_the_consumers_key_authority(tmp_path: Path) -> None:
    _, carried = _poc(tmp_path, None)
    pinned = {"kind": "pin", "keys": [{"public_key_sha256": key_sha256(carried)}]}
    agreed, _ = _poc(tmp_path, pinned)
    assert (agreed["decision"], agreed["reason"]) == ("supported", "artifact_verifies")
    assert agreed["checks"][-1]["id"] == "key_authority"
    foreign = {"kind": "pin", "keys": [{"public_key_sha256": key_sha256(OTHER)}]}
    refused, _ = _poc(tmp_path, foreign)
    assert (refused["decision"], refused["reason"]) == ("contradicted", "key_not_pinned")
    silent, _ = _poc(tmp_path, None)
    assert (silent["decision"], silent["reason"]) == ("not_established", "no_key_authority_in_policy")
