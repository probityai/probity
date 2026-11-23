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


# ---- break-it counter-examples (b22-verify-break, 15 Nov 2026) -----------------------------------

def _doc(**members) -> bytes:
    return json.dumps({"id": DID, **members}).encode()


def test_a_shared_method_id_never_promotes_a_key_to_assertions() -> None:
    """KEY sits only under verificationMethod; assertionMethod embeds the same id with OTHER.

    A reader that keeps the first copy trusts KEY for assertions, one that keeps the last trusts
    OTHER: the document is malformed, and neither key is authorised.
    """
    shadow = _doc(verificationMethod=[{"id": "#k1", "publicKeyJwk": _jwk(KEY)}],
                  authentication=["#k1"],
                  assertionMethod=[{"id": "#k1", "publicKeyJwk": _jwk(OTHER)}])
    for key in (KEY, OTHER):
        result = authorize(_did_authority(shadow), key, did_document=shadow)
        assert (result.outcome, result.reason) == (UNAUTHORIZED, "did_document_malformed")
    twice = _doc(verificationMethod=[{"id": "#k1", "publicKeyJwk": _jwk(KEY)},
                                     {"id": f"{DID}#k1", "publicKeyJwk": _jwk(OTHER)}],
                 assertionMethod=["#k1"])
    for key in (KEY, OTHER):
        assert authorize(_did_authority(twice), key, did_document=twice).reason == "did_document_malformed"
    listless = _doc(verificationMethod={"id": "#k1"}, assertionMethod=["#k1"])
    assert authorize(_did_authority(listless), KEY, did_document=listless).reason == "did_document_malformed"


@pytest.mark.parametrize("marks", [{"use": "enc"}, {"key_ops": ["encrypt"]}, {"key_ops": "verify"}])
def test_a_jwk_marked_for_another_use_does_not_sign(marks: dict) -> None:
    document = _doc(verificationMethod=[{"id": "#k1", "publicKeyJwk": {**_jwk(KEY), **marks}}],
                    assertionMethod=["#k1"])
    result = authorize(_did_authority(document), KEY, did_document=document)
    assert (result.outcome, result.reason) == (UNAUTHORIZED, "key_not_for_signing")
    signing = _doc(verificationMethod=[{"id": "#k1", "publicKeyJwk": {**_jwk(KEY), "use": "sig",
                                                                       "key_ops": ["verify"]}}],
                   assertionMethod=["#k1"])
    assert authorize(_did_authority(signing), KEY, did_document=signing).outcome == AUTHORIZED


def test_a_key_id_is_read_relative_only_to_this_did() -> None:
    """``did:web:other.example#k9`` is one character shorter than this DID's prefix plus ``#``."""
    foreign = "did:web:other.example#k9"
    document = _doc(verificationMethod=[{"id": foreign, "publicKeyJwk": _jwk(KEY)}],
                    assertionMethod=[foreign])
    assert authorize(_did_authority(document), KEY, kid="k9", did_document=document).reason == (
        "key_id_mismatch")
    assert authorize(_did_authority(document), KEY, kid=foreign, did_document=document).outcome == (
        AUTHORIZED)


def test_a_pin_that_names_a_key_id_needs_the_record_to_name_it() -> None:
    authority = {"kind": "pin", "keys": [{"public_key_sha256": key_sha256(KEY), "kid": "k1"}]}
    assert authorize(authority, KEY).reason == "key_id_mismatch"
    either = {"kind": "pin", "keys": [{"public_key_sha256": key_sha256(KEY), "kid": "k1"},
                                      {"public_key_sha256": key_sha256(KEY)}]}
    assert authorize(either, KEY).outcome == AUTHORIZED


@pytest.mark.parametrize("text", ["2026-W46-1T00:00:00Z", "20261115T000000Z", "2026-11-15T00:00:00,5Z",
                                  "2026-11-15 00:00:00Z", "2026-11-15T00:00Z", "2026-11-15T00:00:00",
                                  "2026-02-30T00:00:00Z", "2026-11-15T00:00:00+24:00",
                                  "\uff12026-11-15T00:00:00Z",
                                  # A leap second falls only at 23:59:60 UTC (RFC 3339 section 5.7).
                                  "2026-11-16T12:30:60Z", "2026-12-31T23:59:60+01:00"])
def test_a_binding_instant_that_is_not_rfc_3339_is_the_consumers_case_error(text: str) -> None:
    authority = {"kind": "registry", "bindings": [
        {"subject": "agent-a", "public_key_sha256": key_sha256(KEY), "not_before": text}]}
    with pytest.raises(CaseError):
        authorize(authority, KEY, subject="agent-a", at=_t("2026-12-01T00:00:00+00:00"))


def test_rfc_3339_forms_python_alone_would_misread_are_read_exactly() -> None:
    from agent_evidence_verify.key_authority import parse_instant

    assert parse_instant("2026-12-31T23:59:60Z") < parse_instant("2027-01-01T00:00:00Z")
    assert parse_instant("2026-12-31T23:59:60Z") > parse_instant("2026-12-31T23:59:59.5Z")
    assert parse_instant("2026-11-15t00:00:00z") == parse_instant("2026-11-15T00:00:00+00:00")
    assert parse_instant("2026-11-15T00:00:00.123456Z") < parse_instant("2026-11-15T00:00:00.1234567Z")
    assert parse_instant("2026-11-15T00:00:00.1234567Z") < parse_instant("2026-11-15T00:00:00.123457Z")
    assert parse_instant("2026-11-15T00:00:00.1234560Z") == parse_instant("2026-11-15T00:00:00.123456Z")
    assert parse_instant("2026-12-31T23:59:60.999999999Z") < parse_instant("2027-01-01T00:00:00Z")
    assert parse_instant("1990-12-31T15:59:60-08:00") == parse_instant("1990-12-31T23:59:60Z")
    assert parse_instant("2026-11-15T01:00:00+01:00") == parse_instant("2026-11-15T00:00:00Z")


def test_a_revoked_key_stays_revoked_under_a_second_binding() -> None:
    authority = {"kind": "registry", "bindings": [
        {"subject": "agent-a", "public_key_sha256": key_sha256(KEY), "not_before": "2026-01-01T00:00:00Z",
         "revoked_at": "2026-03-01T00:00:00Z"},
        {"subject": "agent-a", "public_key_sha256": key_sha256(KEY), "not_before": "2026-01-01T00:00:00Z"},
    ]}
    before = authorize(authority, KEY, subject="agent-a", at=_t("2026-02-01T00:00:00+00:00"))
    after = authorize(authority, KEY, subject="agent-a", at=_t("2026-04-01T00:00:00+00:00"))
    assert before.outcome == AUTHORIZED
    assert (after.outcome, after.reason) == (UNAUTHORIZED, "key_revoked")
    assert after.key_set_sha256 == key_set_fingerprint([])


@pytest.mark.parametrize("field,value", [("index", True), ("index", 1.0), ("tree_size", 2.0),
                                         ("tree_size", True)])
def test_an_inclusion_proof_counts_in_json_integers_only(field: str, value) -> None:
    leaves = [b"x", kt_leaf(KEY, "agent-a")]
    root, paths = _log(leaves)
    authority = {"kind": "kt-inclusion", "tree_size": 2, "root_sha256": root.hex()}
    proof = {"index": 1, "tree_size": 2, "path": [h.hex() for h in paths[1]]}
    assert authorize(authority, KEY, subject="agent-a", inclusion_proof=proof).outcome == AUTHORIZED
    bent = {**proof, field: value}
    result = authorize(authority, KEY, subject="agent-a", inclusion_proof=bent)
    assert (result.outcome, result.reason) == (UNAUTHORIZED, "inclusion_proof_malformed")


# ---- the first consumer: proof_of_control/v1 -----------------------------------------------------

#: Read from the checkout, never from the installed package: the floor lane runs these tests
#: against an installed wheel, which carries no ``examples/``.
POC_EXAMPLE = Path(__file__).resolve().parents[1] / "examples/corpus-routes/proof-of-control/artifact.json"

def _poc(tmp_path: Path, key_authority) -> dict:
    artifact = json.loads(POC_EXAMPLE.read_text())
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


def _poc_with(tmp_path: Path, key_authority: dict, extra: dict[str, bytes],
              artifact: dict | None = None) -> tuple[dict, bytes, dict]:
    """The example chain (or ``artifact``) judged under ``key_authority``, ``extra`` bound beside it."""
    artifact = json.loads(POC_EXAMPLE.read_text()) if artifact is None else artifact
    files = {"artifact": json.dumps(artifact).encode(), **extra}
    bindings = {}
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
        bindings[name] = {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": bindings}
    assessment = {"claim_type": "proof_of_control/v1", "input": "artifact", "key_authority": key_authority}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return adjudicate(case, policy, tmp_path), bytes.fromhex(artifact["public_key"]), artifact


def _resigned(issuer: str) -> tuple[dict, bytes]:
    """The example chain with every record's ``iss`` set to ``issuer``, signed again by a fresh key."""
    from agent_evidence_verify.adapters.proof_of_control import jcs

    private = Ed25519PrivateKey.generate()
    artifact = json.loads(POC_EXAMPLE.read_text())
    for record in artifact["records"]:
        record["iss"] = issuer
        body = {name: value for name, value in record.items() if name != "signature"}
        record["signature"] = private.sign(jcs(body)).hex()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    artifact["public_key"] = public.hex()
    return artifact, public


def test_a_did_web_authority_decides_through_proof_of_control(tmp_path: Path) -> None:
    """Before the fix the adapter never bound the DID document: every did-web policy was unknown.

    The records must also name the DID as their issuer: the example chain says
    ``https://verifier.example/poc``, and a DID's key does not vouch for another issuer.
    """
    _, carried, _ = _poc_with(tmp_path, {"kind": "pin", "keys": [
        {"public_key_sha256": key_sha256(KEY)}]}, {})
    foreign = _did(key=carried)
    elsewhere, _, _ = _poc_with(tmp_path, _did_authority(foreign), {"did.json": foreign})
    assert (elsewhere["decision"], elsewhere["reason"]) == ("contradicted", "record_subject_not_did")
    artifact, public = _resigned(DID)
    document = _did(key=public)
    agreed, _, _ = _poc_with(tmp_path, _did_authority(document), {"did.json": document},
                             artifact=artifact)
    assert (agreed["decision"], agreed["reason"]) == ("supported", "artifact_verifies")
    assert agreed["scope"]["key_authority_document"]["sha256"] == hashlib.sha256(document).hexdigest()
    hidden = _did(key=public, asserting=False)
    refused, _, _ = _poc_with(tmp_path, _did_authority(hidden), {"did.json": hidden}, artifact=artifact)
    assert (refused["decision"], refused["reason"]) == ("contradicted", "key_not_in_assertion_method")


def test_a_registry_authority_reads_each_records_issuer_and_issue_time(tmp_path: Path) -> None:
    """The example chain's records say iss https://verifier.example/poc, iat 1754400000 (5 Aug 2025)."""
    _, carried, artifact = _poc_with(tmp_path, {"kind": "pin", "keys": [
        {"public_key_sha256": key_sha256(KEY)}]}, {})
    issuer = artifact["records"][0]["iss"]

    def registry(not_before: str, **more) -> dict:
        return {"kind": "registry", "bindings": [{"subject": issuer, "public_key_sha256": key_sha256(carried),
                                                  "not_before": not_before, **more}]}

    covered, _, _ = _poc_with(tmp_path, registry("2025-01-01T00:00:00Z"), {})
    assert (covered["decision"], covered["reason"]) == ("supported", "artifact_verifies")
    early, _, _ = _poc_with(tmp_path, registry("2025-09-01T00:00:00Z"), {})
    assert (early["decision"], early["reason"]) == ("contradicted", "key_outside_validity")
    revoked, _, _ = _poc_with(tmp_path, registry("2025-01-01T00:00:00Z",
                                                 revoked_at="2025-08-01T00:00:00Z"), {})
    assert (revoked["decision"], revoked["reason"]) == ("contradicted", "key_revoked")


def test_a_kt_inclusion_authority_reads_the_proof_the_policy_names(tmp_path: Path) -> None:
    _, carried, artifact = _poc_with(tmp_path, {"kind": "pin", "keys": [
        {"public_key_sha256": key_sha256(KEY)}]}, {})
    issuer = artifact["records"][0]["iss"]
    root, paths = _log([b"x", kt_leaf(carried, issuer)])
    authority = {"kind": "kt-inclusion", "tree_size": 2, "root_sha256": root.hex(),
                 "inclusion_proof": "proof.json"}
    proof = json.dumps({"index": 1, "tree_size": 2, "path": [h.hex() for h in paths[1]]}).encode()
    agreed, _, _ = _poc_with(tmp_path, authority, {"proof.json": proof})
    assert (agreed["decision"], agreed["reason"]) == ("supported", "artifact_verifies")
    broken, _, _ = _poc_with(tmp_path, authority, {"proof.json": b'{"index":1,"index":1}'})
    assert (broken["decision"], broken["reason"]) == ("contradicted", "inclusion_proof_malformed")
    silent, _, _ = _poc_with(tmp_path, {k: v for k, v in authority.items() if k != "inclusion_proof"}, {})
    assert (silent["decision"], silent["reason"]) == ("not_established", "inclusion_proof_unavailable")
    with pytest.raises(CaseError):
        _poc_with(tmp_path, {"kind": "pin", "keys": [{"public_key_sha256": key_sha256(carried)}],
                             "document": "proof.json"}, {"proof.json": proof})


# ---- round 2 of the break-it pass: inputs the first fixes still accepted ---------------------------

def _two_materials(first: bytes, second: bytes) -> bytes:
    method = {"id": f"{DID}#k1", "type": "Multikey", "controller": DID, "publicKeyJwk": _jwk(first),
              "publicKeyMultibase": "z" + _b58(b"\xed\x01" + second)}
    return json.dumps({"id": DID, "verificationMethod": [method], "assertionMethod": ["#k1"]}).encode()


def _b58(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number, text = int.from_bytes(data, "big"), ""
    while number:
        number, rest = divmod(number, 58)
        text = alphabet[rest] + text
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + text


def test_a_method_with_two_key_materials_is_malformed() -> None:
    """Counter-example: publicKeyJwk names KEY and publicKeyMultibase names OTHER in one method.

    The JWK was read and the multibase key ignored, so KEY was authorised; a reader that prefers
    the multibase value trusts OTHER instead. DID Core 1.0 section 5.2.1 forbids the pair.
    """
    document = _two_materials(KEY, OTHER)
    for key in (KEY, OTHER):
        answer = authorize(_did_authority(document), key, did_document=document)
        assert (answer.outcome, answer.reason) == (UNAUTHORIZED, "did_document_malformed")


def test_a_did_key_does_not_speak_for_another_subject() -> None:
    """Counter-example: the DID's assertion key signs a record that names another issuer."""
    document = _did()
    other = authorize(_did_authority(document), KEY, subject="did:web:mallory.example",
                      did_document=document)
    assert (other.outcome, other.reason) == (UNAUTHORIZED, "record_subject_not_did")
    same = authorize(_did_authority(document), KEY, subject=DID, did_document=document)
    assert (same.outcome, same.reason) == (AUTHORIZED, "key_in_assertion_method")
    unnamed = authorize(_did_authority(document), KEY, did_document=document)
    assert unnamed.outcome == AUTHORIZED


@pytest.mark.parametrize(("authority", "member"), [
    ({"kind": "did-web", "did": DID, "document": "did.json", "document_sha256": "0" * 64,
      "kid": "#k9"}, "kid"),
    ({"kind": "registry", "bindings": [{"subject": "s", "public_key_sha256": "0" * 64,
                                        "not_before": "2026-01-01T00:00:00Z"}],
      "revocations": []}, "revocations"),
    ({"kind": "pin", "keys": [{"public_key_sha256": "0" * 64}], "subject": "s"}, "subject"),
    ({"kind": "kt-inclusion", "tree_size": 1, "root_sha256": "0" * 64, "index": 0}, "index"),
])
def test_a_member_no_kind_reads_is_the_consumers_case_error(authority: dict, member: str) -> None:
    """Counter-example: a restriction written under a member nobody reads widened the trust.

    ``kid`` on a did-web authority and ``revocations`` beside registry bindings were ignored, so a
    key the consumer meant to exclude was authorised.
    """
    with pytest.raises(CaseError, match=member):
        authorize(authority, KEY, subject="s", at=_t("2026-06-01T00:00:00+00:00"))


@pytest.mark.parametrize("authority", [
    {"kind": "pin", "keys": [{"public_key_sha256": "0" * 64, "kid": 1}]},
    {"kind": "registry", "bindings": [{"subject": ["s"], "public_key_sha256": "0" * 64,
                                       "not_before": "2026-01-01T00:00:00Z"}]},
])
def test_a_key_id_or_subject_that_is_not_a_string_is_the_consumers_case_error(authority: dict) -> None:
    with pytest.raises(CaseError):
        authorize(authority, KEY, subject="s", at=_t("2026-06-01T00:00:00+00:00"))


def test_a_bound_finer_than_a_microsecond_orders_exactly() -> None:
    """Counter-example: a record 0.5 microseconds before not_before was authorised.

    Truncating ``.0000005`` put the bound on the record's own microsecond; the comparison is now
    exact on both sides.
    """
    def registry(**bounds: str) -> dict:
        return {"kind": "registry", "bindings": [{"subject": "s", "public_key_sha256": key_sha256(KEY),
                                                  **bounds}]}

    start = _t("2026-01-01T00:00:00+00:00")
    early = authorize(registry(not_before="2026-01-01T00:00:00.0000005Z"), KEY, subject="s", at=start)
    assert (early.outcome, early.reason) == (UNAUTHORIZED, "key_outside_validity")
    inside = authorize(registry(not_before="2025-01-01T00:00:00Z",
                                not_after="2026-01-01T00:00:00.0000005Z"), KEY, subject="s", at=start)
    assert inside.outcome == AUTHORIZED
    revoked = authorize(registry(not_before="2025-01-01T00:00:00Z",
                                 revoked_at="2026-01-01T00:00:00.0000005Z"), KEY, subject="s", at=start)
    assert revoked.outcome == AUTHORIZED


def test_a_float_iat_is_compared_as_the_number_it_is() -> None:
    """Counter-example: an ``iat`` 0.2 microseconds before not_before was authorised.

    ``1767225600 + 3 * 2**-22`` is 0.715 microseconds past 2026-01-01T00:00:00Z. Read through
    ``datetime.fromtimestamp`` it became 0.000001 and the bound 0.0000009 rounded up to the same
    microsecond, so the key read as valid before its validity began.
    """
    def registry(**bounds: str) -> dict:
        return {"kind": "registry", "bindings": [{"subject": "s", "public_key_sha256": key_sha256(KEY),
                                                  **bounds}]}

    iat = 1767225600 + 3 * 2**-22
    early = authorize(registry(not_before="2026-01-01T00:00:00.0000009Z"), KEY, subject="s", at=iat)
    assert (early.outcome, early.reason) == (UNAUTHORIZED, "key_outside_validity")
    inside = authorize(registry(not_before="2026-01-01T00:00:00.0000007Z"), KEY, subject="s", at=iat)
    assert inside.outcome == AUTHORIZED
    ended = authorize(registry(not_before="2025-01-01T00:00:00Z",
                               not_after="2026-01-01T00:00:00.0000008Z"), KEY, subject="s", at=iat)
    assert ended.outcome == AUTHORIZED
    revoked = authorize(registry(not_before="2025-01-01T00:00:00Z",
                                 revoked_at="2026-01-01T00:00:00.0000007Z"), KEY, subject="s", at=iat)
    assert (revoked.outcome, revoked.reason) == (UNAUTHORIZED, "key_revoked")
    assert authorize(registry(not_before="2026-01-01T00:00:00Z"), KEY, subject="s",
                     at=1767225600).outcome == AUTHORIZED


def test_a_jwk_with_a_list_curve_is_a_key_that_does_not_sign_not_a_crash() -> None:
    """Counter-example: ``"crv": []`` in a DID document's JWK raised TypeError out of authorize."""
    from agent_evidence_verify.key_authority import jwk_key_bytes

    with pytest.raises(CaseError):
        jwk_key_bytes({"kty": "OKP", "crv": [], "x": "AA"})
    with pytest.raises(CaseError):
        jwk_key_bytes({"kty": ["OKP"], "crv": "Ed25519", "x": "AA"})

