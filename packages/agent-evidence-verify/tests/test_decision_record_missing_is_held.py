"""Must-not-verify cases: a source the reader did not apply never reads as a clean result.

Each case gives the reader an input whose relying party asked for something the reader would
otherwise drop without a word: a trust-policy member the published schema does not define, a
revocation without its time or with a reason outside the schema's two, a relying-party source under
a name the reader does not know, a corpus member that names its profile under a misspelled member,
and a seal dated before stages the relying party observed. Each must refuse, never accept.
"""

from __future__ import annotations

import base64
import copy

import pytest
from agent_evidence_verify import decision_record as dr
from agent_evidence_verify import ocsf_decision
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from test_decision_record import POLICY, VECTORS, _record, _relying_party

SIGNED = dr.compact(VECTORS["attachments"]["A0"])


def _with_seal_key(**changes) -> dict:
    policy = copy.deepcopy(POLICY)
    seal = next(k for k in policy["keys"] if k["key_ref"] == "org-seal-1")
    seal.update(changes)
    return policy


def _signature(policy: dict) -> dict:
    return dr.read(SIGNED, trust_policy=policy)


def test_the_unchanged_policy_still_verifies_the_seal():
    report = _signature(POLICY)
    assert report["trust_policy"]["status"] == dr.VERIFIED
    assert report["issuer_signature"]["status"] == dr.VERIFIED


@pytest.mark.parametrize("where,member", [
    ("key", {"revoked": "2026-10-01T09:00:00Z"}),
    ("key", {"revokedAt": "2026-10-01T09:00:00Z", "revocationReason": "compromised"}),
    ("top", {"require_timestamp": True}),
])
def test_a_trust_policy_member_the_schema_does_not_define_is_refused(where, member):
    policy = _with_seal_key(**member) if where == "key" else {**copy.deepcopy(POLICY), **member}
    report = _signature(policy)
    assert report["trust_policy"]["status"] == dr.FAILED
    assert report["issuer_signature"]["status"] == dr.FAILED
    assert dr.verdict(report, "baseline") == ("reject", "issuer_signature:failed")


@pytest.mark.parametrize("changes", [
    {"revocation_reason": "compromised"},
    {"revoked_at": "2026-10-01T11:00:00Z"},
    {"revoked_at": "2026-10-01T11:00:00Z", "revocation_reason": "key_compromise"},
    {"revoked_at": "2026-10-01T11:00:00Z", "revocation_reason": "Compromised"},
])
def test_a_revocation_the_schema_does_not_allow_is_refused(changes):
    report = _signature(_with_seal_key(**changes))
    assert report["trust_policy"]["status"] == dr.FAILED
    assert report["issuer_signature"]["status"] == dr.FAILED


def test_a_relying_party_source_under_an_unknown_name_is_not_dropped():
    doc = VECTORS["attachments"]["A0"]
    party = _relying_party(doc, dr.sha256_hex(SIGNED))
    request_id = next(s["request_id"] for s in doc["stages"] if s["kind"] == "request")
    party["target_effect"] = {request_id: 2}
    report = dr.read(SIGNED, record=_record("R0"), trust_policy=POLICY, relying_party=party)
    assert dr.verdict(report, "strict")[0] == "reject"
    assert report["strict"]["single_effect_per_request"]["status"] == dr.FAILED


def _member(**members) -> dict:
    unsigned = copy.deepcopy(VECTORS["attachments"]["A0"])
    unsigned.pop("issuer_signature")
    return {"attachment": dr.compact(unsigned).decode("utf-8"), **members}


def test_the_unsigned_member_is_accepted_by_baseline_and_refused_by_strict():
    assert dr.read_member(_member())[1] == "accept"
    assert dr.read_member(_member(profile="strict"))[1] == "reject"


@pytest.mark.parametrize("misspelled", ["profle", "Profile", "trustpolicy", "relying_parties"])
def test_a_corpus_member_with_a_member_the_reader_does_not_know_is_not_read(misspelled):
    with pytest.raises(ValueError, match="does not define"):
        dr.read_member(_member(**{misspelled: "strict"}))


def test_an_ocsf_corpus_member_with_a_member_the_reader_does_not_know_is_not_read():
    with pytest.raises(ValueError, match="does not define"):
        ocsf_decision.read_member({"records": "", "profle": "strict"})


# --- a seal dated before stages the relying party observed ---------------------------------------

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEY_REF = "org-seal-test"


def _sealed(doc: dict, sealed_at: str) -> bytes:
    placeholder = "A" * 88
    doc = copy.deepcopy(doc)
    doc["issuer_signature"] = {"algorithm": "Ed25519", "key_ref": KEY_REF,
                               "signed_bytes_ref": "dps-signatures 0.2.0 organisation_seal",
                               "sealed_at": sealed_at, "value_b64": placeholder}
    text = dr.compact(doc).decode("utf-8")
    digest = dr.sha256_hex(text.encode("utf-8"))
    value = base64.b64encode(KEY.sign(dr.seal_signed_bytes(KEY_REF, doc["decision_id"], digest,
                                                          sealed_at))).decode("ascii")
    return text.replace(f'"value_b64":"{placeholder}"', f'"value_b64":"{value}"').encode("utf-8")


def _test_policy(**changes) -> dict:
    public = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    key = {"key_ref": KEY_REF, "holder": "Seal test key (test only)", "role": "organisation",
           "algorithm": "Ed25519", "public_key_hex": public,
           "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z", **changes}
    return {"profile": "dps-anchoring-trust-policy", "profile_version": "0.2.0",
            "policy_ref": "urn:example:trust-policy:seal-test", "tsas": [], "keys": [key],
            "checkpoint_sources": []}


def _strict(sealed_at: str, **key_changes) -> dict:
    doc = VECTORS["attachments"]["A0"]
    data = _sealed(doc, sealed_at)
    return dr.read(data, record=_record("R0"), trust_policy=_test_policy(**key_changes),
                   relying_party=_relying_party(doc, dr.sha256_hex(data)))


def test_a_seal_dated_after_every_observed_stage_is_accepted_by_strict():
    report = _strict("2026-10-01T10:00:00Z")
    assert report["issuer_signature"]["status"] == dr.VERIFIED
    assert dr.verdict(report, "strict") == ("accept", None)


def test_a_seal_dated_before_an_observed_stage_is_refused_by_strict():
    # The seal states 09:15, but it covers an attempt the relying party itself observed at 09:16:05:
    # the stated time cannot be when it was made. The key is not retired, so the signature verifies.
    report = _strict("2026-10-01T09:15:00Z")
    assert report["issuer_signature"]["status"] == dr.VERIFIED  # on the issuer's own stated time
    assert report["strict"]["time_independent"]["status"] == dr.FAILED
    assert dr.verdict(report, "strict") == ("reject", "time_independent:failed")
