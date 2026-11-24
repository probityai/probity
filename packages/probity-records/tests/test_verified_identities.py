"""The verified identities of a request: a pure function from credentials and a pinned bundle to canonical identities,
refused for every forged, swapped-key, replayed, expired, wrong-audience and downgraded credential."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from probity_records.canonical_identity import CanonicalIdentity
from probity_records.identity import b64url
from probity_records.possession import (
    DEFAULT_SKEW,
    REPLAY_GRACE,
    cnf_for_certificate,
    cnf_for_jwk,
    proof_key,
    public_jwk,
)
from probity_records.verified_identities import (
    RequestFacts,
    TrustBundle,
    VerifiedIdentitiesRefused,
    verified_identities,
    verify_request,
)
from probity_records.verified_identities_vectors import (
    AT,
    EXPECTED_REFUSALS,
    HOLDER_KEY,
    NOW,
    bundle,
    certificate,
    check,
    judge,
    request,
    stamp,
    token,
    vectors,
)

SHARED = Path(__file__).resolve().parents[1] / "vectors" / "shared" / "verified_identities.json"
ROWS = vectors()


def test_the_shared_file_is_the_generated_vectors_and_this_package_reports_them() -> None:
    assert ROWS == vectors()
    assert json.loads(SHARED.read_text()) == json.loads(json.dumps(ROWS))
    assert check(json.loads(SHARED.read_text())) == []


@pytest.mark.parametrize("row", ROWS, ids=[r["id"] for r in ROWS])
def test_each_vector_is_refused_exactly_when_and_why_it_should_be(row: dict) -> None:
    want = EXPECTED_REFUSALS.get(row["id"])
    assert row["expected"] == ({"refused": want} if want else row["expected"])
    if want is None:
        assert "identities" in row["expected"]


def test_every_refusal_id_is_a_vector() -> None:
    assert set(EXPECTED_REFUSALS) <= {r["id"] for r in ROWS}


def _identity(vid: str) -> dict:
    return next(r for r in ROWS if r["id"] == vid)["expected"]["identities"][0]


def test_the_stamp_names_the_same_identity_as_the_tokens_it_replaces() -> None:
    assert _identity("VI9") == _identity("VI1")


def test_a_user_alone_is_unknown_never_a_human_acting() -> None:
    found = _identity("VI4")
    assert found["kind"] == "unknown"
    assert CanonicalIdentity.from_document(found).acl_key() != found["user"]["id"]


def test_a_sub_agent_shows_its_parent_root_first() -> None:
    chain = [ref["subject"] for ref in _identity("VI2")["chain"]]
    assert chain == ["orchestrator", "agent-refunds"]


def test_the_transport_identity_is_returned_beside_the_request_identity() -> None:
    row = next(r for r in ROWS if r["id"] == "VI6")
    assert [i["kind"] for i in row["expected"]["identities"]] == ["agent", "transport"]


def test_the_result_is_identities_only_never_a_decision() -> None:
    found = verified_identities({"user": token("user"), "agent": token("agent")}, bundle(), AT)
    assert isinstance(found, list) and all(isinstance(i, CanonicalIdentity) for i in found)


def test_a_key_the_token_names_is_never_used_even_when_it_is_the_pinned_key() -> None:
    from probity_records.verified_identities_vectors import USER_KEY, _jwk

    forged = token("agent", header={"jwk": _jwk(USER_KEY, "idp-1")})
    with pytest.raises(VerifiedIdentitiesRefused) as err:
        verified_identities({"user": token("user"), "agent": forged}, bundle(), AT)
    assert err.value.code == "token_header_names_a_key"


def _proof_of(vid: str) -> dict:
    return next(r for r in ROWS if r["id"] == vid)["expected"]["proof"]


def test_the_proof_and_the_stamp_nonce_are_returned_for_a_store_to_spend() -> None:
    holder = cnf_for_jwk(public_jwk(HOLDER_KEY))["jkt"]
    assert _proof_of("VI10") == {"method": "dpop", "iat": NOW, "jkt": holder, "jti": "dpop-0001",
                                 "key": proof_key(holder, "dpop-0001"), "expires": NOW + DEFAULT_SKEW + REPLAY_GRACE}
    assert next(r for r in ROWS if r["id"] == "VI9")["expected"]["stamp"] == {"nonce": "stamp-0001",
                                                                               "expires": NOW + 50}


def test_the_spend_window_covers_every_second_the_freshness_check_still_accepts_the_proof() -> None:
    oldest = _proof_of("VI16")
    assert oldest["iat"] == NOW - DEFAULT_SKEW
    assert oldest["expires"] == NOW + REPLAY_GRACE
    assert oldest["key"] != _proof_of("VI10")["key"]


def test_the_single_use_key_hashes_the_jti_as_utf8() -> None:
    proof = _proof_of("VI17")
    assert proof["jti"] == "dpop-\u00e9-0002"
    assert proof["key"] == b64url(hashlib.sha256(f"{proof['jkt']}.{proof['jti']}".encode("utf-8")).digest())


def test_a_certificate_proof_names_the_confirmed_thumbprint_and_has_nothing_to_spend() -> None:
    assert _proof_of("VI11") == {"method": "mtls", "x5t#S256": cnf_for_certificate(certificate())["x5t#S256"]}


def test_a_stamped_request_is_verified_from_its_header_lines_and_never_from_tokens() -> None:
    stamped = judge({"tokens": {}, "bundle": bundle(), "at": AT, "transport": None, "request": request(headers=stamp())})
    assert stamped == next(r for r in ROWS if r["id"] == "VI9")["expected"]
    as_token = judge({"tokens": {"stamp": "x"}, "bundle": bundle(), "at": AT, "transport": None, "request": request()})
    assert as_token == {"refused": "principal_role_not_configured"}


def test_a_short_rsa_key_is_refused_in_the_bundle() -> None:
    doc = bundle()
    doc["issuers"]["https://rsa.example"] = {"keys": [{"kty": "RSA", "kid": "r", "e": "AQAB", "n": "AQAB" * 10}],
                                             "pins": [{"thumbprint": "x", "roles": ["user"], "tenants": ["acme"]}]}
    with pytest.raises(VerifiedIdentitiesRefused) as err:
        TrustBundle.parse(doc)
    assert err.value.code == "trust_bundle_malformed"


def test_a_transport_identity_of_another_kind_is_a_programming_error() -> None:
    with pytest.raises(TypeError):
        verify_request({"user": token("user"), "agent": token("agent")}, bundle(), AT,
                       CanonicalIdentity.parse(_identity("VI1")["id"]))


def test_a_request_without_facts_cannot_prove_a_key_bound_token() -> None:
    from probity_records.verified_identities_vectors import HOLDER_CNF

    with pytest.raises(VerifiedIdentitiesRefused) as err:
        verify_request({"user": token("user"), "agent": token("agent", cnf=HOLDER_CNF)}, bundle(), AT)
    assert err.value.code == "dpop_proof_missing"
    assert RequestFacts(method="GET", url="https://x.example/").content is None
    assert judge(next(r for r in ROWS if r["id"] == "VR22")) == {"refused": "dpop_proof_missing"}
