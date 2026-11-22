"""Proof of possession: a presentation verifies only with proof of the key the grant's ``cnf`` names.

The cases are the RFC 9449 and RFC 8037 examples, an accepted DPoP and mTLS presentation, the adversarial set
(wrong method or target, stale proofs, swapped keys, algorithm and method downgrades, bearer presentation), the
possession record a tool-call record carries, and replay found offline from the records alone.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID
from probity_records import Signer, issue_grant, raw_public
from probity_records.core import canonical
from probity_records.grants import GRANT_DOMAIN, verify_chain
from probity_records.identity import (
    b64url,
    jwk_thumbprint,
    jwks_digest,
    possession_grade,
    verify_token,
)
from probity_records.possession import (
    REPLAY_GRACE,
    CertificateProof,
    DpopProof,
    check_dpop,
    check_possession,
    cnf_for_certificate,
    cnf_for_jwk,
    cnf_for_signer,
    duplicate_proofs,
    possession_record,
    possession_record_problem,
    proof_key,
    public_jwk,
    sign_dpop,
)

AT = "2026-11-21T12:00:00Z"
NOW = 1795262400  # AT as seconds since the epoch
ISSUER = "https://idp.example.com/realms/agents"
GATEWAY = "https://gw.example.com"
URL = f"{GATEWAY}/tools/refund"
TOOLS = {"refund": {"args": {"amount_cents": {"type": "range", "min": 1, "max": 5000}}}}
ARGS = {"amount_cents": 1200}
CONTENT = canonical(ARGS)

ROOT, HOLDER = Signer.generate(), Signer.generate()
DPOP_KEY = ec.generate_private_key(ec.SECP256R1())
OTHER_KEY = ec.generate_private_key(ec.SECP256R1())
IDP_KEY = Ed25519PrivateKey.generate()


def _idp_jwk() -> dict[str, str]:
    raw = IDP_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"crv": "Ed25519", "kid": "k1", "kty": "OKP", "x": b64url(raw)}


IDP_JWK = _idp_jwk()
JWKS = {"keys": [IDP_JWK]}


def _iso(seconds: int) -> str:
    return dt.datetime.fromtimestamp(seconds, dt.UTC).isoformat().replace("+00:00", "Z")


def agent_credential(cnf: dict | None, aud: str = GATEWAY) -> tuple[str, dict]:
    """A signed agent access token and the principal that names it."""
    claims = {"iss": ISSUER, "sub": "agent-refunds", "client_id": "agent-refunds", "aud": aud,
              "iat": NOW - 600, "exp": NOW + 600, "jti": "at-1"}
    if cnf is not None:
        claims["cnf"] = cnf
    head = b64url(json.dumps({"alg": "EdDSA", "kid": "k1", "typ": "at+jwt"}, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    token = f"{head}.{body}.{b64url(IDP_KEY.sign(f'{head}.{body}'.encode()))}"
    principal = {"audience": [aud], "authMethod": "private_key_jwt", "clientId": "agent-refunds",
                 "expiresAt": _iso(NOW + 600), "issuedAt": _iso(NOW - 600), "issuer": ISSUER,
                 "jwksDigest": jwks_digest(JWKS), "key": dict(IDP_JWK), "keyThumbprint": jwk_thumbprint(IDP_JWK),
                 "kid": "k1", "source": "jwt-access-token", "subject": "agent-refunds",
                 "tokenDigest": hashlib.sha256(token.encode()).hexdigest()}
    if cnf is not None:
        principal["cnf"] = cnf
    return token, principal


def grant(cnf: dict) -> list[dict]:
    return [issue_grant(ROOT, grant_id="g-1", holder_key=raw_public(HOLDER), cnf=cnf, tools=TOOLS,
                        not_before="2026-11-01T00:00:00Z", expires_at="2026-12-01T00:00:00Z")]


DPOP_CNF = cnf_for_jwk(public_jwk(DPOP_KEY))
TOKEN, AGENT = agent_credential(DPOP_CNF)
CHAIN = grant(DPOP_CNF)


def proof(key=DPOP_KEY, *, method="POST", url=URL, iat=NOW, jti="j-1", token=TOKEN, content=CONTENT, **kw) -> str:
    return sign_dpop(key, method, url, iat=iat, jti=jti, access_token=token, content=content, **kw)


def present(cnf=DPOP_CNF, *, dpop=None, cert=None, token=TOKEN, method="POST", url=URL, content=CONTENT):
    """Verify one request's proof of possession of the key ``cnf`` confirms."""
    return check_possession(cnf, method=method, url=url, at=AT, access_token=token, dpop=dpop,
                            client_certificate=cert, content=content)


# ---------- the standards' own examples ----------

def test_thumbprints_match_rfc_8037_and_rfc_9449() -> None:
    assert jwk_thumbprint({"crv": "Ed25519", "kty": "OKP",
                           "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}) == \
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    assert jwk_thumbprint({"kty": "EC", "crv": "P-256", "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
                           "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}) == \
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"


RFC9449_FIGURE_13 = (
    "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscE"
    "JoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19"
    ".eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZW"
    "RyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9"
    ".2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA")


def test_the_rfc_9449_resource_request_example_verifies() -> None:
    kw = {"expected_jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
          "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", "require_content_binding": False}
    result, reason = check_dpop(RFC9449_FIGURE_13, "GET", "https://resource.example.org/protectedresource",
                                _iso(1562262618), **kw)
    assert reason == "ok" and result is not None and result.jti == "e1j3V_bKic8-LAEB"
    assert result.replay_exp == 1562262618 + 120 + REPLAY_GRACE
    # Another access token: the proof's ath binds it to the RFC's token only.
    assert check_dpop(RFC9449_FIGURE_13, "GET", "https://resource.example.org/protectedresource",
                      _iso(1562262618), **{**kw, "access_token": "other"})[1] == "dpop_ath_mismatch"


# ---------- accepted presentations ----------

def test_a_dpop_proof_by_the_confirmed_key_verifies() -> None:
    result, reason = present(dpop=proof())
    assert reason == "ok" and isinstance(result, DpopProof), reason
    assert possession_record(result) == {"iat": NOW, "jkt": DPOP_CNF["jkt"], "jti": "j-1", "method": "dpop"}


def test_an_eddsa_dpop_key_and_one_key_for_delegation_and_presentation() -> None:
    cnf = cnf_for_signer(HOLDER)
    token, _ = agent_credential(cnf)
    assert present(cnf, dpop=proof(HOLDER.key, token=token), token=token)[1] == "ok"


def _certificate(key, *, days=(-1, 30)) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-refunds")])
    start = dt.datetime.fromtimestamp(NOW, dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(start + dt.timedelta(days=days[0]))
            .not_valid_after(start + dt.timedelta(days=days[1])).sign(key, hashes.SHA256()))
    return cert.public_bytes(Encoding.DER)


CERT = _certificate(DPOP_KEY)
MTLS_CNF = cnf_for_certificate(CERT)
MTLS_TOKEN = agent_credential(MTLS_CNF)[0]
EXPIRED = _certificate(DPOP_KEY, days=(-9, -1))


def test_a_client_certificate_with_the_confirmed_thumbprint_verifies_over_mtls() -> None:
    result, reason = present(MTLS_CNF, cert=CERT, token=MTLS_TOKEN)
    assert reason == "ok" and result == CertificateProof(MTLS_CNF["x5t#S256"])
    assert possession_record(result) == {"method": "mtls", "x5t#S256": MTLS_CNF["x5t#S256"]}
    assert MTLS_CNF["x5t#S256"] == b64url(hashlib.sha256(CERT).digest())


def test_an_ans_profile_proof_with_its_certificate_in_x5c_verifies() -> None:
    with_x5c = _resign(proof(), {**HEAD, "x5c": [base64.b64encode(CERT).decode()]})
    assert present(dpop=with_x5c)[1] == "ok"


# ---------- the adversarial set: each one is refused ----------

def _resign(token: str, header: dict | None = None, payload: dict | None = None, key=DPOP_KEY) -> str:
    """Rewrite a proof's header or payload and sign it again with ``key``."""
    h, p, _ = token.split(".")
    hb = b64url(json.dumps(header, separators=(",", ":")).encode()) if header is not None else h
    pb = b64url(json.dumps(payload, separators=(",", ":")).encode()) if payload is not None else p
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(key.sign(f"{hb}.{pb}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{hb}.{pb}.{b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _parts(token: str) -> tuple[dict, dict]:
    h, p, _ = token.split(".")
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return json.loads(pad(h)), json.loads(pad(p))


HEAD, BODY = _parts(proof())

ADVERSARIAL = {
    "bearer presentation, no proof": (lambda: present(dpop=None), "dpop_proof_missing"),
    "cnf names no method": (lambda: present({}, dpop=proof()), "cnf_invalid"),
    "cnf absent": (lambda: present(None, dpop=proof()), "cnf_missing"),
    "wrong htm": (lambda: present(dpop=proof(method="GET")), "dpop_htm_mismatch"),
    "wrong htu host": (lambda: present(dpop=proof(url="https://evil.example.com/tools/refund")), "dpop_htu_mismatch"),
    "wrong htu path": (lambda: present(dpop=proof(url=f"{GATEWAY}/tools/delete")), "dpop_htu_mismatch"),
    "wrong htu port": (lambda: present(dpop=proof(url="https://gw.example.com:8443/tools/refund")),
                       "dpop_htu_mismatch"),
    "stale iat": (lambda: present(dpop=proof(iat=NOW - 121)), "dpop_iat_stale"),
    "future iat": (lambda: present(dpop=proof(iat=NOW + 121)), "dpop_iat_future"),
    "proof key is not the cnf key": (lambda: present(dpop=proof(OTHER_KEY)), "dpop_key_not_confirmed"),
    "jwk swapped into a signed proof": (lambda: present(dpop=".".join(
        [b64url(json.dumps({**HEAD, "jwk": public_jwk(OTHER_KEY)}).encode())] + proof().split(".")[1:])),
        "dpop_key_not_confirmed"),
    "signature by another key under the cnf jwk": (lambda: present(dpop=_resign(proof(), key=OTHER_KEY)),
                                                   "dpop_signature_unverified"),
    "alg none": (lambda: present(dpop=_resign(proof(), {**HEAD, "alg": "none"})), "dpop_alg_not_allowed"),
    "alg HS256": (lambda: present(dpop=_resign(proof(), {**HEAD, "alg": "HS256"})), "dpop_alg_not_allowed"),
    "alg RS256": (lambda: present(dpop=_resign(proof(), {**HEAD, "alg": "RS256"})), "dpop_alg_not_allowed"),
    "alg EdDSA with an EC key": (lambda: present(dpop=_resign(proof(), {**HEAD, "alg": "EdDSA"})),
                                 "dpop_jwk_invalid"),
    "typ JWT": (lambda: present(dpop=_resign(proof(), {**HEAD, "typ": "JWT"})), "dpop_typ_invalid"),
    "private d in jwk": (lambda: present(dpop=_resign(proof(), {**HEAD, "jwk": {**HEAD["jwk"], "d": "AAAA"}})),
                         "dpop_jwk_private"),
    "unknown header member kid": (lambda: present(dpop=_resign(proof(), {**HEAD, "kid": "k"})),
                                  "dpop_header_member_unknown"),
    "duplicate alg member": (lambda: present(dpop=".".join(
        [b64url(('{"alg":"ES256","typ":"dpop+jwt","alg":"none","jwk":' + json.dumps(HEAD["jwk"]) + "}").encode())]
        + proof().split(".")[1:])), "dpop_duplicate_member"),
    "x5c with another key": (lambda: present(dpop=_resign(proof(), {**HEAD, "x5c": [base64.b64encode(
        _certificate(OTHER_KEY)).decode()]})), "dpop_x5c_key_mismatch"),
    "ath absent with a token": (lambda: present(dpop=_resign(proof(), payload={
        k: v for k, v in BODY.items() if k != "ath"})), "dpop_ath_missing"),
    "ath present without a token": (lambda: present(dpop=proof(), token=None), "dpop_ath_unexpected"),
    "ath for another token": (lambda: present(dpop=proof(token="another.token.value")), "dpop_ath_mismatch"),
    "content rewritten after signing": (lambda: present(dpop=proof(), content=canonical({"amount_cents": 4999})),
                                        "dpop_content_mismatch"),
    "content digest absent": (lambda: present(dpop=_resign(proof(), payload={
        k: v for k, v in BODY.items() if k != "ans_content_digest"})), "dpop_content_unbound"),
    "oversized jti": (lambda: present(dpop=proof(jti="j" * 129)), "dpop_jti_invalid"),
    "not a compact JWS": (lambda: present(dpop="a.b"), "dpop_malformed"),
    "dpop for a certificate-bound grant": (lambda: present(MTLS_CNF, dpop=proof(token=MTLS_TOKEN),
                                                           token=MTLS_TOKEN), "mtls_certificate_missing"),
    "certificate for a key-bound grant": (lambda: present(cert=CERT), "dpop_proof_missing"),
    "another client certificate": (lambda: present(MTLS_CNF, cert=_certificate(DPOP_KEY, days=(-2, 31))),
                                   "mtls_certificate_not_confirmed"),
    "expired client certificate": (lambda: present(cnf_for_certificate(EXPIRED), cert=EXPIRED),
                                   "mtls_certificate_expired"),
    "garbage client certificate": (lambda: present(MTLS_CNF, cert=b"not a certificate"),
                                   "mtls_certificate_not_confirmed"),
}


@pytest.mark.parametrize("case", sorted(ADVERSARIAL))
def test_every_adversarial_presentation_is_refused(case: str) -> None:
    run, reason = ADVERSARIAL[case]
    assert run() == (None, reason)


def test_a_bearer_grant_cannot_be_issued_or_verified() -> None:
    with pytest.raises(TypeError):
        issue_grant(ROOT, grant_id="g", holder_key=raw_public(HOLDER), tools=TOOLS,  # type: ignore[call-arg]
                    not_before="2026-11-01T00:00:00Z", expires_at="2026-12-01T00:00:00Z")
    for bad, code in ((None, "cnf_missing"), ({**DPOP_CNF, **MTLS_CNF}, "cnf_invalid"),
                      ({"jwk": public_jwk(DPOP_KEY)}, "cnf_invalid"), ({"jkt": "short"}, "cnf_invalid")):
        body = {k: v for k, v in CHAIN[0]["body"].items() if k != "cnf"}
        if bad is not None:
            body["cnf"] = bad
        signed = {"body": body, "sig": base64.b64encode(ROOT.sign(GRANT_DOMAIN + canonical(body))).decode()}
        leaf, reason = verify_chain([signed], {ROOT.key_id}, AT)
        assert leaf is None and reason == f"grant_invalid:0:{code}", (bad, reason)


def test_a_forged_grant_with_a_swapped_cnf_fails_its_signature() -> None:
    body = {**CHAIN[0]["body"], "cnf": cnf_for_jwk(public_jwk(OTHER_KEY))}
    forged = [{"body": body, "sig": CHAIN[0]["sig"]}]
    assert verify_chain(forged, {ROOT.key_id}, AT) == (None, "grant_signature_unverified:0")


def test_the_principal_records_its_cnf_and_grades_possession() -> None:
    assert verify_token(AGENT, TOKEN, JWKS) is None
    assert verify_token({**AGENT, "cnf": MTLS_CNF}, TOKEN, JWKS) == "token_claim_mismatch:cnf"
    assert possession_grade({"user": AGENT, "agent": AGENT}) == "sender-constrained"
    bare = {k: v for k, v in AGENT.items() if k != "cnf"}
    assert possession_grade({"user": bare, "agent": bare}) == "bearer"


# ---------- the possession record, checked against the grant ----------

DPOP_RECORD = {"iat": NOW, "jkt": DPOP_CNF["jkt"], "jti": "j-1", "method": "dpop"}
MTLS_RECORD = {"method": "mtls", "x5t#S256": MTLS_CNF["x5t#S256"]}

RECORD_CASES = {
    "dpop record for its grant": (DPOP_RECORD, DPOP_CNF, None),
    "mtls record for its grant": (MTLS_RECORD, MTLS_CNF, None),
    "another key's thumbprint": ({**DPOP_RECORD, "jkt": cnf_for_jwk(public_jwk(OTHER_KEY))["jkt"]}, DPOP_CNF,
                                 "possession_not_the_grant_key"),
    "mtls record for a key-bound grant": (MTLS_RECORD, DPOP_CNF, "possession_not_the_grant_key"),
    "dpop record for a certificate-bound grant": (DPOP_RECORD, MTLS_CNF, "possession_not_the_grant_key"),
    "bearer method": ({"method": "bearer"}, DPOP_CNF, "possession_record_malformed"),
    "dpop record without its jti": ({k: v for k, v in DPOP_RECORD.items() if k != "jti"}, DPOP_CNF,
                                    "possession_record_malformed"),
    "dpop record with an extra member": ({**DPOP_RECORD, "exp": NOW}, DPOP_CNF, "possession_record_malformed"),
    "iat as text": ({**DPOP_RECORD, "iat": str(NOW)}, DPOP_CNF, "possession_record_malformed"),
    "iat as a boolean": ({**DPOP_RECORD, "iat": True}, DPOP_CNF, "possession_record_malformed"),
    "oversized jti": ({**DPOP_RECORD, "jti": "j" * 129}, DPOP_CNF, "possession_record_malformed"),
    "not an object": ("dpop", DPOP_CNF, "possession_record_malformed"),
    "grant cnf not an object": (DPOP_RECORD, None, "possession_not_the_grant_key"),
}


@pytest.mark.parametrize("case", sorted(RECORD_CASES))
def test_a_possession_record_names_the_grant_key(case: str) -> None:
    record, cnf, expected = RECORD_CASES[case]
    assert possession_record_problem(record, cnf) == expected


# ---------- replay found from the records alone ----------

def allow(permit: str, at: int, record: dict | None = DPOP_RECORD) -> dict:
    """A tool-call authorize record whose grant evidence carries ``record``."""
    evidence = {"kind": "grant", "chain": CHAIN} if record is None else {"kind": "grant", "chain": CHAIN,
                                                                         "possession": record}
    return {"predicateType": "tool-call", "predicate": {"phase": "authorize", "decision": "allow",
                                                        "permitId": permit, "at": _iso(at), "authority": evidence}}


def test_one_proof_spent_on_two_permits_inside_its_lifetime_is_found() -> None:
    journal = [(1, allow("p1", NOW)), (2, allow("p2", NOW + 30))]
    assert duplicate_proofs(journal) == [(2, "dpop_proof_replayed:1")]


def test_the_last_second_of_the_lifetime_still_counts_and_the_next_does_not() -> None:
    edge = NOW + 120 + REPLAY_GRACE
    assert duplicate_proofs([(1, allow("p1", NOW)), (2, allow("p2", edge))]) == [(2, "dpop_proof_replayed:1")]
    assert duplicate_proofs([(1, allow("p1", NOW)), (2, allow("p2", edge + 1))]) == []
    assert duplicate_proofs([(1, allow("p1", NOW)), (2, allow("p2", NOW + 40))], skew=30) == []


def test_one_permit_recorded_again_on_a_retry_spends_its_proof_once() -> None:
    assert duplicate_proofs([(1, allow("p1", NOW)), (2, allow("p1", NOW + 5))]) == []


def test_distinct_proofs_and_records_without_a_dpop_use_are_not_replays() -> None:
    other_jti = {**DPOP_RECORD, "jti": "j-2"}
    other_key = {**DPOP_RECORD, "jkt": cnf_for_jwk(public_jwk(OTHER_KEY))["jkt"]}
    journal = [(1, allow("p1", NOW)), (2, allow("p2", NOW, other_jti)), (3, allow("p3", NOW, other_key)),
               (4, allow("p4", NOW, MTLS_RECORD)), (5, allow("p5", NOW, MTLS_RECORD)), (6, allow("p6", NOW, None)),
               (7, {"predicateType": "tool-call", "predicate": {"phase": "intent", "permitId": "p1"}})]
    assert duplicate_proofs(journal) == []


def test_every_later_spend_names_the_first_and_an_unreadable_time_is_reported() -> None:
    journal = [(3, allow("p1", NOW)), (5, allow("p2", NOW + 1)), (8, allow("p3", NOW + 2))]
    assert duplicate_proofs(journal) == [(5, "dpop_proof_replayed:3"), (8, "dpop_proof_replayed:3")]
    broken = allow("p2", NOW)
    broken["predicate"]["at"] = "yesterday"
    assert duplicate_proofs([(1, allow("p1", NOW)), (2, broken)]) == [(2, "dpop_proof_use_time_invalid")]


def test_a_proof_spent_again_after_its_lifetime_opens_a_new_window() -> None:
    later = NOW + 1000
    journal = [(1, allow("p1", NOW)), (2, allow("p2", later, {**DPOP_RECORD, "iat": later})),
               (3, allow("p3", later + 10, {**DPOP_RECORD, "iat": later}))]
    assert duplicate_proofs(journal) == [(3, "dpop_proof_replayed:2")]


def test_the_single_use_key_binds_the_confirmed_key_and_the_jti() -> None:
    other = cnf_for_jwk(public_jwk(OTHER_KEY))["jkt"]
    assert proof_key(DPOP_CNF["jkt"], "j-1") != proof_key(other, "j-1")
    assert proof_key(DPOP_CNF["jkt"], "j-1") != proof_key(DPOP_CNF["jkt"], "j-2")
    assert len(proof_key(DPOP_CNF["jkt"], "j" * 128)) == 43
