"""Proof of possession: a grant is usable only by the agent that holds the key its ``cnf`` names.

The cases are the RFC 9449 and RFC 8037 examples, an accepted DPoP and mTLS presentation, and the adversarial
set: replay, wrong method or target, stale proofs, swapped keys, downgrades and bearer presentation.
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
    Presentation,
    ReplayCache,
    ReplayCacheFull,
    cnf_for_certificate,
    cnf_for_jwk,
    cnf_for_signer,
    public_jwk,
    sign_dpop,
    verify_dpop,
    verify_held_grant,
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
PINS = {ISSUER: frozenset({jwk_thumbprint(IDP_JWK)})}


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


def held(chain=CHAIN, *, tool="refund", args=ARGS, dpop=None, cert=None, token=TOKEN, agent=AGENT,
         method="POST", url=URL, content=CONTENT, replay=None, audience=GATEWAY) -> dict:
    p = Presentation(method=method, url=url, access_token=token, dpop=dpop, client_certificate=cert,
                     content=content)
    return verify_held_grant(chain, tool, args, AT, {ROOT.key_id}, presentation=p, agent=agent, jwks=JWKS,
                             pins=PINS, audience=audience, replay=replay if replay is not None else ReplayCache())


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


def test_the_rfc_9449_resource_request_example_verifies_once() -> None:
    replay = ReplayCache()
    kw = {"expected_jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
          "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU", "require_content_binding": False}
    result, reason = verify_dpop(RFC9449_FIGURE_13, "GET", "https://resource.example.org/protectedresource",
                                 _iso(1562262618), replay, **kw)
    assert reason == "ok" and result is not None and result.jti == "e1j3V_bKic8-LAEB"
    again = verify_dpop(RFC9449_FIGURE_13, "GET", "https://resource.example.org/protectedresource",
                        _iso(1562262619), replay, **kw)
    assert again == (None, "dpop_replayed")
    # Another access token: the proof's ath binds it to the RFC's token only.
    assert verify_dpop(RFC9449_FIGURE_13, "GET", "https://resource.example.org/protectedresource",
                       _iso(1562262618), ReplayCache(), **{**kw, "access_token": "other"})[1] == "dpop_ath_mismatch"


# ---------- accepted presentations ----------

def test_a_grant_held_by_the_authenticated_agent_is_allowed_with_dpop() -> None:
    verdict = held(dpop=proof())
    assert verdict["decision"] == "allow", verdict
    assert verdict["possession"] == {"method": "dpop", "jkt": DPOP_CNF["jkt"], "jti": "j-1"}


def test_an_eddsa_dpop_key_and_one_key_for_delegation_and_presentation() -> None:
    cnf = cnf_for_signer(HOLDER)
    token, agent = agent_credential(cnf)
    verdict = held(grant(cnf), dpop=proof(HOLDER.key, token=token), token=token, agent=agent)
    assert verdict["decision"] == "allow", verdict


def _certificate(key, *, days=(-1, 30)) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-refunds")])
    start = dt.datetime.fromtimestamp(NOW, dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(start + dt.timedelta(days=days[0]))
            .not_valid_after(start + dt.timedelta(days=days[1])).sign(key, hashes.SHA256()))
    return cert.public_bytes(Encoding.DER)


CERT = _certificate(DPOP_KEY)
MTLS_CNF = cnf_for_certificate(CERT)
MTLS_TOKEN, MTLS_AGENT = agent_credential(MTLS_CNF)
EXPIRED = _certificate(DPOP_KEY, days=(-9, -1))
EXPIRED_TOKEN, EXPIRED_AGENT = agent_credential(cnf_for_certificate(EXPIRED))


def test_a_grant_bound_to_a_client_certificate_is_allowed_over_mtls() -> None:
    verdict = held(grant(MTLS_CNF), cert=CERT, token=MTLS_TOKEN, agent=MTLS_AGENT)
    assert verdict["decision"] == "allow", verdict
    assert verdict["possession"] == {"method": "mtls", "x5t#S256": MTLS_CNF["x5t#S256"]}
    assert MTLS_CNF["x5t#S256"] == b64url(hashlib.sha256(CERT).digest())


def test_an_ans_profile_proof_with_its_certificate_in_x5c_verifies() -> None:
    with_x5c = _resign(proof(), {**HEAD, "x5c": [base64.b64encode(CERT).decode()]})
    assert held(dpop=with_x5c)["decision"] == "allow"


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
    "bearer presentation, no proof": (lambda: held(dpop=None), "dpop_proof_missing"),
    "wrong htm": (lambda: held(dpop=proof(method="GET")), "dpop_htm_mismatch"),
    "wrong htu host": (lambda: held(dpop=proof(url="https://evil.example.com/tools/refund")), "dpop_htu_mismatch"),
    "wrong htu path": (lambda: held(dpop=proof(url=f"{GATEWAY}/tools/delete")), "dpop_htu_mismatch"),
    "wrong htu port": (lambda: held(dpop=proof(url="https://gw.example.com:8443/tools/refund")), "dpop_htu_mismatch"),
    "stale iat": (lambda: held(dpop=proof(iat=NOW - 121)), "dpop_iat_stale"),
    "future iat": (lambda: held(dpop=proof(iat=NOW + 121)), "dpop_iat_future"),
    "proof key is not the cnf key": (lambda: held(dpop=proof(OTHER_KEY)), "dpop_key_not_confirmed"),
    "jwk swapped into a signed proof": (lambda: held(dpop=".".join(
        [b64url(json.dumps({**HEAD, "jwk": public_jwk(OTHER_KEY)}).encode())] + proof().split(".")[1:])),
        "dpop_key_not_confirmed"),
    "signature by another key under the cnf jwk": (lambda: held(dpop=_resign(proof(), key=OTHER_KEY)),
                                                   "dpop_signature_unverified"),
    "alg none": (lambda: held(dpop=_resign(proof(), {**HEAD, "alg": "none"})), "dpop_alg_not_allowed"),
    "alg HS256": (lambda: held(dpop=_resign(proof(), {**HEAD, "alg": "HS256"})), "dpop_alg_not_allowed"),
    "alg RS256": (lambda: held(dpop=_resign(proof(), {**HEAD, "alg": "RS256"})), "dpop_alg_not_allowed"),
    "alg EdDSA with an EC key": (lambda: held(dpop=_resign(proof(), {**HEAD, "alg": "EdDSA"})), "dpop_jwk_invalid"),
    "typ JWT": (lambda: held(dpop=_resign(proof(), {**HEAD, "typ": "JWT"})), "dpop_typ_invalid"),
    "private d in jwk": (lambda: held(dpop=_resign(proof(), {**HEAD, "jwk": {**HEAD["jwk"], "d": "AAAA"}})),
                         "dpop_jwk_private"),
    "unknown header member kid": (lambda: held(dpop=_resign(proof(), {**HEAD, "kid": "k"})),
                                  "dpop_header_member_unknown"),
    "duplicate alg member": (lambda: held(dpop=".".join(
        [b64url(('{"alg":"ES256","typ":"dpop+jwt","alg":"none","jwk":' + json.dumps(HEAD["jwk"]) + "}").encode())]
        + proof().split(".")[1:])), "dpop_duplicate_member"),
    "x5c with another key": (lambda: held(dpop=_resign(proof(), {**HEAD, "x5c": [base64.b64encode(
        _certificate(OTHER_KEY)).decode()]})), "dpop_x5c_key_mismatch"),
    "ath absent with a token": (lambda: held(dpop=_resign(proof(), payload={
        k: v for k, v in BODY.items() if k != "ath"})), "dpop_ath_missing"),
    "ath for another token": (lambda: held(dpop=proof(token="another.token.value")), "dpop_ath_mismatch"),
    "content rewritten after signing": (lambda: held(dpop=proof(), content=canonical({"amount_cents": 4999})),
                                        "dpop_content_mismatch"),
    "content digest absent": (lambda: held(dpop=_resign(proof(), payload={
        k: v for k, v in BODY.items() if k != "ans_content_digest"})), "dpop_content_unbound"),
    "oversized jti": (lambda: held(dpop=proof(jti="j" * 129)), "dpop_jti_invalid"),
    "not a compact JWS": (lambda: held(dpop="a.b"), "dpop_malformed"),
    "agent token for another audience": (lambda: held(dpop=proof(token=agent_credential(
        DPOP_CNF, aud="https://other.example.com")[0]), token=agent_credential(
        DPOP_CNF, aud="https://other.example.com")[0], agent=agent_credential(
        DPOP_CNF, aud="https://other.example.com")[1]), "agent_token_wrong_audience"),
    "bearer agent credential": (lambda: held(dpop=proof(token=agent_credential(None)[0]),
                                             token=agent_credential(None)[0], agent=agent_credential(None)[1]),
                                "agent_credential_is_bearer"),
    "grant holder is another key than the agent's": (lambda: held(
        dpop=proof(OTHER_KEY, token=agent_credential(cnf_for_jwk(public_jwk(OTHER_KEY)))[0]),
        token=agent_credential(cnf_for_jwk(public_jwk(OTHER_KEY)))[0],
        agent=agent_credential(cnf_for_jwk(public_jwk(OTHER_KEY)))[1]), "grant_holder_is_not_the_agent"),
    "presented token is not the principal's": (lambda: held(dpop=proof(token=agent_credential(DPOP_CNF)[0]),
                                                            token=agent_credential(DPOP_CNF)[0] + "x"),
                                               "agent_token:token_digest_mismatch"),
    "principal claims a cnf its token lacks": (lambda: held(dpop=proof(token=agent_credential(None)[0]),
                                                            token=agent_credential(None)[0],
                                                            agent={**agent_credential(None)[1], "cnf": DPOP_CNF}),
                                               "agent_token:token_claim_mismatch:cnf"),
    "dpop for a certificate-bound grant": (lambda: held(grant(MTLS_CNF), dpop=proof(token=MTLS_TOKEN),
                                                        token=MTLS_TOKEN, agent=MTLS_AGENT),
                                           "mtls_certificate_missing"),
    "certificate for a key-bound grant": (lambda: held(cert=CERT), "dpop_proof_missing"),
    "another client certificate": (lambda: held(grant(MTLS_CNF), cert=_certificate(DPOP_KEY, days=(-2, 31)),
                                                token=MTLS_TOKEN, agent=MTLS_AGENT), "mtls_certificate_not_confirmed"),
    "expired client certificate": (lambda: held(grant(cnf_for_certificate(EXPIRED)), cert=EXPIRED,
                                                token=EXPIRED_TOKEN, agent=EXPIRED_AGENT), "mtls_certificate_expired"),
    "garbage client certificate": (lambda: held(grant(MTLS_CNF), cert=b"not a certificate", token=MTLS_TOKEN,
                                                agent=MTLS_AGENT), "mtls_certificate_not_confirmed"),
}


@pytest.mark.parametrize("case", sorted(ADVERSARIAL))
def test_every_adversarial_presentation_is_refused(case: str) -> None:
    run, reason = ADVERSARIAL[case]
    verdict = run()
    assert verdict["decision"] == "deny" and verdict["reason"] == reason, verdict
    assert verdict["possession"] is None


def test_a_replayed_proof_is_refused_and_a_refused_call_spends_no_jti() -> None:
    replay = ReplayCache()
    assert held(dpop=proof(), tool="delete", replay=replay)["reason"] == "tool_not_granted"
    assert len(replay) == 0
    assert held(dpop=proof(), replay=replay)["decision"] == "allow"
    assert held(dpop=proof(), replay=replay)["reason"] == "dpop_replayed"


def test_a_delegated_grant_is_held_by_the_child_holder_not_the_parent() -> None:
    sub_key = ec.generate_private_key(ec.SECP256R1())
    sub_cnf = cnf_for_jwk(public_jwk(sub_key))
    parent = issue_grant(ROOT, grant_id="g-p", holder_key=raw_public(HOLDER), cnf=DPOP_CNF, tools=TOOLS, max_depth=1,
                         not_before="2026-11-01T00:00:00Z", expires_at="2026-12-01T00:00:00Z")
    child = issue_grant(HOLDER, grant_id="g-c", holder_key=raw_public(Signer.generate()), cnf=sub_cnf, tools=TOOLS,
                        parent=parent, not_before="2026-11-01T00:00:00Z", expires_at="2026-12-01T00:00:00Z")
    # The parent's holder presents the child grant: refused, the child names another key.
    assert held([parent, child], dpop=proof())["reason"] == "grant_holder_is_not_the_agent"
    token, agent = agent_credential(sub_cnf)
    assert held([parent, child], dpop=proof(sub_key, token=token), token=token, agent=agent)["decision"] == "allow"


def test_a_bearer_grant_cannot_be_issued_or_verified() -> None:
    with pytest.raises(TypeError):
        issue_grant(ROOT, grant_id="g", holder_key=raw_public(HOLDER), tools=TOOLS,  # type: ignore[call-arg]
                    not_before="2026-11-01T00:00:00Z", expires_at="2026-12-01T00:00:00Z")
    for bad, code in ((None, "grant_cnf_missing"), ({**DPOP_CNF, **MTLS_CNF}, "grant_cnf_invalid"),
                      ({"jwk": public_jwk(DPOP_KEY)}, "grant_cnf_invalid"), ({"jkt": "short"}, "grant_cnf_invalid")):
        body = {k: v for k, v in CHAIN[0]["body"].items() if k != "cnf"}
        if bad is not None:
            body["cnf"] = bad
        signed = {"body": body, "sig": base64.b64encode(ROOT.sign(GRANT_DOMAIN + canonical(body))).decode()}
        leaf, reason = verify_chain([signed], {ROOT.key_id}, AT)
        assert leaf is None and reason == f"grant_invalid:0:{code}", (bad, reason)


def test_a_forged_grant_with_a_swapped_cnf_fails_its_signature() -> None:
    body = {**CHAIN[0]["body"], "cnf": cnf_for_jwk(public_jwk(OTHER_KEY))}
    forged = [{"body": body, "sig": CHAIN[0]["sig"]}]
    assert held(forged, dpop=proof(OTHER_KEY))["reason"] == "grant_signature_unverified:0"


def test_the_replay_cache_fails_closed_when_full_and_forgets_expired_proofs() -> None:
    cache = ReplayCache(max_entries=2)
    assert cache.check_and_store("a", exp=NOW + 10, now=NOW) is False
    assert cache.check_and_store("b", exp=NOW + 10, now=NOW) is False
    assert cache.check_and_store("a", exp=NOW + 10, now=NOW) is True
    with pytest.raises(ReplayCacheFull):
        cache.check_and_store("c", exp=NOW + 10, now=NOW)
    assert cache.check_and_store("c", exp=NOW + 30, now=NOW + 11) is False
    full = ReplayCache(max_entries=0)
    assert held(dpop=proof(), replay=full)["reason"] == "replay_cache_full"


def test_the_principal_records_its_cnf_and_grades_possession() -> None:
    assert verify_token(AGENT, TOKEN, JWKS) is None
    assert verify_token({**AGENT, "cnf": MTLS_CNF}, TOKEN, JWKS) == "token_claim_mismatch:cnf"
    assert possession_grade({"user": AGENT, "agent": AGENT}) == "sender-constrained"
    bare = {k: v for k, v in AGENT.items() if k != "cnf"}
    assert possession_grade({"user": bare, "agent": bare}) == "bearer"
