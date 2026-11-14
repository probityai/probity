"""Approvals made by an OpenID Connect sign-in: counted under the provider key the counter pinned, only for the
exact body the sign-in's nonce commits to, only for a sign-in made after the body was issued."""

from __future__ import annotations

import base64
from typing import Any

from probity_records import Signer, build_approval_binding, embed_approval_binding, sign_approval
from probity_records.identity import jwk_thumbprint
from probity_records.identity_vectors import _jwk, _key, _principal, _token
from probity_records.oidc_approval import (
    approval_nonce,
    embed_oidc_approval,
    principal_id,
    verify_oidc_approval,
)
from probity_records.quorum import count_bindings, validate_policy

ISSUER = "https://idp.example.com/realms/acme"
CLIENT = "probity-gateway"
SUB = "4f1c2b7e-dave"
IDP = _key("oidc-approval-idp")
JWK = _jwk(IDP, "idp-1")
JWKS = {"keys": [JWK]}
PINS = {ISSUER: [jwk_thumbprint(JWK)]}
ISSUED, EXPIRES, DECIDED = "2026-11-10T09:00:00Z", "2026-11-10T09:10:00Z", "2026-11-10T09:01:30Z"
EPOCH = 1794301200  # ISSUED as seconds since the epoch
BOB = Signer.generate()
POLICY = {"policyId": "acme-wires", "threshold": 2,
          "approvers": {"dave": {"issuer": ISSUER, "subject": SUB},
                        "bob": base64.b64encode(BOB.public.public_bytes_raw()).decode()}}
USE = {"approvalId": "req-1", "event": "mcp/tools-call", "phase": "pre-execution", "principal": "agent:acme",
       "target": "https://wires.example/mcp", "tool": "wire", "usedAt": DECIDED}
PAYLOAD = b'{"usd":900}'
RELEASE = {"firstServedAt": "2000-01-01T00:00:00Z", "graceSeconds": 0, "lastServedAt": "2999-01-01T00:00:00Z",
           "lookup": "ok", "releaseId": "test"}


def body(approver: str = "dave", key: str | None = None, **over: Any) -> dict[str, Any]:
    import hashlib

    return {"approvalId": "req-1", "approver": approver, "event": "mcp/tools-call", "expiresAt": EXPIRES,
            "issuedAt": ISSUED, "keyId": key or principal_id(ISSUER, SUB), "payloadSha256":
            hashlib.sha256(PAYLOAD).hexdigest(), "phase": "pre-execution", "principal": "agent:acme",
            "target": USE["target"], "tool": "wire", **over}


def oidc(approval: dict[str, Any], *, nonce: str | None = None, auth_offset: int = 60, sub: str = SUB,
         signer: Any = IDP) -> dict[str, Any]:
    claims = {"aud": CLIENT, "auth_time": EPOCH + auth_offset, "azp": CLIENT, "exp": EPOCH + 300,
              "iat": EPOCH + 61, "iss": ISSUER, "nonce": nonce or approval_nonce(approval), "sub": sub}
    token = _token(signer, "idp-1", claims)
    principal = _principal(token, JWK, JWKS, "id-token", {**claims, "client_id": CLIENT})
    principal["authMethod"] = "client_secret_basic"
    record, payload = build_approval_binding(approval, USE, PAYLOAD, [], {approval["approver"]: approval["keyId"]},
                                             DECIDED, RELEASE)
    return embed_oidc_approval(record, payload, token, principal, JWKS)


def keyed(approval: dict[str, Any]) -> dict[str, Any]:
    signed = sign_approval(BOB, approval)
    record, payload = build_approval_binding(approval, USE, PAYLOAD, [], {"bob": BOB.key_id}, DECIDED, RELEASE)
    return embed_approval_binding(record, payload, signed["sig"])


def test_a_fresh_sign_in_for_this_body_counts_beside_a_key_approval() -> None:
    validate_policy(POLICY)
    counted, problems = count_bindings(POLICY, [oidc(body()), keyed(body("bob", BOB.key_id))], DECIDED,
                                       oidc_pins=PINS)
    assert (counted, problems) == ({"dave", "bob"}, [])


def test_an_azp_only_id_token_names_its_client() -> None:
    assert verify_oidc_approval(oidc(body()), POLICY["approvers"]["dave"], PINS) is None


def test_each_refusal_has_its_own_code() -> None:
    pinned = POLICY["approvers"]["dave"]
    good = body()
    edited = oidc(good)
    edited["record"]["approval"] = {**good, "payloadSha256": "0" * 64}  # body edited after the sign-in
    cases = {
        "approval_nonce_mismatch": edited,
        "approval_auth_not_fresh": oidc(good, auth_offset=-3600),  # a session from before the request
        "principal_key_not_pinned": oidc(good, signer=_key("another-idp")),
        "approval_principal_not_pinned": oidc(good, sub="someone-else"),
        "approval_key_id_is_not_the_principal": oidc(body(key="f" * 64)),
    }
    pins = PINS
    for code, embedded in cases.items():
        if code == "principal_key_not_pinned":
            # the forged token carries the right JWK snapshot but its signature is not that key's
            assert verify_oidc_approval(embedded, pinned, pins) == "token_signature_unverified"
            other = {"keys": [_jwk(_key("another-idp"), "idp-1")]}
            embedded = {**embedded, "approvalJwks": other,
                        "approvalPrincipal": {**embedded["approvalPrincipal"], "key": other["keys"][0],
                                              "keyThumbprint": jwk_thumbprint(other["keys"][0])}}
        assert verify_oidc_approval(embedded, pinned, pins) == code, code


def test_nothing_counts_without_pins_and_a_token_for_another_request_does_not_count() -> None:
    _, problems = count_bindings(POLICY, [oidc(body())], DECIDED)
    assert problems == ["binding_0:principal_issuer_untrusted"]
    replayed = oidc(body(approvalId="req-0"))
    replayed["record"]["approval"] = body()
    _, problems = count_bindings(POLICY, [replayed], DECIDED, oidc_pins=PINS)
    assert problems == ["binding_0:approval_nonce_mismatch"]


def test_one_principal_never_counts_twice() -> None:
    counted, problems = count_bindings(POLICY, [oidc(body()), oidc(body())], DECIDED, oidc_pins=PINS)
    assert counted == {"dave"} and problems == ["binding_1:duplicate_approver"]
