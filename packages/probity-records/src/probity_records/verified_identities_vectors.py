"""Conformance vectors for ``verified_identities`` and the agent stamp verifier (``stamp``).

Each vector is ``{"id", "description", "tokens", "bundle", "at", "transport", "request", "expected"}``. ``tokens`` maps a
role or ``stamp`` to a compact JWS; ``transport`` is a canonical identity string or null; ``request`` is null or
``{"method", "url", "contentB64", "dpop", "clientCertificateB64"}`` (absent values null). ``expected`` is
``{"refused": code}`` or ``{"identities": [documents], "proof": "dpop" | "mtls" | null, "stampJti": jti | null}``.
A conforming verifier reports exactly these.

Every key here is derived from a fixed seed and every signature is deterministic (Ed25519, RFC 6979 ECDSA, RSA PKCS #1
v1.5), so the file regenerates byte for byte.
"""

from __future__ import annotations

import base64
import copy
import json
import random
from datetime import UTC, datetime, timedelta
from functools import cache
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from .canonical_identity import CanonicalIdentity, Ref
from .core import sha256_hex
from .digests import act_chain_digest
from .identity import b64url, jwk_thumbprint
from .possession import (
    CertificateProof,
    DpopProof,
    cnf_for_certificate,
    cnf_for_jwk,
    public_jwk,
    sign_dpop,
)
from .stamp import STAMP_TYP, stamp_key_id
from .verified_identities import RequestFacts, VerifiedIdentitiesRefused, verify_request

AT = "2026-11-23T12:00:00+00:00"
NOW = int(datetime.fromisoformat(AT).timestamp())
ENV = "prod"
TENANT = "acme"
AUDIENCE = "https://billing.example.com/mcp"
IDP = "https://idp.example.com/realms/agents"
IDP_EC = "https://login.example.org/tenant-b"
IDP_RSA = "https://sso.example.net"
GATEWAY = "gateway.example.com/t/acme"
URL = "https://billing.example.com/mcp/refund"
PAYOUT = "https://billing.example.com/mcp/payout"
BODY = b'{"jsonrpc":"2.0","method":"tools/call","id":1}'


def _ed(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _probable_prime(rng: random.Random, bits: int) -> int:
    while True:
        n = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if all(n % p for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)) and _miller_rabin(n, rng):
            return n


def _miller_rabin(n: int, rng: random.Random) -> bool:
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(40):
        x = pow(rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


@cache
def _rsa() -> rsa.RSAPrivateKey:
    """A 2048-bit RSA key from a fixed seed, so the vectors regenerate byte for byte."""
    rng, e = random.Random(20261123), 65537
    while True:
        p, q = _probable_prime(rng, 1024), _probable_prime(rng, 1024)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            break
    d = pow(e, -1, phi)
    numbers = rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p),
                                    rsa.RSAPublicNumbers(e, p * q))  # fmt: skip
    return numbers.private_key()


@cache
def _ec() -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(0x5EED_0F_EC_2026, ec.SECP256R1())


def _jwk(key: Any, kid: str | None) -> dict[str, Any]:
    if isinstance(key, rsa.RSAPrivateKey):
        n = key.public_key().public_numbers()
        jwk: dict[str, Any] = {"kty": "RSA", "n": b64url(n.n.to_bytes(256, "big")), "e": b64url(n.e.to_bytes(3, "big"))}
    else:
        jwk = public_jwk(key)
    return jwk if kid is None else {**jwk, "kid": kid}


USER_KEY, ROGUE_KEY, STAMP_KEY, HOLDER_KEY, OTHER_HOLDER = _ed(1), _ed(2), _ed(3), _ed(4), _ed(5)
OTHER_STAMP_KEY = _ed(6)


def _sign(key: Any, header: dict[str, Any], claims: dict[str, Any]) -> str:
    head = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    body = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    data = f"{head}.{body}".encode("ascii")
    if isinstance(key, Ed25519PrivateKey):
        sig = key.sign(data)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64url(sig)}"


def _alg(key: Any) -> str:
    return "EdDSA" if isinstance(key, Ed25519PrivateKey) else "ES256" if isinstance(key, ec.EllipticCurvePrivateKey) \
        else "RS256"


def token(role: str, *, key: Any = None, kid: str = "idp-1", iss: str = IDP, header: dict[str, Any] | None = None,
          **claims: Any) -> str:
    """One identity-provider credential for ``role``; keyword claims override the defaults (None drops one)."""
    key = USER_KEY if key is None else key
    typ = {"user": "at+jwt", "agent": "at+jwt", "sponsor": "JWT"}[role]
    head = {"alg": _alg(key), "typ": typ, "kid": kid, **(header or {})}
    body = {"user": {"sub": "alice@example.com", "client_id": "agent-refunds", "act": {"sub": "agent-refunds"}},
            "agent": {"sub": "agent-refunds", "client_id": "agent-refunds"},
            "sponsor": {"sub": "owner@example.com", "azp": "console"}}[role]
    full = {"iss": iss, "aud": AUDIENCE, "iat": NOW - 60, "exp": NOW + 300, **copy.deepcopy(body), **claims}
    return _sign(key, {k: v for k, v in head.items() if v is not None}, {k: v for k, v in full.items() if v is not None})


def pin(key: Any, roles: list[str], tenants: list[str] | None = None, kid: str | None = "idp-1") -> tuple[dict, dict]:
    jwk = _jwk(key, kid)
    return jwk, {"thumbprint": jwk_thumbprint(jwk), "roles": roles, "tenants": tenants or [TENANT]}


def bundle(profile: str = "basic", **issuers: Any) -> dict[str, Any]:
    user_jwk, user_pin = pin(USER_KEY, ["user", "agent", "sponsor"])
    stamp_jwk, stamp_pin = pin(STAMP_KEY, ["stamp"], kid=None)
    base = {IDP: {"keys": [user_jwk], "pins": [user_pin]}, GATEWAY: {"keys": [stamp_jwk], "pins": [stamp_pin]}}
    return {"version": 1, "environment": ENV, "tenant": TENANT, "audience": AUDIENCE, "profile": profile,
            "issuers": {**base, **issuers}}  # fmt: skip


def stamp(*, key: Ed25519PrivateKey = STAMP_KEY, aud: str = AUDIENCE, iat: int = NOW - 10, exp: int = NOW + 50,
          request_sha256: str | None = sha256_hex(BODY), identity: str | None = None, extra: dict | None = None,
          claim: dict | None = None, kid: str | None = None, iss: str = GATEWAY) -> str:  # fmt: skip
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    act = act_chain_digest({"sub": "agent-refunds"})
    ident = CanonicalIdentity(kind="agent", user=Ref("user", ENV, IDP, "alice@example.com"),
                              chain=(Ref("agent", ENV, IDP, "agent-refunds"),), act=act)  # fmt: skip
    body = {"user": {"iss": IDP, "sub": "alice@example.com"},
            "agent": {"iss": IDP, "sub": "agent-refunds", "client_id": "agent-refunds"},
            "principals": "sha256:" + "e5" * 32, "act": act, "grants": None,
            "identity": identity or ident.render(), **(claim or {})}  # fmt: skip
    claims = {"iss": iss, "aud": aud, "iat": iat, "exp": exp, "jti": "stamp-0001",
              "request_sha256": request_sha256, "stamp": body, **(extra or {})}  # fmt: skip
    return _sign(key, {"alg": "EdDSA", "typ": STAMP_TYP, "kid": kid or stamp_key_id(raw)}, claims)


@cache
def certificate() -> bytes:
    key = _ed(7)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-refunds")])
    start = datetime(2026, 11, 1, tzinfo=UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(20261123).not_valid_before(start).not_valid_after(start + timedelta(days=60))
            .sign(key, None))  # fmt: skip
    return cert.public_bytes(serialization.Encoding.DER)


def request(*, dpop: str | None = None, cert: bytes | None = None, content: bytes | None = BODY,
            method: str = "POST", url: str = URL) -> dict[str, Any]:
    return {"method": method, "url": url, "contentB64": None if content is None else base64.b64encode(content).decode(),
            "dpop": dpop, "clientCertificateB64": None if cert is None else base64.b64encode(cert).decode()}


def _proof(access: str, *, key: Ed25519PrivateKey = HOLDER_KEY, url: str = URL, jti: str = "dpop-0001") -> str:
    return sign_dpop(key, "POST", url, iat=NOW, jti=jti, access_token=access, content=BODY)


TRANSPORT = CanonicalIdentity(kind="transport", service=Ref("service", ENV, "spiffe://mesh.example.org", "billing-gw"))
HOLDER_CNF = cnf_for_jwk(public_jwk(HOLDER_KEY))


def _cases() -> list[tuple[str, str, dict[str, Any]]]:
    user, agent, sponsor = token("user"), token("agent"), token("sponsor")
    bound = token("agent", cnf=HOLDER_CNF)
    cert_bound = token("agent", cnf=cnf_for_certificate(certificate()))
    ec_jwk, ec_pin = pin(_ec(), ["user", "agent"], kid="ec-1")
    rsa_jwk, rsa_pin = pin(_rsa(), ["user", "agent"], kid="rsa-1")
    rogue_jwk, _ = pin(ROGUE_KEY, ["user"])
    user_only_jwk, user_only_pin = pin(ROGUE_KEY, ["user"], kid="idp-2")
    other_tenant_jwk, other_tenant_pin = pin(ROGUE_KEY, ["user", "agent"], tenants=["globex"], kid="idp-3")
    sub_act = {"sub": "agent-refunds", "act": {"sub": "orchestrator"}}

    def c(tokens: dict, **kw: Any) -> dict[str, Any]:
        return {"tokens": tokens, "bundle": kw.get("bundle", bundle(kw.get("profile", "basic"))), "at": kw.get("at", AT),
                "transport": kw.get("transport"), "request": kw.get("request")}  # fmt: skip

    return [
        ("VI1", "an agent acts for a user: kind agent, the act claim's digest", c({"user": user, "agent": agent})),
        ("VI2", "a sub-agent acts: the chain shows its parent, root first",
         c({"user": token("user", act=sub_act), "agent": agent})),
        ("VI3", "an agent acting for no user names its sponsor", c({"agent": agent, "sponsor": sponsor})),
        ("VI4", "a user's credential with no agent credential: kind unknown, never a human acting",
         c({"user": token("user", act=None)})),
        ("VI5", "the same under the strict profile is refused", c({"user": token("user", act=None)}, profile="strict")),
        ("VI6", "the transport identity is returned beside the request identity",
         c({"user": user, "agent": agent}, transport=TRANSPORT.render())),
        ("VI7", "an ES256 identity provider", c({"user": token("user", key=_ec(), kid="ec-1", iss=IDP_EC),
                                                 "agent": token("agent", key=_ec(), kid="ec-1", iss=IDP_EC)},
                                                bundle=bundle(**{IDP_EC: {"keys": [ec_jwk], "pins": [ec_pin]}}))),
        ("VI8", "an RS256 identity provider", c({"user": token("user", key=_rsa(), kid="rsa-1", iss=IDP_RSA),
                                                 "agent": token("agent", key=_rsa(), kid="rsa-1", iss=IDP_RSA)},
                                                bundle=bundle(**{IDP_RSA: {"keys": [rsa_jwk], "pins": [rsa_pin]}}))),
        ("VI9", "a stamp from the pinned gateway names the identity the gateway verified",
         c({"stamp": stamp()}, request=request())),
        ("VI10", "a key-bound agent token with a DPoP proof for this request",
         c({"user": user, "agent": bound}, request=request(dpop=_proof(bound)))),
        ("VI11", "a certificate-bound agent token with the confirmed client certificate",
         c({"user": user, "agent": cert_bound}, request=request(cert=certificate()))),
        ("VI12", "an identity assertion grant as the user's credential",
         c({"user": token("user", header={"typ": "oauth-id-jag+jwt"}), "agent": agent})),
        # --- refused: the credential ---
        ("VR1", "a forged token: the claims changed after signing",
         c({"user": user, "agent": _swap_claims(agent, sub="agent-payouts")})),
        ("VR2", "a rogue key signs under the pinned kid", c({"user": user, "agent": token("agent", key=ROGUE_KEY)})),
        ("VR3", "the token names its own key in jwk", c({"user": user, "agent": token("agent", key=ROGUE_KEY,
                                                                                     header={"jwk": rogue_jwk})})),
        ("VR4", "the token names a key URL in jku",
         c({"user": user, "agent": token("agent", header={"jku": "https://evil.example/jwks"})})),
        ("VR5", "an unknown critical extension", c({"user": user, "agent": token("agent", header={"crit": ["exp2"],
                                                                                                  "exp2": 1})})),
        ("VR6", "a token for another audience", c({"user": user, "agent": token("agent", aud="https://other.example")})),
        ("VR7", "an expired token", c({"user": user, "agent": token("agent", iat=NOW - 600, exp=NOW - 1)})),
        ("VR8", "a token not yet valid by nbf", c({"user": user, "agent": token("agent", nbf=NOW + 60)})),
        ("VR9", "an issuer the bundle does not pin", c({"user": user, "agent": token("agent", iss="https://x.example")})),
        ("VR10", "a kid that selects no pinned key", c({"user": user, "agent": token("agent", kid="idp-9")})),
        ("VR11", "a key pinned for users only signs an agent token",
         c({"user": user, "agent": token("agent", key=ROGUE_KEY, kid="idp-2")},
           bundle=bundle(**{IDP: {"keys": [_jwk(USER_KEY, "idp-1"), user_only_jwk],
                                  "pins": [pin(USER_KEY, ["user", "agent", "sponsor"])[1], user_only_pin]}}))),
        ("VR12", "a key pinned for another tenant",
         c({"user": user, "agent": token("agent", key=ROGUE_KEY, kid="idp-3")},
           bundle=bundle(**{IDP: {"keys": [_jwk(USER_KEY, "idp-1"), other_tenant_jwk],
                                  "pins": [pin(USER_KEY, ["user", "agent", "sponsor"])[1], other_tenant_pin]}}))),
        ("VR13", "alg none", c({"user": user, "agent": _alg_none(agent)})),
        ("VR14", "an ID token presented as the agent's access token",
         c({"user": user, "agent": token("agent", header={"typ": "JWT"})})),
        ("VR15", "the user's act claim names another agent",
         c({"user": token("user", act={"sub": "agent-payouts"}), "agent": agent})),
        ("VR16", "the user's credential was issued to another client",
         c({"user": token("user", client_id="other-app"), "agent": agent})),
        ("VR17", "an agent marker only in a header: the agent value is not a credential",
         c({"user": user, "agent": "aid1!agent;chain=agent:prod/x/agent-refunds"})),
        ("VR18", "the user's credential names an agent that presented no credential", c({"user": user})),
        ("VR19", "no credential at all", c({})),
        ("VR20", "a role this verifier does not take", c({"user": user, "approver": sponsor})),
        ("VR21", "a sponsor with no agent", c({"user": token("user", act=None), "sponsor": sponsor})),
        # --- refused: possession ---
        ("VR22", "a key-bound agent token with no proof", c({"user": user, "agent": bound}, request=request())),
        ("VR23", "a key-bound agent token and its proof for one route, replayed on another route",
         c({"user": user, "agent": bound}, request=request(dpop=_proof(bound), url=PAYOUT))),
        ("VR24", "a proof by another key", c({"user": user, "agent": bound},
                                             request=request(dpop=_proof(bound, key=OTHER_HOLDER)))),
        ("VR25", "a certificate-bound agent token with no certificate",
         c({"user": user, "agent": cert_bound}, request=request())),
        # --- refused: the stamp ---
        ("VS1", "a stamp beside the tokens it replaces", c({"stamp": stamp(), "agent": agent}, request=request())),
        ("VS2", "a forged stamp", c({"stamp": _swap_claims(stamp(), aud="https://other.example")}, request=request())),
        ("VS3", "a stamp signed by an unpinned key", c({"stamp": stamp(key=OTHER_STAMP_KEY)}, request=request())),
        ("VS4", "a stamp for another audience", c({"stamp": stamp(aud="https://other.example")}, request=request())),
        ("VS5", "an expired stamp", c({"stamp": stamp(iat=NOW - 100, exp=NOW - 1)}, request=request())),
        ("VS6", "a stamp bound to other request bytes", c({"stamp": stamp()}, request=request(content=b"{}"))),
        ("VS7", "a stamp with an unknown claim", c({"stamp": stamp(extra={"scope": "admin"})}, request=request())),
        ("VS8", "a stamp whose identity names another agent",
         c({"stamp": stamp(identity=CanonicalIdentity(kind="agent", user=Ref("user", ENV, IDP, "alice@example.com"),
                                                      chain=(Ref("agent", ENV, IDP, "agent-payouts"),),
                                                      act=act_chain_digest({"sub": "agent-refunds"})).render())},
           request=request())),
        ("VS9", "a stamp from staging read in prod",
         c({"stamp": stamp(identity=CanonicalIdentity(kind="agent", user=Ref("user", "staging", IDP, "alice@example.com"),
                                                      chain=(Ref("agent", "staging", IDP, "agent-refunds"),),
                                                      act=act_chain_digest({"sub": "agent-refunds"})).render())},
           request=request())),
        ("VS10", "a stamp living longer than five minutes", c({"stamp": stamp(exp=NOW + 600)}, request=request())),
        ("VS11", "a stamp naming the user acting alone",
         c({"stamp": stamp(claim={"agent": {"iss": IDP, "sub": "alice@example.com", "client_id": "agent-refunds"}})},
           request=request())),
        ("VS12", "an identity provider's key signs a stamp under the provider's name",
         c({"stamp": stamp(key=USER_KEY, iss=IDP)}, request=request())),
        # --- refused: the bundle ---
        ("VB1", "a bundle pin naming no listed key",
         c({"user": user, "agent": agent}, bundle=bundle(**{IDP: {"keys": [_jwk(USER_KEY, "idp-1")],
                                                                  "pins": [user_only_pin]}}))),
        ("VB2", "a bundle carrying a private key",
         c({"user": user, "agent": agent}, bundle=bundle(**{IDP: {"keys": [{**_jwk(USER_KEY, "idp-1"), "d": "AA"}],
                                                                  "pins": [pin(USER_KEY, ["user"])[1]]}}))),
    ]


def _swap_claims(jws: str, **claims: Any) -> str:
    head, body, sig = jws.split(".")
    doc = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    doc.update(claims)
    return f"{head}.{b64url(json.dumps(doc, separators=(',', ':'), sort_keys=True).encode())}.{sig}"


def _alg_none(jws: str) -> str:
    head, body, _ = jws.split(".")
    doc = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    return f"{b64url(json.dumps({**doc, 'alg': 'none'}, separators=(',', ':')).encode())}.{body}.AA"


def judge(case: dict[str, Any]) -> dict[str, Any]:
    """What this package reports for one vector input."""
    raw = case["request"]
    facts = None if raw is None else RequestFacts(
        method=raw["method"], url=raw["url"],
        content=None if raw["contentB64"] is None else base64.b64decode(raw["contentB64"]), dpop=raw["dpop"],
        client_certificate=None if raw["clientCertificateB64"] is None else base64.b64decode(raw["clientCertificateB64"]))
    transport = None if case["transport"] is None else CanonicalIdentity.parse(case["transport"])
    try:
        found = verify_request(case["tokens"], case["bundle"], case["at"], transport, request=facts)
    except VerifiedIdentitiesRefused as exc:
        return {"refused": exc.code}
    proof = "dpop" if isinstance(found.proof, DpopProof) else "mtls" if isinstance(found.proof, CertificateProof) \
        else None
    return {"identities": [i.document() for i in found.identities], "proof": proof,
            "stampJti": None if found.stamp is None else found.stamp.jti}


def vectors() -> list[dict[str, Any]]:
    return [{"id": vid, "description": description, **case, "expected": judge(case)}
            for vid, description, case in _cases()]


EXPECTED_REFUSALS = {
    "VI5": "identity_actor_unknown", "VR1": "token_signature_unverified", "VR2": "token_signature_unverified",
    "VR3": "token_header_names_a_key", "VR4": "token_header_names_a_key", "VR5": "token_critical_unsupported",
    "VR6": "token_wrong_audience", "VR7": "principal_expired", "VR8": "token_not_yet_valid",
    "VR9": "principal_issuer_untrusted", "VR10": "token_kid_unknown", "VR11": "principal_key_not_pinned",
    "VR12": "principal_key_not_pinned", "VR13": "token_signature_unverified", "VR14": "token_type_mismatch",
    "VR15": "principal_act_names_another_agent", "VR16": "principal_user_token_not_issued_to_agent",
    "VR17": "token_malformed", "VR18": "principal_credential_missing", "VR19": "principal_credential_missing",
    "VR20": "principal_role_not_configured", "VR21": "principals_need_agent", "VR22": "dpop_proof_missing",
    "VR23": "dpop_htu_mismatch", "VR24": "dpop_key_not_confirmed", "VR25": "mtls_certificate_missing",
    "VS1": "identity_sources_mixed", "VS2": "stamp_forged", "VS3": "stamp_key_mismatch", "VS4": "stamp_wrong_audience",
    "VS5": "stamp_expired", "VS6": "stamp_request_mismatch", "VS7": "stamp_malformed",
    "VS8": "stamp_identity_mismatch", "VS9": "identity_environment_mismatch", "VS10": "stamp_lifetime_too_long",
    "VS11": "stamp_downgraded", "VS12": "principal_key_not_pinned", "VB1": "trust_bundle_malformed",
    "VB2": "trust_bundle_malformed",
}


def check(rows: list[dict[str, Any]]) -> list[str]:
    """The ids of vectors whose input this package judges differently from their expected outcome."""
    return [row["id"] for row in rows if judge(row) != row["expected"]]

