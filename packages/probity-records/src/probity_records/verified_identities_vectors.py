"""Conformance vectors for ``verified_identities`` and the agent stamp verifier (``stamp``).

Each vector is ``{"id", "description", "tokens", "bundle", "at", "transport", "request", "expected"}``. ``tokens`` maps a
role to a compact JWS; ``transport`` is a canonical identity string or null; ``request`` is null or
``{"method", "url", "contentB64", "dpop", "clientCertificateB64", "headers"}`` (absent values null; ``headers`` is the
list of ``[name, value]`` header lines, where an agent stamp travels). ``expected`` is ``{"refused": code}`` or
``{"identities": [documents], "proof": proof | null, "stamp": {"nonce", "expires"} | null}``, where ``proof`` is
``possession_record`` of the proof and, for a DPoP proof, its single-use ``key`` (``proof_key(jkt, jti)``) and the
last second ``expires`` (the proof's ``replay_exp``) a store must remember it: ``{"method": "dpop", "iat", "jkt",
"jti", "key", "expires"}`` or ``{"method": "mtls", "x5t#S256"}``. A service that keeps state spends the proof's
``key`` and the stamp's ``nonce`` once, each until its ``expires``. A conforming verifier reports exactly these.

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

from agent_evidence_verify import structured_fields as sf
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from .canonical_identity import CanonicalIdentity, Ref
from .digests import act_chain_digest
from .identity import b64url, jwk_thumbprint
from .possession import (
    CertificateProof,
    DpopProof,
    cnf_for_certificate,
    cnf_for_jwk,
    possession_record,
    proof_key,
    public_jwk,
    sign_dpop,
)
from .stamp import (
    ALG,
    CONTENT_DIGEST_HEADER,
    COVERED,
    LABEL,
    PRINCIPALS_HEADER,
    SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER,
    TAG,
    content_digest,
    signature_base,
    stamp_key_id,
)
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


def _segment(doc: dict[str, Any], *, sort_keys: bool = True) -> str:
    """One JWS segment of ``doc``. The text starts ``{`` and a newline: legal JSON, and it keeps the segment from
    opening with the base64 of ``{"``, which a secret scanner reads as the start of a live token."""
    text = json.dumps(doc, separators=(",", ":"), sort_keys=sort_keys)
    return b64url(("{\n" + text[1:]).encode())


def _sign(key: Any, header: dict[str, Any], claims: dict[str, Any]) -> str:
    head = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    body = _segment(claims)
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
    bodies: dict[str, dict[str, Any]] = {
        "user": {"sub": "alice@example.com", "client_id": "agent-refunds", "act": {"sub": "agent-refunds"}},
        "agent": {"sub": "agent-refunds", "client_id": "agent-refunds"},
        "sponsor": {"sub": "owner@example.com", "azp": "console"},
    }
    body = bodies[role]
    full = {"iss": iss, "aud": AUDIENCE, "iat": NOW - 60, "exp": NOW + 300, **copy.deepcopy(body), **claims}
    return _sign(key, {k: v for k, v in head.items() if v is not None}, {k: v for k, v in full.items() if v is not None})


def pin(key: Any, roles: list[str], tenants: list[str] | None = None, kid: str | None = "idp-1") -> tuple[dict, dict]:
    jwk = _jwk(key, kid)
    return jwk, {"thumbprint": jwk_thumbprint(jwk), "roles": roles, "tenants": tenants or [TENANT]}


def bundle(profile: str = "basic", issuers: dict[str, Any] | None = None) -> dict[str, Any]:
    user_jwk, user_pin = pin(USER_KEY, ["user", "agent", "sponsor"])
    stamp_jwk, stamp_pin = pin(STAMP_KEY, ["stamp"], kid=None)
    base = {IDP: {"keys": [user_jwk], "pins": [user_pin]}, GATEWAY: {"keys": [stamp_jwk], "pins": [stamp_pin]}}
    return {"version": 2, "environment": ENV, "tenant": TENANT, "audience": AUDIENCE, "profile": profile,
            "issuers": {**base, **(issuers or {})}, "anchors": []}  # fmt: skip


STAMP_ACT = act_chain_digest({"sub": "agent-refunds"})
STAMP_IDENTITY = CanonicalIdentity(kind="agent", user=Ref("user", ENV, IDP, "alice@example.com"),
                                   chain=(Ref("agent", ENV, IDP, "agent-refunds"),), act=STAMP_ACT).render()  # fmt: skip
STAMP_PRINCIPALS = "sha256:" + "e5" * 32


def principals_field(identity: str = STAMP_IDENTITY, *, client: str = "agent-refunds",
                     principals: str = STAMP_PRINCIPALS, extra: dict[str, Any] | None = None) -> str:  # fmt: skip
    """A ``Probity-Principals`` value; ``extra`` adds or replaces members (an ``sf.Item`` each)."""
    members: dict[str, Any] = {"id": sf.Item(identity), "client": sf.Item(client), "principals": sf.Item(principals)}
    return sf.serialize_dictionary({**members, **(extra or {})})


def stamp(*, signer: Ed25519PrivateKey = STAMP_KEY, named_signer: Ed25519PrivateKey | None = None, method: str = "POST",
          url: str = URL, body: bytes | None = BODY, created: int = NOW - 10, expires: int = NOW + 50,
          nonce: Any = "stamp-0001", principals: str | None = None, covered: tuple[str, ...] = COVERED,
          params: dict[str, Any] | None = None, names: tuple[str, str, str, str] | None = None) -> list[list[str]]:  # fmt: skip
    """The four stamp header lines a gateway sends for one request, signed over ``method``, ``url`` and ``body``.

    The keyword arguments build the attack cases: ``named_signer`` names another key than the signing one, ``covered``
    and ``params`` change the signature input, ``names`` spells the four field names."""
    raw = (named_signer or signer).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    value = principals_field() if principals is None else principals
    digest = content_digest(body)
    members = {"created": created, "expires": expires, "nonce": nonce, "keyid": stamp_key_id(raw), "alg": ALG,
               "tag": TAG, **(params or {})}  # fmt: skip
    inner = sf.InnerList([sf.Item(c) for c in covered], {k: v for k, v in members.items() if v is not None})
    base = signature_base(method=method, target_uri=url, content_digest_value=digest, principals_value=value,
                          params=inner)  # fmt: skip
    signature = sf.serialize_dictionary({LABEL: sf.Item(signer.sign(base))})
    spelled = names or ("Probity-Principals", "Content-Digest", "Signature-Input", "Signature")
    return [[spelled[0], value], [spelled[1], digest], [spelled[2], sf.serialize_dictionary({LABEL: inner})],
            [spelled[3], signature]]  # fmt: skip


def drop(lines: list[list[str]], name: str) -> list[list[str]]:
    return [line for line in lines if line[0].lower() != name]


def replace(lines: list[list[str]], name: str, value: str) -> list[list[str]]:
    return [[n, value if n.lower() == name else v] for n, v in lines]


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
            method: str = "POST", url: str = URL, headers: list[list[str]] | None = None) -> dict[str, Any]:  # fmt: skip
    return {"method": method, "url": url, "contentB64": None if content is None else base64.b64encode(content).decode(),
            "dpop": dpop, "clientCertificateB64": None if cert is None else base64.b64encode(cert).decode(),
            "headers": headers or []}  # fmt: skip


def _proof(access: str, *, key: Ed25519PrivateKey = HOLDER_KEY, url: str = URL, jti: str = "dpop-0001",
           iat: int = NOW) -> str:
    """A DPoP proof, re-signed with the claims segment shaped as in ``_segment``."""
    head, body, _ = sign_dpop(key, "POST", url, iat=iat, jti=jti, access_token=access, content=BODY).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    shaped = _segment(claims, sort_keys=False)
    return f"{head}.{shaped}.{b64url(key.sign(f'{head}.{shaped}'.encode('ascii')))}"


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
                                                bundle=bundle(issuers={IDP_EC: {"keys": [ec_jwk], "pins": [ec_pin]}}))),
        ("VI8", "an RS256 identity provider", c({"user": token("user", key=_rsa(), kid="rsa-1", iss=IDP_RSA),
                                                 "agent": token("agent", key=_rsa(), kid="rsa-1", iss=IDP_RSA)},
                                                bundle=bundle(issuers={IDP_RSA: {"keys": [rsa_jwk], "pins": [rsa_pin]}}))),
        ("VI9", "a stamp from the pinned gateway names the identity the gateway verified",
         c({}, request=request(headers=stamp()))),
        ("VI13", "the stamp's field names in another case are the same fields",
         c({}, request=request(headers=stamp(names=("PROBITY-PRINCIPALS", "content-digest", "SIGNATURE-input",
                                                    "signature"))))),
        ("VI14", "another signer's Signature and Signature-Input are not a stamp: the tokens decide",
         c({"user": user, "agent": agent},
           request=request(headers=[["Signature-Input", 'sig1=("@method");created=1'], ["Signature", "sig1=:AAAA:"]]))),
        ("VI15", "a stamp over a request with no body binds the digest of no bytes",
         c({}, request=request(method="GET", content=None, headers=stamp(method="GET", body=None)))),
        ("VI10", "a key-bound agent token with a DPoP proof for this request",
         c({"user": user, "agent": bound}, request=request(dpop=_proof(bound)))),
        ("VI16", "a DPoP proof at the oldest iat the freshness check accepts: it is remembered past the skew",
         c({"user": user, "agent": bound}, request=request(dpop=_proof(bound, iat=NOW - 120)))),
        ("VI17", "a DPoP proof whose jti is not ASCII: the single-use key hashes the jti's UTF-8 bytes",
         c({"user": user, "agent": bound}, request=request(dpop=_proof(bound, jti="dpop-\u00e9-0002")))),
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
           bundle=bundle(issuers={IDP: {"keys": [_jwk(USER_KEY, "idp-1"), user_only_jwk],
                                  "pins": [pin(USER_KEY, ["user", "agent", "sponsor"])[1], user_only_pin]}}))),
        ("VR12", "a key pinned for another tenant",
         c({"user": user, "agent": token("agent", key=ROGUE_KEY, kid="idp-3")},
           bundle=bundle(issuers={IDP: {"keys": [_jwk(USER_KEY, "idp-1"), other_tenant_jwk],
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
        ("VR26", "an agent acting for no user and naming no sponsor", c({"agent": agent})),
        ("VR27", "the act claim names the acting agent as its own parent",
         c({"user": token("user", act={"sub": "agent-refunds", "act": {"sub": "agent-refunds"}}), "agent": agent})),
        # --- refused: possession ---
        ("VR22", "a key-bound agent token with no proof", c({"user": user, "agent": bound}, request=request())),
        ("VR23", "a key-bound agent token and its proof for one route, replayed on another route",
         c({"user": user, "agent": bound}, request=request(dpop=_proof(bound), url=PAYOUT))),
        ("VR24", "a proof by another key", c({"user": user, "agent": bound},
                                             request=request(dpop=_proof(bound, key=OTHER_HOLDER)))),
        ("VR25", "a certificate-bound agent token with no certificate",
         c({"user": user, "agent": cert_bound}, request=request())),
        # --- refused: the stamp ---
        ("VS1", "a stamp beside the tokens it replaces", c({"agent": agent}, request=request(headers=stamp()))),
        ("VS2", "a forged stamp: the signature bytes changed", c({}, request=request(headers=replace(
            stamp(), SIGNATURE_HEADER, sf.serialize_dictionary({LABEL: sf.Item(bytes(64))}))))),
        ("VS3", "a stamp signed by a key the bundle does not list", c({}, request=request(headers=stamp(signer=OTHER_STAMP_KEY)))),
        ("VS4", "a stamp naming the pinned key but signed by another (swapped key)",
         c({}, request=request(headers=stamp(signer=OTHER_STAMP_KEY, named_signer=STAMP_KEY)))),
        ("VS5", "an expired stamp", c({}, request=request(headers=stamp(created=NOW - 100, expires=NOW - 1)))),
        ("VS6", "a stamp for other body bytes", c({}, request=request(content=b"{}", headers=stamp()))),
        ("VS7", "a stamp whose body and content digest were both replaced",
         c({}, request=request(content=b"{}", headers=replace(stamp(), CONTENT_DIGEST_HEADER, content_digest(b"{}"))))),
        ("VS8", "a stamp signed for another target, replayed on this one",
         c({}, request=request(headers=stamp(url=PAYOUT)))),
        ("VS9", "a stamp signed for another method", c({}, request=request(headers=stamp(method="PUT")))),
        ("VS10", "a stamp signed for another authority", c({}, request=request(headers=stamp(
            url="https://billing.example.com:8443/mcp/refund")))),
        ("VS11", "a stamp whose principals were swapped for another user's after signing",
         c({}, request=request(headers=replace(stamp(), PRINCIPALS_HEADER, principals_field(
             CanonicalIdentity(kind="agent", user=Ref("user", ENV, IDP, "mallory@example.com"),
                               chain=(Ref("agent", ENV, IDP, "agent-refunds"),), act=STAMP_ACT).render()))))),
        ("VS12", "a stamp field given twice", c({}, request=request(headers=[*stamp(), ["probity-principals",
                                                                                  principals_field()]]))),
        ("VS13", "a stamp with no Signature line", c({}, request=request(headers=drop(stamp(), SIGNATURE_HEADER)))),
        ("VS14", "a stamp with no principals field", c({}, request=request(headers=drop(stamp(), PRINCIPALS_HEADER)))),
        ("VS15", "a stamp that does not cover the content digest",
         c({}, request=request(headers=stamp(covered=("@method", "@target-uri", "@authority", PRINCIPALS_HEADER))))),
        ("VS16", "a stamp covering the components in another order",
         c({}, request=request(headers=stamp(covered=("@target-uri", "@method", "@authority", CONTENT_DIGEST_HEADER,
                                                      PRINCIPALS_HEADER))))),
        ("VS17", "a stamp with another tag", c({}, request=request(headers=stamp(params={"tag": "web-bot-auth"})))),
        ("VS18", "a stamp naming another algorithm", c({}, request=request(headers=stamp(params={"alg": "hmac-sha256"})))),
        ("VS19", "a stamp with no expires", c({}, request=request(headers=stamp(params={"expires": None})))),
        ("VS20", "a stamp living longer than five minutes", c({}, request=request(headers=stamp(expires=NOW + 600)))),
        ("VS21", "a stamp not yet valid", c({}, request=request(headers=stamp(created=NOW + 60, expires=NOW + 120)))),
        ("VS22", "a stamp whose principals field is not a structured dictionary",
         c({}, request=request(headers=stamp(principals="alice for agent-refunds")))),
        ("VS23", "a stamp whose principals field carries another member",
         c({}, request=request(headers=stamp(principals=principals_field(extra={"scope": sf.Item("admin")}))))),
        ("VS24", "a stamp whose identity is not a canonical string",
         c({}, request=request(headers=stamp(principals=principals_field("alice acting through agent-refunds"))))),
        ("VS25", "a stamp naming the user acting alone (downgraded)",
         c({}, request=request(headers=stamp(principals=principals_field(
             CanonicalIdentity(kind="unknown", user=Ref("user", ENV, IDP, "alice@example.com")).render()))))),
        ("VS26", "a stamp naming an agent acting for no user",
         c({}, request=request(headers=stamp(principals=principals_field(CanonicalIdentity(
             kind="agent", chain=(Ref("agent", ENV, IDP, "agent-refunds"),),
             sponsors=(Ref("sponsor", ENV, IDP, "owner@example.com"),)).render()))))),
        ("VS27", "a stamp whose principals digest is not an identity digest",
         c({}, request=request(headers=stamp(principals=principals_field(principals="e5" * 32))))),
        ("VS28", "a stamp from staging read in prod",
         c({}, request=request(headers=stamp(principals=principals_field(CanonicalIdentity(kind="agent", user=Ref("user", "staging", IDP, "alice@example.com"), chain=(Ref("agent", "staging", IDP, "agent-refunds"),), act=STAMP_ACT).render()))))),
        ("VS29", "an identity provider's key signs a stamp", c({}, request=request(headers=stamp(signer=USER_KEY)))),
        ("VS30", "a stamp key pinned for another tenant",
         c({}, bundle=bundle(issuers={GATEWAY: {"keys": [_jwk(STAMP_KEY, None)],
                                          "pins": [pin(STAMP_KEY, ["stamp"], tenants=["globex"], kid=None)[1]]}}),
           request=request(headers=stamp()))),
        ("VS31", "a stamp whose nonce is an Integer, not a String", c({}, request=request(headers=stamp(nonce=7)))),
        ("VS32", "a stamp presented as a token role", c({"stamp": "not-a-token"}, request=request())),
        ("VS33", "a content digest carrying a second algorithm",
         c({}, request=request(headers=replace(stamp(), CONTENT_DIGEST_HEADER, content_digest(BODY) + ", sha-512=:AAAA:")))),
        ("VS34", "a Signature-Input that is not a structured dictionary",
         c({}, request=request(headers=replace(stamp(), SIGNATURE_INPUT_HEADER, "probity=(\"@method\"")))),
        # --- refused: the bundle ---
        ("VB1", "a bundle pin naming no listed key",
         c({"user": user, "agent": agent}, bundle=bundle(issuers={IDP: {"keys": [_jwk(USER_KEY, "idp-1")],
                                                                  "pins": [user_only_pin]}}))),
        ("VB2", "a bundle carrying a private key",
         c({"user": user, "agent": agent}, bundle=bundle(issuers={IDP: {"keys": [{**_jwk(USER_KEY, "idp-1"), "d": "AA"}],
                                                                  "pins": [pin(USER_KEY, ["user"])[1]]}}))),
    ]


def _swap_claims(jws: str, **claims: Any) -> str:
    head, body, sig = jws.split(".")
    doc = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    doc.update(claims)
    return f"{head}.{_segment(doc)}.{sig}"


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
        client_certificate=None if raw["clientCertificateB64"] is None else base64.b64decode(raw["clientCertificateB64"]),
        headers=tuple((name, value) for name, value in raw["headers"]))
    transport = None if case["transport"] is None else CanonicalIdentity.parse(case["transport"])
    try:
        found = verify_request(case["tokens"], case["bundle"], case["at"], transport, request=facts)
    except VerifiedIdentitiesRefused as exc:
        return {"refused": exc.code}
    return {"identities": [i.document() for i in found.identities], "proof": proof_document(found.proof),
            "stamp": None if found.stamp is None else {"nonce": found.stamp.nonce, "expires": found.stamp.expires}}


def proof_document(proof: DpopProof | CertificateProof | None) -> dict[str, Any] | None:
    """The proof as the vectors write it: what a service that keeps state spends once, and until when."""
    if proof is None:
        return None
    if isinstance(proof, DpopProof):
        return {**possession_record(proof), "key": proof_key(proof.jkt, proof.jti), "expires": proof.replay_exp}
    return possession_record(proof)


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
    "VR26": "identity_attribute_missing", "VR27": "identity_chain_repeats_agent",
    "VS1": "identity_sources_mixed", "VS2": "stamp_forged", "VS3": "stamp_key_mismatch", "VS4": "stamp_forged",
    "VS5": "stamp_expired", "VS6": "stamp_request_mismatch", "VS7": "stamp_forged", "VS8": "stamp_forged",
    "VS9": "stamp_forged", "VS10": "stamp_forged", "VS11": "stamp_forged", "VS12": "stamp_repeated",
    "VS13": "stamp_malformed", "VS14": "stamp_malformed", "VS15": "stamp_header_invalid",
    "VS16": "stamp_header_invalid", "VS17": "stamp_header_invalid", "VS18": "stamp_header_invalid",
    "VS19": "stamp_header_invalid", "VS20": "stamp_lifetime_too_long", "VS21": "stamp_not_yet_valid",
    "VS22": "stamp_malformed", "VS23": "stamp_malformed", "VS24": "stamp_identity_mismatch",
    "VS25": "stamp_downgraded", "VS26": "stamp_no_user", "VS27": "stamp_malformed",
    "VS28": "identity_environment_mismatch", "VS29": "principal_key_not_pinned", "VS30": "principal_key_not_pinned",
    "VS31": "stamp_header_invalid", "VS32": "principal_role_not_configured", "VS33": "stamp_malformed",
    "VS34": "stamp_malformed", "VB1": "trust_bundle_malformed",
    "VB2": "trust_bundle_malformed",
}


def check(rows: list[dict[str, Any]]) -> list[str]:
    """The ids of vectors whose input this package judges differently from their expected outcome."""
    return [row["id"] for row in rows if judge(row) != row["expected"]]

