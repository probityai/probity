"""Deterministic conformance vectors for the four-principal block and ID-JAG credentials.

Every key comes from a fixed seed and every time is fixed, so the vectors are byte-identical on every
run and any verifier (this package, the TypeScript verifier) can be checked against them. Each vector
is ``{"id", "description", "at", "principals", "pins", "approvers", "revocations", "audiences",
"tokens", "jwks", "expected"}`` where ``expected`` is ``{"problems": [...], "grade": "strict" |
"basic" | None, "act": ...}``, ``tokens`` maps a role to its escrowed token for ``verify_token``,
``revocations`` lists the auditor's revocation entries ``{"kind": "key" | "principal", "id",
"revokedAt"}`` (a key by its RFC 7638 thumbprint, a principal as ``<issuer>#<subject>``) and
``audiences`` maps a role to the audiences the auditor pins for its own deployment; ``jwksByIssuer``
is each issuer's JWKS snapshot (``jwks`` is the first issuer's).

``python -m probity_records identity-vectors`` prints them as JSON; ``check`` re-runs them.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .core import sha256_hex
from .grants import ts
from .identity import (
    b64url,
    check_principals,
    jwk_thumbprint,
    jwks_digest,
    principal_id,
    verify_token,
)

AT = "2026-11-08T12:00:00Z"
_AT_EPOCH = 1794139200  # AT as seconds since the epoch
IAT, EXP = _AT_EPOCH - 2400, _AT_EPOCH + 1200  # 11:20 .. 12:20 on the vectors' day
ISSUER = "https://idp.example.com/realms/agents"
PARTNER = "https://partner-idp.example.net"


def _iso_at(seconds: int) -> str:
    from .identity import _iso

    return _iso(seconds)


def _key(seed: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


def _jwk(priv: Ed25519PrivateKey, kid: str) -> dict[str, str]:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"crv": "Ed25519", "kid": kid, "kty": "OKP", "x": b64url(raw)}


def _token(priv: Ed25519PrivateKey, kid: str, claims: dict[str, Any], typ: str = "JWT") -> str:
    head = b64url(json.dumps({"alg": "EdDSA", "kid": kid, "typ": typ}, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return f"{head}.{body}.{b64url(priv.sign(f'{head}.{body}'.encode()))}"


def _principal(token: str, jwk: dict, jwks: dict, source: str, claims: dict) -> dict[str, Any]:
    from .identity import _iso

    p = {"audience": [claims["aud"]], "authMethod": "private_key_jwt", "clientId": claims["client_id"],
         "expiresAt": _iso(claims["exp"]), "issuedAt": _iso(claims["iat"]), "issuer": claims["iss"],
         "jwksDigest": jwks_digest(jwks), "key": jwk, "keyThumbprint": jwk_thumbprint(jwk), "kid": jwk["kid"],
         "source": source, "subject": claims["sub"], "tokenDigest": sha256_hex(token.encode())}
    if "act" in claims:
        p["act"] = claims["act"]
    return p


def base() -> dict[str, Any]:
    priv = _key("probity-identity-vectors/issuer-key-1")
    jwk = _jwk(priv, "k1")
    jwks = {"keys": [jwk]}
    specs = {
        "user": ("id-jag", "oauth-id-jag+jwt", {"sub": "alice@example.com", "client_id": "agent-refunds",
                                                "aud": "https://api.example.com", "act": {"sub": "agent-refunds"}}),
        "agent": ("jwt-access-token", "at+jwt", {"sub": "agent-refunds", "client_id": "agent-refunds",
                                                 "aud": "https://api.example.com"}),
        "sponsor": ("id-token", "JWT", {"sub": "owner@example.com", "client_id": "console",
                                        "aud": "console"}),
        "approver": ("id-token", "JWT", {"sub": "bob@example.com", "client_id": "console", "aud": "console"}),
    }
    principals, tokens = {}, {}
    for role, (source, typ, extra) in specs.items():
        claims = {"iss": ISSUER, "iat": IAT, "exp": EXP, "jti": f"jti-{role}", **extra}
        tokens[role] = _token(priv, "k1", claims, typ)
        principals[role] = _principal(tokens[role], dict(jwk), jwks, source, claims)
    return {"at": AT, "principals": principals, "pins": {ISSUER: [jwk_thumbprint(jwk)]},
            "approvers": ["bob@example.com"], "revocations": [], "audiences": {}, "tokens": tokens, "jwks": jwks,
            "jwksByIssuer": {ISSUER: jwks}}


def revoked_by(entries: list[dict[str, Any]]):
    """The ``revoked(kind, id, at)`` question answered from a vector's revocation entries."""
    def revoked(kind: str, ident: str, at: str) -> bool:
        return any(e["kind"] == kind and e["id"] == ident and ts(e["revokedAt"]) <= ts(at) for e in entries)
    return revoked


def _partner_agent(v: dict[str, Any], *, act_iss: str | None = None) -> None:
    """Move the agent principal to a second pinned issuer that reuses the same subject string; with
    ``act_iss`` the user's credential is re-minted with an ``act`` naming that issuer."""
    priv = _key("probity-identity-vectors/partner-key-1")
    jwk = _jwk(priv, "p1")
    jwks = {"keys": [jwk]}
    claims = {"iss": PARTNER, "iat": IAT, "exp": EXP, "jti": "jti-agent-partner", "sub": "agent-refunds",
              "client_id": "agent-refunds", "aud": "https://api.example.com"}
    v["tokens"]["agent"] = _token(priv, "p1", claims, "at+jwt")
    v["principals"]["agent"] = _principal(v["tokens"]["agent"], jwk, jwks, "jwt-access-token", claims)
    v["pins"][PARTNER] = [jwk_thumbprint(jwk)]
    v["jwksByIssuer"][PARTNER] = jwks
    if act_iss is not None:
        user_priv = _key("probity-identity-vectors/issuer-key-1")
        user_jwk = _jwk(user_priv, "k1")
        claims = {"iss": ISSUER, "iat": IAT, "exp": EXP, "jti": "jti-user", "sub": "alice@example.com",
                  "client_id": "agent-refunds", "aud": "https://api.example.com",
                  "act": {"sub": "agent-refunds", "iss": act_iss}}
        v["tokens"]["user"] = _token(user_priv, "k1", claims, "oauth-id-jag+jwt")
        v["principals"]["user"] = _principal(v["tokens"]["user"], user_jwk, {"keys": [user_jwk]}, "id-jag", claims)


def _revoke(v: dict[str, Any], kind: str, ident: str, at: str) -> None:
    v["revocations"].append({"kind": kind, "id": ident, "revokedAt": at})


def _mut(vid: str, description: str, fn) -> dict[str, Any]:
    v = base()
    fn(v)
    return {"id": vid, "description": description, **v}


def vectors() -> list[dict[str, Any]]:
    out = [
        _mut("ID1", "four principals, user credential names the agent in act: strict", lambda v: None),
        _mut("ID2", "no act on the user credential: accepted, graded basic, act-absent",
             lambda v: v["principals"]["user"].pop("act")),
        _mut("ID3", "no sponsor: accepted, basic", lambda v: v["principals"].pop("sponsor")),
        _mut("ID4", "thumbprint does not recompute from the key",
             lambda v: v["principals"]["agent"].__setitem__("keyThumbprint", "A" * 43)),
        _mut("ID5", "credential expired at the record time",
             lambda v: v.__setitem__("at", _iso_at(EXP))),
        _mut("ID6", "issuer missing", lambda v: v["principals"]["user"].pop("issuer")),
        _mut("ID7", "issuer not pinned by the auditor", lambda v: v.__setitem__("pins", {})),
        _mut("ID8", "key not pinned for the issuer", lambda v: v.__setitem__("pins", {ISSUER: ["B" * 43]})),
        _mut("ID9", "act names an agent other than the agent principal",
             lambda v: v["principals"]["user"].__setitem__("act", {"sub": "agent-payroll"})),
        _mut("ID10", "approver principal did not sign an approval",
             lambda v: v.__setitem__("approvers", ["carol@example.com"])),
        _mut("ID11", "kid differs from the key", lambda v: v["principals"]["agent"].__setitem__("kid", "k2")),
        _mut("ID12", "private member in the key",
             lambda v: v["principals"]["agent"]["key"].__setitem__("d", "AA")),
        _mut("ID13", "credential not yet valid", lambda v: v.__setitem__("at", _iso_at(IAT - 1))),
        _mut("ID14", "agent principal missing", lambda v: v["principals"].pop("agent")),
        _mut("ID15", "act names the agent's subject, but the agent principal is another pinned issuer's",
             lambda v: _partner_agent(v)),
        _mut("ID16", "act carries iss naming the agent principal's issuer (cross-domain): strict",
             lambda v: _partner_agent(v, act_iss=PARTNER)),
        _mut("ID17", "the issuer's signing key was revoked before the record time, still pinned",
             lambda v: _revoke(v, "key", v["principals"]["agent"]["keyThumbprint"], "2026-11-08T11:30:00Z")),
        _mut("ID18", "the issuer's signing key was revoked after the record time: strict",
             lambda v: _revoke(v, "key", v["principals"]["agent"]["keyThumbprint"], "2026-11-08T12:30:00Z")),
        _mut("ID19", "the sponsor was suspended before the record time",
             lambda v: _revoke(v, "principal", principal_id(v["principals"]["sponsor"]), "2026-11-01T00:00:00Z")),
        _mut("ID20", "the agent's credential was minted for another deployment's audience",
             lambda v: v.__setitem__("audiences", {"agent": ["https://api.other-tenant.example.org"]})),
        _mut("ID21", "every credential's audience is one the auditor pins for its role: strict",
             lambda v: v.__setitem__("audiences", {"user": ["https://api.example.com"],
                                                   "agent": ["https://api.example.com"],
                                                   "sponsor": ["console"], "approver": ["console"]})),
        _mut("ID22", "act carries iss naming another issuer than the agent principal's",
             lambda v: v["principals"]["user"].__setitem__("act", {"sub": "agent-refunds", "iss": PARTNER})),
    ]
    for v in out:
        problems, grade = check_principals(v["principals"], v["at"], {k: frozenset(t) for k, t in v["pins"].items()},
                                           set(v["approvers"]), revoked_by(v["revocations"]),
                                           {r: frozenset(a) for r, a in v["audiences"].items()})
        token_checks = {role: verify_token(p, v["tokens"][role], v["jwksByIssuer"].get(p.get("issuer"), v["jwks"]))
                        for role, p in v["principals"].items() if role in v["tokens"]}
        v["expected"] = {"problems": problems, "grade": grade,
                         "act": "act-chain" if "act" in v["principals"].get("user", {}) else "act-absent",
                         "tokens": token_checks}
    return copy.deepcopy(out)


def check(vs: list[dict[str, Any]]) -> list[str]:
    """The ids whose recomputed outcome differs from the vector's expected outcome."""
    fresh = {v["id"]: v["expected"] for v in vectors()}
    return [v["id"] for v in vs if fresh.get(v["id"]) != v["expected"]]
