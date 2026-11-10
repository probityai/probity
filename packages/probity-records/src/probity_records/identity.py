"""The four principals behind one tool call, each bound by digest to the credential that proved it.

A tool-call record may carry ``principals``: ``user`` (who invoked), ``agent`` (what executed),
``sponsor`` (the accountable owner) and ``approver`` (who approved, when a human did). Each is the
audit-record ``principal`` member (issuer, subject, clientId, audience, authMethod, source,
tokenDigest, issuedAt, expiresAt, kid, key, keyThumbprint, jwksDigest; ``tenant`` optional) plus
``act``, the token's delegation chain (RFC 8693 ``act``), when it had one. ``source`` adds
``id-jag`` (an Identity Assertion JWT Authorization Grant, ``typ`` ``oauth-id-jag+jwt``).

Refused: a missing or unknown member, a thumbprint that does not recompute from ``key``, a ``kid``
mismatch, a credential not valid at the record's time, an issuer the auditor did not pin or a key
whose thumbprint the auditor did not pin for that issuer, an ``act`` chain that names an agent other
than the agent principal, and an approver principal who is not among the approvals the record counts.

Graded, never refused, on delegation: ``act-chain`` when the user's credential names the agent in
``act``, ``act-absent`` when it carries no ``act``. ``strict`` conformance needs all four principals
and ``act-chain``; anything else that passes is ``basic``. An auditor may require ``strict``.

When the auditor holds the token itself and the JWKS snapshot, ``verify_token`` re-verifies the JWS
signature and every claim the principal states, closing the gap the audit-record member leaves open
(that the signature verified).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .core import canonical, sha256_hex
from .grants import ts

ROLES = ("user", "agent", "sponsor", "approver")
MEMBERS = ("issuer", "subject", "clientId", "audience", "authMethod", "source", "tokenDigest", "issuedAt",
           "expiresAt", "kid", "key", "keyThumbprint", "jwksDigest")
OPTIONAL = ("tenant", "act")
SOURCES = ("jwt-access-token", "id-token", "jwt-assertion", "id-jag")
AUTH_METHODS = ("none", "client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt",
                "tls_client_auth", "self_signed_tls_client_auth")
THUMBPRINT_MEMBERS = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y"), "OKP": ("crv", "kty", "x")}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint, base64url without padding."""
    members = THUMBPRINT_MEMBERS.get(str(jwk.get("kty")))
    if members is None or any(m not in jwk for m in members):
        raise ValueError("jwk_unsupported")
    data = json.dumps({m: jwk[m] for m in members}, sort_keys=True, separators=(",", ":")).encode()
    return b64url(hashlib.sha256(data).digest())


def jwks_digest(jwks: Mapping[str, Any]) -> str:
    return sha256_hex(canonical(dict(jwks)))


def _shape(p: Any) -> str | None:
    if not isinstance(p, dict):
        return "principal_malformed"
    if any(m not in p for m in MEMBERS):
        return "principal_member_missing"
    if set(p) - set(MEMBERS) - set(OPTIONAL):
        return "principal_member_unknown"
    if not isinstance(p["issuer"], str) or not p["issuer"].startswith("https://"):
        return "principal_issuer_invalid"
    if not all(isinstance(p[m], str) and p[m] for m in ("subject", "clientId", "kid", "keyThumbprint")):
        return "principal_malformed"
    aud = p["audience"]
    if not isinstance(aud, list) or not aud or len(set(map(str, aud))) != len(aud):
        return "principal_malformed"
    if p["source"] not in SOURCES or p["authMethod"] not in AUTH_METHODS:
        return "principal_malformed"
    for m in ("tokenDigest", "jwksDigest"):
        if not isinstance(p[m], str) or len(p[m]) != 64 or any(c not in "0123456789abcdef" for c in p[m]):
            return "principal_malformed"
    if not isinstance(p["key"], dict) or any(k in p["key"] for k in ("d", "p", "q", "dp", "dq", "qi", "k")):
        return "principal_key_invalid"
    return None


def _act_subjects(act: Any) -> list[str] | None:
    """The actor subjects of an RFC 8693 ``act`` chain, outermost (current actor) first."""
    out = []
    while act is not None:
        if not isinstance(act, dict) or not isinstance(act.get("sub"), str):
            return None
        out.append(act["sub"])
        act = act.get("act")
    return out


def check_principal(p: Any, at: str, pins: Mapping[str, Any]) -> str | None:
    problem = _shape(p)
    if problem:
        return problem
    try:
        thumb = jwk_thumbprint(p["key"])
    except ValueError:
        return "principal_key_invalid"
    if thumb != p["keyThumbprint"]:
        return "principal_thumbprint_mismatch"
    if p["key"].get("kid") != p["kid"]:
        return "principal_kid_mismatch"
    try:
        issued, expires, when = ts(p["issuedAt"]), ts(p["expiresAt"]), ts(at)
    except (ValueError, TypeError):
        return "principal_malformed"
    if expires <= issued:
        return "principal_malformed"
    if when < issued:
        return "principal_not_yet_valid"
    if when >= expires:
        return "principal_expired"
    pinned = pins.get(p["issuer"])
    if pinned is None:
        return "principal_issuer_untrusted"
    if thumb not in pinned:
        return "principal_key_not_pinned"
    if "act" in p and _act_subjects(p["act"]) is None:
        return "principal_act_malformed"
    return None


def check_principals(block: Any, at: str, pins: Mapping[str, Any],
                     approvers: set[str] | None = None) -> tuple[list[str], str | None]:
    """(problems, grade) for one record's ``principals``. Grade is ``strict`` or ``basic``; None
    when a problem refuses the block."""
    if not isinstance(block, dict) or not block or set(block) - set(ROLES):
        return ["principals_malformed"], None
    problems = [f"principal_{role}:{prob}" for role in ROLES if role in block
                for prob in [check_principal(block[role], at, pins)] if prob]
    if "user" not in block or "agent" not in block:
        problems.append("principals_need_user_and_agent")
    if problems:
        return problems, None
    user, agent = block["user"], block["agent"]
    chain = _act_subjects(user.get("act")) if "act" in user else []
    if chain and chain[0] not in (agent["subject"], agent["clientId"]):
        return ["principal_act_names_another_agent"], None
    if "approver" in block and approvers is not None and block["approver"]["subject"] not in approvers:
        return ["principal_approver_not_an_approval_signer"], None
    strict = chain and all(r in block for r in ROLES)
    return [], "strict" if strict else "basic"


def act_grade(block: Mapping[str, Any]) -> str:
    return "act-chain" if "act" in block.get("user", {}) else "act-absent"


def _verify_jws(alg: str, jwk: Mapping[str, Any], signing_input: bytes, sig: bytes) -> bool:
    try:
        if alg == "EdDSA" and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            Ed25519PublicKey.from_public_bytes(unb64url(jwk["x"])).verify(sig, signing_input)
        elif alg == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64url(jwk["x"]), "big"),
                                                int.from_bytes(unb64url(jwk["y"]), "big"), ec.SECP256R1()).public_key()
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        elif alg == "RS256" and jwk.get("kty") == "RSA":
            key = rsa.RSAPublicNumbers(int.from_bytes(unb64url(jwk["e"]), "big"),
                                       int.from_bytes(unb64url(jwk["n"]), "big")).public_key()
            key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True


def _iso(seconds: Any) -> str:
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.fromtimestamp(int(seconds), UTC).isoformat().replace("+00:00", "Z")


def verify_token(p: Mapping[str, Any], token: str, jwks: Mapping[str, Any]) -> str | None:
    """None when ``token`` is the credential ``p`` names, its JWS verifies under the key ``p`` names,
    that key is in the JWKS snapshot whose digest ``p`` carries, and every stated claim matches."""
    if sha256_hex(token.encode("ascii")) != p.get("tokenDigest"):
        return "token_digest_mismatch"
    if jwks_digest(jwks) != p.get("jwksDigest"):
        return "jwks_digest_mismatch"
    if dict(p.get("key", {})) not in [dict(k) for k in jwks.get("keys", [])]:
        return "key_not_in_jwks"
    try:
        head_b64, body_b64, sig_b64 = token.split(".")
        header, claims = json.loads(unb64url(head_b64)), json.loads(unb64url(body_b64))
    except (ValueError, TypeError):
        return "token_malformed"
    if header.get("kid") != p.get("kid"):
        return "token_kid_mismatch"
    if p.get("source") == "id-jag" and header.get("typ") != "oauth-id-jag+jwt":
        return "token_typ_not_id_jag"
    if not _verify_jws(str(header.get("alg")), p["key"], f"{head_b64}.{body_b64}".encode(), unb64url(sig_b64)):
        return "token_signature_unverified"
    aud = claims.get("aud")
    # An ID token names its client in ``azp`` (OpenID Connect Core 1.0, section 2); an access token in ``client_id``.
    client = claims.get("client_id") or (claims.get("azp") if p.get("source") == "id-token" else None)
    expected = {"issuer": claims.get("iss"), "subject": claims.get("sub"), "clientId": client,
                "audience": aud if isinstance(aud, list) else [aud], "issuedAt": _iso(claims.get("iat", 0)),
                "expiresAt": _iso(claims.get("exp", 0))}
    for member, value in expected.items():
        if p.get(member) != value:
            return f"token_claim_mismatch:{member}"
    if claims.get("act") != p.get("act"):
        return "token_claim_mismatch:act"
    return None
