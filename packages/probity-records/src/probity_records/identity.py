"""The four principals behind one tool call, each bound by digest to the credential that proved it.

A tool-call record may carry ``principals``: ``user`` (who invoked), ``agent`` (what executed),
``sponsor`` (the accountable owner) and ``approver`` (who approved, when a human did). Each is the
audit-record ``principal`` member (issuer, subject, clientId, audience, authMethod, source,
tokenDigest, issuedAt, expiresAt, kid, key, keyThumbprint, jwksDigest; ``tenant`` optional) plus
``act``, the token's delegation chain (RFC 8693 ``act``), when it had one, and ``cnf``, the key the token is
bound to (RFC 7800; RFC 9449 ``jkt`` or RFC 8705 ``x5t#S256``), when it is sender-constrained. ``source`` adds
``id-jag`` (an Identity Assertion JWT Authorization Grant, ``typ`` ``oauth-id-jag+jwt``).

Refused: a missing or unknown member, a thumbprint that does not recompute from ``key``, a ``kid``
mismatch, a credential not valid at the record's time, an issuer the auditor did not pin or a key
whose thumbprint the auditor did not pin for that issuer, an ``act`` chain that names an agent other
than the agent principal, and an approver principal who is not among the approvals the record counts.

Graded, never refused, on delegation: ``act-chain`` when the user's credential names the agent in
``act``, ``act-absent`` when it carries no ``act``. ``strict`` conformance needs all four principals
and ``act-chain``; anything else that passes is ``basic``. An auditor may require ``strict``.

Autonomous: an agent that runs with no person in its session. Its block carries no ``user``; it carries the agent,
the ``sponsor`` who answers for it, the digest of its standing grant (``standingGrant``, a capability grant that names
that sponsor and a review date, ``grants.py``) and its ``session`` ({"id", "startedAt"}). ``check_principals`` grades
it ``autonomous`` when the standing grant is one the verifier resolved from content it verified against its own
pinned grant roots, is inside its window and before its review date, is held by the agent's confirmed key (``cnf``)
and names this sponsor; the sponsor is registered for this agent in the registry the auditor pins; and the approver
is present exactly when an approval admitted the call. The sponsor's credential is checked at the grant's
``notBefore``, the moment the sponsor answered for it, never per call. A ``user`` in such a block is refused
(``principals_autonomous_has_user``): an autonomous block never carries a person's token. ``autonomous`` is
strict-equivalent: an auditor that requires ``strict`` accepts it.

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
#: The members of an autonomous block beside its roles.
AUTONOMOUS = ("session", "standingGrant")
#: The longest session id an autonomous block carries.
SESSION_ID_MAX = 256
MEMBERS = ("issuer", "subject", "clientId", "audience", "authMethod", "source", "tokenDigest", "issuedAt",
           "expiresAt", "kid", "key", "keyThumbprint", "jwksDigest")
OPTIONAL = ("tenant", "act", "cnf")
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
    if "cnf" in p:
        from .possession import cnf_problem

        if cnf_problem(p["cnf"]):
            return "principal_cnf_invalid"
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


def sponsor_id(issuer: str, subject: str) -> str:
    """The id a sponsor goes by in the revocation list (kind ``sponsor``): ``<issuer>#<subject>``. An issuer is an
    https URL with no fragment (OpenID Connect Discovery 1.0, section 3), so the first ``#`` splits it
    unambiguously; ValueError for anything else."""
    if (not isinstance(issuer, str) or not issuer.startswith("https://") or "#" in issuer
            or not isinstance(subject, str) or not subject):  # fmt: skip
        raise ValueError("sponsor_id_invalid")
    ident = f"{issuer}#{subject}"
    if len(ident) > 512 or not all("\x21" <= c <= "\x7e" for c in ident):
        raise ValueError("sponsor_id_invalid")
    return ident


def _session_problem(session: Any, at: str) -> str | None:
    if (not isinstance(session, dict) or set(session) != {"id", "startedAt"} or not isinstance(session["id"], str)
            or not 0 < len(session["id"]) <= SESSION_ID_MAX
            or not all("\x21" <= c <= "\x7e" for c in session["id"])):  # fmt: skip
        return "principals_session_malformed"
    try:
        started_late = ts(session["startedAt"]) > ts(at)
    except (TypeError, ValueError):
        return "principals_session_malformed"
    return "principals_session_not_started" if started_late else None


def _grant_problems(block: Mapping[str, Any], at: str,
                    standing_grants: Mapping[str, Mapping[str, Any]]) -> list[str]:  # fmt: skip
    digest = block["standingGrant"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return ["principals_standing_grant_malformed"]
    grant = standing_grants.get(digest)
    if grant is None:
        return ["principals_standing_grant_unknown"]
    if "sponsor" not in grant or "reviewBy" not in grant:
        return ["principals_standing_grant_not_standing"]
    problems = []
    when = ts(at)
    if when < ts(grant["notBefore"]):
        problems.append("principals_standing_grant_not_yet_valid")
    elif when >= ts(grant["expiresAt"]):
        problems.append("principals_standing_grant_expired")
    elif when >= ts(grant["reviewBy"]):
        problems.append("principals_standing_grant_unreviewed")
    cnf = block["agent"].get("cnf")
    if cnf is None or cnf != grant.get("cnf"):
        problems.append("principals_standing_grant_not_held_by_agent")
    sponsor = block["sponsor"]
    if {"issuer": sponsor["issuer"], "subject": sponsor["subject"]} != grant["sponsor"]:
        problems.append("principals_sponsor_not_the_grant_sponsor")
    return problems


def _check_autonomous(block: dict[str, Any], at: str, pins: Mapping[str, Any], approvers: set[str] | None,
                      sponsors: Mapping[str, Any] | None,
                      standing_grants: Mapping[str, Mapping[str, Any]]) -> tuple[list[str], str | None]:  # fmt: skip
    if "user" in block:
        return ["principals_autonomous_has_user"], None
    problems = [f"principals_need_{name}" for name, member in
                (("agent", "agent"), ("sponsor", "sponsor"), ("session", "session"),
                 ("standing_grant", "standingGrant")) if member not in block]  # fmt: skip
    if problems:
        return problems, None
    grant = standing_grants.get(block["standingGrant"]) if isinstance(block["standingGrant"], str) else None
    sponsored_at = str(grant["notBefore"]) if grant is not None and "notBefore" in grant else at
    for role in ("agent", "approver"):
        if role in block:
            prob = check_principal(block[role], at, pins)
            if prob:
                problems.append(f"principal_{role}:{prob}")
    prob = check_principal(block["sponsor"], sponsored_at, pins)
    if prob:
        problems.append(f"principal_sponsor:{prob}")
    session = _session_problem(block["session"], at)
    if session:
        problems.append(session)
    if problems:
        return problems, None
    problems = _grant_problems(block, at, standing_grants)
    agent, sponsor = block["agent"], block["sponsor"]
    if sponsors is None:
        problems.append("principals_sponsors_not_pinned")
    elif (sponsor["issuer"], sponsor["subject"]) not in {tuple(s) for s in sponsors.get(agent["clientId"], ())}:
        problems.append("principal_sponsor_not_registered")
    if "approver" in block and approvers is None:
        problems.append("principal_approver_without_approval")
    elif approvers is not None and "approver" not in block:
        problems.append("principals_need_approver")
    elif "approver" in block and approvers is not None and block["approver"]["subject"] not in approvers:
        problems.append("principal_approver_not_an_approval_signer")
    return (problems, None) if problems else ([], "autonomous")


def check_principals(block: Any, at: str, pins: Mapping[str, Any], approvers: set[str] | None = None, *,
                     sponsors: Mapping[str, Any] | None = None,
                     standing_grants: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[list[str], str | None]:
    """(problems, grade) for one record's ``principals``. Grade is ``strict``, ``basic`` or ``autonomous``; None
    when a problem refuses the block.

    ``sponsors`` is the registry the auditor pins: agent client id to the (issuer, subject) pairs registered as its
    sponsors. ``standing_grants`` maps a grant digest to a grant body the caller verified against its own pinned
    grant roots (``grants.chain_digests``); nothing in the record chooses either."""
    if not isinstance(block, dict) or not block or set(block) - set(ROLES) - set(AUTONOMOUS):
        return ["principals_malformed"], None
    if set(block) & set(AUTONOMOUS):
        return _check_autonomous(block, at, pins, approvers, sponsors, standing_grants or {})
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
    from datetime import UTC, datetime

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
    if claims.get("cnf") != p.get("cnf"):
        return "token_claim_mismatch:cnf"
    return None


def possession_grade(block: Mapping[str, Any]) -> str:
    """``sender-constrained`` when the agent's credential confirms a key (RFC 7800 ``cnf``), else ``bearer``:
    a bearer credential is usable by whoever copies it."""
    return "sender-constrained" if "cnf" in block.get("agent", {}) else "bearer"
