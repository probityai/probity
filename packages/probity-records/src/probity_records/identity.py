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

``approver`` is one principal when one person approved, or a list of at least two principals when an approval took
several (an M-of-N quorum): each member a full principal, each a counted signer of the approval, no subject named
twice (``principal_approver_duplicate``). A list of fewer than two is refused (``principal_approver_list_too_short``):
one approval takes the single form, so one block has one spelling. A member that fails the principal checks is refused
as ``principal_approver:<code>``, as the single form is. The list is a set: its order is the writer's and
neither the verdict, a permit's parties (``journal._parties``) nor the digest (``digests.principals_digest`` sorts the
members) depends on it.
An issuer's pins are a collection of thumbprints (a set, list or tuple); a pin written as one string is
refused rather than searched, so a string that merely contains a thumbprint pins nothing.

Graded, never refused, on delegation: ``act-chain`` when the user's credential names the agent in
``act``, ``act-absent`` when it carries no ``act``. ``strict`` conformance needs the user, the agent and the
sponsor, ``act-chain``, and the approvers exactly when an approval admitted the call: a call no human approved is
strict without one, and an approved call is strict only with every approver the approval counts named
(``approvers-partial`` when the block names some of them). An approver principal no approval counts is refused
(``principal_approver_without_approval``) under every profile: it states that a person approved when none did. Anything else that passes is ``basic`` (``strict_shortfall`` names what it lacks). An auditor may
require ``strict``.

Autonomous: an agent that runs with no person in its session. Its block carries no ``user``; it carries the agent,
the ``sponsor`` who answers for it, the digest of its standing grant (``standingGrant``, a capability grant that names
that sponsor and a review date, ``grants.py``) and its ``session`` ({"id", "startedAt"}). ``check_principals`` grades
it ``autonomous`` when the standing grant is one the verifier resolved from content it verified against its own
pinned grant roots, is inside its window and before its review date, is held by the agent's confirmed key (``cnf``)
and names this sponsor; the sponsor is registered for this agent in the registry the auditor pins; and the approvers
are named exactly when an approval admitted the call, every one it counts (``principals_need_every_approver`` when the
block names some of them: an autonomous block has no basic grade to fall to). The sponsor's credential is checked at the grant's
``notBefore``, the moment the sponsor answered for it, never per call. A ``user`` in such a block is refused
(``principals_autonomous_has_user``): an autonomous block never carries a person's token. ``autonomous`` is
strict-equivalent: an auditor that requires ``strict`` accepts it.

When the auditor holds the token itself and the JWKS snapshot, ``verify_token`` re-verifies the JWS
signature and every claim the principal states, closing the gap the audit-record member leaves open
(that the signature verified). It also refuses a token whose ``typ`` names another credential type than
the principal's ``source`` (an identity assertion grant presented as an access token, or the reverse), and,
given the record's time, a token whose ``nbf`` is after it (RFC 7519, section 4.1.5).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .core import (
    TOKEN_MAX_DEPTH,
    admitted_loads,
    ascii_lower,
    canonical,
    exact_int,
    sha256_hex,
)
from .grants import micros, ts

#: Every JWK member that carries private key material: the members of the IANA "JSON Web Key Parameters" registry whose
#: information class is Private. RFC 7518 section 6.2.2 (EC ``d``), section 6.3.2 (RSA ``d``, ``p``, ``q``, ``dp``,
#: ``dq``, ``qi`` and ``oth``, the other primes of a multi-prime key), section 6.4.1 (``k``), RFC 8037 section 2 (OKP
#: ``d``) and the AKP key type's ``priv``. Every reader that refuses private material reads this one set, and the
#: TypeScript twin is ``PRIVATE_JWK_MEMBERS`` in verify.ts; tests/test_private_jwk_members.py holds them equal.
PRIVATE_JWK_MEMBERS: Final = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"})


class PrivateKeyMaterial(ValueError):
    """A received JWK that carries a member of ``PRIVATE_JWK_MEMBERS``: a key whose private half is published proves
    nobody holds it, and a pin on it lets anyone sign as its issuer."""


def has_private_member(jwk: object) -> bool:
    """True when ``jwk`` is a JSON object carrying any member of ``PRIVATE_JWK_MEMBERS`` (TypeScript:
    ``hasPrivateMember``). Member names are case-sensitive (RFC 7517 section 4), so ``D`` is not ``d``."""
    return isinstance(jwk, Mapping) and not PRIVATE_JWK_MEMBERS.isdisjoint(jwk)


def refuse_private(jwk: object) -> None:
    """Raise ``PrivateKeyMaterial`` for a JWK that carries private material.

    Every reader of a received JWK goes through this by construction: ``public_jwk`` calls it first, and
    ``jwk_thumbprint`` and every signature check read key bytes only through ``public_jwk``.
    tests/test_private_jwk_members.py finds every function that reads a JWK and refuses each member through it."""
    if has_private_member(jwk):
        raise PrivateKeyMaterial("a JWK carries private key material")

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
#: The JOSE ``typ`` values that name one credential type (``application/`` prefix and case ignored, RFC 7515
#: section 4.1.9): an identity assertion grant (draft-ietf-oauth-identity-assertion-authz-grant) and an RFC 9068
#: access token. A token whose ``typ`` names another source than the principal states is refused.
TYP_SOURCES = {"oauth-id-jag+jwt": "id-jag", "at+jwt": "jwt-access-token"}
#: The containers an issuer's pinned thumbprints may come in; a string is never one (``in`` would search it).
PIN_SETS = (set, frozenset, list, tuple)
THUMBPRINT_MEMBERS = {"RSA": ("e", "kty", "n"), "EC": ("crv", "kty", "x", "y"), "OKP": ("crv", "kty", "x")}
#: The fewest principals an approver list holds: one approval takes the single form.
APPROVER_LIST_MIN = 2


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: object) -> bytes:
    """The bytes of one unpadded base64url segment; ``ValueError`` unless ``text`` is its canonical spelling.

    Only the canonical text of each segment is read: ``base64.urlsafe_b64decode`` alone skips a space, a newline or
    any other byte outside the alphabet and accepts a last digit with stray low bits, so one token would have many
    spellings, many digests, and a different answer from a reader that decodes strictly. The TypeScript twin's
    ``strictB64url`` applies the same rule. ``text`` is typed ``object`` because callers pass received JSON values
    unread; anything but a ``str`` is a ``ValueError``.
    """
    if not isinstance(text, str) or not text.isascii() or "=" in text:
        raise ValueError("not unpadded ASCII base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))  # binascii.Error is a ValueError
    if b64url(data) != text:
        raise ValueError("not the canonical base64url of its bytes")
    return data


# The coordinate or key bytes of each curve these readers verify (RFC 7518 section 6.2.1.2, RFC 8037 section 2).
CURVE_BYTES = {("EC", "P-256"): 32, ("OKP", "Ed25519"): 32}


def public_jwk(jwk: Mapping[str, Any]) -> dict[str, bytes]:
    """The key bytes of a public JWK these readers verify; ``ValueError`` unless every key member has one spelling.

    Each of ``x``, ``y``, ``n`` and ``e`` is read with ``unb64url``, so only its canonical base64url counts. An EC
    coordinate is the full size of its curve (RFC 7518 section 6.2.1.2: "MUST be the full size of a coordinate"), an
    Ed25519 ``x`` is 32 bytes, and RSA ``n`` and ``e`` use the minimum number of octets (RFC 7518 section 2,
    Base64urlUInt: no leading zero octet). Without this one key has several spellings, several RFC 7638
    thumbprints, and a pin or a duplicate check keyed on the thumbprint can be stepped around. A key carrying a
    member of ``PRIVATE_JWK_MEMBERS`` is ``PrivateKeyMaterial``.
    """
    refuse_private(jwk)
    kty = jwk.get("kty")
    if kty == "RSA":
        n, e = unb64url(jwk.get("n")), unb64url(jwk.get("e"))
        if not n or not e or n[0] == 0 or e[0] == 0:
            raise ValueError("an RSA n or e is not the minimum number of octets")
        return {"n": n, "e": e}
    crv = jwk.get("crv")
    # A received kty or crv may be any JSON value; only a string names a curve (a list would not even hash).
    size = CURVE_BYTES.get((kty, crv)) if isinstance(kty, str) and isinstance(crv, str) else None
    if size is None:
        raise ValueError("jwk_unsupported")
    out = {m: unb64url(jwk.get(m)) for m in (("x", "y") if kty == "EC" else ("x",))}
    if any(len(v) != size for v in out.values()):
        raise ValueError("a key coordinate is not the full size of its curve")
    return out


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint, base64url without padding, of a key ``public_jwk`` reads; else ``ValueError``.

    A thumbprint names one key, so it exists only for the one spelling of that key, and never for a key that carries
    private material."""
    refuse_private(jwk)
    kty = jwk.get("kty")
    members = THUMBPRINT_MEMBERS.get(kty) if isinstance(kty, str) else None  # only a string names a key type
    if members is None or any(m not in jwk for m in members):
        raise ValueError("jwk_unsupported")
    public_jwk(jwk)
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
    if not isinstance(p["key"], dict) or has_private_member(p["key"]):
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
    if not isinstance(pinned, PIN_SETS) or thumb not in pinned:
        return "principal_key_not_pinned"
    if "act" in p and _act_subjects(p["act"]) is None:
        return "principal_act_malformed"
    return None


def approver_principals(block: Mapping[str, Any]) -> list[Any]:
    """The approver principals a block names, in the writer's order: none, the single form's one, or a list's
    members."""
    named = block.get("approver")
    if named is None:
        return []
    return list(named) if isinstance(named, list) else [named]


def approver_subjects(block: Mapping[str, Any]) -> set[str]:
    """The subjects of the approvers a block names (call only on a block whose approvers passed their checks)."""
    return {p["subject"] for p in approver_principals(block)}


def _role_problems(block: Mapping[str, Any], role: str, at: str, pins: Mapping[str, Any]) -> list[str]:
    """``principal_<role>:<code>`` for each principal of ``role`` that fails the principal checks, the approver list's
    own refusals (too short, a subject twice), or nothing."""
    if role == "approver" and isinstance(block["approver"], list):
        members = block["approver"]
        if len(members) < APPROVER_LIST_MIN:
            return ["principal_approver_list_too_short"]
        found = [f"principal_approver:{prob}" for m in members for prob in [check_principal(m, at, pins)] if prob]
        if found:
            return found
        return ["principal_approver_duplicate"] if len({m["subject"] for m in members}) != len(members) else []
    prob = check_principal(block[role], at, pins)
    problems: list[str] = []
    if prob:
        problems.append(f"principal_{role}:{prob}")
    return problems


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
                      counted: set[str] | None, sponsors: Mapping[str, Any] | None,
                      standing_grants: Mapping[str, Mapping[str, Any]]) -> tuple[list[str], str | None]:  # fmt: skip
    if "user" in block:
        return ["principals_autonomous_has_user"], None
    problems = [code for code, member in
                (("principals_need_agent", "agent"), ("principals_need_sponsor", "sponsor"),
                 ("principals_need_session", "session"), ("principals_need_standing_grant", "standingGrant"))
                if member not in block]  # fmt: skip
    if problems:
        return problems, None
    grant = standing_grants.get(block["standingGrant"]) if isinstance(block["standingGrant"], str) else None
    for role in ("agent", "approver"):
        if role in block:
            problems += _role_problems(block, role, at, pins)
    # The sponsor answered for the grant when it was issued: with no resolved grant there is no such instant, and
    # the grant's own refusal below is the reason the block falls.
    prob = None if grant is None or "notBefore" not in grant else check_principal(block["sponsor"],
                                                                                 str(grant["notBefore"]), pins)
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
    named = approver_subjects(block)
    if "approver" in block and approvers is None:
        problems.append("principal_approver_without_approval")
    elif approvers is not None and "approver" not in block:
        problems.append("principals_need_approver")
    elif "approver" in block and approvers is not None and not named <= approvers:
        problems.append("principal_approver_not_an_approval_signer")
    elif counted and not counted <= named:
        problems.append("principals_need_every_approver")
    return (problems, None) if problems else ([], "autonomous")


def check_principals(block: Any, at: str, pins: Mapping[str, Any], approvers: set[str] | None = None, *,
                     counted: set[str] | None = None, sponsors: Mapping[str, Any] | None = None,
                     standing_grants: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[list[str], str | None]:
    """(problems, grade) for one record's ``principals``. Grade is ``strict``, ``basic`` or ``autonomous``; None
    when a problem refuses the block.

    ``approvers`` are the people the block may name as approver; ``counted`` are the people the approval counted,
    whom strict (and an autonomous block) needs every one of named. For an allow the two are the same set, the
    default (``counted`` None). A deny counts nobody: its ``approvers`` are the people whose binding it carries and
    its ``counted`` is empty, so a deny naming one of two such people is graded as it was before the list form.

    ``sponsors`` is the registry the auditor pins: agent client id to the (issuer, subject) pairs registered as its
    sponsors. ``standing_grants`` maps a grant digest to a grant body the caller verified against its own pinned
    grant roots (``grants.chain_digests``); nothing in the record chooses either."""
    if not isinstance(block, dict) or not block or set(block) - set(ROLES) - set(AUTONOMOUS):
        return ["principals_malformed"], None
    if set(block) & set(AUTONOMOUS):
        return _check_autonomous(block, at, pins, approvers, approvers if counted is None else counted, sponsors,
                                 standing_grants or {})
    problems = [found for role in ROLES if role in block for found in _role_problems(block, role, at, pins)]
    if "user" not in block or "agent" not in block:
        problems.append("principals_need_user_and_agent")
    if problems:
        return problems, None
    user, agent = block["user"], block["agent"]
    chain = _act_subjects(user.get("act")) if "act" in user else []
    if chain and chain[0] not in (agent["subject"], agent["clientId"]):
        return ["principal_act_names_another_agent"], None
    if "approver" in block:
        if not approvers:
            return ["principal_approver_without_approval"], None
        if not approver_subjects(block) <= approvers:
            return ["principal_approver_not_an_approval_signer"], None
    return [], "basic" if strict_shortfall(block, approvers, counted) else "strict"


def strict_shortfall(block: Mapping[str, Any], approvers: set[str] | None,
                     counted: set[str] | None = None) -> str | None:
    """What keeps a human-session block that passed from ``strict``: ``act-absent`` (the user credential names no
    agent in ``act``), ``sponsor-absent``, ``approver-absent`` (an approval admitted the call and the block does not
    name who gave it), or ``approvers-partial`` (it names some of the approvers the approval counts, not all); None
    when it is strict. ``approver-absent`` reads ``approvers``, the people the block may name; ``approvers-partial``
    reads ``counted``, the people the approval counted (default: ``approvers``; empty for a deny, which counts
    nobody). The gateway writer applies the same rule."""
    if "act" not in block.get("user", {}):
        return "act-absent"
    if "sponsor" not in block:
        return "sponsor-absent"
    if approvers and "approver" not in block:
        return "approver-absent"
    counted = approvers if counted is None else counted
    if counted and not counted <= approver_subjects(block):
        return "approvers-partial"
    return None


def act_grade(block: Mapping[str, Any]) -> str:
    return "act-chain" if "act" in block.get("user", {}) else "act-absent"


def _verify_jws(alg: str, jwk: Mapping[str, Any], signing_input: bytes, sig: bytes) -> bool:
    try:
        raw = public_jwk(jwk)
        if alg == "EdDSA" and jwk.get("kty") == "OKP":
            Ed25519PublicKey.from_public_bytes(raw["x"]).verify(sig, signing_input)
        elif alg == "ES256" and jwk.get("kty") == "EC":
            point = ec.EllipticCurvePublicNumbers(int.from_bytes(raw["x"], "big"), int.from_bytes(raw["y"], "big"),
                                                  ec.SECP256R1()).public_key()  # fmt: skip
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            point.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        elif alg == "RS256" and jwk.get("kty") == "RSA":
            rsa_key = rsa.RSAPublicNumbers(int.from_bytes(raw["e"], "big"), int.from_bytes(raw["n"], "big")).public_key()
            rsa_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True


def _iso(seconds: int) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


_B64URL_SEGMENT: Final = re.compile(r"[A-Za-z0-9_-]*")
#: The whole seconds of years 1 to 9999, the range both readers print a time claim in the same way.
_CLAIM_TIME_RANGE: Final = (-62135596800, 253402300799)


def token_segments(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes] | None:
    """A compact JWS read strictly: its header, its claims and its signature bytes, or None when it is not one.

    Three segments of the base64url alphabet without padding; the header and the claims each one JSON object that
    jcs-admit admits (no duplicate member, no ``NaN`` or ``Infinity``, valid UTF-8, no lone surrogate), parsed with
    integers and floats kept apart. The TypeScript twin's ``tokenSegments`` reads a token by the same rules, so a token a
    provider signed is one value to both readers."""
    parts = token.split(".")
    if len(parts) != 3 or not all(_B64URL_SEGMENT.fullmatch(s) and len(s) % 4 != 1 for s in parts):
        return None
    try:
        header = admitted_loads(unb64url(parts[0]), max_depth=TOKEN_MAX_DEPTH)
        claims = admitted_loads(unb64url(parts[1]), max_depth=TOKEN_MAX_DEPTH)
        signature = unb64url(parts[2])  # a signature in a second spelling (stray low bits) is not a compact JWS either
    except ValueError:
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return None
    return header, claims, signature


def _claim_time(claims: Mapping[str, Any], name: str) -> str | None:
    """A token time claim (``iat``, ``exp``) as its principal field prints it, ``1970-01-01T00:00:00Z`` when absent;
    None when it is not an integer number of seconds (a float, ``1.0`` included, a string, a boolean, null) within
    years 1 to 9999."""
    value = claims.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int) or not _CLAIM_TIME_RANGE[0] <= value <= _CLAIM_TIME_RANGE[1]:
        return None
    return _iso(value)


def verify_token(p: Mapping[str, Any], token: str, jwks: Mapping[str, Any], at: str | None = None) -> str | None:
    """None when ``token`` is the credential ``p`` names, its JWS verifies under the key ``p`` names,
    that key is in the JWKS snapshot whose digest ``p`` carries, its ``typ`` names no other credential
    type than ``p``'s ``source``, and every stated claim matches. With ``at`` (the record's time), a token
    whose ``nbf`` is after ``at`` is refused as not yet valid."""
    if not isinstance(token, str) or not token.isascii():  # received text: refused before it is hashed or read
        return "token_malformed"
    if sha256_hex(token.encode("ascii")) != p.get("tokenDigest"):
        return "token_digest_mismatch"
    if jwks_digest(jwks) != p.get("jwksDigest"):
        return "jwks_digest_mismatch"
    if dict(p.get("key", {})) not in [dict(k) for k in jwks.get("keys", [])]:
        return "key_not_in_jwks"
    segments = token_segments(token)
    if segments is None:
        return "token_malformed"
    header, claims, signature = segments
    if "crit" in header:  # RFC 7515 section 4.1.11: a verifier that implements no extension refuses one that is demanded
        return "token_critical_unsupported"
    head_b64, body_b64, _ = token.split(".")
    if header.get("kid") != p.get("kid"):
        return "token_kid_mismatch"
    if p.get("source") == "id-jag" and header.get("typ") != "oauth-id-jag+jwt":
        return "token_typ_not_id_jag"
    # Type first: a typ or an alg that is not a string names nothing, in either reader.
    typ, alg = header.get("typ"), header.get("alg")
    named = TYP_SOURCES.get(ascii_lower(typ).removeprefix("application/")) if isinstance(typ, str) else None
    if named is not None and named != p.get("source"):
        return f"token_type_mismatch:{named}"
    if not isinstance(alg, str) or not _verify_jws(alg, p["key"], f"{head_b64}.{body_b64}".encode(), signature):
        return "token_signature_unverified"
    aud = claims.get("aud")
    # An ID token names its client in ``azp`` (OpenID Connect Core 1.0, section 2); an access token in ``client_id``.
    client = claims.get("client_id") or (claims.get("azp") if p.get("source") == "id-token" else None)
    issued, expires = _claim_time(claims, "iat"), _claim_time(claims, "exp")
    if issued is None or expires is None:
        return "token_malformed"
    expected = {"issuer": claims.get("iss"), "subject": claims.get("sub"), "clientId": client,
                "audience": aud if isinstance(aud, list) else [aud], "issuedAt": issued, "expiresAt": expires}
    for member, value in expected.items():
        if p.get(member) != value:
            return f"token_claim_mismatch:{member}"
    if claims.get("act") != p.get("act"):
        return "token_claim_mismatch:act"
    if claims.get("cnf") != p.get("cnf"):
        return "token_claim_mismatch:cnf"
    if at is not None and "nbf" in claims:
        nbf = claims["nbf"]
        if not exact_int(nbf):
            return "token_malformed"
        if nbf * 1_000_000 > micros(at):
            return "token_not_yet_valid"
    return None


def possession_grade(block: Mapping[str, Any]) -> str:
    """``sender-constrained`` when the agent's credential confirms a key (RFC 7800 ``cnf``), else ``bearer``:
    a bearer credential is usable by whoever copies it."""
    return "sender-constrained" if "cnf" in block.get("agent", {}) else "bearer"
