"""``audit_principal/v1``: does this signed audit record carry a conforming authenticated principal?

An agent audit record may carry an optional ``principal`` member: the identity provider's
authenticated principal that the decision point established before it let the agent act. The claim:
this DSSE envelope is an agent audit record under the observer key the consumer pinned, its
``principal`` member is well formed, and it is bound to the record by hash (``tokenDigest`` equals
``agent.credentialDigest``), to the delegation by subject, to the decision by lifetime, and to the
issuer's key by RFC 7638 thumbprint. The rules, their order and their refusal codes are a port of
probityai/agent-evidence-vectors, ``packaging/agent_evidence_vectors/auditrecord.py``
(``_rule_principal`` and the helpers it calls), vectors PR1 to PR11 of
``corpora/vectors-agent-audit-record``, which tests/data/audit-principal copies.

Only the ``principal`` rule and the signature are checked. The rest of the record's rules belong to
the full audit-record reader and are not repeated here. Rule order is load-bearing: the first
refusal is the code a corpus member pins, and the signature is checked last, after every rule that
reads carried bytes only, as in ``observed_effect/v1``.

Decisions: a record with a conforming principal and a valid signature is ``supported`` /
``principal_conforms``; a record without a ``principal`` member is ``not_established`` /
``principal_absent``; any refusal is ``contradicted`` with its code as the reason. The check keeps
the verdict, ``malformed`` (a defect in the carried bytes) or ``invalid`` (a coherent record whose
signature fails).
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..common import _digest
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "audit_principal/v1"
PREDICATE_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-audit-record"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
LIMIT = ("Checks the principal member's shape and bindings and the envelope signature under the "
         "pinned observer key. It does not establish that the identity provider issued the token, "
         "that the issuer's key is the one in the snapshot, or that the rest of the record "
         "conforms: the token and the JWKS are not carried.")

#: I-JSON's safe-integer bound; the profile refuses a larger integer, a float, a repeated member
#: name and a nesting past 128 levels, as the reference reader does.
IJSON_LIMIT = 2**53
MAX_DEPTH = 128
#: The clock-skew tolerance of the draft, in seconds, around the decision's ``reportedAt``.
SKEW_TOLERANCE = datetime.timedelta(seconds=300)

PRINCIPAL_MEMBERS = (
    "issuer", "subject", "clientId", "audience", "authMethod", "source", "tokenDigest",
    "issuedAt", "expiresAt", "kid", "key", "keyThumbprint", "jwksDigest",
)
PRINCIPAL_OPTIONAL = ("tenant",)
#: IANA "OAuth Token Endpoint Authentication Methods" as RFC 7591 and RFC 8705 populate it.
PRINCIPAL_AUTH_METHODS = frozenset({
    "none", "client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt",
    "tls_client_auth", "self_signed_tls_client_auth",
})
#: An RFC 9068 access token, an OpenID Connect ID token, or an RFC 7523 assertion.
PRINCIPAL_SOURCES = frozenset({"jwt-access-token", "id-token", "jwt-assertion"})
#: The members RFC 7638 Section 3.2 hashes, by key type (RSA and EC from RFC 7638, OKP from RFC 8037).
THUMBPRINT_MEMBERS: dict[str, tuple[str, ...]] = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}
#: Members that make a JWK a private key; ``key`` is the issuer's public key.
JWK_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class Malformed(Exception):
    """A defect in the carried bytes. Reached before any trust input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class Report:
    """One verification: the verdict, the single first refusal, and whether a principal was read."""

    verdict: str
    codes: list[str]
    principal_present: bool = field(default=True)


def _pae(payload_type: str, payload: bytes) -> bytes:
    """The DSSE pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(kind), kind, len(payload), payload)


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Malformed("duplicate-member")
        out[key] = value
    return out


def _safe_int(text: str) -> int:
    value = int(text)
    if abs(value) >= IJSON_LIMIT:
        raise Malformed("unsafe-integer")
    return value


def _refuse_float(text: str) -> float:
    raise Malformed("value-not-representable")


def _no_constant(token: str) -> Any:
    raise Malformed("not-parseable")


def _depth(node: Any) -> int:
    if isinstance(node, dict):
        return 1 + max((_depth(v) for v in node.values()), default=0)
    if isinstance(node, list):
        return 1 + max((_depth(v) for v in node), default=0)
    return 0


def _parse(raw: bytes) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    """The envelope, the payload bytes and the statement, under the JSON profile."""
    try:
        envelope = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_int=_safe_int,
            parse_float=_refuse_float, parse_constant=_no_constant)
    except Malformed:
        raise
    except (KeyError, TypeError, ValueError, binascii.Error, RecursionError) as error:
        raise Malformed("not-parseable") from error
    if not isinstance(envelope, dict) or not isinstance(statement, dict):
        raise Malformed("not-parseable")
    if _depth(statement) > MAX_DEPTH:
        raise Malformed("nesting-too-deep")
    return envelope, payload, statement


def _text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _is_digest(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _instant(value: Any) -> datetime.datetime:
    if not isinstance(value, str):
        raise Malformed("timestamp-malformed")
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError as error:
        raise Malformed("timestamp-malformed") from error
    if parsed.tzinfo is None:
        raise Malformed("timestamp-malformed")
    return parsed


def jwk_thumbprint(key: dict[str, Any]) -> str:
    """The RFC 7638 SHA-256 thumbprint of a public JWK, base64url without padding."""
    body = {name: key[name] for name in THUMBPRINT_MEMBERS[key["kty"]]}
    canonical = jcs_canonical.canonical("rfc8785", json.dumps(body, ensure_ascii=False))
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode("ascii")


def _key_shape(key: Any) -> None:
    if not isinstance(key, dict) or key.get("kty") not in THUMBPRINT_MEMBERS:
        raise Malformed("principal-malformed")
    if set(key) & JWK_PRIVATE_MEMBERS:
        raise Malformed("principal-malformed")
    if not all(_text(key.get(name)) for name in THUMBPRINT_MEMBERS[key["kty"]]):
        raise Malformed("principal-malformed")


def _issuer_audience(principal: dict[str, Any]) -> None:
    issuer = principal["issuer"]
    if not isinstance(issuer, str) or not issuer.startswith("https://") or len(issuer) == 8:
        raise Malformed("principal-malformed")
    audience = principal["audience"]
    if (not isinstance(audience, list) or not audience
            or not all(_text(item) for item in audience) or len(set(audience)) != len(audience)):
        raise Malformed("principal-malformed")


def _shape(principal: Any) -> None:
    if not isinstance(principal, dict):
        raise Malformed("principal-malformed")
    if any(name not in principal for name in PRINCIPAL_MEMBERS):
        raise Malformed("principal-member-missing")
    if set(principal) - set(PRINCIPAL_MEMBERS) - set(PRINCIPAL_OPTIONAL):
        raise Malformed("principal-member-unknown")
    if not all(_text(principal[name]) for name in ("subject", "clientId", "kid", "keyThumbprint")):
        raise Malformed("principal-malformed")
    _issuer_audience(principal)
    if principal["authMethod"] not in PRINCIPAL_AUTH_METHODS:
        raise Malformed("principal-malformed")
    if principal["source"] not in PRINCIPAL_SOURCES:
        raise Malformed("principal-malformed")
    if not _is_digest(principal["tokenDigest"]) or not _is_digest(principal["jwksDigest"]):
        raise Malformed("principal-malformed")
    if "tenant" in principal and not _text(principal["tenant"]):
        raise Malformed("principal-malformed")
    _key_shape(principal["key"])


def _lifetime(principal: dict[str, Any], reported_at: Any) -> None:
    """Issued no later than the decision and not expired at it, each within the skew tolerance."""
    try:
        issued = _instant(principal["issuedAt"])
        expires = _instant(principal["expiresAt"])
    except Malformed as error:
        raise Malformed("principal-malformed") from error
    if expires <= issued:
        raise Malformed("principal-malformed")
    decided = _instant(reported_at)
    if issued - decided > SKEW_TOLERANCE:
        raise Malformed("principal-not-yet-valid")
    if decided - expires > SKEW_TOLERANCE:
        raise Malformed("principal-expired")


def _rules(predicate: dict[str, Any]) -> None:
    """The principal rule, in the reference reader's order."""
    principal = predicate["principal"]
    _shape(principal)
    delegation = predicate["delegation"]
    if delegation["subjectKind"] == "user" and principal["subject"] != delegation["subject"]:
        raise Malformed("principal-subject-mismatch")
    if principal["tokenDigest"] != predicate["agent"]["credentialDigest"]:
        raise Malformed("principal-credential-unbound")
    _lifetime(principal, predicate["decision"]["reportedAt"])
    if principal["key"].get("kid") != principal["kid"]:
        raise Malformed("principal-kid-mismatch")
    if principal["keyThumbprint"] != jwk_thumbprint(principal["key"]):
        raise Malformed("principal-thumbprint-mismatch")


def verify(raw: bytes, observer_public_key: str) -> Report:
    """Judge the principal of one DSSE envelope carrying an agent audit record statement."""
    try:
        envelope, payload, statement = _parse(raw)
        if statement.get("_type") != STATEMENT_TYPE:
            raise Malformed("statement-type-unexpected")
        if statement.get("predicateType") != PREDICATE_TYPE:
            raise Malformed("predicate-type-unexpected")
        predicate = statement.get("predicate")
        if not isinstance(predicate, dict):
            raise Malformed("unhandled-shape:predicate")
        if "principal" not in predicate:
            return Report("absent", ["principal-absent"], principal_present=False)
        _rules(predicate)
    except Malformed as error:
        return Report("malformed", [error.code])
    except (KeyError, TypeError) as error:
        return Report("malformed", [f"unhandled-shape:{error.__class__.__name__}"])
    try:
        signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
        public_key = bytes.fromhex(observer_public_key)
    except (KeyError, IndexError, TypeError, ValueError, binascii.Error):
        return Report("malformed", ["envelope-signature-unreadable"])
    if len(public_key) != 32 or not isinstance(envelope.get("payloadType"), str):
        return Report("malformed", ["envelope-signature-unreadable"])
    if not _ed25519_verify(public_key, _pae(envelope["payloadType"], payload), signature):
        return Report("invalid", ["envelope-signature-invalid"])
    return Report("valid", [])


def report_check(report: Report) -> dict[str, Any]:
    """The verdict and the first refusal a consumer may read from one verification."""
    return {"id": "audit_principal_rules", "status": "pass" if report.verdict == "valid" else "fail",
            "verdict": report.verdict, "codes": report.codes}


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge the principal of one bound audit record envelope under the consumer's pinned key."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"envelope", "observer_public_key"})
    key = _digest(assessment["observer_public_key"], "assessment.observer_public_key")
    raw, binding = bound(artifacts, artifact_root, assessment["envelope"], "assessment.envelope")
    scope = {"envelope": binding, "predicate_type": PREDICATE_TYPE, "observer_public_key": key,
             "limit": LIMIT}
    if raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "envelope_unavailable")
    report = verify(raw, key)
    check = report_check(report)
    if report.verdict == "absent":
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "principal_absent", [check])
    if report.verdict != "valid":
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", report.codes[0], [check])
    return decision(case_id, CLAIM_TYPE, scope, "supported", "principal_conforms", [check])

