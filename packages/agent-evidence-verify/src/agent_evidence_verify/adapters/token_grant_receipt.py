"""``token_grant_receipt/v1``: did the identity provider record this token grant as the consumer expects?

An identity provider that runs the Keycloak evidence hook writes one DSSE envelope per completed
token exchange, client credentials grant or CIBA grant. The envelope carries an in-toto Statement
whose ``predicateType`` is :data:`PREDICATE_TYPE`; its subject is the SHA-256 of the issued access
token's ``jti``, and its predicate names the issuer, the grant type, the client that asked (the
actor), the user the token names, the presented subject token by digest, the audience and the
scope. No token value is carried.

The claim is checked in this order:

1. The envelope is parsed strictly (canonical padded base64, one payload type).
2. A signature verifies under the recorder key the consumer pinned. Otherwise the decision is
   ``not_established``: the pinned key does not establish the record, which says nothing about
   the grant.
3. The statement is read under a strict JSON profile (no repeated member, no float, closed member
   sets). A malformed signed record raises :class:`CaseError`.
4. When the consumer supplies the recorder's log, every line must verify under the same key and
   the hash chain must hold from the first line to the last, and the envelope must be one of its
   lines. A broken chain is ``not_established`` with reason ``receipt_log_unestablished``.
5. Each expectation the consumer pinned is compared with the record. Every comparison is reported
   as a check; the first that fails names the reason, and the decision is ``contradicted``.

``supported`` means the pinned key signed a receipt for this grant that matches every pinned
expectation. It does not establish that the identity provider's policy allowed the grant, or that
a grant the log does not show never happened unless the consumer also checks the log's completeness.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..common import CaseError, _digest, _object, _string
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "token_grant_receipt/v1"
PREDICATE_TYPE = "https://w3id.org/agent-evidence/predicate/v1/token-grant-receipt"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
SUBJECT_NAME = "access-token-id"
GRANT_TYPES = frozenset({
    "urn:ietf:params:oauth:grant-type:token-exchange",
    "client_credentials",
    "urn:openid:params:grant-type:ciba",
})
LIMIT = ("Checks a receipt the pinned recorder key signed against the consumer's expectations. It "
         "does not establish that the identity provider's policy allowed the grant, that the "
         "recorder saw every grant, or who holds the recorder key.")

PREDICATE_MEMBERS = frozenset({
    "issuer", "grantType", "eventId", "issuedAt", "actor", "subject", "subjectToken",
    "actorTokenSha256", "requestedTokenType", "audience", "scope", "refreshTokenIdSha256",
    "recorder", "chain",
})
EXPECTED_REQUIRED = frozenset({"issuer", "grant_type", "actor_client_id", "access_token_id_sha256"})
EXPECTED_OPTIONAL = frozenset({"subject_user_id", "subject_token_sha256", "audience", "scope_allowed"})
MAX_LOG_LINES = 100_000
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _b64(text: Any, label: str) -> bytes:
    if isinstance(text, str) and len(text) % 4 == 0 and _B64.fullmatch(text):
        try:
            data = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            data = None
        if data is not None and base64.b64encode(data).decode("ascii") == text:
            return data
    raise CaseError(f"{label}: expected canonical padded base64")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CaseError(f"repeated JSON member {key!r}")
        out[key] = value
    return out


def _refuse(text: str) -> Any:
    raise CaseError(f"JSON value {text!r} is outside the receipt profile")


def _strict_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_float=_refuse, parse_constant=_refuse)
    except (UnicodeDecodeError, ValueError) as error:
        raise CaseError(f"{label}: not strict UTF-8 JSON") from error


def pae(payload_type: str, payload: bytes) -> bytes:
    """The DSSE v1 pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(kind), kind, len(payload), payload)


def _envelope(raw: bytes, label: str) -> tuple[str, bytes, list[bytes]]:
    envelope = _object(_strict_json(raw, label), label, {"payload", "payloadType", "signatures"})
    kind = _string(envelope["payloadType"], f"{label}.payloadType")
    payload = _b64(envelope["payload"], f"{label}.payload")
    entries = envelope["signatures"]
    if not isinstance(entries, list) or not entries or len(entries) > 16:
        raise CaseError(f"{label}.signatures: expected 1 to 16 entries")
    signatures = []
    for index, entry in enumerate(entries):
        entry = _object(entry, f"{label}.signatures[{index}]", {"sig"}, {"keyid"})
        signatures.append(_b64(entry["sig"], f"{label}.signatures[{index}].sig"))
    return kind, payload, signatures


def _signed(key: Ed25519PublicKey, kind: str, payload: bytes, signatures: list[bytes]) -> bool:
    pre_image = pae(kind, payload)
    for signature in signatures:
        try:
            key.verify(signature, pre_image)
        except InvalidSignature:
            continue
        return True
    return False


def _text_or_null(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _string(value, label)


def _digest_or_null(value: Any, label: str) -> str | None:
    return None if value is None else _digest(value, label)


def _words(value: Any, label: str) -> list[str]:
    if (not isinstance(value, list) or not all(isinstance(item, str) and item for item in value)
            or value != sorted(set(value))):
        raise CaseError(f"{label}: expected a sorted list of distinct nonempty strings")
    return value


def _predicate(statement: Any) -> dict:
    """The predicate of a token grant receipt statement, its every member checked for shape."""
    statement = _object(statement, "statement", {"_type", "subject", "predicateType", "predicate"})
    if statement["_type"] != STATEMENT_TYPE or statement["predicateType"] != PREDICATE_TYPE:
        raise CaseError("statement: not a token grant receipt")
    subjects = statement["subject"]
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise CaseError("statement.subject: expected exactly one subject")
    subject = _object(subjects[0], "statement.subject[0]", {"name", "digest"})
    if subject["name"] != SUBJECT_NAME:
        raise CaseError(f"statement.subject[0].name: expected {SUBJECT_NAME}")
    digest = _object(subject["digest"], "statement.subject[0].digest", {"sha256"})
    p = _object(statement["predicate"], "predicate", set(PREDICATE_MEMBERS))
    _string(p["issuer"], "predicate.issuer")
    if p["grantType"] not in GRANT_TYPES:
        raise CaseError("predicate.grantType: not a recorded grant type")
    _string(p["eventId"], "predicate.eventId")
    if not isinstance(p["issuedAt"], str) or not _INSTANT.fullmatch(p["issuedAt"]):
        raise CaseError("predicate.issuedAt: expected RFC 3339 UTC to whole seconds")
    actor = _object(p["actor"], "predicate.actor", {"clientId", "authMethod"})
    _string(actor["clientId"], "predicate.actor.clientId")
    _text_or_null(actor["authMethod"], "predicate.actor.authMethod")
    _string(_object(p["subject"], "predicate.subject", {"userId"})["userId"], "predicate.subject.userId")
    if p["subjectToken"] is not None:
        token = _object(p["subjectToken"], "predicate.subjectToken", {"sha256", "issuedTo"})
        _digest(token["sha256"], "predicate.subjectToken.sha256")
        _text_or_null(token["issuedTo"], "predicate.subjectToken.issuedTo")
    _digest_or_null(p["actorTokenSha256"], "predicate.actorTokenSha256")
    _text_or_null(p["requestedTokenType"], "predicate.requestedTokenType")
    _words(p["audience"], "predicate.audience")
    _words(p["scope"], "predicate.scope")
    _digest_or_null(p["refreshTokenIdSha256"], "predicate.refreshTokenIdSha256")
    recorder = _object(p["recorder"], "predicate.recorder", {"id", "version", "keyId"})
    for name in ("id", "version"):
        _string(recorder[name], f"predicate.recorder.{name}")
    _digest(recorder["keyId"], "predicate.recorder.keyId")
    chain = _object(p["chain"], "predicate.chain", {"stream", "index", "previous"})
    _string(chain["stream"], "predicate.chain.stream")
    if type(chain["index"]) is not int or chain["index"] < 0:
        raise CaseError("predicate.chain.index: expected a nonnegative integer")
    _digest_or_null(chain["previous"], "predicate.chain.previous")
    return {**p, "accessTokenIdSha256": _digest(digest["sha256"], "statement.subject[0].digest.sha256")}


def _read_receipt(raw: bytes, key: Ed25519PublicKey, label: str) -> tuple[bool, dict | None]:
    """Whether the pinned key signed the envelope, and its predicate when it did."""
    kind, payload, signatures = _envelope(raw, label)
    if not _signed(key, kind, payload, signatures):
        return False, None
    if kind != PAYLOAD_TYPE:
        raise CaseError(f"{label}.payloadType: expected {PAYLOAD_TYPE}")
    return True, _predicate(_strict_json(payload, f"{label}.payload"))


def _log_check(log: bytes, envelope: bytes, key: Ed25519PublicKey) -> dict:
    """Every log line signed by the pinned key and chained to the one before it."""
    check: dict[str, Any] = {"id": "receipt_log", "status": "met"}
    lines = log.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if not lines or len(lines) > MAX_LOG_LINES:
        return {**check, "status": "failed", "detail": "the log holds no line or too many lines"}
    previous: str | None = None
    stream: str | None = None
    first_index: int | None = None
    for number, line in enumerate(lines):
        try:
            signed, predicate = _read_receipt(line, key, f"log line {number}")
        except CaseError as error:
            return {**check, "status": "failed", "line": number, "detail": str(error)}
        if not signed or predicate is None:
            return {**check, "status": "failed", "line": number, "detail": "signature does not verify"}
        chain = predicate["chain"]
        if number == 0:
            stream, first_index = chain["stream"], chain["index"]
            if (first_index == 0) != (chain["previous"] is None):
                return {**check, "status": "failed", "line": 0, "detail": "chain start is inconsistent"}
        elif (chain["stream"] != stream or chain["index"] != first_index + number
              or chain["previous"] != previous):
            return {**check, "status": "failed", "line": number, "detail": "chain link broken"}
        previous = hashlib.sha256(line).hexdigest()
    if envelope.rstrip(b"\n") not in lines:
        return {**check, "status": "failed", "detail": "the envelope is not a line of the log"}
    return {**check, "lines": len(lines), "stream": stream, "first_index": first_index,
            "head_sha256": previous}


def _expected(value: Any) -> dict:
    expected = _object(value, "assessment.expected", set(EXPECTED_REQUIRED), set(EXPECTED_OPTIONAL))
    for name in ("issuer", "grant_type", "actor_client_id", "subject_user_id"):
        if name in expected:
            _string(expected[name], f"assessment.expected.{name}")
    for name in ("access_token_id_sha256", "subject_token_sha256"):
        if name in expected:
            _digest(expected[name], f"assessment.expected.{name}")
    for name in ("audience", "scope_allowed"):
        if name in expected:
            _words(sorted(set(expected[name])) if isinstance(expected[name], list) else expected[name],
                   f"assessment.expected.{name}")
    return expected


def _comparisons(expected: dict, p: dict) -> list[tuple[str, str, Any, Any, bool]]:
    """``(field, reason, expected, observed, holds)`` for each pinned expectation."""
    token = p["subjectToken"] or {}
    rows = [
        ("issuer", "grant_issuer_mismatch", expected["issuer"], p["issuer"]),
        ("grant_type", "grant_type_mismatch", expected["grant_type"], p["grantType"]),
        ("actor_client_id", "grant_actor_mismatch", expected["actor_client_id"], p["actor"]["clientId"]),
        ("access_token_id_sha256", "grant_token_mismatch", expected["access_token_id_sha256"],
         p["accessTokenIdSha256"]),
    ]
    if "subject_user_id" in expected:
        rows.append(("subject_user_id", "grant_subject_mismatch", expected["subject_user_id"],
                     p["subject"]["userId"]))
    if "subject_token_sha256" in expected:
        rows.append(("subject_token_sha256", "grant_subject_token_mismatch",
                     expected["subject_token_sha256"], token.get("sha256")))
    if "audience" in expected:
        rows.append(("audience", "grant_audience_mismatch", sorted(set(expected["audience"])), p["audience"]))
    out = [(name, reason, want, seen, want == seen) for name, reason, want, seen in rows]
    if "scope_allowed" in expected:
        allowed = sorted(set(expected["scope_allowed"]))
        out.append(("scope_allowed", "grant_scope_exceeds_expected", allowed, p["scope"],
                    set(p["scope"]) <= set(allowed)))
    return out


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge one bound receipt envelope under the consumer's pinned recorder key."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"envelope", "recorder_public_key", "expected"}, {"log"})
    key_hex = _digest(assessment["recorder_public_key"], "assessment.recorder_public_key")
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
    key_id = hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()
    expected = _expected(assessment["expected"])
    raw, binding = bound(artifacts, artifact_root, assessment["envelope"], "assessment.envelope")
    scope: dict[str, Any] = {"envelope": binding, "predicate_type": PREDICATE_TYPE,
                             "recorder_public_key": key_hex, "recorder_key_id": key_id,
                             "expected": expected, "limit": LIMIT}
    if raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "envelope_unavailable")
    signed, predicate = _read_receipt(raw, key, "envelope")
    signature = {"id": "receipt_signature", "status": "met" if signed else "failed", "key_id": key_id}
    if not signed or predicate is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "receipt_signature_unverified",
                        [signature])
    if predicate["recorder"]["keyId"] != key_id:
        raise CaseError("predicate.recorder.keyId: names a key other than the one that signed it")
    checks = [signature]
    if "log" in assessment:
        log, log_binding = bound(artifacts, artifact_root, assessment["log"], "assessment.log")
        scope["log"] = log_binding
        if log is None:
            return decision(case_id, CLAIM_TYPE, scope, "not_established", "receipt_log_unavailable", checks)
        log_check = _log_check(log, raw, key)
        checks.append(log_check)
        if log_check["status"] != "met":
            return decision(case_id, CLAIM_TYPE, scope, "not_established", "receipt_log_unestablished",
                            checks)
    scope["record"] = {"event_id": predicate["eventId"], "issued_at": predicate["issuedAt"],
                       "chain": predicate["chain"]}
    failed = None
    for name, reason, want, seen, holds in _comparisons(expected, predicate):
        checks.append({"id": f"expected_{name}", "status": "met" if holds else "failed",
                       "expected": want, "observed": seen})
        if not holds and failed is None:
            failed = reason
    if failed is not None:
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", failed, checks)
    return decision(case_id, CLAIM_TYPE, scope, "supported", "grant_recorded_as_expected", checks)
