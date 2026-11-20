"""``evidence_digest/v1`` and ``event_log_completeness/v1``: does a digest bind the copy a consumer reads,
and is an event log the whole log?

A telemetry record commonly carries a digest of each piece of evidence, and a session log commonly links
each event to the one before it. Both fail in ways a recomputation that only asks "do the digests match"
cannot see: the digest binds a second copy of the evidence while the consumer reads the first; every
digest is removed and zero mismatches read as a pass; a body written with a repeated member hashes to
one value under a last-wins reader and means another under a first-wins reader; a digest set is signed
by a key the set carries for itself; and in a log, an event is dropped, two are swapped, a status is
flipped, a link is rewritten, a body is edited, or the tail is cut.

These claim types answer from the consumer's inputs, never from the record. They share their check
order and reason codes with ``cbor_receipt_chain/v1``: a missing record set, then the shape of each
record (a repeated member is ``no_duplicate_member``), then the signature under the key the record
carries, then ``signer_pinned`` under the key authority the consumer's policy names (the embedded key
proves nothing alone), then duplicates, then order and links, then the head the consumer kept outside
the record. The first failure is the reason.

``evidence_digest/v1``
    The consumer names the manifest of digests and, for every item it reads, the artifact holding the
    exact copy it reads. Each reference declares ``hash_alg`` and ``canonicalization`` (``rfc8785``,
    ``cbor-deterministic`` or ``raw``). The verdict is over the consumed copies: N of N must carry
    exactly one digest, and each digest must equal the declared hash of that copy's canonical bytes.
    No consumed item is ``not_established`` / ``empty_denominator``, never a pass. A reference that
    declares no canonical form is ``not_established`` / ``undeclared_canonical_form``.

``event_log_completeness/v1``
    One event per line, each an I-JSON object with ``seq`` (contiguous from the declared first value)
    and ``prev`` (SHA-256 over the RFC 8785 bytes of the event before it, the consumer's pinned
    ``first_prev`` for the first). The head is a signed ledger head in the
    ``probity-witness-ledger-head-v0`` format (``count``, ``head`` digest, ``keyid`` and an Ed25519
    signature over ``domain || 0x00 || RFC 8785 {format, count, head}``) that the consumer retained
    outside the log. The consumer's coverage boundary names the session and first sequence number the
    log is claimed to cover; an event outside it is refused. No events is ``empty_denominator``; no
    head is ``head_not_anchored``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import key_authority
from ..common import CaseError, _string
from ..ijson import IJSONError, decode_utf8, describe, parse_ijson
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision
from .cbor_receipt_chain import Malformed, decode

DIGEST_CLAIM = "evidence_digest/v1"
LOG_CLAIM = "event_log_completeness/v1"
MANIFEST_SCHEMA = "evidence-digest-manifest/v1"
HEAD_FORMAT = "probity-witness-ledger-head-v0"
CANONICAL_FORMS = ("rfc8785", "cbor-deterministic", "raw")
HASHES = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512}
HEX = frozenset("0123456789abcdef")
DIGEST_LIMIT = ("Recomputes each digest over the copy the consumer names as the one it reads. It shows "
                "that every consumed item is bound by one digest under a declared canonical form and, "
                "when signed, by a key the consumer's authority admits; it does not show that the "
                "content is true or that nothing else was consumed.")
LOG_LIMIT = ("Reads the log against the consumer's pinned first link, coverage boundary and retained "
             "signed head. It shows that the events inside the boundary form one contiguous, linked "
             "sequence ending at that head; it does not show that no event was left unrecorded by the "
             "producer, or anything about events outside the boundary.")


class _Refused(Exception):
    """A check failed: (check id, detail)."""

    def __init__(self, check: str, detail: str) -> None:
        super().__init__(detail)
        self.check, self.detail = check, detail


def _strict(data: bytes | str, label: str) -> Any:
    """Strict I-JSON: a repeated member is its own refusal, every other defect is a shape refusal."""
    try:
        return parse_ijson(data)
    except IJSONError as exc:
        check = "no_duplicate_member" if exc.code == "duplicate-member" else "record_shape"
        raise _Refused(check, f"{label}: {describe(exc)}") from exc


def _hex_digest(value: Any, size: int | None, label: str) -> str:
    if (not isinstance(value, str) or not value or set(value) - HEX
            or (size is not None and len(value) != size)):
        raise _Refused("record_shape", f"{label}: expected a lowercase hex digest")
    return value


# --- deterministic CBOR (RFC 8949 section 4.2.1), for the cbor-deterministic form -------------------

def _head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([major << 5 | arg])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if arg < 1 << (8 * size):
            return bytes([major << 5 | info]) + arg.to_bytes(size, "big")
    raise Malformed("integer out of range")


def cbor_encode(value: Any) -> bytes:
    """Core deterministic encoding: shortest arguments, definite lengths, map keys in bytewise order."""
    if value is False or value is True or value is None:
        return {False: b"\xf4", True: b"\xf5", None: b"\xf6"}[value]
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        pairs = sorted((cbor_encode(k), cbor_encode(v)) for k, v in value.items())
        return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise Malformed(f"{type(value).__name__} has no deterministic encoding")


def canonical_bytes(form: str, data: bytes, label: str) -> bytes:
    """The bytes a declared canonical form hashes, from the consumed copy's bytes, or a refusal."""
    if form == "raw":
        return data
    if form == "rfc8785":
        try:
            text = decode_utf8(data)
        except IJSONError as exc:
            raise _Refused("canonical_form", f"{label}: {describe(exc)}") from exc
        _strict(text, label)
        try:
            return jcs_canonical.canonical("rfc8785", text)
        except jcs_canonical.Refusal as exc:
            raise _Refused("canonical_form", f"{label}: {exc}") from exc
    try:
        value = decode(data)
    except Malformed as exc:
        check = "no_duplicate_member" if "repeated map key" in str(exc) else "canonical_form"
        raise _Refused(check, f"{label}: {exc}") from exc
    if cbor_encode(value) != data:
        raise _Refused("canonical_form", f"{label}: the bytes are not the deterministic encoding")
    return data


# --- shared signature and key-authority steps --------------------------------------------------------

def _authority(assessment: dict) -> Any:
    authority = assessment.get("authority")
    if authority is not None and not isinstance(authority, dict):
        raise CaseError("assessment.authority: expected a key authority object")
    return authority


def _signer(authority: Any, key: bytes, checks: list[dict]) -> str | None:
    """Ask the consumer's authority about ``key``; return a not_established reason, or None."""
    answer = key_authority.authorize(authority, key)
    checks.append(answer.check())
    if answer.outcome == key_authority.UNAUTHORIZED:
        raise _Refused("signer_pinned", f"the signing key is not admitted ({answer.reason})")
    if answer.outcome == key_authority.UNKNOWN:
        checks.append({"id": "signer_pinned", "status": "unavailable", "detail": answer.reason})
        return "signer_not_established"
    checks.append({"id": "signer_pinned", "status": "pass", "detail": answer.reason})
    return None


def _ed25519(key: bytes, signature: bytes, message: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise _Refused("signature", "the signature does not verify under the key the record carries") from exc


def _b64(text: Any, label: str, *, url: bool) -> bytes:
    if not isinstance(text, str) or not text:
        raise _Refused("record_shape", f"{label}: expected base64 text")
    try:
        if url:
            if "=" in text or set(text) - set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"):
                raise ValueError("not base64url")
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
            if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
                raise ValueError("non-canonical base64url")
            return raw
        return base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _Refused("record_shape", f"{label}: {exc}") from exc


def _finish(case_id: str, claim: str, scope: dict, checks: list[dict], run: Any) -> dict:
    try:
        result, reason = run()
    except _Refused as refused:
        checks.append({"id": refused.check, "status": "fail", "detail": refused.detail})
        return {**decision(case_id, claim, scope, "contradicted", refused.check, checks),
                "vantage": "independent"}
    return {**decision(case_id, claim, scope, result, reason, checks), "vantage": "independent"}


# --- evidence_digest/v1 ------------------------------------------------------------------------------

def _consumed_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise CaseError("assessment.consumed: expected an object of item id to case artifact name")
    return {_string(k, "assessment.consumed key"): _string(v, f"assessment.consumed.{k}")
            for k, v in value.items()}


def _reference(ref: Any, index: int) -> dict:
    label = f"refs[{index}]"
    if not isinstance(ref, dict):
        raise _Refused("record_shape", f"{label}: expected an object")
    unknown = set(ref) - {"id", "hash_alg", "canonicalization", "digest"}
    if unknown or not {"id", "hash_alg", "digest"} <= set(ref):
        raise _Refused("record_shape", f"{label}: members are id, hash_alg, canonicalization, digest")
    if not isinstance(ref["id"], str) or not ref["id"]:
        raise _Refused("record_shape", f"{label}.id: expected a string")
    if ref["hash_alg"] not in HASHES:
        raise _Refused("record_shape", f"{label}.hash_alg: expected one of {sorted(HASHES)}")
    form = ref.get("canonicalization")
    if form is not None and form not in CANONICAL_FORMS:
        raise _Refused("record_shape", f"{label}.canonicalization: expected one of {list(CANONICAL_FORMS)}")
    size = HASHES[ref["hash_alg"]]().digest_size * 2
    return {"id": ref["id"], "alg": ref["hash_alg"], "form": form,
            "digest": _hex_digest(ref["digest"], size, f"{label}.digest")}


def check_manifest(manifest_raw: bytes, consumed: dict[str, bytes | None], authority: Any,
                   require_signature: bool, checks: list[dict]) -> tuple[str, str]:
    """(decision, reason) for one digest manifest against the consumer's consumed copies."""
    manifest = _strict(manifest_raw, "manifest")
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != MANIFEST_SCHEMA
            or not isinstance(manifest.get("refs"), list)
            or set(manifest) - {"schema_version", "refs", "signature"}):
        raise _Refused("record_shape", f"manifest: expected a {MANIFEST_SCHEMA} object with refs")
    checks.append({"id": "record_shape", "status": "pass", "detail": "the manifest is strict I-JSON"})
    pending = None
    signature = manifest.get("signature")
    if signature is None:
        checks.append({"id": "signature", "status": "unavailable", "detail": "the manifest is not signed"})
        if require_signature:
            pending = "unsigned_manifest"
    else:
        if not isinstance(signature, dict) or set(signature) != {"alg", "public_key", "value"} \
                or signature["alg"] != "Ed25519":
            raise _Refused("record_shape", "manifest.signature: expected {alg: Ed25519, public_key, value}")
        key = _b64(signature["public_key"], "manifest.signature.public_key", url=True)
        body = {k: v for k, v in manifest.items() if k != "signature"}
        message = MANIFEST_SCHEMA.encode("ascii") + b"\x00" + jcs_canonical._value(body).encode("utf-8")
        _ed25519(key, _b64(signature["value"], "manifest.signature.value", url=True), message)
        checks.append({"id": "signature", "status": "pass", "detail": "the manifest signature verifies"})
        pending = _signer(authority, key, checks)
    refs = [_reference(ref, i) for i, ref in enumerate(manifest["refs"])]
    ids = [r["id"] for r in refs]
    if len(set(ids)) != len(ids):
        raise _Refused("no_duplicate_reference", "two references name the same item")
    checks.append({"id": "no_duplicate_reference", "status": "pass", "detail": "no item is referenced twice"})
    by_id = {r["id"]: r for r in refs}
    total = len(consumed)
    if total == 0:
        checks.append({"id": "coverage", "status": "unavailable", "detail": "0 of 0: the consumer names no item"})
        return "not_established", "empty_denominator"
    bound_ids = [i for i in consumed if i in by_id]
    if len(bound_ids) != total:
        missing = sorted(set(consumed) - set(bound_ids))
        raise _Refused("coverage", f"{len(bound_ids)} of {total} consumed items carry a digest; "
                       f"unbound: {missing[:5]}")
    unread = sorted(set(by_id) - set(consumed))
    checks.append({"id": "coverage", "status": "pass",
                   "detail": f"{total} of {total} consumed items carry one digest"
                   + (f"; {len(unread)} references name no consumed item" if unread else "")})
    undeclared = []
    for item_id, data in consumed.items():
        ref = by_id[item_id]
        if ref["form"] is None:
            undeclared.append(item_id)
            continue
        if data is None:
            pending = pending or "consumed_copy_unavailable"
            continue
        if HASHES[ref["alg"]](canonical_bytes(ref["form"], data, item_id)).hexdigest() != ref["digest"]:
            raise _Refused("consumed_copy_bound",
                           f"{item_id}: the digest does not bind the copy the consumer reads")
    if undeclared:
        checks.append({"id": "canonical_form", "status": "unavailable",
                       "detail": f"{len(undeclared)} references declare no canonical form"})
        return "not_established", "undeclared_canonical_form"
    checks.append({"id": "consumed_copy_bound", "status": "pass" if pending is None else "unavailable",
                   "detail": "every available digest binds the copy the consumer reads"})
    if pending is not None:
        return "not_established", pending
    return "supported", "digests_bind_consumed_copy"


def adjudicate_digest(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Consumer claim adapter: the digest manifest and the copies the consumer reads."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, DIGEST_CLAIM, {"manifest", "consumed"}, {"authority", "require_signature"})
    authority = _authority(assessment)
    require = assessment.get("require_signature", False)
    if not isinstance(require, bool):
        raise CaseError("assessment.require_signature: expected a boolean")
    names = _consumed_map(assessment["consumed"])
    manifest, manifest_binding = bound(artifacts, artifact_root, assessment["manifest"], "assessment.manifest")
    consumed, bindings = {}, {}
    for item_id, name in names.items():
        consumed[item_id], bindings[item_id] = bound(artifacts, artifact_root, name, f"assessment.consumed.{item_id}")
    scope = {"manifest": manifest_binding, "consumed": bindings, "items": len(names), "limit": DIGEST_LIMIT}
    if manifest is None:
        return decision(case_id, DIGEST_CLAIM, scope, "not_established", "records_unavailable")
    checks: list[dict] = []
    return _finish(case_id, DIGEST_CLAIM, scope, checks,
                   lambda: check_manifest(manifest, consumed, authority, require, checks))


# --- event_log_completeness/v1 ------------------------------------------------------------------------

def event_digest(event: Any) -> str:
    """SHA-256 over the RFC 8785 bytes of one event: the link the next event names."""
    return hashlib.sha256(jcs_canonical._value(event).encode("utf-8")).hexdigest()


def _coverage(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) - {"session", "first_seq"} or "first_seq" not in value:
        raise CaseError("assessment.coverage: expected {first_seq, session?}")
    first = value["first_seq"]
    if isinstance(first, bool) or not isinstance(first, int) or first < 0:
        raise CaseError("assessment.coverage.first_seq: expected a non-negative integer")
    if "session" in value:
        _string(value["session"], "assessment.coverage.session")
    return value


def _events(data: bytes) -> list[dict]:
    try:
        text = decode_utf8(data)
    except IJSONError as exc:
        raise _Refused("record_shape", f"events: {describe(exc)}") from exc
    out = []
    for number, line in enumerate(text.split("\n"), 1):
        if not line.strip(" \t\r"):
            continue
        event = _strict(line, f"line {number}")
        if not isinstance(event, dict):
            raise _Refused("record_shape", f"line {number}: an event is an object")
        seq, prev = event.get("seq"), event.get("prev")
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise _Refused("record_shape", f"line {number}: seq is an integer")
        _hex_digest(prev, 64, f"line {number}.prev")
        out.append(event)
    return out


def _ledger_head(raw: bytes) -> tuple[dict, bytes]:
    head = _strict(raw, "head")
    if not isinstance(head, dict) or set(head) != {"format", "count", "head", "keyid", "signature"} \
            or head["format"] != HEAD_FORMAT:
        raise _Refused("record_shape", f"head: expected a {HEAD_FORMAT} object")
    count = head["count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise _Refused("record_shape", "head.count: expected a non-negative integer")
    _hex_digest(head["head"], 64, "head.head")
    key = bytes.fromhex(_hex_digest(head["keyid"], 64, "head.keyid"))
    payload = {k: head[k] for k in ("format", "count", "head")}
    message = HEAD_FORMAT.encode("ascii") + b"\x00" + jcs_canonical._value(payload).encode("utf-8")
    _ed25519(key, _b64(head["signature"], "head.signature", url=False), message)
    return head, key


def check_log(data: bytes, head_raw: bytes | None, first_prev: str, coverage: dict, authority: Any,
              checks: list[dict]) -> tuple[str, str]:
    """(decision, reason) for one event log against the consumer's pins."""
    events = _events(data)
    if not events:
        checks.append({"id": "records_present", "status": "unavailable", "detail": "the log holds no events"})
        return "not_established", "empty_denominator"
    checks.append({"id": "record_shape", "status": "pass", "detail": f"{len(events)} events are strict I-JSON"})
    session = coverage.get("session")
    if session is not None:
        outside = [i for i, e in enumerate(events) if e.get("session") != session]
        if outside:
            raise _Refused("coverage_boundary", f"events {outside[:5]} lie outside session {session!r}")
    pending = None
    key = None
    if head_raw is not None:
        head, key = _ledger_head(head_raw)
        checks.append({"id": "signature", "status": "pass", "detail": "the head signature verifies"})
        pending = _signer(authority, key, checks)
    else:
        checks.append({"id": "signature", "status": "unavailable", "detail": "no head retained"})
    digests = [event_digest(e) for e in events]
    if len(set(digests)) != len(digests):
        raise _Refused("no_duplicate_event", "the same event appears more than once")
    checks.append({"id": "no_duplicate_event", "status": "pass", "detail": "no event repeats"})
    first = coverage["first_seq"]
    for i, event in enumerate(events):
        if event["seq"] != first + i:
            raise _Refused("sequence", f"event {i} has seq {event['seq']}, expected {first + i}")
    checks.append({"id": "sequence", "status": "pass",
                   "detail": f"seq runs {first} to {first + len(events) - 1} without a gap"})
    for i, event in enumerate(events):
        want = first_prev if i == 0 else digests[i - 1]
        if event["prev"] != want:
            raise _Refused("chain_order", f"event {i} does not link to "
                           + ("the pinned first link" if i == 0 else f"event {i - 1}"))
    checks.append({"id": "chain_order", "status": "pass", "detail": "each event links to the one before it"})
    if head_raw is None:
        checks.append({"id": "head_anchor", "status": "unavailable", "detail": "no head: a cut tail cannot be seen"})
        return "not_established", "head_not_anchored"
    if head["count"] != len(events) or head["head"] != digests[-1]:
        raise _Refused("head_anchor", f"last event {digests[-1][:16]} of {len(events)} against the "
                       f"retained head {head['head'][:16]} of {head['count']}")
    checks.append({"id": "head_anchor", "status": "pass", "detail": "the last event and the count match the head"})
    if pending is not None:
        return "not_established", pending
    return "supported", "event_log_complete"


def adjudicate_log(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Consumer claim adapter: the event log, the retained head and the consumer's pins."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, LOG_CLAIM, {"records", "first_prev", "coverage"}, {"head", "authority"})
    first_prev = assessment["first_prev"]
    if not isinstance(first_prev, str) or len(first_prev) != 64 or set(first_prev) - HEX:
        raise CaseError("assessment.first_prev: expected lowercase SHA-256")
    coverage = _coverage(assessment["coverage"])
    authority = _authority(assessment)
    data, records_binding = bound(artifacts, artifact_root, assessment["records"], "assessment.records")
    scope: dict[str, Any] = {"records": records_binding, "coverage": coverage, "limit": LOG_LIMIT}
    head_raw = None
    if assessment.get("head") is not None:
        head_raw, scope["head"] = bound(artifacts, artifact_root, assessment["head"], "assessment.head")
        if head_raw is None:
            return decision(case_id, LOG_CLAIM, scope, "not_established", "head_unavailable")
    if data is None:
        return decision(case_id, LOG_CLAIM, scope, "not_established", "records_unavailable")
    checks: list[dict] = []
    return _finish(case_id, LOG_CLAIM, scope, checks,
                   lambda: check_log(data, head_raw, first_prev, coverage, authority, checks))
