"""Whether a key may speak for a record: one check every signature verdict goes through.

A valid signature proves only that someone holding the key signed the bytes. A verifier that stops
there accepts a record signed by a key the record itself supplied, a key named in a DID document but
not listed for assertions, a key revoked before the record was made, or a key bound to another
subject. Six rows of the conformance matrix found that hole in six verifiers, ours among them. This
module closes it once: an adapter computes the signature, then asks :func:`authorize` whether the
key was authorised, under an authority the consumer's policy names. The record never names its own
authority.

Authority kinds, each a JSON object in the consumer policy:

``pin``
    ``{"kind": "pin", "keys": [{"public_key_sha256": "<hex>", "kid": "<optional>"}]}``. The key is
    authorised when the SHA-256 of its bytes is pinned and, when every pin of that key names a
    ``kid``, the record names one of those key ids (a record that names no key id cannot meet a
    pin that names one).
``did-web``
    ``{"kind": "did-web", "did": "did:web:...", "document": "<artifact>",
    "document_sha256": "<hex>"}``. The consumer pins the bytes of the DID document; the key is
    authorised when a verification method listed under ``assertionMethod`` carries it and, when the
    record names a key id, that method's id is the key id. A method present only under
    ``verificationMethod`` or ``authentication`` is not authorised to make assertions. A document in
    which two verification methods (listed or embedded under any relationship) share an id, after a
    relative ``#fragment`` is resolved against the DID, is malformed (DID Core 1.0 section 5.2): a
    reader that kept the first and one that kept the last would trust different keys. A JWK whose
    ``use`` is not ``sig``, or whose ``key_ops`` omits ``verify``, does not sign. A method that
    carries more than one verification material property (``publicKeyJwk`` and
    ``publicKeyMultibase``, say) is malformed (DID Core 1.0 section 5.2.1): one reader would trust
    the JWK and another the multibase key. The DID is the subject the key speaks for: a record
    whose own subject is another identifier is refused, so a key of ``did:web:alice`` never
    vouches for a record that says ``did:web:bob`` issued it.
``registry``
    ``{"kind": "registry", "bindings": [{"subject": "...", "public_key_sha256": "<hex>",
    "not_before": "<RFC 3339>", "not_after": "<RFC 3339, optional>",
    "revoked_at": "<RFC 3339, optional>"}]}``. The key is authorised for a subject at an instant when
    a binding of that subject and key covers the instant and no binding of that subject and key was
    revoked at or before it: revocation ends the key for the subject, so a second, unrevoked
    binding of the same key does not bring it back. Instants are RFC 3339 ``date-time`` exactly
    (section 5.6: ``T`` and ``Z`` in either case, a numeric offset or ``Z``, no week or ordinal
    dates, no basic format); a leap second (``:60``) is read only where one can fall, at 23:59 UTC
    once the offset is applied, as the last microsecond of that minute, and a fraction finer than a
    microsecond rounds up, so a bound compares exactly with a record time, which is on the
    microsecond grid.
``kt-inclusion``
    ``{"kind": "kt-inclusion", "tree_size": n, "root_sha256": "<hex>", "inclusion_proof":
    "<artifact, optional>"}``. The consumer pins a transparency-log tree head; the case artifact
    the policy names supplies an RFC 6962 inclusion proof
    ``{"index": i, "tree_size": n, "path": ["<hex>", ...]}`` for the leaf
    ``RFC 8785({"key_sha256": "<hex>", "subject": "<subject>"})``. The key is authorised when the
    proof reaches the pinned root. ``index`` and ``tree_size`` are JSON integers, never ``true`` or
    ``2.0``. Inclusion shows the binding was logged; it does not show a later log entry did not
    revoke it.

Each kind reads only the members named above; any other member is the consumer's error and is
refused, because a restriction the consumer wrote under a name this module does not read (a
``kid`` on a ``did-web`` authority, a ``revocations`` list beside ``bindings``) would otherwise
widen what is trusted without a word.

Outcomes: ``authorized``; ``unauthorized`` with a reason (the evidence says the key may not speak
for the record); ``unknown`` with a reason (the evidence to decide is missing). An adapter maps
``unauthorized`` to ``contradicted`` and ``unknown`` to ``not_established``: an agreement needs
key authority. Every outcome carries the consumer's key-set fingerprint, so a verdict says which
keys it trusted.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .adapters import jcs_canonical
from .adapters.proof_of_control import check_inclusion, leaf_hash
from .common import CaseError
from .ijson import IJSONError, parse_ijson

KINDS = ("pin", "did-web", "registry", "kt-inclusion")
AUTHORIZED, UNAUTHORIZED, UNKNOWN = "authorized", "unauthorized", "unknown"
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: The members each kind reads; any other member of the consumer's authority is refused.
_MEMBERS = {"pin": {"kind", "keys"}, "did-web": {"kind", "did", "document", "document_sha256"},
            "registry": {"kind", "bindings"},
            "kt-inclusion": {"kind", "tree_size", "root_sha256", "inclusion_proof"}}
#: The curve and point length of each JWK key type this module turns into raw key bytes.
_EC_CURVES = {"P-256": 32, "P-384": 48}
_OKP_CURVES = {"Ed25519": 32, "Ed448": 57}
_MULTICODEC = {b"\xed\x01": "Ed25519"}


@dataclass(frozen=True)
class Authority:
    """One answer: the outcome, why, under which kind, and the key-set fingerprint trusted."""

    outcome: str
    reason: str
    kind: str
    key_set_sha256: str

    def check(self) -> dict:
        """The check an adapter appends to its decision."""
        return {"id": "key_authority", "status": {AUTHORIZED: "pass", UNAUTHORIZED: "fail",
                                                  UNKNOWN: "unavailable"}[self.outcome],
                "kind": self.kind, "outcome": self.outcome, "reason": self.reason,
                "key_set_sha256": self.key_set_sha256}


def key_sha256(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()


def key_set_fingerprint(key_digests: Iterable[str]) -> str:
    """SHA-256 over the sorted, distinct key digests, one per line: which keys a verdict trusted."""
    lines = sorted(set(key_digests))
    return hashlib.sha256("".join(d + "\n" for d in lines).encode("ascii")).hexdigest()


def _b64url(text: Any, label: str) -> bytes:
    if not isinstance(text, str) or "=" in text or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise CaseError(f"{label}: expected unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise CaseError(f"{label}: expected unpadded base64url") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        raise CaseError(f"{label}: base64url is not in canonical form")
    return raw


def jwk_key_bytes(jwk: Any, label: str = "jwk") -> bytes:
    """Raw public key bytes of a JWK: the OKP ``x``, or the uncompressed EC point 0x04 || x || y."""
    if not isinstance(jwk, dict) or "d" in jwk:
        raise CaseError(f"{label}: expected a public JWK")
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if not isinstance(kty, str) or not isinstance(crv, str):  # a list ``crv`` is unhashable
        raise CaseError(f"{label}: kty and crv are strings")
    if kty == "OKP" and crv in _OKP_CURVES:
        x = _b64url(jwk.get("x"), f"{label}.x")
        if len(x) != _OKP_CURVES[crv]:
            raise CaseError(f"{label}.x: wrong length for {crv}")
        return x
    if kty == "EC" and crv in _EC_CURVES:
        size = _EC_CURVES[crv]
        x, y = _b64url(jwk.get("x"), f"{label}.x"), _b64url(jwk.get("y"), f"{label}.y")
        if len(x) != size or len(y) != size:
            raise CaseError(f"{label}: wrong coordinate length for {crv}")
        return b"\x04" + x + y
    raise CaseError(f"{label}: unsupported key type {kty!r} {crv!r}")


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def multibase_key_bytes(value: Any, label: str = "publicKeyMultibase") -> bytes:
    """Raw key bytes of a base58btc multibase multicodec key (``z`` prefix, Ed25519 0xed01)."""
    if not isinstance(value, str) or not value.startswith("z") or len(value) < 2:
        raise CaseError(f"{label}: expected a base58btc multibase value")
    number = 0
    for char in value[1:]:
        digit = _B58.find(char)
        if digit < 0:
            raise CaseError(f"{label}: not base58btc")
        number = number * 58 + digit
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    raw = b"\x00" * (len(value[1:]) - len(value[1:].lstrip("1"))) + body
    codec = _MULTICODEC.get(raw[:2])
    if codec != "Ed25519" or len(raw) != 34:
        raise CaseError(f"{label}: only an Ed25519 multicodec key is read")
    return raw[2:]


#: RFC 3339 section 5.6 ``date-time``. ABNF literals are case-insensitive, so ``t`` and ``z`` match.
_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
                      r"(?:([Zz])|([+-])(\d{2}):(\d{2}))", re.ASCII)


#: An instant's order key: ``day * 86401 + second of the UTC day + fraction``, exact. A UTC day has
#: 86401 one-second slots so that a leap second (``23:59:60``) orders after every instant of
#: ``23:59:59`` and before the next day, which no count of POSIX seconds can do.
Instant = Fraction
_DAY = 86_400


def _instant(day: int, second_of_day: Fraction) -> Instant:
    return day * (_DAY + 1) + second_of_day


def parse_instant(value: Any, label: str = "instant") -> Instant:
    """An RFC 3339 ``date-time`` as an exact :data:`Instant`, or :class:`CaseError`.

    ``datetime.fromisoformat`` is not this: from Python 3.11 it also reads ISO 8601 week dates
    (``2026-W46-1T00:00:00Z``), the basic format (``20261115T000000Z``), a comma fraction and a
    space separator, none of which RFC 3339 allows, and it refuses a leap second, which RFC 3339
    allows. Two verifiers reading one policy would then bound a key's validity differently. A
    fraction is kept to its last digit, not to the microsecond a ``datetime`` holds: a rounded bound
    orders wrongly against a record time between the two grid points it falls between.
    """
    match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise CaseError(f"{label}: expected an RFC 3339 date-time with an offset")
    year, month, day, hour, minute, second = (int(match.group(n)) for n in range(1, 7))
    fraction, zulu, sign, off_hour, off_minute = match.group(7, 8, 9, 10, 11)
    try:
        ordinal = datetime.date(year, month, day).toordinal()
        if hour > 23 or minute > 59 or second > 60:
            raise ValueError("time of day out of range")
        offset = 0
        if not zulu:
            if int(off_hour) > 23 or int(off_minute) > 59:
                raise ValueError("offset out of range")
            offset = (int(off_hour) * 60 + int(off_minute)) * 60 * (-1 if sign == "-" else 1)
        local = hour * 3600 + minute * 60 + min(second, 59) - offset
        utc_day, second_of_day = ordinal + local // _DAY, local % _DAY
        if second == 60:  # RFC 3339 section 5.7: a leap second ends a UTC day, at 23:59:60
            if second_of_day != _DAY - 1:
                raise ValueError("a leap second falls only in the last minute of a UTC day")
            second_of_day = _DAY
    except ValueError as exc:
        raise CaseError(f"{label}: expected an RFC 3339 date-time with an offset") from exc
    exact = Fraction(int(fraction), 10 ** len(fraction)) if fraction else Fraction(0)
    return _instant(utc_day, second_of_day + exact)


_EPOCH_ORDINAL = datetime.date(1970, 1, 1).toordinal()


def record_instant(at: Any, label: str = "at") -> Instant:
    """A record's own time as an exact :data:`Instant`: an aware ``datetime``, POSIX seconds, or an
    RFC 3339 ``date-time`` string.

    POSIX seconds (an ``int``, or a ``float`` read exactly as the double it is) are what a token's
    ``iat`` carries; a ``datetime`` holds microseconds; a string is read by :func:`parse_instant`
    to its last fraction digit, leap second included, as a catalog check time is written.
    """
    if isinstance(at, str):
        return parse_instant(at, label)
    if isinstance(at, datetime.datetime):
        if at.utcoffset() is None:
            raise CaseError(f"{label}: expected an aware datetime")
        utc = at.astimezone(datetime.UTC)
        second_of_day = utc.hour * 3600 + utc.minute * 60 + utc.second
        return _instant(utc.toordinal(), second_of_day + Fraction(utc.microsecond, 10**6))
    if isinstance(at, (int, float)) and not isinstance(at, bool) and math.isfinite(at):
        seconds = Fraction(at)
        day = math.floor(seconds / _DAY)
        return _instant(_EPOCH_ORDINAL + day, seconds - day * _DAY)
    raise CaseError(f"{label}: expected an aware datetime, POSIX seconds or an RFC 3339 date-time")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise CaseError(f"{label}: expected lowercase SHA-256 hex")
    return value


def _pin(config: dict, key: bytes, kid: str | None) -> tuple[str, str, list[str]]:
    keys = config.get("keys")
    if not isinstance(keys, list) or not keys:
        raise CaseError("authority.keys: expected a non-empty list of pins")
    pins = []
    for index, pin in enumerate(keys):
        if (not isinstance(pin, dict) or not set(pin) <= {"public_key_sha256", "kid"}
                or not isinstance(pin.get("kid", ""), str)):
            raise CaseError(f"authority.keys[{index}]: expected public_key_sha256 and optional "
                            "string kid")
        pins.append((_digest(pin.get("public_key_sha256"), f"authority.keys[{index}]"),
                     pin.get("kid")))
    digests = [d for d, _ in pins]
    matches = [pin_kid for d, pin_kid in pins if d == key_sha256(key)]
    if not matches:
        return UNAUTHORIZED, "key_not_pinned", digests
    if all(pin_kid is not None for pin_kid in matches) and kid not in matches:
        return UNAUTHORIZED, "key_id_mismatch", digests
    return AUTHORIZED, "key_pinned", digests


#: The verification relationships of DID Core 1.0 section 5.3, each of which may embed a method.
_RELATIONSHIPS = ("authentication", "assertionMethod", "keyAgreement", "capabilityInvocation",
                  "capabilityDelegation")


class _MalformedDocument(ValueError):
    """A DID document two conforming readers could resolve to different keys."""


def _did_methods(document: dict, did: str) -> tuple[dict[str, dict], set[str]]:
    """The verification methods by id, and the ids listed under ``assertionMethod``.

    Every method, whether listed under ``verificationMethod`` or embedded under a relationship,
    must carry a distinct id once a relative ``#fragment`` is resolved against the DID; a repeat
    raises :class:`_MalformedDocument` rather than letting one copy shadow the other.
    """
    methods: dict[str, dict] = {}

    def absolute(ref: str) -> str:
        return did + ref if ref.startswith("#") else ref

    def add(method: Any) -> str:
        if not isinstance(method, dict) or not isinstance(method.get("id"), str):
            raise _MalformedDocument("a verification method carries a string id")
        mid = absolute(method["id"])
        if sum(1 for name in method if name.startswith("publicKey")) > 1:
            raise _MalformedDocument(f"{mid} carries more than one verification material property")
        if mid in methods:
            raise _MalformedDocument(f"two verification methods share the id {mid}")
        methods[mid] = method
        return mid

    def entries(member: str) -> list:
        value = document.get(member, [])
        if not isinstance(value, list):
            raise _MalformedDocument(f"{member} is a list")
        return value

    for method in entries("verificationMethod"):
        add(method)
    asserting = set()
    for relationship in _RELATIONSHIPS:
        for entry in entries(relationship):
            if isinstance(entry, str):
                ref = absolute(entry)
            elif isinstance(entry, dict):
                ref = add(entry)
            else:
                raise _MalformedDocument(f"{relationship} lists ids and methods")
            if relationship == "assertionMethod":
                asserting.add(ref)
    return methods, asserting


def _method_key(method: dict, label: str) -> tuple[bytes | None, bool]:
    """The method's raw key, and whether it may verify signatures."""
    try:
        if "publicKeyJwk" in method:
            jwk = method["publicKeyJwk"]
            return jwk_key_bytes(jwk, label), _jwk_signs(jwk)
        if "publicKeyMultibase" in method:
            return multibase_key_bytes(method["publicKeyMultibase"], label), True
    except CaseError:
        return None, False
    return None, False


def _jwk_signs(jwk: dict) -> bool:
    """RFC 7517 sections 4.2 and 4.3: a key marked for encryption, or not for verify, never signs."""
    if "use" in jwk and jwk["use"] != "sig":
        return False
    ops = jwk.get("key_ops")
    return ops is None or (isinstance(ops, list) and "verify" in ops)


def _did_web(config: dict, key: bytes, kid: str | None, subject: str | None,
             document_bytes: bytes | None) -> tuple[str, str, list[str]]:
    did = config.get("did")
    if not isinstance(did, str) or not did.startswith("did:web:"):
        raise CaseError("authority.did: expected a did:web identifier")
    pinned = _digest(config.get("document_sha256"), "authority.document_sha256")
    if document_bytes is None:
        return UNKNOWN, "did_document_unavailable", []
    if hashlib.sha256(document_bytes).hexdigest() != pinned:
        return UNAUTHORIZED, "did_document_not_pinned", []
    try:
        document = parse_ijson(document_bytes)
    except IJSONError:
        return UNAUTHORIZED, "did_document_malformed", []
    if not isinstance(document, dict) or document.get("id") != did:
        return UNAUTHORIZED, "did_document_id_mismatch", []
    try:
        methods, asserting = _did_methods(document, did)
    except _MalformedDocument:
        return UNAUTHORIZED, "did_document_malformed", []
    keyed = {mid: _method_key(m, f"verificationMethod {mid}") for mid, m in methods.items()}
    trusted = [key_sha256(raw) for mid, (raw, signs) in keyed.items()
               if raw is not None and signs and mid in asserting]
    if subject is not None and subject != did:
        return UNAUTHORIZED, "record_subject_not_did", trusted
    holders = [mid for mid, (raw, _) in keyed.items() if raw == key]
    if not holders:
        return UNAUTHORIZED, "key_not_in_did_document", trusted
    asserted = [mid for mid in holders if mid in asserting]
    if not asserted:
        return UNAUTHORIZED, "key_not_in_assertion_method", trusted
    signing = [mid for mid in asserted if keyed[mid][1]]
    if not signing:
        return UNAUTHORIZED, "key_not_for_signing", trusted

    def names(mid: str) -> tuple[str, ...]:
        relative = mid[len(did):] if mid.startswith(did + "#") else None
        return (mid, relative) if relative else (mid,)

    if kid is not None and not any(kid in names(mid) for mid in signing):
        return UNAUTHORIZED, "key_id_mismatch", trusted
    return AUTHORIZED, "key_in_assertion_method", trusted


def _registry(config: dict, key: bytes, subject: str | None, at: Instant | None,
              ) -> tuple[str, str, list[str]]:
    bindings = config.get("bindings")
    if not isinstance(bindings, list) or not bindings:
        raise CaseError("authority.bindings: expected a non-empty list")
    parsed = []
    for index, binding in enumerate(bindings):
        label = f"authority.bindings[{index}]"
        if not isinstance(binding, dict) or not {"subject", "public_key_sha256", "not_before"} <= set(
                binding) or not set(binding) <= {"subject", "public_key_sha256", "not_before",
                                                 "not_after", "revoked_at"}:
            raise CaseError(f"{label}: expected subject, public_key_sha256, not_before, "
                            "and optional not_after and revoked_at")
        if not isinstance(binding["subject"], str):
            raise CaseError(f"{label}.subject: expected a string")
        parsed.append((binding["subject"], _digest(binding["public_key_sha256"], label),
                       parse_instant(binding["not_before"], f"{label}.not_before"),
                       parse_instant(binding["not_after"], f"{label}.not_after")
                       if "not_after" in binding else None,
                       parse_instant(binding["revoked_at"], f"{label}.revoked_at")
                       if "revoked_at" in binding else None))
    if subject is None:
        return UNKNOWN, "record_subject_unknown", [d for _, d, *_ in parsed]
    if at is None:
        return UNKNOWN, "record_time_unknown", [d for _, d, *_ in parsed]
    mine = [b for b in parsed if b[0] == subject]
    # Revocation ends a key for the subject: the earliest revocation of any binding of that key.
    ended: dict[str, Instant] = {}
    for _, digest, _, _, revoked in mine:
        if revoked is not None and (digest not in ended or revoked < ended[digest]):
            ended[digest] = revoked
    trusted = [d for _, d, start, end, _ in mine
               if start <= at and (end is None or at < end) and (d not in ended or at < ended[d])]
    digest = key_sha256(key)
    if not any(b[1] == digest for b in mine):
        return UNAUTHORIZED, "key_not_bound_to_subject", trusted
    if digest in trusted:
        return AUTHORIZED, "key_bound_at_time", trusted
    if digest in ended and ended[digest] <= at:
        return UNAUTHORIZED, "key_revoked", trusted
    return UNAUTHORIZED, "key_outside_validity", trusted


def _json_int(value: Any) -> bool:
    """A JSON integer: Python's ``bool`` is an ``int`` and ``2.0 == 2``, so neither test alone is."""
    return isinstance(value, int) and not isinstance(value, bool)


def kt_leaf(key: bytes, subject: str) -> bytes:
    """The leaf a key-transparency log holds for one key bound to one subject."""
    text = json.dumps({"key_sha256": key_sha256(key), "subject": subject}, ensure_ascii=False)
    return jcs_canonical.canonical("rfc8785", text)


def _kt_inclusion(config: dict, key: bytes, subject: str | None, proof: Any,
                  ) -> tuple[str, str, list[str]]:
    size = config.get("tree_size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise CaseError("authority.tree_size: expected a positive integer")
    root = bytes.fromhex(_digest(config.get("root_sha256"), "authority.root_sha256"))
    if subject is None:
        return UNKNOWN, "record_subject_unknown", []
    if proof is None:
        return UNKNOWN, "inclusion_proof_unavailable", []
    if (not isinstance(proof, dict) or set(proof) != {"index", "tree_size", "path"}
            or not all(_json_int(proof[m]) for m in ("index", "tree_size"))
            or not isinstance(proof["path"], list)
            or not all(isinstance(h, str) and _HEX64.fullmatch(h) for h in proof["path"])):
        return UNAUTHORIZED, "inclusion_proof_malformed", []
    if proof["tree_size"] != size:
        return UNKNOWN, "inclusion_proof_for_another_tree_head", []
    path = [bytes.fromhex(h) for h in proof["path"]]
    if check_inclusion(proof["index"], size, leaf_hash(kt_leaf(key, subject)), path, root) is not None:
        return UNAUTHORIZED, "key_not_in_log", []
    return AUTHORIZED, "key_in_log", [key_sha256(key)]


def authorize(authority: Any, key: bytes, *, kid: str | None = None, subject: str | None = None,
              at: datetime.datetime | float | None = None, did_document: bytes | None = None,
              inclusion_proof: Any = None) -> Authority:
    """Decide whether ``key`` may speak for a record, under the consumer's ``authority``.

    ``kid``, ``subject`` and ``at`` are what the record says about its own signer and time; they
    select among the consumer's bindings and never extend them. ``did_document`` and
    ``inclusion_proof`` are evidence bytes the case supplies, checked against the consumer's pins.
    A malformed ``authority`` raises :class:`CaseError`: it is the consumer's own input.
    """
    if authority is None:
        return Authority(UNKNOWN, "no_key_authority_in_policy", "none", key_set_fingerprint([]))
    if not isinstance(authority, dict) or authority.get("kind") not in KINDS:
        raise CaseError(f"authority.kind: expected one of {list(KINDS)}")
    if not isinstance(key, bytes) or not key:
        raise CaseError("the signing key is not key bytes")
    kind = authority["kind"]
    unread = sorted(set(authority) - _MEMBERS[kind])
    if unread:
        raise CaseError(f"authority: {kind} reads no member {', '.join(unread)}")
    if kind == "pin":
        outcome, reason, trusted = _pin(authority, key, kid)
    elif kind == "did-web":
        outcome, reason, trusted = _did_web(authority, key, kid, subject, did_document)
    elif kind == "registry":
        outcome, reason, trusted = _registry(authority, key, subject,
                                             None if at is None else record_instant(at))
    else:
        outcome, reason, trusted = _kt_inclusion(authority, key, subject, inclusion_proof)
    return Authority(outcome, reason, kind, key_set_fingerprint(trusted))


def authority_evidence(authority: Any, artifacts: dict, artifact_root: Any,
                       scope: dict) -> tuple[bytes | None, Any]:
    """The DID document bytes and the inclusion proof the consumer's authority names as case
    artifacts, each bound and recorded in ``scope``; ``(None, None)`` when the kind reads neither."""
    from .adapters.bound_records import bound
    document = proof = None
    if not isinstance(authority, dict):
        return document, proof
    kind = authority.get("kind")
    if kind == "did-web":
        document, scope["key_authority_document"] = bound(
            artifacts, artifact_root, authority.get("document"), "assessment.key_authority.document")
    elif kind == "kt-inclusion":
        if "inclusion_proof" in authority:
            raw, scope["key_authority_inclusion_proof"] = bound(
                artifacts, artifact_root, authority["inclusion_proof"],
                "assessment.key_authority.inclusion_proof")
            if raw is not None:
                try:
                    proof = parse_ijson(raw)
                except IJSONError:
                    proof = "malformed"  # authorize() answers inclusion_proof_malformed
    elif "document" in authority or "inclusion_proof" in authority:
        raise CaseError("assessment.key_authority: evidence named for a kind that reads none")
    return document, proof
