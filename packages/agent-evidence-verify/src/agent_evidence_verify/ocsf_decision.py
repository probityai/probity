"""Read a stream of OCSF API Activity decision records and report each dimension on its own.

The records are those of the Praxis Policy Engine's ``ocsf-audit`` sink: OCSF API Activity events
(``class_uid`` 6003) carrying the ``security_control`` ruling, the engine's decision facts under
``unmapped."aid.*"``, and, when chaining is on, ``attestation_list[0]`` with a SHA-256 ``fingerprint``
over the RFC 8785 bytes of the event, a ``prev_event`` link to its predecessor and a DSSE signature
(ECDSA P-256) whose bytes ride at ``unmapped.signature_b64``. The format is specified as AID-EMIT-1,
and the sink's three ``SAMPLE-OUTPUT*.md`` files are its conformance vectors. This reader was written
from that published text and those samples, without the sink's code.

:func:`read` takes the records' exact bytes (one record per line) and returns one report. Every check
is its own dimension with a ``status`` of ``verified``, ``failed``, ``not_checked``, ``unavailable``
or ``not_supported``; nothing merges them into one pass.

Per record: ``structural_validity`` (strict JSON, a member named twice at any depth is not read),
``decision_consistency`` (the ruling's ids, captions, verdict and steps say one thing), ``fingerprint``
(recomputed by the published rule), ``signature`` (with a key taken only from the relying party's own
key set, never chosen by the record's key id) and ``key_binding`` (whether the signed bytes and the
relying party's key set name the key that signed; the key id itself rides outside the signed bytes).

Over the stream: ``record_uniqueness``, ``chain_links``, ``chain_gaps``, ``chain_head``,
``stream_sequence`` (``stream_seq`` dense per ``(epoch, stream_id)``, ``emission_seq`` in order),
``stream_head`` and ``tail``. No record can show that later records were not deleted, so ``tail`` is
``verified`` only against a head the relying party holds from a source the emitter does not control;
without one it is ``not_checked``, never a pass.

Two profiles decide what a relying party accepts (:func:`verdict`). ``baseline`` is the format's own
reading: a dimension that failed refuses. ``strict`` also requires every record signed and verified,
the signing key named by the signed bytes and the relying party's key set, the tail anchored, the
chain and stream openings supplied, and every number readable alike by an exact reader and a
double-based one.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import itertools
import json
import re
from dataclasses import dataclass
from datetime import date
from fractions import Fraction
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .adapters.jcs_canonical import Refusal, _number, _string_form
from .decision_record import (
    FAILED,
    NOT_CHECKED,
    NOT_SUPPORTED,
    UNAVAILABLE,
    VERIFIED,
    Instant,
    Tally,
    dim,
    instant,
)
from .ijson import JSON_WHITESPACE, IJSONError, decode_utf8, parse_ijson

SUITE = "ocsf-decision/v1"
PAYLOAD_TYPE = "application/vnd.ocsf.event+json"
CLASS_UID = 6003
PROFILES = ("baseline", "strict")

#: Dimensions read on every record, in the order a refusal names the first that failed.
RECORD_DIMENSIONS = ("structural_validity", "decision_consistency", "fingerprint", "signature",
                     "key_binding")
#: Dimensions read over the whole stream, after the record dimensions.
STREAM_DIMENSIONS = ("trust_policy", "record_uniqueness", "chain_links", "chain_gaps", "chain_head",
                     "stream_sequence", "stream_head", "tail")
#: Dimensions the strict profile adds, each its own.
STRICT_DIMENSIONS = ("signature_required", "key_named_by_signed_bytes", "tail_anchored",
                     "opening_supplied", "numbers_interoperable")
#: Dimensions whose ``failed`` refuses under ``baseline``.
BASELINE_REFUSES = RECORD_DIMENSIONS + STREAM_DIMENSIONS

MAX_SAFE_INTEGER = 2**53 - 1
#: ``instant()`` counts seconds from 0001-01-01 (the proleptic ordinal), not from 1970. OCSF's ``time``
#: counts milliseconds from 1970-01-01T00:00:00Z (schema.ocsf.io, timestamp_t), so a millisecond time
#: is moved onto the same axis before it is compared with a key's RFC 3339 window.
UNIX_EPOCH_SECONDS = date(1970, 1, 1).toordinal() * 86400
_INT_MIN, _INT_MAX = -(2**63), 2**64 - 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_B64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

#: The four rulings the format writes (README "What a record carries"): action_id, action,
#: disposition_id, disposition.
RULINGS = {
    (1, "Allowed", 1, "Allowed"): "allow",
    (4, "Modified", 1, "Allowed"): "allow-modified",
    (2, "Denied", 2, "Blocked"): "deny",
    (3, "Observed", 17, "Logged"): "observed",
}
STEP_ACTIONS = ("allowed", "denied", "deny_ignored", "modified_payload", "modified_extensions",
                "aborted", "error")
#: The mapped blocks a sink without the matching read capability leaves out, silently.
CAPABILITY_BLOCKS = (("actor", "read_subject"), ("ai_agent", "read_agent"),
                     ("delegation", "read_delegation"), ("unmapped.cmf.security.labels", "read_labels"),
                     ("unmapped.cmf.workload_identity", "read_workload"))
#: Members the published rule removes before hashing: never covered by the fingerprint or signature.
OUTSIDE_SIGNED = ("attestation_list[0].fingerprint", "attestation_list[0].signatures",
                  "unmapped.signature_b64", "unmapped.signature_key_id")


class NotRead(ValueError):
    """Bytes this reader refuses to read at all."""


# --- reading and canonical bytes ------------------------------------------------------------------

class Wide(int):
    """An integer token outside +-(2**53 - 1): read exactly, as the format's rule requires."""


def _exact_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:
        raise IJSONError("unsafe-integer", f"integer token of {len(text)} digits") from exc
    if not _INT_MIN <= value <= _INT_MAX:
        raise IJSONError("unsafe-integer",
                         f"{text} is outside 64 bits, where the format's exact-integer rule has no form")
    return Wide(value) if abs(value) > MAX_SAFE_INTEGER else value


def read_record(text: str) -> Any:
    """One record as strict JSON: UTF-8, no member twice, no lone surrogate, integers kept exactly."""
    try:
        return parse_ijson(text, parse_int=_exact_int)
    except IJSONError as exc:
        raise NotRead(f"not read: {exc}") from exc


def _canon(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(int(value))  # the format writes integers exactly, never through a double
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string_form(value)
    if isinstance(value, list):
        return "[" + ",".join(_canon(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string_form(k) + ":" + _canon(value[k]) for k in keys) + "}"
    raise Refusal(f"{type(value).__name__} is not a JSON value")


def canonical(value: Any) -> bytes:
    """RFC 8785 bytes, with integers written exactly as the format's verifier rule says."""
    return _canon(value).encode("utf-8")


def signing_input(record: dict) -> bytes:
    """The published verifier rule, steps 1 to 3: the bytes the fingerprint and signature cover."""
    event = copy.deepcopy(record)
    att = event["attestation_list"][0]
    att.pop("fingerprint", None)
    att.pop("signatures", None)
    unmapped = event.get("unmapped")
    if isinstance(unmapped, dict):
        unmapped.pop("signature_b64", None)
        unmapped.pop("signature_key_id", None)
        if not unmapped:
            del event["unmapped"]
    return canonical(event)


def pae(payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding of ``payload`` under the format's payload type."""
    kind = PAYLOAD_TYPE.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _wide_numbers(value: Any, path: str = "") -> list[str]:
    """Paths of integers a double-based reader reads as another number."""
    out: list[str] = []
    stack: list[tuple[Any, str]] = [(value, path)]
    while stack:
        node, where = stack.pop()
        if isinstance(node, Wide) and int(float(node)) != int(node):
            out.append(where or "/")
        elif isinstance(node, dict):
            stack.extend((v, f"{where}/{k}") for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((v, f"{where}/{i}") for i, v in enumerate(node))
    return sorted(out)


def _get(obj: Any, *names: str) -> Any:
    for name in names:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(name)
    return obj


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _b64(text: Any) -> bytes | None:
    if not isinstance(text, str) or not text or not _B64.match(text):
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _b64url(text: Any) -> bytes | None:
    if not isinstance(text, str) or not _B64URL.match(text):
        return None
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None
    return data if base64.urlsafe_b64encode(data).decode("ascii").rstrip("=") == text else None


def _time(value: Any) -> Instant:
    """The record's ``time``: an RFC 3339 string as emitted, or OCSF's millisecond integer."""
    if _int(value):
        return Instant(str(value), UNIX_EPOCH_SECONDS + Fraction(int(value), 1000))
    return instant(value)


# --- the relying party's key set -------------------------------------------------------------------

@dataclass(frozen=True)
class Key:
    kid: str
    authority_uid: str
    public: ec.EllipticCurvePublicKey
    not_before: Instant | None
    not_after: Instant | None

    def covers(self, at: Instant) -> bool:
        if self.not_before is not None and at.seconds < self.not_before.seconds:
            return False
        return not (self.not_after is not None and at.seconds > self.not_after.seconds)


class TrustPolicy:
    """The relying party's own JWKS: P-256 keys, each bound to the authority it belongs to."""

    def __init__(self, keys: list[Key], findings: list[str]) -> None:
        self.keys = keys
        self.findings = findings

    @classmethod
    def read(cls, doc: Any) -> TrustPolicy:
        findings: list[str] = []
        keys: list[Key] = []
        entries = doc.get("keys") if isinstance(doc, dict) else None
        if not isinstance(entries, list) or not entries:
            return cls([], ["the trust policy lists no keys"])
        seen_kid: set[str] = set()
        seen_point: dict[bytes, str] = {}
        for i, entry in enumerate(entries):
            key = cls._entry(entry, i, findings)
            if key is None:
                continue
            point = key.public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            if key.kid in seen_kid:
                findings.append(f"keys[{i}]: kid {key.kid!r} is listed twice")
                continue
            if point in seen_point:
                findings.append(f"keys[{i}]: the public key of {seen_point[point]!r} is listed again as "
                                f"{key.kid!r}")
                continue
            seen_kid.add(key.kid)
            seen_point[point] = key.kid
            keys.append(key)
        return cls(keys, findings)

    @staticmethod
    def _entry(entry: Any, i: int, findings: list[str]) -> Key | None:
        where = f"keys[{i}]"
        if not isinstance(entry, dict):
            findings.append(f"{where}: not an object")
            return None
        if entry.get("kty") != "EC" or entry.get("crv") != "P-256":
            findings.append(f"{where}: not an EC P-256 key")
            return None
        kid, authority = entry.get("kid"), entry.get("authority_uid")
        if not isinstance(kid, str) or not kid or not isinstance(authority, str) or not authority:
            findings.append(f"{where}: a key needs a kid and the authority_uid it belongs to")
            return None
        x, y = _b64url(entry.get("x")), _b64url(entry.get("y"))
        if x is None or y is None or len(x) != 32 or len(y) != 32:
            findings.append(f"{where}: x and y must be 32-byte base64url values")
            return None
        try:
            public = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                   ec.SECP256R1()).public_key()
        except ValueError:
            findings.append(f"{where}: the point is not on P-256")
            return None
        window = []
        for name in ("not_before", "not_after"):
            if name not in entry:
                window.append(None)
                continue
            at = instant(entry[name])
            if not at.ok:
                findings.append(f"{where}: {name} names no instant ({at.why})")
                return None
            window.append(at)
        return Key(kid, authority, public, window[0], window[1])

    def report(self) -> dict:
        if self.findings:
            return dim(FAILED, *self.findings, keys=len(self.keys))
        return dim(VERIFIED, keys=len(self.keys))


def jwk(public: ec.EllipticCurvePublicKey, kid: str, authority_uid: str, **window: str) -> dict:
    """A trust-policy entry for ``public``, as this reader reads one."""
    numbers = public.public_numbers()

    def enc(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).decode("ascii").rstrip("=")

    return {"kty": "EC", "crv": "P-256", "kid": kid, "x": enc(numbers.x), "y": enc(numbers.y),
            "authority_uid": authority_uid, **window}


# --- one record ------------------------------------------------------------------------------------

@dataclass
class Record:
    index: int
    line: int
    text: str
    doc: dict | None
    report: dict

    @property
    def att(self) -> dict | None:
        lst = self.doc.get("attestation_list") if self.doc else None
        return lst[0] if isinstance(lst, list) and lst and isinstance(lst[0], dict) else None

    @property
    def uid(self) -> str | None:
        value = _get(self.doc, "metadata", "uid")
        return value if isinstance(value, str) else None

    @property
    def fingerprint(self) -> str | None:
        value = _get(self.att, "fingerprint", "value")
        return value if isinstance(value, str) else None


def _fingerprint_shape(fp: Any, where: str, tally: Tally) -> None:
    if not isinstance(fp, dict):
        tally.fail(f"{where} is not an object")
        return
    for name, want in (("algorithm_id", 3), ("encoding_id", 1), ("serialization_id", 2)):
        if fp.get(name) != want:
            tally.fail(f"{where}.{name} is {fp.get(name)!r}, not {want} (SHA-256, Hex, JCS)")
    if not isinstance(fp.get("value"), str) or not _HEX64.match(fp["value"]):
        tally.fail(f"{where}.value is not 64 lowercase hex digits")


def structural_validity(doc: Any) -> dict:
    """The members the reader relies on, each with the shape the format gives it."""
    tally = Tally()
    if not isinstance(doc, dict):
        return dim(FAILED, "a record is a JSON object")
    if doc.get("class_uid") != CLASS_UID:
        tally.fail(f"class_uid is {doc.get('class_uid')!r}, not {CLASS_UID} (API Activity)")
    activity = doc.get("activity_id")
    if not _int(activity):
        tally.fail("activity_id is not an integer")
    elif doc.get("type_uid") != CLASS_UID * 100 + activity:
        tally.fail(f"type_uid is {doc.get('type_uid')!r}, not class_uid * 100 + activity_id "
                   f"({CLASS_UID * 100 + activity})")
    if not _time(doc.get("time")).ok:
        tally.fail("time names no instant")
    unmapped = doc.get("unmapped")
    if unmapped is not None and not isinstance(unmapped, dict):
        tally.fail("unmapped is not an object")
        unmapped = None
    if "attestation_list" in doc:
        lst = doc["attestation_list"]
        if not isinstance(lst, list) or not lst or not isinstance(lst[0], dict):
            tally.fail("attestation_list is not a list whose first entry is an object")
        else:
            _attestation_shape(doc, lst[0], unmapped or {}, tally)
            if len(lst) > 1:
                tally.skip(f"attestation_list carries {len(lst) - 1} entries after the first; they are "
                           "hashed but not read")
    elif unmapped and ("signature_b64" in unmapped or "signature_key_id" in unmapped):
        tally.fail("a signature rides on a record with no attestation to bind it")
    stream = (unmapped or {}).get("aid.stream")
    if stream is not None:
        if not isinstance(stream, dict):
            tally.fail("unmapped.\"aid.stream\" is not an object")
        else:
            for name in ("epoch", "stream_seq", "emission_seq"):
                if not _int(stream.get(name)) or stream[name] < 0:
                    tally.fail(f"aid.stream.{name} is not a non-negative integer")
            if not isinstance(stream.get("stream_id"), str) or not stream["stream_id"]:
                tally.fail("aid.stream.stream_id is not a string")
    return tally.result()


def _attestation_shape(doc: dict, att: dict, unmapped: dict, tally: Tally) -> None:
    for name in ("uid", "chain_uid"):
        if not isinstance(att.get(name), str) or not att[name]:
            tally.fail(f"attestation_list[0].{name} is not a string")
    if not isinstance(_get(doc, "metadata", "uid"), str):
        tally.fail("metadata.uid, the uid the next record's prev_event names, is not a string")
    _fingerprint_shape(att.get("fingerprint"), "attestation_list[0].fingerprint", tally)
    if "authority_uid" in att and not isinstance(att["authority_uid"], str):
        tally.fail("attestation_list[0].authority_uid is not a string")
    prev = att.get("prev_event")
    if prev is not None:
        if not isinstance(prev, dict) or not isinstance(prev.get("uid"), str) or not _int(prev.get("type_uid")):
            tally.fail("attestation_list[0].prev_event needs uid and type_uid")
        else:
            _fingerprint_shape(prev.get("fingerprint"), "attestation_list[0].prev_event.fingerprint", tally)
    signed = "signature_b64" in unmapped
    sigs = att.get("signatures")
    if sigs is not None:
        if not isinstance(sigs, list) or not sigs or not all(isinstance(s, dict) for s in sigs):
            tally.fail("attestation_list[0].signatures is not a list of objects")
        elif any(s.get("algorithm_id") != 3 or s.get("serialization_id") != 5 for s in sigs):
            tally.fail("attestation_list[0].signatures names an algorithm other than ECDSA over DSSE")
        if not signed:
            tally.fail("attestation_list[0].signatures describes a signature the record does not carry")
    elif signed:
        tally.fail("unmapped.signature_b64 carries a signature its attestation does not describe")
    if "signature_key_id" in unmapped and not isinstance(unmapped["signature_key_id"], str):
        tally.fail("unmapped.signature_key_id is not a string")


def decision_consistency(doc: dict) -> dict:
    """The ruling read every way the record states it: ids, captions, verdict, steps, status."""
    tally = Tally()
    key = (doc.get("action_id"), doc.get("action"), doc.get("disposition_id"), doc.get("disposition"))
    try:
        ruling = RULINGS.get(key)
    except TypeError:  # a list or object in a ruling member: no ruling, refused below
        ruling = None
    if ruling is None:
        tally.fail(f"action and disposition {list(key)} are not one of the format's four rulings")
    decision = _get(doc, "unmapped", "aid.decision")
    if decision is None:
        if ruling not in (None, "observed"):
            tally.skip("no aid.decision: the ruling is stated only by the base-event fields")
        return tally.result(ruling=ruling)
    if not isinstance(decision, dict) or not isinstance(decision.get("steps"), list):
        tally.fail("aid.decision has no list of steps")
        return tally.result(ruling=ruling)
    steps = decision["steps"]
    actions = [s.get("action") if isinstance(s, dict) else None for s in steps]
    for i, action in enumerate(actions):
        if action not in STEP_ACTIONS:
            tally.fail(f"aid.decision.steps[{i}].action {action!r} is not in the format's vocabulary")
    verdict = decision.get("verdict")
    deny = verdict.get("deny") if isinstance(verdict, dict) else None
    modified = any(a in ("modified_payload", "modified_extensions") for a in actions)
    if isinstance(deny, dict):
        if ruling != "deny":
            tally.fail(f"aid.decision.verdict denies, and the base event records {ruling}")
        if doc.get("status_code") != deny.get("code"):
            tally.fail(f"status_code {doc.get('status_code')!r} is not the verdict's code {deny.get('code')!r}")
        if doc.get("status_detail") != deny.get("reason"):
            tally.fail("status_detail is not the verdict's reason")
    elif verdict == "allow":
        want = "allow-modified" if modified else "allow"
        if ruling != want:
            tally.fail(f"aid.decision.verdict allows {'after a modification ' if modified else ''}and the "
                       f"base event records {ruling}")
    elif verdict == "pending":
        if ruling != "observed":
            tally.fail(f"aid.decision.verdict is pending and the base event records {ruling}")
    else:
        tally.fail(f"aid.decision.verdict {verdict!r} is not allow, a deny object or pending")
    flagged = decision.get("deny_ignored", False)
    if flagged not in (True, False):
        tally.fail("aid.decision.deny_ignored is not a boolean")
    elif flagged != ("deny_ignored" in actions):
        tally.fail(f"aid.decision.deny_ignored is {str(flagged).lower()} and "
                   f"{'a' if 'deny_ignored' in actions else 'no'} step is deny_ignored")
    return tally.result(ruling=ruling, verdict="deny" if isinstance(deny, dict) else verdict,
                        deny_ignored="deny_ignored" in actions)


def fingerprint(record: Record) -> tuple[dict, bytes | None]:
    att = record.att
    if att is None:
        return dim(UNAVAILABLE, "the record is not chained: it carries no attestation and no fingerprint"), None
    data = signing_input(record.doc)
    got = sha256_hex(data)
    if got != record.fingerprint:
        return dim(FAILED, f"the bytes the rule covers hash to {got}, not the stated fingerprint",
                   recomputed=got), data
    return dim(VERIFIED, recomputed=got), data


def _signature_bytes(text: Any) -> tuple[bytes | None, str]:
    raw = _b64(text)
    if raw is None:
        return None, "unmapped.signature_b64 is not canonical padded base64"
    try:
        r, s = decode_dss_signature(raw)
    except ValueError:
        return None, "the signature is not a DER-encoded ECDSA signature"
    if encode_dss_signature(r, s) != raw:
        return None, "the signature is not in canonical DER"
    if not (0 < r < _P256_ORDER and 0 < s < _P256_ORDER):
        return None, "the signature's r or s is outside the P-256 group"
    return raw, ""


def signature(record: Record, data: bytes | None, policy: TrustPolicy | None) -> tuple[dict, Key | None]:
    """The DSSE signature, tried against every key of the relying party's set; the key id picks none."""
    unmapped = record.doc.get("unmapped") if isinstance(record.doc.get("unmapped"), dict) else {}
    if "signature_b64" not in unmapped:
        why = ("unsigned: the fingerprint chain is a checksum anyone with write access to the records "
               "recomputes")
        return dim(UNAVAILABLE, why), None
    if data is None:
        return dim(NOT_CHECKED, "the record carries no attestation for the signature to cover"), None
    if policy is None:
        return dim(NOT_CHECKED, "no trust policy is configured"), None
    raw, why = _signature_bytes(unmapped["signature_b64"])
    if raw is None:
        return dim(FAILED, why), None
    message = pae(data)
    for key in policy.keys:
        try:
            key.public.verify(raw, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            continue
        notes = []
        if decode_dss_signature(raw)[1] > _P256_ORDER // 2:
            notes.append("s is in the upper half of the group, so (r, n - s) verifies too: the signature "
                         "bytes do not identify the record uniquely")
        return dim(VERIFIED, *notes, key=key.kid), key
    return dim(FAILED, "no key in the relying party's trust policy verifies the signature"), None


def key_binding(record: Record, sig: dict, key: Key | None, policy: TrustPolicy | None) -> dict:
    """Whether the signed bytes, read against the relying party's key set, name the key that signed.

    The record's key id (``unmapped.signature_key_id``) is removed before hashing, so it is a label
    anyone can change. It is compared with the key that verified, never used to choose one.
    """
    if key is None or policy is None:
        return dim(NOT_CHECKED, f"the signature is {sig['status']}")
    tally = Tally()
    authority = _get(record.att, "authority_uid")
    at = _time(record.doc.get("time"))
    kid = _get(record.doc, "unmapped", "signature_key_id")
    if not isinstance(authority, str):
        tally.fail("the signed bytes name no authority_uid, so nothing signed names the signer")
    elif key.authority_uid != authority:
        tally.fail(f"the key that verified, {key.kid!r}, belongs to {key.authority_uid!r}; the signed "
                   f"bytes name {authority!r}")
    if at.ok and not key.covers(at):
        tally.fail(f"the key that verified, {key.kid!r}, was not valid at the record's time {at.text}")
    if kid is not None and kid != key.kid:
        named = next((k for k in policy.keys if k.kid == kid), None)
        tally.fail(f"the unsigned key id names {kid!r}"
                   + (", another key of the relying party's set" if named else
                      ", which the relying party's set does not hold")
                   + f"; {key.kid!r} verified")
    if tally.failed:
        return tally.result(key=key.kid)
    rivals = [k.kid for k in policy.keys
              if k.authority_uid == authority and (not at.ok or k.covers(at))]
    if len(rivals) > 1:
        return dim(UNAVAILABLE, f"{len(rivals)} keys of {authority!r} were valid at {at.text} "
                   f"({', '.join(rivals)}); the signed bytes name the authority, not the key, and the key "
                   "id rides outside them", key=key.kid)
    return dim(VERIFIED, key=key.kid,
               basis="the signed authority_uid and the relying party's key set name one key at the "
                     "record's time")


def _absent_blocks(doc: dict) -> list[str]:
    out = []
    for path, capability in CAPABILITY_BLOCKS:
        node: Any = doc
        if path.startswith("unmapped."):
            node = _get(doc, "unmapped", path[len("unmapped."):])
        else:
            node = doc.get(path)
        if node is None:
            out.append(f"{path} ({capability})")
    return out


def read_one(index: int, line: int, text: str, policy: TrustPolicy | None) -> Record:
    record = Record(index, line, text, None, {"index": index, "line": line,
                                              "record_digest": sha256_hex(text.encode("utf-8"))})
    out = record.report
    try:
        doc = read_record(text)
    except NotRead as exc:
        out["read"] = False
        out["structural_validity"] = dim(FAILED, str(exc))
        for name in RECORD_DIMENSIONS[1:]:
            out[name] = dim(NOT_CHECKED, "the record is not read")
        return record
    out["structural_validity"] = structural_validity(doc)
    if out["structural_validity"]["status"] == FAILED:
        for name in RECORD_DIMENSIONS[1:]:
            out[name] = dim(NOT_CHECKED, "the record does not have the format's shape")
        return record
    record.doc = doc
    out["uid"] = record.uid
    out["chain_uid"] = _get(record.att, "chain_uid")
    out["decision_consistency"] = decision_consistency(doc)
    out["fingerprint"], data = fingerprint(record)
    out["signature"], key = signature(record, data, policy)
    out["key_binding"] = key_binding(record, out["signature"], key, policy)
    present = [m for m in OUTSIDE_SIGNED if _present(doc, m)]
    out["outside_signed_bytes"] = present
    out["absent_blocks"] = _absent_blocks(doc)
    out["wide_numbers"] = _wide_numbers(doc)
    return record


def _present(doc: dict, member: str) -> bool:
    if member.startswith("attestation_list[0]."):
        att = (doc.get("attestation_list") or [None])[0]
        return isinstance(att, dict) and member.rsplit(".", 1)[1] in att
    return isinstance(doc.get("unmapped"), dict) and member.rsplit(".", 1)[1] in doc["unmapped"]


# --- the stream ------------------------------------------------------------------------------------

def split_lines(data: bytes) -> list[tuple[int, str]]:
    """Records one per line (LF, with a CR before it dropped), blank lines skipped."""
    text = decode_utf8(data)
    out = []
    for number, piece in enumerate(text.split("\n"), start=1):
        line = piece.removesuffix("\r")
        if line.strip(JSON_WHITESPACE):
            out.append((number, line))
    return out


_SEQ = re.compile(r"-([0-9]{6,})$")


def _seq(uid: str, chain_uid: str, att: bool = False) -> int | None:
    prefix = f"{chain_uid}-att-" if att else f"{chain_uid}-"
    if not uid.startswith(prefix):
        return None
    tail = uid[len(prefix):]
    return int(tail) if tail.isdigit() and len(tail) >= 6 else None


def record_uniqueness(records: list[Record]) -> tuple[dict, list[Record]]:
    """Two records with one uid: identical bytes are one record delivered twice; different bytes refuse."""
    tally = Tally()
    by_uid: dict[str, Record] = {}
    kept: list[Record] = []
    for rec in records:
        uid = rec.uid
        if uid is None:
            kept.append(rec)
            continue
        first = by_uid.get(uid)
        if first is None:
            by_uid[uid] = rec
            kept.append(rec)
        elif canonical(first.doc) == canonical(rec.doc):
            tally.skip(f"records {first.index} and {rec.index} are one record ({uid}) delivered twice")
        else:
            tally.fail(f"records {first.index} and {rec.index} both claim uid {uid} with different "
                       "content: a replica or a restart sharing a chain_uid, or a substitution")
    status = tally.status()
    if status == NOT_CHECKED:  # a duplicate delivery is a finding, not a check left undone
        status = VERIFIED
    return dim(status, *(tally.failed + tally.unchecked)), kept


def chains(records: list[Record]) -> tuple[dict, dict, dict, dict]:
    """``chain_links``, ``chain_gaps``, ``chain_head`` and the segments per chain, for ``tail``."""
    chained = [r for r in records if r.att is not None]
    if not chained:
        none = dim(UNAVAILABLE, "no chained record is supplied", applies=False)
        return none, none, none, {}
    links, gaps, heads = Tally(), Tally(), Tally()
    groups: dict[str, list[Record]] = {}
    for rec in chained:
        groups.setdefault(rec.att["chain_uid"], []).append(rec)
    segments: dict[str, list[list[Record]]] = {}
    for chain_uid, members in groups.items():
        by_uid = {r.uid: r for r in members}
        successor: dict[str, Record] = {}
        starts = []
        for rec in members:
            _uid_pattern(rec, chain_uid, links)
            prev = rec.att.get("prev_event")
            if prev is None:
                starts.append(rec)
                continue
            if prev["uid"] in successor:
                links.fail(f"records {successor[prev['uid']].index} and {rec.index} both name {prev['uid']} "
                           "as their predecessor: the chain forks")
                continue
            successor[prev["uid"]] = rec
            before = by_uid.get(prev["uid"])
            if before is None:
                starts.append(rec)
                continue
            _link(before, rec, chain_uid, links)
        segs = [_walk(s, successor, links) for s in starts]
        covered = sum(len(s) for s in segs)
        if covered != len(members):
            links.fail(f"chain {chain_uid}: {len(members) - covered} records sit on a cycle or a fork "
                       "and are reached from no start")
        segs.sort(key=lambda s: (s[0].att.get("prev_event") is not None, _seq(s[0].uid, chain_uid) or 0,
                                 s[0].index))
        segments[chain_uid] = segs
        geneses = [s for s in segs if s[0].att.get("prev_event") is None]
        if len(geneses) > 1:
            links.fail(f"chain {chain_uid}: records {', '.join(str(s[0].index) for s in geneses)} each open "
                       "the chain")
        for seg in segs[1:]:
            if seg[0].att.get("prev_event") is None:
                continue
            prev_uid = seg[0].att["prev_event"]["uid"]
            gaps.fail(f"chain {chain_uid}: record {seg[0].index} names {prev_uid} as its predecessor, which "
                      f"is not supplied{_missing(segs, seg, chain_uid)}")
        if not geneses and segs:
            first = segs[0][0]
            heads.gone(f"chain {chain_uid}: the earliest supplied record names "
                       f"{first.att['prev_event']['uid']} as its predecessor; the chain's opening is not "
                       "supplied")
    return links.result(), gaps.result(), heads.result(), segments


def _missing(segs: list, seg: list, chain_uid: str) -> str:
    here = _seq(seg[0].uid, chain_uid)
    earlier = [s for s in segs if s is not seg and (_seq(s[-1].uid, chain_uid) or -1) < (here or 0)]
    if here is None or not earlier:
        return ""
    last = max(_seq(s[-1].uid, chain_uid) or 0 for s in earlier)
    lost = here - last - 1
    return f" ({lost} record{'s' if lost != 1 else ''} missing between seq {last} and {here})" if lost > 0 else ""


def _uid_pattern(rec: Record, chain_uid: str, tally: Tally) -> None:
    seq = _seq(rec.uid, chain_uid)
    att_seq = _seq(rec.att["uid"], chain_uid, att=True)
    if seq is not None and att_seq is not None and seq != att_seq:
        tally.fail(f"record {rec.index}: metadata.uid is seq {seq} and the attestation uid is seq {att_seq}")


def _link(before: Record, rec: Record, chain_uid: str, tally: Tally) -> None:
    prev = rec.att["prev_event"]
    if prev["fingerprint"].get("value") != before.fingerprint:
        tally.fail(f"record {rec.index}: prev_event.fingerprint is not the fingerprint of {prev['uid']} "
                   f"(record {before.index})")
    if prev["type_uid"] != before.doc.get("type_uid"):
        tally.fail(f"record {rec.index}: prev_event.type_uid is {prev['type_uid']}, and {prev['uid']} is "
                   f"type {before.doc.get('type_uid')}")
    if before.att["chain_uid"] != chain_uid:
        tally.fail(f"record {rec.index}: its predecessor sits on chain {before.att['chain_uid']}")
    a, b = _seq(before.uid, chain_uid), _seq(rec.uid, chain_uid)
    if a is not None and b is not None and b != a + 1:
        tally.fail(f"record {rec.index}: seq {b} links to seq {a}")


def _walk(start: Record, successor: dict[str, Record], tally: Tally) -> list[Record]:
    out, node, seen = [start], start, {start.uid}
    while node.uid in successor:
        node = successor[node.uid]
        if node.uid in seen:
            tally.fail(f"record {node.index} closes a cycle")
            break
        seen.add(node.uid)
        out.append(node)
    return out


def streams(records: list[Record]) -> tuple[dict, dict, dict]:
    """``stream_sequence`` and ``stream_head`` over ``unmapped."aid.stream"``, and the groups."""
    groups: dict[tuple[int, str], list[Record]] = {}
    for rec in records:
        stream = _get(rec.doc, "unmapped", "aid.stream")
        if isinstance(stream, dict):
            groups.setdefault((int(stream["epoch"]), stream["stream_id"]), []).append(rec)
    if not groups:
        none = dim(UNAVAILABLE, "no record carries aid.stream", applies=False)
        return none, none, {}
    seq, head = Tally(), Tally()
    out = {}
    for (epoch, stream_id), members in sorted(groups.items()):
        name = f"stream {stream_id} epoch {epoch}"
        by_seq: dict[int, Record] = {}
        for rec in members:
            n = int(rec.doc["unmapped"]["aid.stream"]["stream_seq"])
            if n in by_seq:
                seq.fail(f"{name}: records {by_seq[n].index} and {rec.index} both carry stream_seq {n}")
                continue
            by_seq[n] = rec
        order = sorted(by_seq)
        for a, b in itertools.pairwise(order):
            if b != a + 1:
                seq.fail(f"{name}: stream_seq {a + 1}" + (f" to {b - 1}" if b - 1 > a + 1 else "")
                         + " not supplied, between records that are: lost records")
            ea = by_seq[a].doc["unmapped"]["aid.stream"]["emission_seq"]
            eb = by_seq[b].doc["unmapped"]["aid.stream"]["emission_seq"]
            if not eb > ea:
                seq.fail(f"{name}: emission_seq {eb} at stream_seq {b} does not follow {ea} at stream_seq {a}")
        if order and order[0] != 0:
            head.gone(f"{name}: the stream opens at stream_seq 0; stream_seq 0 to {order[0] - 1} are not "
                      "supplied")
        out[(epoch, stream_id)] = by_seq
    return seq.result(), head.result(), out


def tail(segments: dict, groups: dict, heads: Any) -> dict:
    """The end of each chain and stream, against heads the relying party holds independently."""
    if not segments and not groups:
        return dim(UNAVAILABLE, "no chained record and no stream stamp is supplied")
    tally = Tally()
    heads = heads if isinstance(heads, list) else []
    chain_heads = {h["chain_uid"]: h for h in heads if isinstance(h, dict) and isinstance(h.get("chain_uid"), str)}
    stream_heads = {(h["epoch"], h["stream_id"]): h for h in heads
                    if isinstance(h, dict) and _int(h.get("epoch")) and isinstance(h.get("stream_id"), str)}
    for chain_uid, segs in segments.items():
        last = segs[-1][-1]
        held = chain_heads.pop(chain_uid, None)
        if held is None:
            tally.skip(f"chain {chain_uid}: no independent head is supplied; deleting the last records "
                       f"leaves a chain that still verifies, ending at {last.uid}")
            continue
        matches = [r for seg in segs for r in seg if r.uid == held.get("uid")]
        if not matches:
            lost = ""
            a, b = _seq(last.uid, chain_uid), _seq(str(held.get("uid")), chain_uid)
            if a is not None and b is not None and b > a:
                lost = f": {b - a} record{'s' if b - a != 1 else ''} after seq {a} are missing"
            tally.fail(f"chain {chain_uid}: the head the relying party holds, {held.get('uid')}, is not "
                       f"supplied{lost}")
        elif matches[0].fingerprint != held.get("fingerprint"):
            tally.fail(f"chain {chain_uid}: record {matches[0].index} has the head's uid and another "
                       "fingerprint")
        elif matches[0] is not last:
            tally.skip(f"chain {chain_uid}: records after the head {held.get('uid')} are not anchored by it")
    for key, by_seq in groups.items():
        top = max(by_seq)
        held = stream_heads.pop(key, None)
        name = f"stream {key[1]} epoch {key[0]}"
        if held is None:
            if not segments:
                tally.skip(f"{name}: no independent head is supplied; deleting the last records leaves "
                           f"a stream that still reads as dense, ending at stream_seq {top}")
            continue
        want = held.get("stream_seq")
        if not _int(want):
            tally.fail(f"{name}: the head the relying party holds has no stream_seq")
        elif want > top:
            tally.fail(f"{name}: the relying party's head is stream_seq {want}; stream_seq {top + 1} to "
                       f"{want} are not supplied")
        elif want < top:
            tally.skip(f"{name}: records after stream_seq {want} are not anchored by the head")
    for chain_uid in chain_heads:
        tally.fail(f"chain {chain_uid}: the relying party holds a head and no record of the chain is supplied")
    for key in stream_heads:
        tally.fail(f"stream {key[1]} epoch {key[0]}: the relying party holds a head and no record of the "
                   "stream is supplied")
    return tally.result()


# --- the report ------------------------------------------------------------------------------------

SCOPE = {"covers": "supplied_records_only",
         "not_assessed": ["truth_of_recorded_claims", "records_the_sink_never_wrote",
                          "decision_recomputation", "content_digests", "sink_capabilities"]}


def _rollup(records: list[Record], name: str) -> dict:
    tally = Tally()
    for rec in records:
        d = rec.report[name]
        text = "; ".join(d.get("findings", [])) or d["status"]
        if d["status"] == FAILED:
            tally.fail(f"record {rec.index}: {text}")
        elif d["status"] == NOT_CHECKED:
            tally.skip(f"record {rec.index}: {text}")
        elif d["status"] == UNAVAILABLE:
            tally.gone(f"record {rec.index}: {text}")
    if not records:
        return dim(UNAVAILABLE, "no record is supplied")
    return tally.result()


def read(data: bytes, *, trust_policy: Any = None, relying_party: dict | None = None) -> dict:
    """Read the records' exact bytes, one per line, and report every dimension separately."""
    out: dict[str, Any] = {"format": {"class_uid": CLASS_UID, "payload_type": PAYLOAD_TYPE,
                                      "rule": "AID-EMIT-1 record_integrity"},
                           "input_digest": sha256_hex(data)}
    try:
        lines = split_lines(data)
    except IJSONError as exc:
        out["records"] = []
        out["structural_validity"] = dim(FAILED, f"not read: {exc}")
        for name in RECORD_DIMENSIONS[1:] + STREAM_DIMENSIONS + ("evidence_scope", "content_digests"):
            out[name] = dim(NOT_CHECKED, "the records are not read")
        out["strict"] = {name: dim(NOT_CHECKED, "the records are not read") for name in STRICT_DIMENSIONS}
        out["scope_of_conclusion"] = SCOPE
        out["unread"] = True
        return out
    policy = TrustPolicy.read(trust_policy) if trust_policy is not None else None
    usable = policy if policy is not None and not policy.findings else None
    records = [read_one(i, line, text, usable) for i, (line, text) in enumerate(lines)]
    out["records"] = [r.report for r in records]
    out["unread"] = any(r.report.get("read") is False for r in records)
    for name in RECORD_DIMENSIONS:
        out[name] = _rollup(records, name)
    if policy is None:
        out["trust_policy"] = dim(NOT_CHECKED, "no trust policy is configured")
    else:
        out["trust_policy"] = policy.report()
    read_ok = [r for r in records if r.doc is not None]
    out["record_uniqueness"], kept = record_uniqueness(read_ok)
    out["chain_links"], out["chain_gaps"], out["chain_head"], segments = chains(kept)
    out["stream_sequence"], out["stream_head"], groups = streams(kept)
    out["tail"] = tail(segments, groups, (relying_party or {}).get("heads"))
    absent = sorted({b for r in read_ok for b in r.report["absent_blocks"]})
    out["evidence_scope"] = dim(NOT_CHECKED, *(
        [(f"absent from at least one record: {', '.join(absent)}; the format does not say whether the "
          "sink lacked the read capability or there was nothing to record")] if absent else []),
        basis="the format does not state which read capabilities the sink held")
    out["content_digests"] = (dim(NOT_SUPPORTED, "aid.content digests are not recomputed by this reader")
                              if any(_get(r.doc, "unmapped", "aid.content") is not None for r in read_ok)
                              else dim(UNAVAILABLE, "no record carries aid.content"))
    out["strict"] = strict_dimensions(out, records)
    out["scope_of_conclusion"] = SCOPE
    return out


def strict_dimensions(out: dict, records: list[Record]) -> dict:
    wide = [f"record {r.index}: {p}" for r in records if r.doc is not None for p in r.report["wide_numbers"]]
    opening = Tally()
    for name in ("chain_head", "stream_head"):
        d = out[name]
        if d["status"] == VERIFIED or not d.get("applies", True):
            continue
        add = {FAILED: opening.fail, NOT_CHECKED: opening.skip}.get(d["status"], opening.gone)
        for text in d.get("findings", [f"{name} is {d['status']}"]):
            add(f"{name}: {text}")
    return {
        "signature_required": _rollup(records, "signature"),
        "key_named_by_signed_bytes": _rollup(records, "key_binding"),
        "tail_anchored": dim(out["tail"]["status"], *out["tail"].get("findings", [])),
        "opening_supplied": opening.result(),
        "numbers_interoperable": (dim(FAILED, *[f"{w} is an integer a double-based reader reads as another "
                                                "number, so it canonicalizes to other bytes there" for w in wide])
                                  if wide else dim(VERIFIED)),
    }


def verdict(report: dict, profile: str = "baseline") -> tuple[str, str | None]:
    """What one profile accepts: ``("accept", None)`` or ``("reject", "<dimension>:<status>")``.

    ``baseline`` refuses a report in which any record or stream dimension failed. ``strict`` also
    requires every strict dimension to be ``verified``. Neither changes what the report says.
    """
    if profile not in PROFILES:
        raise ValueError(f"profile {profile!r} is not one of {PROFILES}")
    for name in BASELINE_REFUSES:
        if report[name]["status"] == FAILED:
            return "reject", f"{name}:{FAILED}"
    if profile == "baseline":
        return "accept", None
    for name in STRICT_DIMENSIONS:
        status = report["strict"][name]["status"]
        if status != VERIFIED:
            return "reject", f"{name}:{status}"
    return "accept", None


# --- corpus members and the command line ----------------------------------------------------------

def read_member(member: dict) -> tuple[dict, str, str | None]:
    """Read one corpus member: ``records`` (the exact text), ``trust_policy``, ``relying_party``, ``profile``."""
    report = read(member["records"].encode("utf-8"), trust_policy=member.get("trust_policy"),
                  relying_party=member.get("relying_party"))
    decision, reason = verdict(report, member.get("profile", "baseline"))
    return report, decision, reason


def main(argv: list[str] | None = None) -> int:
    """``agent-evidence-verify ocsf-decision``: one stream's report and a profile's verdict.

    Exit 0 when the profile accepts, 1 when it refuses, 2 when an input cannot be read (no verdict).
    """
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="agent-evidence-verify ocsf-decision",
        description="report every dimension of a stream of OCSF decision records (AID-EMIT-1)")
    parser.add_argument("records", type=Path, help="the records' exact bytes, one record per line")
    parser.add_argument("--trust-policy", type=Path, help="the relying party's own JWKS, keys bound to authorities")
    parser.add_argument("--heads", type=Path,
                        help="heads the relying party holds independently: a JSON list of "
                             '{"chain_uid", "uid", "fingerprint"} and {"epoch", "stream_id", "stream_seq"}')
    parser.add_argument("--profile", choices=PROFILES, default="baseline")
    args = parser.parse_args(argv)
    try:
        data = args.records.read_bytes()
        policy = parse_ijson(args.trust_policy.read_bytes()) if args.trust_policy else None
        heads = parse_ijson(args.heads.read_bytes()) if args.heads else None
    except (OSError, IJSONError) as exc:
        print(f"agent-evidence-verify ocsf-decision: {exc}", file=sys.stderr)
        return 2
    report = read(data, trust_policy=policy, relying_party={"heads": heads})
    out: dict[str, Any] = {"report": report, "profile": args.profile}
    if report["unread"]:
        sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
        print("agent-evidence-verify ocsf-decision: a record is not read", file=sys.stderr)
        return 2
    out["verdict"], out["reason"] = verdict(report, args.profile)
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0 if out["verdict"] == "accept" else 1
