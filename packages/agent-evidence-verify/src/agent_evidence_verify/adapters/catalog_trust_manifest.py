"""``catalog_trust_manifest/v1``: does one signed ARD or AI Catalog object bind its entry, and who signed it?

A catalog object carries a detached JWS (RFC 7515 with RFC 7797 for ``b64: false``) over the RFC 8785
bytes of the object one of four closed constructions names:

``ard-draft-bu-00``
    JCS(trustManifest minus ``signature``), a detached JWS string (draft-bu-dawn-ard-discovery-00
    section 3.5); ES256 or EdDSA.
``field-whole-entry``
    JCS(entry minus trustManifest.signature): measured practice, defined by no revision.
``ai-catalog-2026-11``
    JCS(trustManifests[i] minus its own ``signature.jws`` and ``additionalSignatures``), typ
    ``ai-catalog-trust-manifest+jws``, ES256 only, under the did:web Signer Profile ``did-web-v1``.
``ai-catalog-snapshot``
    JCS(catalog minus its own ``signature.jws`` and ``additionalSignatures``), typ ``ai-catalog+jws``.

The signer's key comes from offline DID documents (the bytes a did:web resolver returned, keyed by
DID, bound as a case artifact): the ``kid`` must be the signer DID plus a fragment, the document's
``id`` that DID, and exactly one verification method listed under ``assertionMethod`` must carry the
key. The signed subject must name the entry (identifier, type, digest, version), the entry must
deliver its artifact by exactly one of ``url`` or ``data``, and the digest must match the artifact
bytes (for ``data``, the RFC 8785 bytes of the value). An ARD url is bound to the entry's publisher
origin (RFC 6454) or to an artifact that names the same identifier. Every attestation the consumer
vendored is a DSSE envelope (read through :mod:`agent_evidence_verify.dsse`, either base64
alphabet, ES256 raw or strict DER) signed by a key a supplied DID document asserts, whose in-toto
Statement names the entry's digest. A publisher role needs the signer to be ``did:web:<publisher>``.
Instants are RFC 3339 read exactly, a second of 60 only on an IERS leap-second day.

The checks, their order and their codes are a port of probityai/agent-evidence-vectors,
``packaging/agent_evidence_vectors/catalogtrust.py`` at commit
01086cf076f276a1704e9a2022aa3a641902f2dc; tests/data/catalog-trust-manifest copies that commit's
115-case corpus, and the parity test requires the reference reader's decision and code on every
case. JSON is read once through :func:`agent_evidence_verify.ijson.parse_ijson`, with the profile's
own number and surrogate rules deferred to the signed bytes, where the profile applies them.

Decisions: a reader refusal is ``contradicted`` with its code. A reader acceptance is ``supported``
(``signature_covers_release`` or ``snapshot_signature_valid``) only when every signing key it
relied on, the manifest signer's and each attestation signer's, is authorised under the consumer's
``key_authority`` (:mod:`agent_evidence_verify.key_authority`); an unauthorised key is
``contradicted`` with the authority's reason, and no authority, or bytes it needs that are missing,
is ``not_established``. Missing evidence is never read as a refusal: an unbound catalog, DID
document set, artifact or vendored attestation is ``not_established``. Nor does it mask one: an
unbound artifact or attestation skips only the checks that read those bytes, and a later check
that fails (the publisher rule, a time, another attestation) still contradicts. A construction or role
outside the closed sets, or a check time that is not an RFC 3339 instant, is the consumer's own
input and a case error.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import math
import re
from fractions import Fraction
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..common import CaseError, _string
from ..ijson import IJSONError, parse_ijson
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "catalog_trust_manifest/v1"
LIMIT = ("Says which key signed which bytes under which construction, and that the signed subject "
         "binds the entry and its artifact. It never says the artifact is safe or that the claims it "
         "carries are true, and it resolves no DID online: the DID documents are the bytes supplied.")

DRAFT, FIELD = "ard-draft-bu-00", "field-whole-entry"
AIC, SNAPSHOT = "ai-catalog-2026-11", "ai-catalog-snapshot"
CONSTRUCTIONS = (DRAFT, FIELD, AIC, SNAPSHOT)
ARD_SHAPED = (DRAFT, FIELD)
TYP = {AIC: "ai-catalog-trust-manifest+jws", SNAPSHOT: "ai-catalog+jws"}
ALGS = {DRAFT: ("ES256", "EdDSA"), FIELD: ("ES256", "EdDSA"), AIC: ("ES256",), SNAPSHOT: ("ES256",)}
KEY_SOURCES = ("jku", "jwk", "x5u", "x5c")
SAFE = 2**53 - 1
PASS_REASON = {DRAFT: "signature_covers_release", FIELD: "signature_covers_release",
               AIC: "signature_covers_release", SNAPSHOT: "snapshot_signature_valid"}
IN_TOTO = "https://in-toto.io/Statement/v1"
#: The AI Catalog did:web Signer Profile, selected by its exact reserved name.
SIGNER_PROFILE = "did-web-v1"
ROLES = ("publisher", "contributor")
PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")
DSSE_TYPE = "application/vnd.in-toto+json"

#: Gates end the read: no later check has an object to look at. ``construction_unknown`` and
#: ``role_unknown`` are the consumer's own input here, so they are case errors carrying the code.
GATES = ("construction_unknown", "role_unknown", "json_invalid", "signature_missing")
#: Every other refusal, in the order the reader applies them; the first that fails is the reason.
CHECKS = (
    "duplicate_member",
    "jws_malformed",
    "typ_missing_or_mismatched",
    "alg_not_allowed_for_profile",
    "key_source_in_header",
    "b64_forbidden_for_profile",
    "jws_crit_unsupported",
    "b64_without_crit",
    "profile_unsupported",
    "signer_not_root_did_web",
    "kid_not_under_identity",
    "did_document_not_identity",
    "kid_not_in_did_document",
    "verification_method_ambiguous",
    "key_not_assertion_method",
    "method_controller_mismatch",
    "jwk_not_signing_key",
    "alg_key_mismatch",
    "number_not_interoperable",
    "no_canonical_form",
    "signature_invalid",
    "signer_not_contributor",
    "subject_missing",
    "subject_entry_mismatch",
    "entry_delivery_not_one",
    "entry_digest_missing_for_url",
    "artifact_digest_mismatch",
    "url_origin_unbound",
    "attestation_digest_mismatch",
    "attestation_unsigned",
    "attestation_transplanted",
    "publisher_not_signer",
    "publisher_authorization_absent",
    "timestamp_invalid",
    "issued_in_future",
    "manifest_expired",
)
REASONS = GATES + CHECKS

#: A JSON text with more than this many arrays and objects open at once is refused before it is
#: parsed, so every reader holds the same values (``json_invalid``).
MAX_NESTING = 64
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
# A non-empty RFC 3986 fragment: pchar, "/" and "?", percent-escapes well formed.
_FRAGMENT = r"(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})+"
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# A root did:web DID: a lowercase ASCII domain (A-labels allowed), no port, path or trailing dot.
_ROOT_DID_WEB = re.compile(rf"did:web:(?:{_LABEL}\.)*{_LABEL}")
# RFC 3339 section 5.6 date-time; "T" and "Z" may be lowercase (section 5.6 NOTE); ASCII digits.
_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})"
                   r"(\.[0-9]+)?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))")
#: The UTC days that end in a leap second, from the IERS list (leap-seconds.list, file hash
#: a9bad145 84c31c70 758402aa b37bfd54 5923836a, expires 28 June 2027). A second of 60 names a
#: real instant only at 23:59:60 UTC on one of them (RFC 3339 section 5.7).
LEAP_SECOND_DAYS = (
    (1972, 6, 30), (1972, 12, 31), (1973, 12, 31), (1974, 12, 31), (1975, 12, 31),
    (1976, 12, 31), (1977, 12, 31), (1978, 12, 31), (1979, 12, 31), (1981, 6, 30),
    (1982, 6, 30), (1983, 6, 30), (1985, 6, 30), (1987, 12, 31), (1989, 12, 31),
    (1990, 12, 31), (1992, 6, 30), (1993, 6, 30), (1994, 6, 30), (1995, 12, 31),
    (1997, 6, 30), (1998, 12, 31), (2005, 12, 31), (2008, 12, 31), (2012, 6, 30),
    (2015, 6, 30), (2016, 12, 31))
#: The P-256 field prime: a JWK coordinate at or past it names no point (SEC 1 section 2.3.4).
P256_FIELD = 2**256 - 2**224 + 2**192 + 2**96 - 1
#: A DER integer of an ES256 signature fits in 32 bytes.
_P256_ORDER_BITS = 256


class Refused(Exception):
    """A check failed; ``args[0]`` is its code."""


class Unavailable(Exception):
    """Evidence a check needs was not supplied; ``args[0]`` is the not_established reason."""


# --------------------------------------------------------------------------- reading

def load(data: bytes) -> Any:
    """Strict JSON under the profile: duplicates refused, nesting bounded at :data:`MAX_NESTING`.

    Integers past 2**53 - 1, non-finite doubles and lone surrogates are kept, because the profile
    refuses them only in the signed bytes (``number_not_interoperable``, ``no_canonical_form``).
    Raises :class:`IJSONError`, or ``ValueError`` for an integer token too long to convert.
    """
    return parse_ijson(data, max_depth=MAX_NESTING, parse_int=int, parse_float=float,
                       lone_surrogates=True)


def b64url_decode(text: Any) -> bytes:
    """Strict unpadded base64url (RFC 7515 section 2), in its one canonical form."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise ValueError("non-canonical base64url")
    return raw


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def index_of(value: Any) -> int | None:
    """An entry or manifest index: a non-negative JSON integer (1.0 is the integer 1), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return value if isinstance(value, int) and 0 <= value <= 2**31 else None


# --------------------------------------------------------------------------- RFC 8785

def _numbers_first(value: Any) -> None:
    """Refuse a number past 2**53 - 1 (a non-finite double included) before any other fault."""
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, bool) or node is None or isinstance(node, str):
            continue
        if isinstance(node, (int, float)):
            if abs(node) > SAFE:
                raise Refused("number_not_interoperable")
            continue
        stack.extend(node.values() if isinstance(node, dict) else node)


def canonical(value: Any) -> bytes:
    """RFC 8785 bytes under the profile's safe-integer reading."""
    _numbers_first(value)
    try:
        return jcs_canonical.serialize(value)
    except jcs_canonical.Refusal as exc:
        raise Refused("no_canonical_form") from exc


# --------------------------------------------------------------------------- signing inputs

def payload(construction: str, catalog: dict[str, Any], entry: int | None,
            manifest: int | None) -> Any:
    """The JSON value whose RFC 8785 bytes a construction signs."""
    if construction == SNAPSHOT:
        out = copy.deepcopy(catalog)
        out.get("signature", {}).pop("jws", None)
        out.pop("additionalSignatures", None)
        return out
    item = catalog["entries"][entry]
    if construction == DRAFT:
        out = copy.deepcopy(item["trustManifest"])
        out.pop("signature", None)
        return out
    if construction == FIELD:
        out = copy.deepcopy(item)
        out["trustManifest"].pop("signature", None)
        return out
    out = copy.deepcopy(item["trustManifests"][manifest])
    out.get("signature", {}).pop("jws", None)
    out.pop("additionalSignatures", None)
    return out


def signed_object(construction: str, catalog: dict[str, Any], entry: int | None,
                  manifest: int | None) -> dict[str, Any] | None:
    """The object that carries the signature, or None when the path names nothing."""
    try:
        if construction == SNAPSHOT:
            return catalog if isinstance(catalog.get("signature"), dict) else None
        if entry is None or (manifest is None and construction == AIC):
            return None
        item = catalog["entries"][entry]
        if construction in ARD_SHAPED:
            value = item.get("trustManifest")
        else:
            value = item.get("trustManifests", [])[manifest]
        return value if isinstance(value, dict) else None
    except (KeyError, IndexError, TypeError, AttributeError):
        return None


def jws_of(construction: str, obj: dict[str, Any]) -> Any:
    if construction in ARD_SHAPED:
        return obj.get("signature")
    signature = obj.get("signature")
    return signature.get("jws") if isinstance(signature, dict) else None


def identity_of(construction: str, obj: dict[str, Any]) -> Any:
    if construction in ARD_SHAPED:
        return obj.get("identity")
    signature = obj.get("signature")
    return signature.get("signer") if isinstance(signature, dict) else None


def times_of(construction: str, obj: dict[str, Any]) -> tuple[Any, Any]:
    holder = obj if construction in ARD_SHAPED else obj.get("signature") or {}
    return holder.get("issuedAt"), holder.get("expiresAt")


# --------------------------------------------------------------------------- keys and signatures

def _coordinate(text: Any) -> int:
    return int.from_bytes(b64url_decode(text), "big")


def public_key(method: dict[str, Any]) -> tuple[str, Any]:
    """The algorithm a method's JWK verifies and the key object, or ``("none", None)``."""
    jwk = method.get("publicKeyJwk")
    if not isinstance(jwk, dict):
        return "none", None
    try:
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            raw = b64url_decode(jwk["x"])
            # The raw 32 bytes: a point that does not decode fails at verification, as the
            # reference rail's does, not here as a key of no algorithm.
            return ("EdDSA", raw) if len(raw) == 32 else ("none", None)
        if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
            x, y = _coordinate(jwk["x"]), _coordinate(jwk["y"])
            if max(x, y) >= P256_FIELD:
                return "none", None
            point = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
            return "ES256", ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except (KeyError, ValueError, TypeError):
        pass
    return "none", None


def key_bytes(method: dict[str, Any]) -> bytes:
    """The raw key bytes the key authority reads: the OKP ``x``, or 0x04 || x || y."""
    from ..key_authority import jwk_key_bytes
    return jwk_key_bytes(method.get("publicKeyJwk"), f"verificationMethod {method.get('id')}")


def verify_signature(alg: str, key: Any, message: bytes, signature: bytes) -> bool:
    """A JWS signature: EdDSA over 64 bytes, or ES256 as raw r || s (RFC 7518 section 3.4)."""
    try:
        if alg == "EdDSA":
            if len(signature) != 64:
                return False
            Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
            return True
        if alg == "ES256" and len(signature) == 64:
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, ValueError):
        return False
    return False


def _der_integer(data: bytes, at: int) -> tuple[int, int] | None:
    """One minimal, non-negative DER INTEGER with a short-form length at ``at``."""
    if at + 2 > len(data) or data[at] != 0x02 or not 0 < data[at + 1] < 0x80:
        return None
    end = at + 2 + data[at + 1]
    body = data[at + 2:end]
    if end > len(data) or body[0] & 0x80 or (len(body) > 1 and body[0] == 0 and body[1] < 0x80):
        return None
    return int.from_bytes(body, "big"), end


def der_signature(data: bytes) -> bytes | None:
    """An ECDSA-Sig-Value (RFC 3279 section 2.2.3) in strict DER as raw r || s, else None."""
    if len(data) < 2 or data[0] != 0x30 or data[1] >= 0x80 or data[1] != len(data) - 2:
        return None
    first = _der_integer(data, 2)
    second = _der_integer(data, first[1]) if first else None
    if first is None or second is None or second[1] != len(data):
        return None
    r, s = first[0], second[0]
    if max(r, s) >= 2**_P256_ORDER_BITS:
        return None
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_dsse_signature(alg: str, key: Any, message: bytes, signature: bytes) -> bool:
    """A DSSE signature: as JWS, and for ES256 also the strict DER form signers commonly write."""
    if verify_signature(alg, key, message, signature):
        return True
    raw = der_signature(signature) if alg == "ES256" else None
    return raw is not None and verify_signature(alg, key, message, raw)


def _jwk_fault(method: dict[str, Any], alg: Any) -> bool:
    """True when the method's JWK is not a public key fit to verify ``alg`` (RFC 7517 4.2-4.4,
    RFC 7518 6.2.1, AI Catalog "JWS Algorithm and Key Requirements")."""
    jwk = method.get("publicKeyJwk")
    if not isinstance(jwk, dict):
        return False  # no key at all is alg_key_mismatch
    if any(name in jwk for name in PRIVATE_JWK_MEMBERS):
        return True
    if "use" in jwk and jwk["use"] != "sig":
        return True
    if "key_ops" in jwk and not (isinstance(jwk["key_ops"], list) and "verify" in jwk["key_ops"]):
        return True
    if "alg" in jwk and jwk["alg"] != alg:
        return True
    if jwk.get("kty") == "EC":
        try:
            return len(b64url_decode(jwk["x"])) != 32 or len(b64url_decode(jwk["y"])) != 32
        except (KeyError, ValueError):
            return True
    return False


def _absolute(ref: Any, base: Any) -> Any:
    """A DID URL with a relative reference resolved against the document id (DID Core 3.2.2)."""
    if isinstance(ref, str) and ref.startswith("#") and isinstance(base, str):
        return base + ref
    return ref


def methods_of(document: dict[str, Any]) -> tuple[list[dict[str, Any]], set[str]]:
    """Every verification method with its id made absolute, and the assertion method ids."""
    base = document.get("id")
    methods: list[dict[str, Any]] = []
    assertion: set[str] = set()
    listed = document.get("verificationMethod", [])
    for method in listed if isinstance(listed, list) else []:
        if isinstance(method, dict) and isinstance(method.get("id"), str):
            methods.append({**method, "id": _absolute(method["id"], base)})
    granted = document.get("assertionMethod", [])
    for item in granted if isinstance(granted, list) else []:
        if isinstance(item, str):
            assertion.add(_absolute(item, base))
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            embedded = {**item, "id": _absolute(item["id"], base)}
            assertion.add(embedded["id"])
            methods.append(embedded)
    return methods, assertion


def root_did_web(identity: Any) -> bool:
    """A root did:web DID: a lowercase ASCII domain of at most 253 octets (RFC 1035 2.3.4) whose
    last label is not all digits (RFC 3696 section 2), which also excludes a dotted IPv4 address."""
    if not isinstance(identity, str) or not _ROOT_DID_WEB.fullmatch(identity):
        return False
    domain = identity[len("did:web:"):]
    return len(domain) <= 253 and not domain.rsplit(".", 1)[-1].isdigit()


# --------------------------------------------------------------------------- instants

def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 in the proleptic Gregorian calendar, year 0000 included."""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


_LEAP_DAYS = frozenset(_days_from_civil(*day) for day in LEAP_SECOND_DAYS)


def _leap_second(before: int) -> bool:
    """True when ``before`` (whole UTC seconds since 1970) is 23:59:59 on a leap-second day."""
    day, of_day = divmod(before, 86400)
    return of_day == 86399 and day in _LEAP_DAYS


def instant(text: Any) -> Fraction | None:
    """An RFC 3339 date-time as exact seconds since 1970, or None when it is not one."""
    match = _TIME.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(match[n]) for n in range(1, 7))
    if month < 1 or month > 12 or day < 1 or day > _days_in_month(year, month) or \
            hour > 23 or minute > 59 or second > 60:
        return None
    seconds = Fraction(_days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60
                       + second)
    if match[7]:
        seconds += Fraction(match[7][1:]) / 10 ** (len(match[7]) - 1)
    if not match[8]:
        offset_hours, offset_minutes = int(match[10]), int(match[11])
        if offset_hours > 23 or offset_minutes > 59:
            return None
        offset = (offset_hours * 60 + offset_minutes) * 60
        seconds -= offset if match[9] == "+" else -offset
    if second == 60 and not _leap_second(math.floor(seconds) - 1):
        return None
    return seconds


# --------------------------------------------------------------------------- binding helpers

def _publisher(identifier: Any) -> str | None:
    parts = identifier.split(":") if isinstance(identifier, str) else []
    return parts[2] if len(parts) > 3 and parts[:2] == ["urn", "air"] else None


def origin(url: Any) -> str | None:
    """The RFC 6454 origin of an https URL as https://<host>, or None. Scheme and host are
    case-insensitive and 443 is the default port; a URL with userinfo is not read (RFC 9110
    section 4.2.4), nor a host with a percent-escape or an IP literal."""
    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(?:[/?#].*)?", url) \
        if isinstance(url, str) else None
    if match is None or match[1].lower() != "https" or "@" in match[2]:
        return None
    host, _, port = match[2].partition(":")
    if not host or "%" in host or "[" in host or port not in ("", "443"):
        return None
    return "https://" + host.lower()


def _dsse_key(keyid: Any, documents: dict[str, Any]) -> tuple[str, Any, dict[str, Any] | None]:
    """The algorithm, key and method a DSSE keyid names, or ``("none", None, None)``."""
    if not isinstance(keyid, str) or "#" not in keyid:
        return "none", None, None
    did = keyid.split("#", 1)[0]
    document = documents.get(did)
    if not isinstance(document, dict) or document.get("id") != did:
        return "none", None, None
    methods, assertion = methods_of(document)
    selected = [m for m in methods if m["id"] == keyid]
    if len(selected) != 1 or keyid not in assertion:
        return "none", None, None
    alg, key = public_key(selected[0])
    if _jwk_fault(selected[0], alg) or key is None:
        return "none", None, None
    return alg, key, selected[0]


def signed_statement(data: bytes, documents: dict[str, Any]) -> tuple[dict[str, Any], str,
                                                                       dict[str, Any]] | None:
    """The in-toto Statement inside a DSSE envelope a supplied DID document's key signed, with the
    keyid and method that verified it, else None. The envelope is read by
    :func:`agent_evidence_verify.dsse.parse` (canonical padded base64 in either alphabet)."""
    from .. import dsse
    try:
        envelope = load(data)
        kind, body, signatures = dsse.parse(envelope)
    except (CaseError, IJSONError, ValueError):
        return None
    if kind != DSSE_TYPE:
        return None
    entries = envelope["signatures"]
    for entry, raw in zip(entries, signatures):
        keyid = entry.get("keyid")
        alg, key, method = _dsse_key(keyid, documents)
        if key is None or method is None:
            continue
        if verify_dsse_signature(alg, key, dsse.pae(kind, body), raw):
            try:
                statement = load(body)
            except (IJSONError, ValueError):
                return None
            if isinstance(statement, dict) and statement.get("_type") == IN_TOTO:
                return statement, keyid, method
            return None
    return None


# --------------------------------------------------------------------------- the reader

class _Read:
    """One catalog object being judged: each method applies a run of consecutive checks."""

    def __init__(self, inputs: dict[str, Any]) -> None:
        self.construction: str = inputs["construction"]
        self.role: str = inputs["role"]
        self.at: Fraction = inputs["at"]
        self.entry_index = index_of(inputs["entry"])
        self.manifest_index = index_of(inputs["manifest"])
        self.raw_catalog: bytes = inputs["catalog"]
        self.raw_documents: bytes = inputs["did_documents"]
        self.supplied_artifact: bytes | None = inputs["artifact"]
        self.attestation_bytes: list[tuple[bool, bytes | None]] = inputs["attestations"]
        self.catalog: dict[str, Any] = {}
        self.documents: dict[str, Any] = {}
        self.obj: dict[str, Any] = {}
        self.entry: dict[str, Any] = {}
        self.parts: list[str] = []
        self.header: dict[str, Any] = {}
        self.signature = b""
        self.alg: Any = None
        self.identity: Any = None
        self.kid: Any = None
        self.method: dict[str, Any] = {}
        self.key_alg = "none"
        self.key: Any = None
        self.artifact_bytes: bytes | None = None
        self.publisher_domain: str | None = None
        #: Each signature the verdict relied on: (role, kid, DID, method).
        self.signers: list[tuple[str, Any, Any, dict[str, Any]]] = []
        #: The first not_established reason met: evidence a check needed was not supplied. The
        #: read goes on past it, so a later check the missing bytes cannot affect still refuses.
        self.missing: str | None = None

    def defer(self, reason: str) -> None:
        """Record missing evidence without ending the read."""
        if self.missing is None:
            self.missing = reason

    def judge(self) -> str:
        """The ordered check list of the profile; the first check that fails is the reason.

        Missing evidence never masks a refusal: an unbound artifact or attestation skips only the
        checks that read those bytes, every later check still runs, and the read is
        :class:`Unavailable` only when none of them fails.
        """
        self.load()
        self.signature_object()
        self.read_header()
        self.signer()
        self.select_key()
        self.signed_bytes()
        self.signers.append(("manifest", self.kid, self.identity, self.method))
        if self.construction == SNAPSHOT:
            self.times(self.catalog)
            return PASS_REASON[self.construction]
        self.subject()
        self.artifact()
        self.bound_origin()
        self.attestations()
        self.publisher_rule()
        self.times(self.obj)
        if self.missing is not None:
            raise Unavailable(self.missing)
        return PASS_REASON[self.construction]

    def load(self) -> None:
        documents: Any = None
        try:
            catalog = load(self.raw_catalog)
            documents = load(self.raw_documents)
        except IJSONError as exc:
            raise Refused("duplicate_member" if exc.code == "duplicate-member"
                          else "json_invalid") from exc
        except ValueError as exc:
            raise Refused("json_invalid") from exc
        if not isinstance(catalog, dict) or not isinstance(documents, dict):
            raise Refused("json_invalid")
        self.catalog, self.documents = catalog, documents

    def signature_object(self) -> None:
        found = signed_object(self.construction, self.catalog, self.entry_index,
                              self.manifest_index)
        if found is None or not isinstance(jws_of(self.construction, found), str):
            raise Refused("signature_missing")
        self.obj = found
        self.parts = jws_of(self.construction, found).split(".")
        if self.construction != SNAPSHOT:
            self.entry = self.catalog["entries"][self.entry_index]

    def read_header(self) -> None:
        """jws_malformed through b64_without_crit: the protected header alone."""
        parts = self.parts
        try:
            if len(parts) != 3 or parts[1] != "":
                raise ValueError("not detached compact serialization")
            header = load(b64url_decode(parts[0]))
            self.signature = b64url_decode(parts[2])
        except ValueError as exc:  # IJSONError is a ValueError
            raise Refused("jws_malformed") from exc
        if not isinstance(header, dict):
            raise Refused("jws_malformed")
        self.header = header
        if "b64" in header and not isinstance(header["b64"], bool):
            raise Refused("jws_malformed")  # RFC 7797 section 3: the b64 value is a boolean
        if self.construction in TYP and header.get("typ") != TYP[self.construction]:
            raise Refused("typ_missing_or_mismatched")
        self.alg = header.get("alg")
        if self.alg not in ALGS[self.construction]:
            raise Refused("alg_not_allowed_for_profile")
        if any(name in header for name in KEY_SOURCES):
            raise Refused("key_source_in_header")
        if self.construction not in ARD_SHAPED and "b64" in header:
            raise Refused("b64_forbidden_for_profile")
        crit = header.get("crit")
        if crit is not None and (not isinstance(crit, list) or not crit
                                 or any(name != "b64" or name not in header for name in crit)):
            raise Refused("jws_crit_unsupported")
        if "b64" in header and not (isinstance(crit, list) and "b64" in crit):
            raise Refused("b64_without_crit")

    def signer(self) -> None:
        """profile_unsupported through did_document_not_identity: who claims to have signed."""
        self.identity = identity = identity_of(self.construction, self.obj)
        if self.construction not in ARD_SHAPED:
            # AI Catalog "Profile Selection": the named procedure, never one inferred.
            if self.obj["signature"].get("profile") != SIGNER_PROFILE:
                raise Refused("profile_unsupported")
            if not root_did_web(identity):
                raise Refused("signer_not_root_did_web")
        self.kid = kid = self.header.get("kid")
        if not (isinstance(kid, str) and isinstance(identity, str)
                and re.fullmatch(re.escape(identity) + "#" + _FRAGMENT, kid) is not None):
            raise Refused("kid_not_under_identity")
        document = self.documents.get(identity)
        if not isinstance(document, dict) or document.get("id") != identity:
            raise Refused("did_document_not_identity")

    def select_key(self) -> None:
        """kid_not_in_did_document through alg_key_mismatch: the key the document gives."""
        methods, assertion = methods_of(self.documents[self.identity])
        selected = [m for m in methods if m["id"] == self.kid]
        if not selected:
            raise Refused("kid_not_in_did_document")
        if len(selected) > 1:
            raise Refused("verification_method_ambiguous")  # exactly one method has the kid
        if self.kid not in assertion:
            raise Refused("key_not_assertion_method")
        self.method = method = selected[0]
        if self.construction not in ARD_SHAPED and method.get("controller") != self.identity:
            raise Refused("method_controller_mismatch")
        self.key_alg, self.key = public_key(method)
        if _jwk_fault(method, self.alg):
            raise Refused("jwk_not_signing_key")
        if self.key_alg != self.alg:
            raise Refused("alg_key_mismatch")

    def signed_bytes(self) -> None:
        """number_not_interoperable, no_canonical_form and signature_invalid."""
        body = canonical(payload(self.construction, self.catalog, self.entry_index,
                                 self.manifest_index))
        unencoded = self.header.get("b64") is False
        message = self.parts[0].encode() + b"." + (body if unencoded else b64url(body).encode())
        if not verify_signature(self.key_alg, self.key, message, self.signature):
            raise Refused("signature_invalid")

    def subject(self) -> None:
        """signer_not_contributor through subject_entry_mismatch."""
        obj, entry = self.obj, self.entry
        if self.construction == AIC and obj.get("contributor") != self.identity:
            raise Refused("signer_not_contributor")
        subject = obj.get("subject")
        if not isinstance(subject, dict):
            raise Refused("subject_missing")
        for member in ("identifier", "type"):
            # Both are required strings on the entry (draft section 3.1, AI Catalog entry).
            if not isinstance(entry.get(member), str) or subject.get(member) != entry.get(member):
                raise Refused("subject_entry_mismatch")
        if subject.get("digest") != entry.get("digest"):
            raise Refused("subject_entry_mismatch")
        if ("version" in subject) != ("version" in entry) or \
                subject.get("version") != entry.get("version"):
            raise Refused("subject_entry_mismatch")

    def artifact(self) -> None:
        entry = self.entry
        # Draft 3.1 and the AI Catalog Catalog Entry: exactly one of url and data.
        if ("url" in entry) == ("data" in entry):
            raise Refused("entry_delivery_not_one")
        if "digest" not in entry and ("url" in entry or self.construction == AIC):
            raise Refused("entry_digest_missing_for_url")
        if "data" in entry:
            # AI Catalog "digest": for data, hash the UTF-8 JCS-canonicalized JSON value; the
            # draft's digest is "of the target artifact referenced by url (or inline data)".
            try:
                self.artifact_bytes = canonical(entry["data"])
            except Refused:
                self.artifact_bytes = None
        else:
            if self.supplied_artifact is None:
                self.defer("artifact_unavailable")  # the digest cannot be checked; read on
                return
            self.artifact_bytes = self.supplied_artifact
        if self.artifact_bytes is None or \
                entry.get("digest") != "sha256:" + sha256_hex(self.artifact_bytes):
            raise Refused("artifact_digest_mismatch")

    def bound_origin(self) -> None:
        """url_origin_unbound: draft 6.2 binds a url to its origin; inline data has none."""
        entry = self.entry
        self.publisher_domain = publisher = _publisher(entry.get("identifier"))
        if self.construction not in ARD_SHAPED or "url" not in entry:
            return
        if publisher is not None and origin(entry.get("url")) == f"https://{publisher.lower()}":
            return
        if self.artifact_bytes is None:
            # Off the publisher's origin only the artifact can bind the url, and it is missing.
            self.defer("artifact_unavailable")
            return
        try:
            descriptor = load(self.artifact_bytes) if self.artifact_bytes else {}
        except ValueError:
            descriptor = {}
        declared = descriptor.get("identifier") if isinstance(descriptor, dict) else None
        if declared != entry.get("identifier"):
            raise Refused("url_origin_unbound")

    def attestations(self) -> None:
        """attestation_digest_mismatch through attestation_transplanted, per vendored file."""
        items = self.obj.get("attestations") or []
        for index, item in enumerate(items if isinstance(items, list) else []):
            named, data = self.attestation_bytes[index] if index < len(self.attestation_bytes) \
                else (False, None)
            if not named:
                continue
            if data is None:
                self.defer("attestation_unavailable")  # the next attestation is still read
                continue
            digest = item.get("digest") if isinstance(item, dict) else None
            if digest != "sha256:" + sha256_hex(data):
                raise Refused("attestation_digest_mismatch")
            found = signed_statement(data, self.documents)
            if found is None:
                raise Refused("attestation_unsigned")
            statement, keyid, method = found
            subjects = statement.get("subject")
            digests = {"sha256:" + s["digest"]["sha256"]
                       for s in (subjects if isinstance(subjects, list) else [])
                       if isinstance(s, dict) and isinstance(s.get("digest"), dict)
                       and isinstance(s["digest"].get("sha256"), str)}
            if self.entry.get("digest") not in digests:
                raise Refused("attestation_transplanted")
            self.signers.append((f"attestation[{index}]", keyid, keyid.split("#", 1)[0], method))

    def publisher_rule(self) -> None:
        if self.role != "publisher":
            return
        domain = self.publisher_domain
        if self.identity != (f"did:web:{domain}" if domain else None):
            raise Refused("publisher_not_signer" if self.construction == AIC
                          else "publisher_authorization_absent")

    def times(self, holder: dict[str, Any]) -> None:
        """RFC 3339 instants: the AI Catalog Signature object requires issuedAt, the draft only
        recommends it, and expiresAt, when present, is later than issuedAt."""
        issued, expires = times_of(self.construction, holder)
        start, end = instant(issued), instant(expires)
        if (issued is None and self.construction not in ARD_SHAPED) or \
                (issued is not None and start is None) or (expires is not None and end is None) \
                or (start is not None and end is not None and end <= start):
            raise Refused("timestamp_invalid")
        if start is not None and self.at < start:
            raise Refused("issued_in_future")
        if end is not None and self.at >= end:
            raise Refused("manifest_expired")


# --------------------------------------------------------------------------- the adapter

_REQUIRED = {"catalog", "did_documents", "construction", "role", "at"}
_OPTIONAL = {"entry", "manifest", "artifact", "attestations", "key_authority"}
_SEVERITY = {"unauthorized": 2, "unknown": 1, "authorized": 0}


def _context(assessment: dict) -> tuple[str, str, Fraction]:
    construction = assessment["construction"]
    if not isinstance(construction, str) or construction not in CONSTRUCTIONS:
        raise CaseError(f"assessment.construction: construction_unknown; expected one of "
                        f"{list(CONSTRUCTIONS)}")
    role = assessment["role"]
    if role not in ROLES:
        raise CaseError(f"assessment.role: role_unknown; expected one of {list(ROLES)}")
    at = instant(assessment["at"])
    if at is None:
        raise CaseError("assessment.at: expected an RFC 3339 date-time")
    return construction, role, at


def judge(inputs: dict[str, Any]) -> tuple[str, str, list[tuple[str, Any, Any, dict[str, Any]]]]:
    """``("accept", reason, signers)``, ``("reject", code, [])`` or ``("unavailable", reason, [])``.

    ``inputs`` holds the construction, role and check instant, the entry and manifest indexes as
    written, the catalog and DID document bytes, the artifact bytes (or None) and, per attestation
    of the signed object, whether the consumer vendored it and its bytes (None when unbound).
    """
    read = _Read(inputs)
    try:
        reason = read.judge()
    except Refused as refusal:
        return "reject", str(refusal.args[0]), []
    except Unavailable as missing:
        return "unavailable", str(missing.args[0]), []
    return "accept", reason, read.signers


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge the bound catalog object, then ask the consumer's key authority about every signer."""
    from ..key_authority import AUTHORIZED, UNAUTHORIZED, authority_evidence, authorize
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, _REQUIRED, _OPTIONAL)
    construction, role, at = _context(assessment)
    scope: dict[str, Any] = {"construction": construction, "role": role, "limit": LIMIT}
    catalog, scope["catalog"] = bound(artifacts, artifact_root, assessment["catalog"],
                                      "assessment.catalog")
    documents, scope["did_documents"] = bound(artifacts, artifact_root,
                                              assessment["did_documents"],
                                              "assessment.did_documents")
    artifact = None
    if "artifact" in assessment:
        artifact, scope["artifact"] = bound(artifacts, artifact_root, assessment["artifact"],
                                            "assessment.artifact")
    named = assessment.get("attestations", [])
    if not isinstance(named, list):
        raise CaseError("assessment.attestations: expected a list of artifact names or nulls")
    vendored: list[tuple[bool, bytes | None]] = []
    scope["attestations"] = []
    for index, name in enumerate(named):
        if name is None:
            vendored.append((False, None))
            scope["attestations"].append(None)
            continue
        data, binding = bound(artifacts, artifact_root, _string(name, f"attestations[{index}]"),
                              f"assessment.attestations[{index}]")
        vendored.append((True, data))
        scope["attestations"].append(binding)
    for label, data in (("catalog", catalog), ("did_documents", documents)):
        if data is None:
            return decision(case_id, CLAIM_TYPE, scope, "not_established", f"{label}_unavailable")
    outcome, reason, signers = judge({
        "construction": construction, "role": role, "at": at,
        "entry": assessment.get("entry", 0), "manifest": assessment.get("manifest", 0),
        "catalog": catalog, "did_documents": documents, "artifact": artifact,
        "attestations": vendored})
    check: dict[str, Any] = {"id": "catalog_trust_manifest", "decision": outcome, "reason": reason,
                             "status": {"accept": "pass", "reject": "fail",
                                        "unavailable": "unavailable"}[outcome]}
    if outcome == "reject":
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", reason, [check])
    if outcome == "unavailable":
        return decision(case_id, CLAIM_TYPE, scope, "not_established", reason, [check])
    check["signers"] = [{"role": who, "kid": kid} for who, kid, _, _ in signers]
    config = assessment.get("key_authority")
    document, proof = authority_evidence(config, artifacts, artifact_root, scope)
    answers = [authorize(config, key_bytes(method), kid=kid, subject=did, at=assessment["at"],
                         did_document=document, inclusion_proof=proof)
               for _, kid, did, method in signers]
    authority = max(answers, key=lambda answer: _SEVERITY[answer.outcome])
    checks = [check, authority.check()]
    if authority.outcome == AUTHORIZED:
        return decision(case_id, CLAIM_TYPE, scope, "supported", reason, checks)
    if authority.outcome == UNAUTHORIZED:
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", authority.reason, checks)
    return decision(case_id, CLAIM_TYPE, scope, "not_established", authority.reason, checks)

