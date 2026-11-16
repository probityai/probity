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
    authorised when the SHA-256 of its bytes is pinned (and, when the pin names a ``kid``, the
    record's key id is that ``kid``).
``did-web``
    ``{"kind": "did-web", "did": "did:web:...", "document": "<artifact>",
    "document_sha256": "<hex>"}``. The consumer pins the bytes of the DID document; the key is
    authorised when a verification method listed under ``assertionMethod`` carries it and, when the
    record names a key id, that method's id is the key id. A method present only under
    ``verificationMethod`` or ``authentication`` is not authorised to make assertions.
``registry``
    ``{"kind": "registry", "bindings": [{"subject": "...", "public_key_sha256": "<hex>",
    "not_before": "<RFC 3339>", "not_after": "<RFC 3339, optional>",
    "revoked_at": "<RFC 3339, optional>"}]}``. The key is authorised for a subject at an instant when
    a binding of that subject covers the instant and was not revoked at or before it.
``kt-inclusion``
    ``{"kind": "kt-inclusion", "tree_size": n, "root_sha256": "<hex>"}``. The consumer pins a
    transparency-log tree head; the case supplies an RFC 6962 inclusion proof
    ``{"index": i, "tree_size": n, "path": ["<hex>", ...]}`` for the leaf
    ``RFC 8785({"key_sha256": "<hex>", "subject": "<subject>"})``. The key is authorised when the
    proof reaches the pinned root.

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
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .adapters import jcs_canonical
from .adapters.proof_of_control import check_inclusion, leaf_hash
from .common import CaseError
from .ijson import IJSONError, parse_ijson

KINDS = ("pin", "did-web", "registry", "kt-inclusion")
AUTHORIZED, UNAUTHORIZED, UNKNOWN = "authorized", "unauthorized", "unknown"
_HEX64 = re.compile(r"[0-9a-f]{64}")
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


def _instant(value: Any, label: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise CaseError(f"{label}: expected an RFC 3339 instant")
    try:
        moment = datetime.datetime.fromisoformat(value)
    except ValueError as exc:
        raise CaseError(f"{label}: expected an RFC 3339 instant") from exc
    if moment.tzinfo is None:
        raise CaseError(f"{label}: an instant carries its offset")
    return moment


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
        if not isinstance(pin, dict) or not set(pin) <= {"public_key_sha256", "kid"}:
            raise CaseError(f"authority.keys[{index}]: expected public_key_sha256 and optional kid")
        pins.append((_digest(pin.get("public_key_sha256"), f"authority.keys[{index}]"),
                     pin.get("kid")))
    digests = [d for d, _ in pins]
    matches = [pin_kid for d, pin_kid in pins if d == key_sha256(key)]
    if not matches:
        return UNAUTHORIZED, "key_not_pinned", digests
    if kid is not None and all(pin_kid is not None and pin_kid != kid for pin_kid in matches):
        return UNAUTHORIZED, "key_id_mismatch", digests
    return AUTHORIZED, "key_pinned", digests


def _did_methods(document: dict, did: str) -> tuple[dict[str, dict], set[str]]:
    """The verification methods by id, and the ids listed under ``assertionMethod``."""
    methods: dict[str, dict] = {}

    def absolute(ref: str) -> str:
        return did + ref if ref.startswith("#") else ref

    for method in document.get("verificationMethod", []) or []:
        if isinstance(method, dict) and isinstance(method.get("id"), str):
            methods[absolute(method["id"])] = method
    asserting = set()
    for entry in document.get("assertionMethod", []) or []:
        if isinstance(entry, str):
            asserting.add(absolute(entry))
        elif isinstance(entry, dict) and isinstance(entry.get("id"), str):
            methods.setdefault(absolute(entry["id"]), entry)
            asserting.add(absolute(entry["id"]))
    return methods, asserting


def _method_key(method: dict, label: str) -> bytes | None:
    try:
        if "publicKeyJwk" in method:
            return jwk_key_bytes(method["publicKeyJwk"], label)
        if "publicKeyMultibase" in method:
            return multibase_key_bytes(method["publicKeyMultibase"], label)
    except CaseError:
        return None
    return None


def _did_web(config: dict, key: bytes, kid: str | None, document_bytes: bytes | None,
             ) -> tuple[str, str, list[str]]:
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
    methods, asserting = _did_methods(document, did)
    keyed = {mid: _method_key(m, f"verificationMethod {mid}") for mid, m in methods.items()}
    trusted = [key_sha256(raw) for mid, raw in keyed.items() if raw is not None and mid in asserting]
    holders = [mid for mid, raw in keyed.items() if raw == key]
    if not holders:
        return UNAUTHORIZED, "key_not_in_did_document", trusted
    if not any(mid in asserting for mid in holders):
        return UNAUTHORIZED, "key_not_in_assertion_method", trusted
    if kid is not None and not any(mid in asserting and kid in (mid, mid[len(did):]) for mid in holders):
        return UNAUTHORIZED, "key_id_mismatch", trusted
    return AUTHORIZED, "key_in_assertion_method", trusted


def _registry(config: dict, key: bytes, subject: str | None, at: datetime.datetime | None,
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
        parsed.append((binding["subject"], _digest(binding["public_key_sha256"], label),
                       _instant(binding["not_before"], f"{label}.not_before"),
                       _instant(binding["not_after"], f"{label}.not_after")
                       if "not_after" in binding else None,
                       _instant(binding["revoked_at"], f"{label}.revoked_at")
                       if "revoked_at" in binding else None))
    if subject is None:
        return UNKNOWN, "record_subject_unknown", [d for _, d, *_ in parsed]
    if at is None:
        return UNKNOWN, "record_time_unknown", [d for _, d, *_ in parsed]
    mine = [b for b in parsed if b[0] == subject]
    trusted = [d for s, d, start, end, revoked in mine
               if start <= at and (end is None or at < end) and (revoked is None or at < revoked)]
    held = [b for b in mine if b[1] == key_sha256(key)]
    if not held:
        return UNAUTHORIZED, "key_not_bound_to_subject", trusted
    if key_sha256(key) in trusted:
        return AUTHORIZED, "key_bound_at_time", trusted
    if any(revoked is not None and revoked <= at for *_, revoked in held):
        return UNAUTHORIZED, "key_revoked", trusted
    return UNAUTHORIZED, "key_outside_validity", trusted


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
              at: datetime.datetime | None = None, did_document: bytes | None = None,
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
    if kind == "pin":
        outcome, reason, trusted = _pin(authority, key, kid)
    elif kind == "did-web":
        outcome, reason, trusted = _did_web(authority, key, kid, did_document)
    elif kind == "registry":
        outcome, reason, trusted = _registry(authority, key, subject, at)
    else:
        outcome, reason, trusted = _kt_inclusion(authority, key, subject, inclusion_proof)
    return Authority(outcome, reason, kind, key_set_fingerprint(trusted))
