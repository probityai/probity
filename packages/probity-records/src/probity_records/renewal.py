"""The renewal ratchet: the signed records of an instance's life, and the offline check that finds a forked key.

Three signed records, all JCS bodies under a domain-separated Ed25519 signature:

- an **instance certificate** (signed by the authority): one instance key, its half-open window, and the ratchet
  ``counter`` at which it was issued (0 for the key the instance was issued with);
- a **renewal request** (signed by the instance's current key): ``counter`` n and ``previous``, the digest of the
  body of renewal n - 1 (of the issuing certificate for n = 1), the key id it signs with, the successor public key
  when it asks to rotate, and its own clock reading;
- a **renewal grant** (signed by the authority): the lease it issues, the digest of the request it answers and, for
  a rotation, the successor's certificate.

The ratchet. Two holders of one software key can each build a request on the same ``previous``; the authority
accepts the first and sees the second as a sibling, and the instance is revoked with the pair kept as evidence. The
exact claim is: "a copied software key is detected within one lease period (<= 60 s) while the legitimate instance
is alive". It says nothing about a copy that renews alone after the legitimate instance has stopped.

The offline half. ``verify_chain`` reads only certificates and requests and a pinned authority root, never a key
a record selects: each request is checked under the keys the instance's certificates certify, and it reports the
chain's length or the fork it found. Anyone holding a journal of the records re-derives the authority's verdict.

Every refusal is a ``RenewalError`` whose ``code`` is a registered ``lifecycle.renewal`` code: a malformed record
(``renewal_record_malformed``, ``renewal_base64_invalid``, the ``*_members_invalid`` and ``*_type_invalid`` codes, the
member codes ``renewal_integer_invalid``, ``renewal_text_invalid``, ``renewal_digest_invalid``,
``renewal_model_invalid``, ``renewal_key_invalid``, ``renewal_counter_invalid``, ``renewal_successor_invalid`` and the
two window codes), a record no pinned key signed (``renewal_signature_unverified``, ``renewal_authority_mismatch``,
``renewal_key_id_mismatch``), and a chain that is not one line from its issuing certificate
(``renewal_certificates_invalid``, ``renewal_identity_changed``, ``renewal_instance_mismatch``,
``renewal_counter_gap``, ``renewal_request_orphaned``). A fork is a result, never a refusal.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .core import canonical, key_id, sha256_hex

CERTIFICATE_TYPE = "instance-certificate/v1"
REQUEST_TYPE = "instance-renewal/v1"
GRANT_TYPE = "instance-renewal-grant/v1"
CERTIFICATE_DOMAIN = b"probity-instance-certificate-v1\x00"
REQUEST_DOMAIN = b"probity-instance-renewal-v1\x00"
GRANT_DOMAIN = b"probity-instance-renewal-grant-v1\x00"

_CERTIFICATE = frozenset({"agent", "authority", "build", "counter", "instance", "key", "keyId", "model", "notAfter",
                          "notBefore", "scope", "session", "type"})  # fmt: skip
#: What an instance certificate states about who runs: every certificate of one instance states the same values.
IDENTITY = ("agent", "build", "model", "session")
#: The model of a deployment that declares none: stated, never left out.
UNDECLARED = "undeclared"
_REQUEST = frozenset({"attestation", "audience", "counter", "instance", "issuedAt", "keyId", "previous", "successor",
                      "type"})  # fmt: skip
_GRANT = frozenset(
    {
        "authority",
        "certificate",
        "counter",
        "instance",
        "issuedAt",
        "lease",
        "requestDigest",
        "type",
    }
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_LEASE = frozenset({"epoch", "leaseId", "notAfter", "notBefore", "source"})


class RenewalError(ValueError):
    """A record that is malformed, forged or out of order; ``code`` is the registered reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class SignerLike(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> bytes: ...


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(text: Any) -> bytes:
    """Canonical base64 text as bytes; anything else is a shape error."""
    if not isinstance(text, str):
        raise RenewalError("renewal_base64_invalid", "expected base64 text")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise RenewalError("renewal_base64_invalid", "not canonical base64") from None
    if b64(raw) != text:
        raise RenewalError("renewal_base64_invalid", "not canonical base64")
    return raw


def raw_public(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def body_digest(body: Mapping[str, Any]) -> str:
    """The digest a successor record names as ``previous`` or ``requestDigest``."""
    return "sha256:" + str(sha256_hex(canonical(dict(body))))


def sign(signer: SignerLike, domain: bytes, body: Mapping[str, Any]) -> dict[str, Any]:
    return {"body": dict(body), "sig": b64(signer.sign(domain + canonical(dict(body))))}


def _parts(signed: Any) -> tuple[dict[str, Any], bytes]:
    if (
        not isinstance(signed, Mapping)
        or set(signed) != {"body", "sig"}
        or not isinstance(signed["body"], Mapping)
    ):
        raise RenewalError("renewal_record_malformed", "a signed record is {body, sig}")
    return dict(signed["body"]), unb64(signed["sig"])


def open_signed(signed: Any, domain: bytes, public: Ed25519PublicKey) -> dict[str, Any]:
    """The body when ``public`` signed it under ``domain``; ``renewal_signature_unverified`` otherwise."""
    body, sig = _parts(signed)
    try:
        public.verify(sig, domain + canonical(body))
    except InvalidSignature:
        raise RenewalError("renewal_signature_unverified") from None
    return body


def _int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**53:
        raise RenewalError("renewal_integer_invalid", f"{what} is a non-negative integer")
    return int(value)


def _text(value: Any, what: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or not value.isascii()
        or not value.isprintable()
    ):
        raise RenewalError("renewal_text_invalid", f"{what} is 1 to 512 printable ASCII characters")
    return str(value)


def _digest(value: Any, what: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RenewalError("renewal_digest_invalid", f"{what} is sha256:<64 lowercase hex>")
    return str(value)


def check_build(value: Any) -> str:
    """The build member: the digest of the code or image the host runs."""
    return _digest(value, "build")


def check_model(value: Any) -> Any:
    """The model member: ``"undeclared"``, or ``{"id"}`` with a ``digest`` only when the host observed the weights."""
    if value == UNDECLARED:
        return value
    if (
        not isinstance(value, dict)
        or "id" not in value
        or not set(value) <= {"id", "digest"}
    ):
        raise RenewalError("renewal_model_invalid", 'model is "undeclared" or {"id"} with an optional "digest"')
    _text(value["id"], "model id")
    if "digest" in value:
        _digest(value["digest"], "model digest")
    return value


# ---------- certificate ----------


@dataclass(frozen=True)
class Certificate:
    """An instance key the authority certified."""

    body: Mapping[str, Any]
    instance: str
    key: Ed25519PublicKey
    key_id: str
    not_before: int
    not_after: int
    counter: int

    def covers(self, at: int) -> bool:
        return self.not_before <= at < self.not_after

    @property
    def digest(self) -> str:
        return body_digest(self.body)


def certificate(authority: SignerLike, *, instance: str, agent: str, session: str, build: str, model: Any, key: bytes,
                not_before: int, not_after: int, counter: int, scope: str) -> dict[str, Any]:  # fmt: skip
    """The authority's signed certificate for one instance key valid over [not_before, not_after). ``build`` is the
    digest of the code or image the host runs; ``model`` is ``UNDECLARED`` or ``{"id"[, "digest"]}``."""
    body = {"agent": agent, "authority": authority.key_id, "build": build, "counter": counter, "instance": instance,
            "key": b64(key), "keyId": sha256_hex(key), "model": model, "notAfter": not_after, "notBefore": not_before,
            "scope": scope, "session": session, "type": CERTIFICATE_TYPE}  # fmt: skip
    check_certificate_body(body)
    return sign(authority, CERTIFICATE_DOMAIN, body)


def check_certificate_body(body: Mapping[str, Any]) -> Certificate:
    if set(body) != _CERTIFICATE:
        raise RenewalError("renewal_certificate_members_invalid", f"members are exactly {sorted(_CERTIFICATE)}")
    if body["type"] != CERTIFICATE_TYPE:
        raise RenewalError("renewal_certificate_type_invalid", "not an instance certificate")
    for name in ("agent", "instance", "scope", "session"):
        _text(body[name], name)
    check_build(body["build"])
    check_model(body["model"])
    raw = unb64(body["key"])
    if len(raw) != 32 or sha256_hex(raw) != body["keyId"]:
        raise RenewalError("renewal_key_invalid", "key is a raw Ed25519 key and keyId its SHA-256")
    start, end, counter = (
        _int(body["notBefore"], "notBefore"),
        _int(body["notAfter"], "notAfter"),
        _int(body["counter"], "counter"),
    )
    if start >= end:
        raise RenewalError("renewal_certificate_window_invalid", "a certificate window ends after it starts")
    return Certificate(dict(body), body["instance"], Ed25519PublicKey.from_public_bytes(raw), body["keyId"], start, end,
                       counter)  # fmt: skip


def open_certificate(signed: Any, roots: Sequence[Ed25519PublicKey]) -> Certificate:
    """The certificate when a pinned root signed it. Nothing in the record selects the root: every one is tried."""
    body, sig = _parts(signed)
    for root in roots:
        try:
            root.verify(sig, CERTIFICATE_DOMAIN + canonical(body))
        except InvalidSignature:
            continue
        cert = check_certificate_body(body)
        if body["authority"] != key_id(root):
            raise RenewalError("renewal_authority_mismatch", "authority names another key")
        return cert
    raise RenewalError(
        "renewal_signature_unverified", "no pinned root signed the certificate"
    )


# ---------- request ----------


def request(key: SignerLike, *, instance: str, counter: int, previous: str, signing_key_id: str,
            successor: bytes | None, issued_at: int, audience: str, attestation: str | None = None) -> dict[str, Any]:  # fmt: skip
    """A renewal request signed by the instance key named ``signing_key_id``."""
    body = {"attestation": attestation, "audience": audience, "counter": counter, "instance": instance,
            "issuedAt": issued_at, "keyId": signing_key_id, "previous": previous,
            "successor": None if successor is None else b64(successor), "type": REQUEST_TYPE}  # fmt: skip
    check_request_body(body)
    return sign(key, REQUEST_DOMAIN, body)


@dataclass(frozen=True)
class Request:
    body: Mapping[str, Any]
    instance: str
    counter: int
    previous: str
    key_id: str
    issued_at: int
    audience: str
    successor: bytes | None
    attestation: str | None

    @property
    def digest(self) -> str:
        return body_digest(self.body)


def check_request_body(body: Mapping[str, Any]) -> Request:
    if set(body) != _REQUEST:
        raise RenewalError("renewal_request_members_invalid", f"members are exactly {sorted(_REQUEST)}")
    if body["type"] != REQUEST_TYPE:
        raise RenewalError("renewal_request_type_invalid", "not a renewal request")
    counter = _int(body["counter"], "counter")
    if counter < 1:
        raise RenewalError("renewal_counter_invalid", "the first renewal is counter 1")
    successor = None
    if body["successor"] is not None:
        successor = unb64(body["successor"])
        if len(successor) != 32:
            raise RenewalError("renewal_successor_invalid", "successor is a raw Ed25519 key")
    attestation = (
        None
        if body["attestation"] is None
        else _digest(body["attestation"], "attestation")
    )
    return Request(dict(body), _text(body["instance"], "instance"), counter, _digest(body["previous"], "previous"),
                   _text(body["keyId"], "keyId"), _int(body["issuedAt"], "issuedAt"), _text(body["audience"], "audience"),
                   successor, attestation)  # fmt: skip


def open_request(
    signed: Any, keys: Iterable[Ed25519PublicKey]
) -> tuple[Request, Ed25519PublicKey]:
    """The request and the key that verified it, trying only the keys the caller holds for the instance.

    The ``keyId`` the request names is a claim checked against the verifying key, never a selector.
    """
    body, sig = _parts(signed)
    shaped = check_request_body(body)
    message = REQUEST_DOMAIN + canonical(body)
    for key in keys:
        try:
            key.verify(sig, message)
        except InvalidSignature:
            continue
        if key_id(key) != shaped.key_id:
            raise RenewalError("renewal_key_id_mismatch", "keyId names another key")
        return shaped, key
    raise RenewalError(
        "renewal_signature_unverified", "no key of the instance signed the request"
    )


# ---------- grant ----------


def grant(authority: SignerLike, *, instance: str, counter: int, request_digest: str, lease: Mapping[str, Any],
          certificate_signed: Mapping[str, Any] | None, issued_at: int) -> dict[str, Any]:  # fmt: skip
    """The authority's signed answer to a renewal: a lease, and the successor's certificate on a rotation."""
    body = {"authority": authority.key_id, "certificate": None if certificate_signed is None else dict(certificate_signed),
            "counter": counter, "instance": instance, "issuedAt": issued_at, "lease": dict(lease),
            "requestDigest": request_digest, "type": GRANT_TYPE}  # fmt: skip
    check_grant_body(body)
    return sign(authority, GRANT_DOMAIN, body)


def check_grant_body(body: Mapping[str, Any]) -> dict[str, Any]:
    if set(body) != _GRANT:
        raise RenewalError("renewal_grant_members_invalid", f"members are exactly {sorted(_GRANT)}")
    if body["type"] != GRANT_TYPE:
        raise RenewalError("renewal_grant_type_invalid", "not a renewal grant")
    _int(body["counter"], "counter"), _int(body["issuedAt"], "issuedAt")
    _text(body["instance"], "instance"), _digest(body["requestDigest"], "requestDigest")
    lease = body["lease"]
    if not isinstance(lease, Mapping) or set(lease) != _LEASE:
        raise RenewalError("renewal_lease_members_invalid", f"a lease is an object with exactly {sorted(_LEASE)}")
    (
        _int(lease["epoch"], "epoch"),
        _text(lease["leaseId"], "leaseId"),
        _text(lease["source"], "source"),
    )
    if _int(lease["notBefore"], "notBefore") >= _int(lease["notAfter"], "notAfter"):
        raise RenewalError("renewal_lease_window_invalid", "a lease ends after it starts")
    return dict(body)


def open_grant(signed: Any, roots: Sequence[Ed25519PublicKey]) -> dict[str, Any]:
    """The grant body when a pinned root signed it."""
    body, sig = _parts(signed)
    for root in roots:
        try:
            root.verify(sig, GRANT_DOMAIN + canonical(body))
        except InvalidSignature:
            continue
        check_grant_body(body)
        if body["authority"] != key_id(root):
            raise RenewalError("renewal_authority_mismatch", "authority names another key")
        return body
    raise RenewalError(
        "renewal_signature_unverified", "no pinned root signed the grant"
    )


# ---------- the offline check ----------


@dataclass(frozen=True)
class Fork:
    """Two different requests that both continue the same ``previous``: one key held by two parties."""

    instance: str
    previous: str
    counter: int
    first: str
    second: str


@dataclass(frozen=True)
class Chain:
    instance: str
    #: The number of renewals on the single line from the issuing certificate.
    length: int
    last_digest: str
    fork: Fork | None


def verify_chain(
    certificates: Iterable[Any],
    requests: Iterable[Any],
    roots: Sequence[Ed25519PublicKey],
) -> Chain:
    """Check one instance's renewals against its certificates and a pinned root; report its length or its fork.

    ``certificates`` are the signed certificates the authority issued the instance (the one for counter 0, then each
    rotation's); ``requests`` are signed renewal requests in any order, identical copies allowed (a retry or a
    replay is one request). A request whose signature no key of the instance verifies, a request outside every key's
    half-open window at its own ``issuedAt``, a request for another instance, a counter that is not one more than
    its predecessor's, or a request that continues nothing the chain holds is a ``RenewalError``; two different
    requests on one ``previous`` is a ``Fork``, not an error.
    """
    certs = [open_certificate(c, roots) for c in certificates]
    instances = {c.instance for c in certs}
    first = [c for c in certs if c.counter == 0]
    if len(instances) != 1 or len(first) != 1:
        raise RenewalError("renewal_certificates_invalid", "one instance and exactly one issuing certificate")
    stated = {canonical({m: c.body[m] for m in IDENTITY}) for c in certs}
    if len(stated) != 1:
        raise RenewalError(
            "renewal_identity_changed",
            f"the certificates of one instance disagree on {IDENTITY}",
        )
    instance = next(iter(instances))
    start = first[0].digest
    by_digest: dict[str, Request] = {}
    for raw in requests:
        shaped = _signed_by_instance(raw, certs)
        if shaped.instance != instance:
            raise RenewalError("renewal_instance_mismatch", "a request for another instance")
        by_digest[shaped.digest] = shaped
    children: dict[str, list[Request]] = {}
    for req in by_digest.values():
        children.setdefault(req.previous, []).append(req)
    last, length = start, 0
    while last in children:
        siblings = children[last]
        if len(siblings) > 1:
            a, b = sorted(siblings, key=lambda r: r.digest)[:2]
            return Chain(
                instance,
                length,
                last,
                Fork(instance, last, length + 1, a.digest, b.digest),
            )
        nxt = siblings[0]
        if nxt.counter != length + 1:
            raise RenewalError("renewal_counter_gap", "a counter is not one more than its predecessor's")
        last, length = nxt.digest, length + 1
    if length != len(by_digest):
        raise RenewalError("renewal_request_orphaned", "a request continues nothing the chain holds")
    return Chain(instance, length, last, None)


def _signed_by_instance(raw: Any, certs: Sequence[Certificate]) -> Request:
    body, _ = _parts(raw)
    issued = body.get("issuedAt")
    at = issued if isinstance(issued, int) and not isinstance(issued, bool) else -1
    keys = [c.key for c in certs if c.covers(at)]
    shaped, _ = open_request(raw, keys)
    return shaped


def fork_proven(
    first: Any,
    second: Any,
    certificates: Iterable[Any],
    roots: Sequence[Ed25519PublicKey],
) -> Fork | None:
    """The fork two signed requests prove, or ``None``: both verify under the instance's certified keys, name the
    same instance and the same ``previous``, and are different requests."""
    certs = [open_certificate(c, roots) for c in certificates]
    a, b = _signed_by_instance(first, certs), _signed_by_instance(second, certs)
    if a.instance != b.instance or a.previous != b.previous or a.digest == b.digest:
        return None
    one, two = sorted((a, b), key=lambda r: r.digest)
    return Fork(
        a.instance, a.previous, min(a.counter, b.counter), one.digest, two.digest
    )
