"""The agent stamp: an RFC 9421 HTTP message signature a service behind a gateway reads to learn who acts for whom.

A gateway that verified a request's principals forwards it upstream with one stamp instead of the inbound credentials,
which it never forwards. The stamp is four request fields:

    Probity-Principals: id="aid1!agent;user=...;chain=...;act=sha256:...;grants=sha256:...", client="...",
                        principals="sha256:..."
    Content-Digest: sha-256=:<base64 of the SHA-256 of the body>:
    Signature-Input: probity=("@method" "@target-uri" "@authority" "content-digest" "probity-principals");created=..;
                     expires=..;nonce="..";keyid="<hex SHA-256 of the raw Ed25519 key>";alg="ed25519";
                     tag="probity-principals/v1"
    Signature: probity=:<Ed25519 signature over the RFC 9421 signature base>:

``id`` is the canonical identity string of the request (``canonical_identity``): it names the user, the agent chain,
the digest of the user credential's RFC 8693 ``act`` claim and the digest of the capability grant chain, so the stamp
carries each exactly once. ``client`` is the agent's client id and ``principals`` the digest of the verified
principals block (``digests``). The covered components are exactly that list, in that order, so the signature binds
the method, the full target URI and its authority, the body bytes and the principals.

``verify_stamp`` is every check of one stamp that needs no memory of earlier stamps. The verifying key is the one the
service pins for the stamp issuer; ``keyid`` is compared with it and never used to find one. The lifetime is at most
``MAX_TTL_SECONDS``. The stamp is single-use: a service that keeps state spends ``(nonce, expires)`` in its own store
after this check passes. Structured fields are read and written by the one strict RFC 8941 reader of the tree,
``agent_evidence_verify.structured_fields``.

Refusal codes, in the order the checks run: ``stamp_dropped`` (no stamp), ``stamp_repeated`` (a stamp field given
twice), ``stamp_malformed`` (a field missing or not its structured type), ``stamp_header_invalid`` (the covered set,
the parameters, ``alg`` or ``tag``), ``stamp_key_mismatch``, ``stamp_request_mismatch`` (the content digest is not the
body's), ``stamp_forged``, ``stamp_lifetime_too_long``, ``stamp_not_yet_valid``, ``stamp_expired``, then the principals
field (``stamp_malformed``, ``stamp_identity_mismatch``, ``stamp_no_user``, ``stamp_downgraded``). A stamp signed for
another method, target or authority fails as ``stamp_forged``: the signature base is built from the request the
verifier received. The format and its reasons are in ``docs/verified-identities.md``.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

from agent_evidence_verify import structured_fields as sf
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical_identity import CanonicalIdentity, IdentityStringError
from .clock import NS_PER_S
from .core import sha256_hex
from .digests import is_digest, stamp_digest

#: The four request fields of a stamp (lower case: field names compare case-insensitively).
PRINCIPALS_HEADER: Final = "probity-principals"
CONTENT_DIGEST_HEADER: Final = "content-digest"
SIGNATURE_INPUT_HEADER: Final = "signature-input"
SIGNATURE_HEADER: Final = "signature"
STAMP_HEADERS: Final = (PRINCIPALS_HEADER, CONTENT_DIGEST_HEADER, SIGNATURE_INPUT_HEADER, SIGNATURE_HEADER)
#: The signature label, its covered components (exactly these, in this order), its algorithm and its tag.
LABEL: Final = "probity"
COVERED: Final = ("@method", "@target-uri", "@authority", CONTENT_DIGEST_HEADER, PRINCIPALS_HEADER)
ALG: Final = "ed25519"
TAG: Final = "probity-principals/v1"
PARAMS: Final = ("created", "expires", "nonce", "keyid", "alg", "tag")
PRINCIPALS_MEMBERS: Final = ("id", "client", "principals")
#: The longest lifetime a stamp may carry; a stamp names one request, so it is never a standing credential.
MAX_TTL_SECONDS: Final = 300
MAX_NONCE_BYTES: Final = 128
_DEFAULT_PORTS: Final = {"http": 80, "https": 443}


class StampRefused(ValueError):
    """A stamp a verifier will not accept; ``code`` is the registered reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Stamp:
    """Who acts for whom on one request.

    ``identity`` is the canonical identity string; the user, the agent, ``act`` and ``grants`` are read from it, so they
    cannot disagree with it. ``agent_client`` is the agent's client id and ``principals`` the digest of the verified
    principals block. Build one with ``Stamp.of``."""

    user_issuer: str
    user_subject: str
    agent_issuer: str
    agent_subject: str
    agent_client: str
    principals: str
    act: str | None
    grants: str | None
    identity: str

    @classmethod
    def of(cls, identity: str, *, client: str, principals: str) -> Stamp:
        """The stamp of a canonical identity string; StampRefused unless it names an agent acting for a user."""
        if not isinstance(client, str) or not client:
            raise StampRefused("stamp_malformed", "client is a non-empty string")
        if not isinstance(principals, str) or not is_digest(principals):
            raise StampRefused("stamp_malformed", "principals is not a sha256: identity digest")
        try:
            found = CanonicalIdentity.parse(identity)
        except IdentityStringError as exc:
            raise StampRefused("stamp_identity_mismatch", f"{exc.code}: the identity is not a canonical string") from exc
        if found.kind != "agent" or found.agent is None:
            raise StampRefused("stamp_downgraded", f"the identity is of kind {found.kind}, not an agent acting")
        if found.user is None:
            raise StampRefused("stamp_no_user", "the identity names no user the agent acts for")
        agent, user = found.agent, found.user
        stamp = cls(user.domain, user.subject, agent.domain, agent.subject, client, principals, found.act,
                    found.grants, found.render())  # fmt: skip
        if stamp.alone:
            raise StampRefused("stamp_downgraded", "the identity names the user acting alone")
        return stamp

    @property
    def digest(self) -> str:
        """The digest of what crosses the hop (``digests.stamp_digest``)."""
        return stamp_digest(self.principals, self.act, self.grants)

    @property
    def alone(self) -> bool:
        """Whether this names the user acting alone: no agent, or an agent that is the user."""
        return (not self.agent_subject or not self.agent_issuer or not self.agent_client
                or (self.agent_issuer, self.agent_subject) == (self.user_issuer, self.user_subject))  # fmt: skip

    @property
    def agent(self) -> tuple[str, str, str]:
        return self.agent_issuer, self.agent_subject, self.agent_client

    @property
    def user(self) -> tuple[str, str]:
        return self.user_issuer, self.user_subject

    def canonical_identity(self) -> CanonicalIdentity:
        return CanonicalIdentity.parse(self.identity)

    def field(self) -> str:
        """The ``Probity-Principals`` field value."""
        try:
            return sf.serialize_dictionary({"id": sf.Item(self.identity), "client": sf.Item(self.agent_client),
                                            "principals": sf.Item(self.principals)})  # fmt: skip
        except sf.SFError as exc:
            raise StampRefused("stamp_malformed", f"a principals member is not an RFC 8941 string: {exc}") from exc

    def document(self) -> dict[str, Any]:
        """The stamp as a record member: what a journal keeps of it."""
        return {"user": {"iss": self.user_issuer, "sub": self.user_subject},
                "agent": {"iss": self.agent_issuer, "sub": self.agent_subject, "client_id": self.agent_client},
                "principals": self.principals, "act": self.act, "grants": self.grants,
                "identity": self.identity}  # fmt: skip

    @classmethod
    def from_field(cls, value: str) -> Stamp:
        """The stamp a ``Probity-Principals`` field value states; StampRefused unless it is exactly the format."""
        try:
            members = sf.parse_dictionary(value)
        except sf.SFError as exc:
            raise StampRefused("stamp_malformed", f"probity-principals is not an RFC 8941 dictionary: {exc}") from exc
        if tuple(members) != PRINCIPALS_MEMBERS:
            raise StampRefused("stamp_malformed", "probity-principals has exactly id, client and principals, in order")
        texts = []
        for name in PRINCIPALS_MEMBERS:
            member = members[name]
            if (not isinstance(member, sf.Item) or member.params or not isinstance(member.value, str)
                    or isinstance(member.value, sf.Token)):  # fmt: skip
                raise StampRefused("stamp_malformed", f"probity-principals {name} is a String with no parameters")
            texts.append(member.value)
        identity, client, principals = texts
        return cls.of(identity, client=client, principals=principals)


@dataclass(frozen=True)
class VerifiedStamp:
    """A stamp that passed every stateless check: the stamp, and the ``nonce`` and ``expires`` a store spends."""

    stamp: Stamp
    nonce: str
    expires: int


def stamp_key_id(public_raw: bytes) -> str:
    """The key id a stamp names: the lowercase hex SHA-256 of the raw Ed25519 public key."""
    return sha256_hex(public_raw)


def content_digest(body: bytes | None) -> str:
    """The RFC 9530 ``Content-Digest`` field value of a body (None for none: the digest of no bytes)."""
    return sf.serialize_dictionary({"sha-256": sf.Item(hashlib.sha256(body or b"").digest())})


def authority(target_uri: str) -> str:
    """The RFC 9421 ``@authority`` of a target URI: the host in lower case, the port only when it is not the default."""
    parts = urlsplit(target_uri)
    if parts.scheme not in _DEFAULT_PORTS or not parts.hostname or parts.username is not None or parts.fragment:
        raise ValueError(f"a stamped target is an absolute http(s) URI with a host and no userinfo or fragment: "
                         f"{target_uri[:120]!r}")  # fmt: skip
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    return host if port is None or port == _DEFAULT_PORTS[parts.scheme] else f"{host}:{port}"


def _params_member(created: int, expires: int, nonce: str, keyid: str) -> sf.InnerList:
    return sf.InnerList([sf.Item(c) for c in COVERED],
                        {"created": created, "expires": expires, "nonce": nonce, "keyid": keyid, "alg": ALG,
                         "tag": TAG})  # fmt: skip


def signature_base(*, method: str, target_uri: str, content_digest_value: str, principals_value: str,
                   params: sf.InnerList) -> bytes:  # fmt: skip
    """The RFC 9421 section 2.5 signature base of a stamp over one request."""
    lines = [f'"@method": {method}', f'"@target-uri": {target_uri}', f'"@authority": {authority(target_uri)}',
             f'"{CONTENT_DIGEST_HEADER}": {content_digest_value.strip()}',
             f'"{PRINCIPALS_HEADER}": {principals_value.strip()}',
             f'"@signature-params": {sf.serialize_inner_list(params)}']  # fmt: skip
    base = "\n".join(lines)
    if not base.isascii() or any(c in base for c in "\r\0"):
        raise StampRefused("stamp_malformed", "the signature base is not single-line ASCII per component")
    return base.encode("ascii")


def sign_stamp(stamp: Stamp, *, seed: bytes, method: str, target_uri: str, body: bytes | None, created: int,
               ttl_seconds: int, nonce: str | None = None) -> dict[str, str]:  # fmt: skip
    """The four stamp fields for one request, signed with the Ed25519 ``seed``; ``created`` is in seconds."""
    if isinstance(ttl_seconds, bool) or not 0 < ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError(f"a stamp lifetime is 1 to {MAX_TTL_SECONDS} seconds")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    params = _params_member(created, created + ttl_seconds, secrets.token_hex(16) if nonce is None else nonce,
                            stamp_key_id(key.public_key().public_bytes_raw()))  # fmt: skip
    principals_value, digest_value = stamp.field(), content_digest(body)
    base = signature_base(method=method, target_uri=target_uri, content_digest_value=digest_value,
                          principals_value=principals_value, params=params)  # fmt: skip
    return {PRINCIPALS_HEADER: principals_value, CONTENT_DIGEST_HEADER: digest_value,
            SIGNATURE_INPUT_HEADER: sf.serialize_dictionary({LABEL: params}),
            SIGNATURE_HEADER: sf.serialize_dictionary({LABEL: sf.Item(key.sign(base))})}  # fmt: skip


Headers = Mapping[str, str] | Iterable[tuple[str, str]]


def _pairs(headers: Headers) -> list[tuple[str, str]]:
    return list(headers.items()) if isinstance(headers, Mapping) else [(n, v) for n, v in headers]


def stamp_fields(headers: Headers) -> dict[str, str] | None:
    """The stamp fields of a request's header lines (name, value pairs), None when it carries no stamp at all.

    StampRefused ``stamp_repeated`` when a stamp field is given more than once, in any case; ``stamp_malformed`` when
    some but not all of a stamp's fields are present. A ``Signature`` or ``Signature-Input`` with no ``probity``
    member belongs to another signer and is not a stamp."""
    found: dict[str, list[str]] = {}
    for name, value in _pairs(headers):
        if name.lower() in STAMP_HEADERS:
            found.setdefault(name.lower(), []).append(value)
    repeated = sorted(name for name, values in found.items() if len(values) > 1)
    if repeated:
        raise StampRefused("stamp_repeated", "given more than once: " + ", ".join(repeated))
    fields = {name: values[0] for name, values in found.items()}
    labelled = [name for name in (SIGNATURE_INPUT_HEADER, SIGNATURE_HEADER)
                if name in fields and _has_label(fields[name])]  # fmt: skip
    if PRINCIPALS_HEADER not in fields and not labelled:
        return None
    missing = [n for n in STAMP_HEADERS if n not in fields or (n in (SIGNATURE_INPUT_HEADER, SIGNATURE_HEADER)
                                                               and n not in labelled)]  # fmt: skip
    if missing:
        raise StampRefused("stamp_malformed", "the stamp lacks " + ", ".join(missing))
    return fields


def _has_label(value: str) -> bool:
    try:
        return LABEL in sf.parse_dictionary(value)
    except sf.SFError as exc:
        raise StampRefused("stamp_malformed", f"a signature field is not an RFC 8941 dictionary: {exc}") from exc


def _params(member: Any) -> tuple[int, int, str, str]:
    if not isinstance(member, sf.InnerList):
        raise StampRefused("stamp_header_invalid", "the probity signature input is an inner list")
    covered = [i.value for i in member.items]
    if covered != list(COVERED) or any(i.params or not isinstance(i.value, str) or isinstance(i.value, sf.Token)
                                       for i in member.items):  # fmt: skip
        raise StampRefused("stamp_header_invalid", "the covered components are exactly " + " ".join(COVERED))
    if set(member.params) != set(PARAMS):
        raise StampRefused("stamp_header_invalid", "the parameters are exactly " + ", ".join(PARAMS))
    p = member.params
    if p["alg"] != ALG or isinstance(p["alg"], sf.Token):
        raise StampRefused("stamp_header_invalid", f"alg is {ALG!r}")
    if p["tag"] != TAG or isinstance(p["tag"], sf.Token):
        raise StampRefused("stamp_header_invalid", f"tag is {TAG!r}")
    for name in ("created", "expires"):
        if isinstance(p[name], bool) or not isinstance(p[name], int):
            raise StampRefused("stamp_header_invalid", f"{name} is an Integer")
    for name in ("nonce", "keyid"):
        if not isinstance(p[name], str) or isinstance(p[name], sf.Token) or not p[name]:
            raise StampRefused("stamp_header_invalid", f"{name} is a non-empty String")
    if len(p["nonce"].encode("ascii")) > MAX_NONCE_BYTES:
        raise StampRefused("stamp_header_invalid", f"nonce is at most {MAX_NONCE_BYTES} bytes")
    return p["created"], p["expires"], p["nonce"], p["keyid"]


def _dictionaries(fields: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        return (sf.parse_dictionary(fields[SIGNATURE_INPUT_HEADER]), sf.parse_dictionary(fields[SIGNATURE_HEADER]),
                sf.parse_dictionary(fields[CONTENT_DIGEST_HEADER]))  # fmt: skip
    except sf.SFError as exc:
        raise StampRefused("stamp_malformed", f"a stamp field is not an RFC 8941 dictionary: {exc}") from exc


def presented_key_id(headers: Headers) -> str:
    """The ``keyid`` a request's stamp names, after the structural checks; a verifier compares it with the keys it
    pins and never uses it to fetch one. StampRefused ``stamp_dropped`` when the request carries no stamp."""
    fields = stamp_fields(headers)
    if fields is None:
        raise StampRefused("stamp_dropped", "the request carries no stamp")
    return _params(_dictionaries(fields)[0][LABEL])[3]


def verify_stamp(headers: Headers, *, method: str, target_uri: str, body: bytes | None, public_raw: bytes,
                 now: int) -> VerifiedStamp:  # fmt: skip
    """The stamp a request's header lines carry, checked under the pinned key ``public_raw``; StampRefused otherwise.

    ``method``, ``target_uri`` and ``body`` are the request the verifier received; ``now`` is its time in nanoseconds
    since the epoch."""
    fields = stamp_fields(headers)
    if fields is None:
        raise StampRefused("stamp_dropped", "the request carries no stamp")
    inputs, signatures, digests = _dictionaries(fields)
    created, expires, nonce, keyid = _params(inputs[LABEL])
    if keyid != stamp_key_id(public_raw):
        raise StampRefused("stamp_key_mismatch", "the stamp names a key other than the pinned one")
    signature = signatures[LABEL]
    if not isinstance(signature, sf.Item) or signature.params or not isinstance(signature.value, bytes):
        raise StampRefused("stamp_malformed", "the probity signature is a Byte Sequence with no parameters")
    sha = digests.get("sha-256")
    if (set(digests) != {"sha-256"} or not isinstance(sha, sf.Item) or sha.params
            or not isinstance(sha.value, bytes)):  # fmt: skip
        raise StampRefused("stamp_malformed", "content-digest is exactly one sha-256 Byte Sequence")
    if sha.value != hashlib.sha256(body or b"").digest():
        raise StampRefused("stamp_request_mismatch", "the content digest is not the digest of the body received")
    base = signature_base(method=method, target_uri=target_uri, content_digest_value=fields[CONTENT_DIGEST_HEADER],
                          principals_value=fields[PRINCIPALS_HEADER], params=inputs[LABEL])  # fmt: skip
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature.value, base)
    except (InvalidSignature, ValueError) as exc:
        raise StampRefused("stamp_forged", "the signature does not verify over this request under the pinned key") from exc
    moment = now / NS_PER_S
    if expires <= created:
        raise StampRefused("stamp_malformed", "expires is not after created")
    if expires - created > MAX_TTL_SECONDS:
        raise StampRefused("stamp_lifetime_too_long", f"{expires - created} s")
    if created > moment:
        raise StampRefused("stamp_not_yet_valid", "created is in the future")
    if moment >= expires:
        raise StampRefused("stamp_expired", "expires has passed")
    return VerifiedStamp(Stamp.from_field(fields[PRINCIPALS_HEADER]), nonce, expires)

