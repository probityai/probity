"""The canonical identity string: who acted in one request, in one form every policy engine compares.

A policy engine that keeps access lists compares strings, and one that reads attributes reads a document. This module
defines both for the verified principals of one request, and the string is the document's ``id``, so the two always
name the same identity. The full grammar, its rules and the reasons for them are in ``docs/canonical-identity.md``;
the shared vectors in ``vectors/shared/canonical_identity.json`` hold every implementation to it.

Version 1, in short::

    identity  = "aid1!" kind *( ";" key "=" value )      ; keys in the order of KEYS, each at most once
    kind      = "human-attested" / "agent" / "unknown" / "transport"
    ref       = type ":" env "/" domain "/" subject      ; one typed, scoped principal
    type      = "user" / "agent" / "service" / "sponsor" / "approver"
    chain     = ref *( ">" ref )                         ; root first, the acting agent last
    evidence  = ( "presence" / "approval" ) ":" digest
    digest    = "sha256:" 64( DIGIT / %x61-66 )

The leading ``aid1!`` is a critical marker: a reader that does not implement version 1 refuses the string, and no
string of this grammar is a plain ``ref``, so an access-list entry ``user:prod/<issuer>/alice`` never equals, and
never prefixes, the identity of an agent acting for alice. The plain user form is rendered only for a
``human-attested`` identity (``plain_user``). Absence of an agent never means a human acted: a request whose actor
could not be established is kind ``unknown``, and the strict profile refuses it.

Every refusal is an ``IdentityStringError`` whose ``code`` is the stable reason the TypeScript twin reports too.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

VERSION: Final = 1
MARKER: Final = "aid1!"
KINDS: Final = ("human-attested", "agent", "unknown", "transport")
TYPES: Final = ("user", "agent", "service", "sponsor", "approver")
KEYS: Final = ("user", "chain", "sponsor", "approver", "service", "evidence", "act", "grants")
EVIDENCE_METHODS: Final = ("presence", "approval")
PROFILES: Final = ("basic", "strict")
#: The type every ref under a key carries.
KEY_TYPES: Final = {"user": "user", "chain": "agent", "sponsor": "sponsor", "approver": "approver",
                    "service": "service"}  # fmt: skip
#: Per kind, the keys it must carry and the keys it may carry.
REQUIRED: Final = {"human-attested": ("user", "evidence"), "agent": ("chain",), "unknown": ("user",),
                   "transport": ("service",)}  # fmt: skip
ALLOWED: Final = {
    "human-attested": ("user", "approver", "evidence", "grants"),
    "agent": ("user", "chain", "sponsor", "approver", "act", "grants"),
    "unknown": ("user",),
    "transport": ("service",),
}
MAX_OCTETS: Final = 8192
MAX_CHAIN: Final = 32
UNRESERVED: Final = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_COMPONENT: Final = re.compile(r"(?:[A-Za-z0-9\-._~]|%[0-9A-F]{2})+")
_ENV: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")


class IdentityStringError(ValueError):
    """A string that is not a canonical identity, or parts that have none; ``code`` is the stable reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _encode(value: str) -> str:
    try:
        octets = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise IdentityStringError("identity_value_not_utf8") from exc
    return "".join(chr(b) if b in UNRESERVED else f"%{b:02X}" for b in octets)


def _decode(text: str) -> str:
    if _COMPONENT.fullmatch(text) is None:
        raise IdentityStringError("identity_component_not_canonical", text[:64])
    octets = bytearray()
    index = 0
    while index < len(text):
        if text[index] == "%":
            octets.append(int(text[index + 1 : index + 3], 16))
            index += 3
        else:
            octets.append(ord(text[index]))
            index += 1
    try:
        value = octets.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IdentityStringError("identity_value_not_utf8") from exc
    if _encode(value) != text:
        raise IdentityStringError("identity_component_not_canonical", text[:64])
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise IdentityStringError("identity_digest_malformed", repr(value)[:80])
    return value


@dataclass(frozen=True)
class Ref:
    """One principal: its type, the environment and trust domain it was verified in, and its subject there.

    ``domain`` is the identifier of the trust root the verifier pinned for it (an issuer URL, a SPIFFE trust domain);
    a subject is unique only within its domain, and the same domain serves several environments, so all three
    together name the principal."""

    type: str
    environment: str
    domain: str
    subject: str

    def __post_init__(self) -> None:
        if self.type not in TYPES:
            raise IdentityStringError("identity_ref_type_unknown", repr(self.type)[:40])
        if not isinstance(self.environment, str) or _ENV.fullmatch(self.environment) is None:
            raise IdentityStringError("identity_environment_malformed", repr(self.environment)[:40])
        for name in ("domain", "subject"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise IdentityStringError("identity_ref_malformed", f"{name} is a non-empty string")
            _encode(value)

    def render(self) -> str:
        return f"{self.type}:{self.environment}/{_encode(self.domain)}/{_encode(self.subject)}"

    def __str__(self) -> str:
        return self.render()

    @classmethod
    def parse(cls, text: str) -> Ref:
        if not isinstance(text, str) or not text.isascii():
            raise IdentityStringError("identity_ref_malformed", "a ref is an ASCII string")
        kind, colon, rest = text.partition(":")
        parts = rest.split("/")
        if not colon or len(parts) != 3:
            raise IdentityStringError("identity_ref_malformed", text[:64])
        if kind not in TYPES:
            raise IdentityStringError("identity_ref_type_unknown", kind[:40])
        return cls(type=kind, environment=parts[0], domain=_decode(parts[1]), subject=_decode(parts[2]))

    def document(self) -> dict[str, str]:
        return {"id": self.render(), "type": self.type, "environment": self.environment, "domain": self.domain,
                "subject": self.subject}  # fmt: skip

    @classmethod
    def from_document(cls, doc: Any) -> Ref:
        if not isinstance(doc, Mapping) or set(doc) != {"id", "type", "environment", "domain", "subject"}:
            raise IdentityStringError("identity_document_malformed", "a ref document has exactly its five members")
        ref = cls(type=doc["type"], environment=doc["environment"], domain=doc["domain"], subject=doc["subject"])
        if doc["id"] != ref.render():
            raise IdentityStringError("identity_document_id_mismatch", "a ref's id is not the render of its parts")
        return ref


@dataclass(frozen=True)
class Evidence:
    """What established that a human acted: a fresh user-presence proof, or an approval bound to this request."""

    method: str
    digest: str

    def __post_init__(self) -> None:
        if self.method not in EVIDENCE_METHODS:
            raise IdentityStringError("identity_evidence_malformed", repr(self.method)[:40])
        _digest(self.digest)

    def render(self) -> str:
        return f"{self.method}:{self.digest}"

    @classmethod
    def parse(cls, text: str) -> Evidence:
        method, colon, value = text.partition(":")
        if not colon:
            raise IdentityStringError("identity_evidence_malformed", text[:64])
        return cls(method=method, digest=value)


@dataclass(frozen=True)
class CanonicalIdentity:
    """The verified identity of one request (or of its transport), as kind and typed, scoped principals.

    ``chain`` lists the agents of the delegation path, root first, the agent that acted last, so a sub-agent's
    identity always shows its parent. ``act`` is the digest of the identity provider's signed RFC 8693 ``act`` claim
    and ``grants`` the digest of the capability grant chain the request ran under."""

    kind: str
    user: Ref | None = None
    chain: tuple[Ref, ...] = ()
    sponsor: Ref | None = None
    approver: Ref | None = None
    service: Ref | None = None
    evidence: Evidence | None = None
    act: str | None = None
    grants: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise IdentityStringError("identity_kind_unknown", repr(self.kind)[:40])
        if not isinstance(self.chain, tuple):
            raise IdentityStringError("identity_chain_malformed", "chain is a tuple of agent refs")
        present = [key for key in KEYS if self._value(key) not in (None, ())]
        for key in present:
            if key not in ALLOWED[self.kind]:
                raise IdentityStringError("identity_attribute_not_allowed", f"{key} in a {self.kind} identity")
        for key in REQUIRED[self.kind]:
            if key not in present:
                raise IdentityStringError("identity_attribute_missing", f"a {self.kind} identity needs {key}")
        for key, want in KEY_TYPES.items():
            refs = self.chain if key == "chain" else (() if self._value(key) is None else (self._value(key),))
            for ref in refs:
                if not isinstance(ref, Ref) or ref.type != want:
                    raise IdentityStringError("identity_ref_type_mismatch", f"{key} carries {want} refs")
        if len(self.chain) > MAX_CHAIN:
            raise IdentityStringError("identity_chain_too_deep", f"more than {MAX_CHAIN} agents")
        if len(set(self.chain)) != len(self.chain):
            raise IdentityStringError("identity_chain_repeats_agent", "an agent appears twice in one chain")
        if self.evidence is not None and not isinstance(self.evidence, Evidence):
            raise IdentityStringError("identity_evidence_malformed", "evidence is an Evidence")
        if self.evidence is not None and self.evidence.method == "approval" and self.approver is None:
            raise IdentityStringError("identity_attribute_missing", "approval evidence needs the approver")
        if self.kind == "agent" and self.user is None and self.sponsor is None:
            raise IdentityStringError("identity_attribute_missing", "an agent acting for no user needs its sponsor")
        if self.act is not None and self.user is None:
            raise IdentityStringError("identity_attribute_missing", "act is a claim of the user's credential")
        for key in ("act", "grants"):
            if self._value(key) is not None:
                _digest(self._value(key))
        if len(self.render()) > MAX_OCTETS:
            raise IdentityStringError("identity_too_long", f"longer than {MAX_OCTETS} octets")

    def _value(self, key: str) -> Any:
        return getattr(self, key)

    def _rendered(self, key: str) -> str:
        value = self._value(key)
        if key == "chain":
            return ">".join(ref.render() for ref in value)
        return value if isinstance(value, str) else value.render()

    def render(self) -> str:
        """The canonical string: byte-equal for two identities exactly when they are the same identity."""
        pairs = [f"{key}={self._rendered(key)}" for key in KEYS if self._value(key) not in (None, ())]
        return MARKER + self.kind + "".join(";" + pair for pair in pairs)

    def __str__(self) -> str:
        return self.render()

    @property
    def agent(self) -> Ref | None:
        """The agent that acted (the last of the chain), None when no agent acted."""
        return self.chain[-1] if self.chain else None

    def plain_user(self) -> str:
        """The bare user ref, what an access list made before agents names: only a human-attested identity has it."""
        if self.kind != "human-attested" or self.user is None:
            raise IdentityStringError("identity_not_human_attested", "only a human-attested identity is the user alone")
        return self.user.render()

    def acl_key(self) -> str:
        """The one string to look up in an access list: the plain user for a human-attested identity, else the full
        canonical string, which no entry naming a principal alone ever equals."""
        return self.plain_user() if self.kind == "human-attested" else self.render()

    def check(self, profile: str) -> None:
        """Refuse an identity the profile does not admit: strict refuses an identity whose actor is unknown."""
        if profile not in PROFILES:
            raise IdentityStringError("identity_profile_unknown", repr(profile)[:40])
        if profile == "strict" and self.kind == "unknown":
            raise IdentityStringError("identity_actor_unknown", "strict admits no request whose actor is unknown")

    @classmethod
    def parse(cls, text: Any) -> CanonicalIdentity:
        if not isinstance(text, str):
            raise IdentityStringError("identity_string_malformed", "an identity string is a str")
        if len(text) > MAX_OCTETS or not text.isascii():
            raise IdentityStringError("identity_too_long" if text.isascii() else "identity_string_malformed",
                                      f"at most {MAX_OCTETS} ASCII octets")  # fmt: skip
        head, bang, _ = text.partition("!")
        if not bang or not head.startswith("aid"):
            raise IdentityStringError("identity_string_malformed", "a canonical identity starts aid<version>!")
        if head + "!" != MARKER:
            raise IdentityStringError("identity_version_unknown", head[:16])
        kind, *pairs = text[len(MARKER) :].split(";")
        if kind not in KINDS:
            raise IdentityStringError("identity_kind_unknown", kind[:40])
        fields: dict[str, Any] = {"kind": kind}
        position = -1
        for pair in pairs:
            key, equals, value = pair.partition("=")
            if not equals or key not in KEYS:
                raise IdentityStringError("identity_attribute_unknown", key[:32])
            if KEYS.index(key) <= position:
                raise IdentityStringError("identity_attribute_order", f"{key} is repeated or out of order")
            position = KEYS.index(key)
            if not value:
                raise IdentityStringError("identity_attribute_empty", key)
            if key == "chain":
                fields[key] = tuple(Ref.parse(part) for part in value.split(">"))
            elif key == "evidence":
                fields[key] = Evidence.parse(value)
            elif key in ("act", "grants"):
                fields[key] = _digest(value)
            else:
                fields[key] = Ref.parse(value)
        identity = cls(**fields)
        if identity.render() != text:
            raise IdentityStringError("identity_string_not_canonical", text[:64])
        return identity

    def document(self) -> dict[str, Any]:
        """The structured form: ``id`` is the canonical string; an absent member is omitted, never null."""
        doc: dict[str, Any] = {"id": self.render(), "version": VERSION, "kind": self.kind}
        for key in KEYS:
            value = self._value(key)
            if value in (None, ()):
                continue
            if key == "chain":
                doc[key] = [ref.document() for ref in value]
            elif key == "evidence":
                doc[key] = {"method": value.method, "digest": value.digest}
            elif isinstance(value, Ref):
                doc[key] = value.document()
            else:
                doc[key] = value
        return doc

    @classmethod
    def from_document(cls, doc: Any) -> CanonicalIdentity:
        """The identity a document states; refused when its ``id`` is not the render of its own parts, so an engine
        that reads the parts and one that compares the id can never disagree about who acted."""
        if not isinstance(doc, Mapping) or not {"id", "version", "kind"} <= set(doc):
            raise IdentityStringError("identity_document_malformed", "an identity document has id, version and kind")
        unknown = set(doc) - {"id", "version", "kind", *KEYS}
        if unknown:
            raise IdentityStringError("identity_attribute_unknown", min(unknown)[:32])
        if doc["version"] != VERSION or isinstance(doc["version"], bool):
            raise IdentityStringError("identity_version_unknown", repr(doc["version"])[:16])
        fields: dict[str, Any] = {"kind": doc["kind"]}
        for key in KEYS:
            if key not in doc:
                continue
            value = doc[key]
            if key == "chain":
                if not isinstance(value, list) or not value:
                    raise IdentityStringError("identity_chain_malformed", "chain is a non-empty list of refs")
                fields[key] = tuple(Ref.from_document(item) for item in value)
            elif key == "evidence":
                if not isinstance(value, Mapping) or set(value) != {"method", "digest"}:
                    raise IdentityStringError("identity_evidence_malformed", "evidence has method and digest")
                fields[key] = Evidence(method=value["method"], digest=value["digest"])
            elif key in ("act", "grants"):
                fields[key] = _digest(value)
            else:
                fields[key] = Ref.from_document(value)
        identity = cls(**fields)
        if doc["id"] != identity.render():
            raise IdentityStringError("identity_document_id_mismatch", "the id is not the render of the parts")
        return identity
