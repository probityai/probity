"""The registry's published formats, checked offline: pinned-key JWS, key documents, naming entries, passports.

A verifier needs four things from a registry and no network to read them:

1. **Pinned-key JWS.** One rule holds every verification (R-A): the key comes from what the verifier pinned, never from
   the presented data. A header that names or carries a key (``jku``, ``jwk``, ``x5u``, ``x5c``) or demands an
   extension (``crit``) is refused; ``kid`` only selects among the keys already pinned for the token's issuer; ``alg``
   is checked against the pinned key's own type, so an ``alg: none`` or an HMAC over a public key is refused.
   Every token has one spelling. ``unb64url`` reads only the canonical base64url of each segment, EdDSA refuses a
   non-canonical S, RS256 is deterministic, and an ES256 signature is read only in its low-S form (s <= n/2): ECDSA
   (r, s) and (r, n - s) both verify, so without that rule one signed statement has two token texts and two digests.
   An ES256 issuer normalizes s before encoding (``s = n - s`` when ``s > n/2``); a high-S signature is refused as
   ``jws_signature_not_low_s``. A token's digest is therefore a stable name for it, and the single-use key of a
   validation is still its statement, ``(issuer, jti)`` (``Validation.spend_key``), never its text, so a signature
   scheme added later that is malleable in some other way cannot make one validation spendable twice.
2. **Domain control.** ``check_validation`` reads a domain-control validation a pinned validator signed for exactly one
   (domain, tenant, canonical id) inside its reuse window. ``pin_key_document`` pins the key document a domain serves
   at ``/.well-known/agent-keys.json``: the chain the connection presented must verify to roots the verifier holds for
   that DNS name, and the document must name the domain, carry public keys only and not be past its ``notAfter``. A key
   bound that way is graded I (independent of the tenant); a key the tenant declares is graded W.
3. **The naming log.** ``verify_entry`` reads a ``probity-naming-log-leaf/v1`` entry from a leaf that an RFC 9162
   inclusion proof ties to a checkpoint the log key signed; ``verify_head`` reads the log's recent signed statement of
   which leaf is a name's current binding, so a moved name or a replaced key binds nothing.
4. **Passports.** ``verify_presentation`` checks one SD-JWT presentation with key binding: the issuer's key from the
   pins, the holder's key from the issuer-signed ``cnf`` (R-B: a passport without proof of possession names an agent
   and proves nobody is it), and every disclosure against the digests the issuer signed.
   The key binding JWT follows the issuer JWT's rules: it names no key and demands no extension (``crit`` is
   ``passport_kb_critical``).

Issuing, serving and appending (the validator, the naming log's writer, the key-document fetch, passport issue and
presentation) are not here. Every refusal is a ``RegistryError`` whose ``code`` is a registered ``registry.*`` code.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from . import witness
from .core import TOKEN_MAX_DEPTH, JsonRefused, admitted_loads, sha256_hex
from .identity import jwk_thumbprint

#: The algorithm each pinned key type admits; the header's ``alg`` must be this one.
ALG_OF_KEY: Final = {("OKP", "Ed25519"): "EdDSA", ("EC", "P-256"): "ES256", ("RSA", None): "RS256"}
#: The order of the P-256 group: an ES256 ``s`` above half of it is the second spelling of a signature.
P256_ORDER: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
MAX_TOKEN_BYTES: Final = 64 << 10
#: Header members that point at a key; a verifier that follows one lets the token choose its own key.
KEY_REFERENCES: Final = ("jku", "jwk", "x5u", "x5c")
ID_PATTERN: Final = re.compile(r"^agt_[a-z2-7]{26}$")
NAME_PATTERN: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

METHODS: Final = ("dns-01", "http-01")
KEY_DOCUMENT_FORMAT: Final = "probity-domain-key-document/v1"
VALIDATION_TYP: Final = "domain-validation+jwt"
#: What a published key may be used for.
USES: Final = ("receipt", "passport-issuer", "discovery")
#: The longest a validation may be reused for a new naming entry.
VALIDATION_REUSE_S: Final = 10 * 86400
MAX_KEY_DOCUMENT_BYTES: Final = 64 << 10
TENANT_DECLARED: Final = "tenant-declared counterparty"
_PRIVATE_MEMBERS: Final = {"d", "p", "q", "dp", "dq", "qi", "k"}

LEAF_FORMAT: Final = "probity-naming-log-leaf/v1"
HEAD_FORMAT: Final = "probity-naming-log-head/v1"
#: The oldest statement of a name's current leaf a relying party accepts.
HEAD_MAX_AGE_MS: Final = 3_600_000
HEAD_SKEW_MS: Final = 60_000

PASSPORT_TYP: Final = "agent-passport+sd-jwt"
KB_TYP: Final = "kb+jwt"
SD_ALG: Final = "sha-256"
#: The longest a passport may live; possession and a fresh lease are checked at every presentation.
MAX_LIFE_S: Final = 86400
#: The longest a key binding JWT may be old at the relying party.
KB_MAX_AGE_S: Final = 300
PLAIN: Final = frozenset({"iss", "sub", "tenant", "epoch", "iat", "exp", "nbf", "cnf", "jti", "_sd", "_sd_alg"})
RESERVED: Final = frozenset({"_sd", "...", "_sd_alg", "cnf"})
MIN_SALT_BYTES: Final = 16

Grade = Literal["I", "W"]
BoundBy = Literal["domain-document", "naming-log", "rail-operator", "tenant-declared"]


class RegistryError(ValueError):
    """A document, assertion or entry the verifier will not accept; ``code`` is the registered reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# --- compact JWS under pinned keys ------------------------------------------------------------------------------


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    """The bytes of one unpadded base64url segment; only the canonical spelling of its bytes is read."""
    if not isinstance(text, str) or not text.isascii() or "=" in text:
        raise RegistryError("jws_malformed", "a segment is not unpadded base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, binascii.Error) as exc:
        raise RegistryError("jws_malformed", "a segment is not base64url") from exc
    # Many strings decode to one value; a token's digest names it, so only one spelling of each segment is read.
    if b64url(data) != text:
        raise RegistryError("jws_malformed", "a segment is not the canonical base64url of its bytes")
    return data


#: The deepest nesting, in containers, a registry document may have.
MAX_JSON_DEPTH: Final = TOKEN_MAX_DEPTH


def strict_json(data: bytes) -> Any:
    """A registry document read by the package's one reader of untrusted JSON (``core.admitted_loads``): a repeated
    member is ``jws_duplicate_member``; invalid UTF-8, a lone surrogate, NaN, a number no double holds or nesting past
    ``MAX_JSON_DEPTH`` is ``jws_malformed``. Two readers of one document see one value, and every string of the value
    encodes as UTF-8, so a leaf re-serialized from it never raises."""
    try:
        return admitted_loads(data, max_depth=MAX_JSON_DEPTH)
    except JsonRefused as exc:
        if exc.variant == "DuplicateMember":
            raise RegistryError("jws_duplicate_member", "a member is repeated") from exc
        raise RegistryError("jws_malformed", f"not admissible UTF-8 JSON: {exc.variant}") from exc


def _alg_of(jwk: Mapping[str, Any]) -> str | None:
    kty = jwk.get("kty")
    return ALG_OF_KEY.get((str(kty), None if kty == "RSA" else str(jwk.get("crv"))))


@dataclass(frozen=True)
class PinnedKeys:
    """One issuer's keys as the verifier pinned them: a JWKS snapshot and the RFC 7638 thumbprints it accepts."""

    issuer: str
    keys: tuple[Mapping[str, Any], ...]
    thumbprints: frozenset[str]

    @classmethod
    def of(cls, issuer: str, jwks: Mapping[str, Any], thumbprints: frozenset[str] | None = None) -> PinnedKeys:
        """Pin ``jwks``; with ``thumbprints`` None, every usable key in the snapshot is accepted."""
        keys = tuple(dict(k) for k in jwks.get("keys", []) if isinstance(k, Mapping))
        if not keys:
            raise ValueError(f"issuer {issuer}: a pin needs at least one key")
        if thumbprints is not None:
            return cls(issuer, keys, thumbprints)
        accepted = set()
        for key in keys:
            try:
                accepted.add(jwk_thumbprint(key))
            except ValueError:
                continue  # an unusable key is refused when a token selects it
        return cls(issuer, keys, frozenset(accepted))

    def select(self, kid: Any) -> Mapping[str, Any]:
        matches = [k for k in self.keys if k.get("kid") == kid]
        if not isinstance(kid, str) or len(matches) != 1:
            raise RegistryError("jws_kid_unknown", f"kid {kid!r} selects no single pinned key of {self.issuer}")
        try:
            print_ = jwk_thumbprint(matches[0])
        except ValueError as exc:
            raise RegistryError("jws_key_invalid", f"kid {kid!r} of {self.issuer}") from exc
        if print_ not in self.thumbprints:
            raise RegistryError("jws_key_not_pinned", f"kid {kid!r} of {self.issuer}")
        return matches[0]


def high_s(alg: Any, signature: bytes) -> bool:
    """Whether ``signature`` is an ES256 signature in its high-S spelling, the one of the two this module never reads."""
    return alg == "ES256" and len(signature) == 64 and int.from_bytes(signature[32:], "big") > P256_ORDER // 2


def _one_spelling(alg: Any, signature: bytes) -> None:
    if high_s(alg, signature):
        raise RegistryError("jws_signature_not_low_s", "an ES256 signature is read only with s <= n/2")


def verify_signature(alg: str, jwk: Mapping[str, Any], signing_input: bytes, signature: bytes) -> bool:
    """True when ``signature`` verifies under the pinned ``jwk`` by ``alg``, the one algorithm that key type admits,
    in its one spelling (an ES256 signature with s <= n/2)."""
    if _alg_of(jwk) != alg:
        return False
    try:
        if alg == "EdDSA":
            Ed25519PublicKey.from_public_bytes(unb64url(jwk["x"])).verify(signature, signing_input)
        elif alg == "ES256":
            if len(signature) != 64 or high_s(alg, signature):
                return False
            point = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64url(jwk["x"]), "big"),
                                                  int.from_bytes(unb64url(jwk["y"]), "big"), ec.SECP256R1())
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            point.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        else:
            numbers = rsa.RSAPublicNumbers(int.from_bytes(unb64url(jwk["e"]), "big"),
                                           int.from_bytes(unb64url(jwk["n"]), "big"))
            if numbers.n.bit_length() < 2048:
                return False
            numbers.public_key().verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, KeyError, TypeError, RegistryError):
        return False
    return True


@dataclass(frozen=True)
class Verified:
    header: dict[str, Any]
    claims: dict[str, Any]
    key: Mapping[str, Any]
    signing_input: bytes


def split(token: str) -> tuple[str, str, str]:
    if not isinstance(token, str) or not token.isascii() or len(token) > MAX_TOKEN_BYTES:
        raise RegistryError("jws_malformed", "a compact JWS is ASCII and bounded")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise RegistryError("jws_malformed", "a compact JWS has three segments")
    return parts[0], parts[1], parts[2]


def _object(segment: str, what: str) -> dict[str, Any]:
    value = strict_json(unb64url(segment))
    if not isinstance(value, dict):
        raise RegistryError("jws_malformed", f"{what} is a JSON object")
    return value


def verify_jws(token: str, pins: Mapping[str, PinnedKeys], *, typ: tuple[str | None, ...]) -> Verified:
    """Verify ``token`` under the pin of the issuer its ``iss`` names; refused otherwise.

    ``typ`` lists the ``typ`` header values this kind of token may carry (None admits an absent ``typ``)."""
    head, body, sig = split(token)
    header = _object(head, "the header")
    named = sorted(set(header) & set(KEY_REFERENCES))
    if named:
        raise RegistryError("jws_header_names_a_key", ", ".join(named))
    if "crit" in header:
        raise RegistryError("jws_header_critical", "no extension is understood, so none may be demanded")
    if header.get("typ") not in typ:
        raise RegistryError("jws_type_mismatch", f"typ {header.get('typ')!r}, expected one of {typ!r}")
    claims = _object(body, "claims")
    iss = claims.get("iss")
    pin = pins.get(iss) if isinstance(iss, str) else None
    if pin is None:
        raise RegistryError("jws_issuer_untrusted", repr(iss))
    key = pin.select(header.get("kid"))
    signing_input = f"{head}.{body}".encode("ascii")
    signature = unb64url(sig)
    _one_spelling(header.get("alg"), signature)
    if not verify_signature(str(header.get("alg")), key, signing_input, signature):
        raise RegistryError("jws_signature_unverified", f"issuer {iss}")
    return Verified(header, claims, key, signing_input)


def int_claim(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise RegistryError("jws_claim_invalid", f"{name} is not an integer")
    return value


def _time_state(claims: Mapping[str, Any], now: int, max_life: int, skew: int) -> tuple[str, str]:
    """``("lifetime"|"early"|"late"|"ok", detail)`` for ``iat <= now + skew``, ``nbf``, ``now < exp``, life."""
    iat, exp = int_claim(claims, "iat"), int_claim(claims, "exp")
    if exp <= iat or exp - iat > max_life:
        return "lifetime", f"exp - iat = {exp - iat} s, at most {max_life} s"
    if iat > now + skew or ("nbf" in claims and int_claim(claims, "nbf") > now + skew):
        return "early", f"iat {iat}, now {now}"
    if now >= exp:
        return "late", f"expired at {exp}, now {now}"
    return "ok", ""


# --- domain control ---------------------------------------------------------------------------------------------


def domain_name(text: Any) -> str:
    """A fully qualified DNS name in its one comparable form: ASCII (A-labels), lower case, no trailing dot."""
    if not isinstance(text, str) or not text.isascii() or len(text) > 253 or text != text.strip():
        raise RegistryError("domain_invalid", repr(text))
    labels = text.lower().split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels) or labels[-1].isdigit():
        raise RegistryError("domain_invalid", repr(text))
    return ".".join(labels)


def _utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("an instant carries its zone")
    return moment.astimezone(UTC)


@dataclass(frozen=True)
class Validation:
    issuer: str
    domain: str
    tenant: str
    subject: str
    method: str
    issued_at: int
    expires_at: int
    jti: str
    digest: str  # SHA-256 of the token, its one spelling: what a naming leaf records

    @property
    def spend_key(self) -> tuple[str, str]:
        """What a validator's single-use store spends: the statement (issuer, jti), never the token's text."""
        return self.issuer, self.jti


def check_validation(token: str, pins: Mapping[str, PinnedKeys], *, domain: str, tenant: str, subject: str,
                     now: int) -> Validation:  # fmt: skip
    """The validation ``token`` states, when a pinned validator signed it for exactly this (domain, tenant, subject)
    and it is inside its reuse window at ``now``; refused otherwise."""
    verified = verify_jws(token, pins, typ=(VALIDATION_TYP,))
    c = verified.claims
    if c.get("domain") != domain_name(domain) or c.get("tenant") != tenant or c.get("sub") != subject:
        raise RegistryError("dcv_validation_mismatch",
                            f"validation is for {c.get('domain')!r} {c.get('tenant')!r} {c.get('sub')!r}")
    if c.get("method") not in METHODS or not isinstance(c.get("jti"), str):
        raise RegistryError("dcv_validation_malformed", "a method and a jti")
    state, detail = _time_state(c, now, VALIDATION_REUSE_S, 0)
    if state == "lifetime":
        raise RegistryError("dcv_validation_lifetime_invalid", detail)
    if state == "early":
        raise RegistryError("dcv_validation_not_yet_valid", detail)
    if state == "late":
        raise RegistryError("dcv_validation_expired", detail)
    return Validation(c["iss"], c["domain"], tenant, subject, c["method"], int_claim(c, "iat"), int_claim(c, "exp"),
                      c["jti"], sha256_hex(token.encode("ascii")))  # fmt: skip


@dataclass(frozen=True)
class DomainKey:
    kid: str
    use: str
    jwk: Mapping[str, Any]
    thumbprint: str


def published_key(entry: Any) -> DomainKey:
    """One key entry of a key document or a naming leaf: ``{kid, use, jwk}`` with a public key and nothing private."""
    if not isinstance(entry, Mapping) or set(entry) != {"kid", "use", "jwk"}:
        raise RegistryError("domain_key_malformed", "a published key is {kid, use, jwk}")
    kid, use, jwk = entry["kid"], entry["use"], entry["jwk"]
    if not isinstance(kid, str) or not kid or use not in USES or not isinstance(jwk, Mapping):
        raise RegistryError("domain_key_malformed", f"kid {kid!r} use {use!r}")
    if _PRIVATE_MEMBERS & set(jwk):
        raise RegistryError("domain_key_private_material", kid)
    if _alg_of(jwk) is None:
        raise RegistryError("domain_key_unsupported", f"{kid}: {jwk.get('kty')!r} {jwk.get('crv')!r}")
    try:
        print_ = jwk_thumbprint(jwk)
    except ValueError as exc:
        raise RegistryError("domain_key_unsupported", kid) from exc
    return DomainKey(kid, use, dict(jwk), print_)


def _keys(entries: Any) -> tuple[DomainKey, ...]:
    if not isinstance(entries, list):
        raise RegistryError("domain_key_malformed", "keys is a list")
    keys = tuple(published_key(e) for e in entries)
    if len({k.kid for k in keys}) != len(keys):
        raise RegistryError("domain_key_malformed", "two keys share a kid")
    return keys


@dataclass(frozen=True)
class PinnedKeyDocument:
    domain: str
    keys: tuple[DomainKey, ...]
    document_sha256: str
    leaf_sha256: str
    chain_sha256: tuple[str, ...]
    pinned_at: str
    not_after: str

    def key(self, kid: str, use: str) -> DomainKey:
        found = [k for k in self.keys if k.kid == kid]
        if len(found) != 1:
            raise RegistryError("domain_key_unknown", f"{self.domain} publishes no key {kid!r}")
        if found[0].use != use:
            raise RegistryError("domain_key_wrong_use", f"{kid} is published for {found[0].use}, not {use}")
        return found[0]


def _instant(text: Any, what: str) -> datetime:
    if not isinstance(text, str) or not text.endswith("Z"):
        raise RegistryError("domain_document_malformed", f"{what} is an RFC 3339 instant in UTC")
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise RegistryError("domain_document_malformed", what) from exc


def verify_chain(domain: str, chain: Sequence[bytes], roots: Sequence[x509.Certificate], at: datetime) -> None:
    """The TLS chain (DER, leaf first) verifies to ``roots`` for the DNS name ``domain`` at ``at``."""
    if not roots:
        raise RegistryError("domain_roots_missing", "a chain is verified to roots the verifier holds; none given")
    if not chain:
        raise RegistryError("domain_chain_missing", "a key document is pinned with the chain it was served over")
    try:
        certs = [x509.load_der_x509_certificate(c) for c in chain]
    except ValueError as exc:
        raise RegistryError("domain_chain_invalid", "a certificate is not DER") from exc
    verifier = (PolicyBuilder().store(Store(list(roots))).time(_utc(at))
                .build_server_verifier(x509.DNSName(domain_name(domain))))
    try:
        verifier.verify(certs[0], certs[1:])
    except VerificationError as exc:
        raise RegistryError("domain_chain_unverified", str(exc)) from exc


def pin_key_document(domain: str, body: bytes, chain: Sequence[bytes], roots: Sequence[x509.Certificate],
                     at: datetime) -> PinnedKeyDocument:  # fmt: skip
    """Pin the key document ``body`` that ``https://<domain>/.well-known/agent-keys.json`` served over a connection
    that presented ``chain``. The chain must verify to ``roots`` for ``domain``; the document must name ``domain``,
    carry public keys only and not be past its ``notAfter``."""
    host = domain_name(domain)
    if len(body) > MAX_KEY_DOCUMENT_BYTES:
        raise RegistryError("domain_document_too_large", f"{len(body)} bytes")
    verify_chain(host, chain, roots, at)
    doc = strict_json(body)
    if not isinstance(doc, dict) or set(doc) != {"format", "domain", "keys", "notAfter"}:
        raise RegistryError("domain_document_malformed", "members are format, domain, keys, notAfter")
    if doc["format"] != KEY_DOCUMENT_FORMAT:
        raise RegistryError("domain_document_malformed", f"format {doc['format']!r}")
    if doc["domain"] != host:
        raise RegistryError("domain_document_wrong_domain", f"served by {host}, names {doc['domain']!r}")
    not_after = _instant(doc["notAfter"], "notAfter")
    if _utc(at) >= not_after:
        raise RegistryError("domain_document_expired", doc["notAfter"])
    keys = _keys(doc["keys"])
    if not keys:
        raise RegistryError("domain_key_malformed", "a key document publishes at least one key")
    return PinnedKeyDocument(host, keys, hashlib.sha256(body).hexdigest(), hashlib.sha256(chain[0]).hexdigest(),
                             tuple(hashlib.sha256(c).hexdigest() for c in chain),
                             _utc(at).strftime("%Y-%m-%dT%H:%M:%SZ"), doc["notAfter"])  # fmt: skip


@dataclass(frozen=True)
class KeyBinding:
    """A counterparty key bound to its identity, and the grade a receipt under it can carry for its acknowledgment."""

    target: str
    kid: str
    use: str
    thumbprint: str
    jwk: Mapping[str, Any]
    bound_by: BoundBy
    grade: Grade
    label: str | None
    independent_of: tuple[str, ...]
    evidence: Mapping[str, Any]


def bind_from_document(target: str, doc: PinnedKeyDocument, kid: str, use: str, *, at: datetime) -> KeyBinding:
    """A key from the pinned key document of the target's own domain: grade I, independent of the tenant.

    ``at`` is the instant the key is used at: a document past its own ``notAfter`` binds nothing."""
    if doc.domain != domain_name(target):
        raise RegistryError("domain_document_wrong_domain", f"the pin is for {doc.domain}, the target is {target}")
    if _utc(at) >= _instant(doc.not_after, "notAfter"):
        raise RegistryError("domain_document_expired", doc.not_after)
    key = doc.key(kid, use)
    return KeyBinding(doc.domain, kid, use, key.thumbprint, key.jwk, "domain-document", "I", None, ("tenant",),
                      {"documentSha256": doc.document_sha256, "leafSha256": doc.leaf_sha256,
                       "pinnedAt": doc.pinned_at})  # fmt: skip


def bind_rail_operator(operator: str, doc: PinnedKeyDocument, kid: str, use: str = "receipt", *,
                       at: datetime) -> KeyBinding:  # fmt: skip
    """A rail operator's published key, from the key document of the operator's own domain: grade I."""
    base = bind_from_document(operator, doc, kid, use, at=at)
    return KeyBinding(base.target, kid, use, base.thumbprint, base.jwk, "rail-operator", "I", None, ("tenant",),
                      base.evidence)  # fmt: skip


def bind_tenant_declared(target: str, jwk: Mapping[str, Any], kid: str, use: str = "receipt") -> KeyBinding:
    """A key the tenant supplied for a counterparty: grade W, labelled; independent of nobody."""
    key = published_key({"kid": kid, "use": use, "jwk": dict(jwk)})
    return KeyBinding(domain_name(target), kid, use, key.thumbprint, key.jwk, "tenant-declared", "W",
                      TENANT_DECLARED, (), {})  # fmt: skip


# --- the naming log ----------------------------------------------------------------------------------------------


def leaf_bytes(entry: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(entry), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


@dataclass(frozen=True)
class Inclusion:
    """What a relying party needs to check one entry: the leaf, its index, the proof and a signed checkpoint."""

    leaf: bytes
    index: int
    proof: tuple[bytes, ...]
    checkpoint: str


_LEAF = frozenset({"format", "name", "domain", "canonicalId", "tenant", "validation", "keys", "admittedAtMs"})
_LEAF_VALIDATION = frozenset({"issuer", "method", "issuedAt", "expiresAt", "digest"})


def _log_line(parsed: witness.Note, log_key: witness.VerifierKey) -> witness.SigLine | None:
    return next((s for s in parsed.sigs if s.name == log_key.name and s.key_id == log_key.id), None)


def _log_signed(log_key: witness.VerifierKey, text: str, line: witness.SigLine) -> bool:
    return log_key.sig_type == witness.SIG_ED25519 and len(line.sig) == 64 and log_key.verify(line.sig, text.encode())


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _leaf_shape(entry: Any) -> str | None:
    """None when ``entry`` is exactly a naming leaf, else what is wrong with it."""
    if not isinstance(entry, dict) or set(entry) != _LEAF or entry["format"] != LEAF_FORMAT:
        return "members are not the leaf's"
    host = entry["domain"]
    if not isinstance(host, str) or not isinstance(entry["name"], str):
        return "name or domain"
    try:
        comparable = domain_name(host) == host
    except RegistryError:
        comparable = False
    label = entry["name"][: -len(host) - 1]
    if not comparable or entry["name"] != f"{label}.{host}":
        return "the name is not one label under the domain"
    if not NAME_PATTERN.match(label) or ID_PATTERN.match(label):
        return "the label is not a name"
    if not isinstance(entry["canonicalId"], str) or not ID_PATTERN.match(entry["canonicalId"]):
        return "canonicalId"
    if not isinstance(entry["tenant"], str) or not _is_int(entry["admittedAtMs"]):
        return "tenant or admittedAtMs"
    v = entry["validation"]
    if (not isinstance(v, dict) or set(v) != _LEAF_VALIDATION or v["method"] not in METHODS
            or not isinstance(v["issuer"], str) or not _is_int(v["issuedAt"]) or not _is_int(v["expiresAt"])
            or not isinstance(v["digest"], str) or not _HEX64.match(v["digest"])):
        return "validation"
    if not isinstance(entry["keys"], list):
        return "keys"
    return None


def verify_entry(inclusion: Inclusion, log_key: witness.VerifierKey) -> dict[str, Any]:
    """The entry ``inclusion`` carries, when its leaf is in the tree the log key signed; refused otherwise."""
    try:
        parsed = witness.parse_note(inclusion.checkpoint)
        line = _log_line(parsed, log_key)
        if line is None:
            raise RegistryError("naming_checkpoint_unsigned", f"no signature by {log_key.name}")
        if not _log_signed(log_key, parsed.text, line):
            raise RegistryError("naming_checkpoint_invalid", f"the signature of {log_key.name} does not verify")
        cp = witness.parse_checkpoint(parsed.text)
    except witness.NoteError as exc:
        raise RegistryError("naming_checkpoint_invalid", str(exc)) from exc
    if cp.origin != log_key.name:
        raise RegistryError("naming_checkpoint_invalid", f"origin {cp.origin}")
    if not witness.verify_inclusion(inclusion.index, cp.size, witness.leaf_hash(inclusion.leaf),
                                    list(inclusion.proof), cp.root):  # fmt: skip
        raise RegistryError("naming_inclusion_unverified", f"leaf {inclusion.index} of {cp.size}")
    try:
        entry = strict_json(inclusion.leaf)
    except RegistryError as exc:
        raise RegistryError("naming_leaf_malformed", exc.code) from exc
    problem = _leaf_shape(entry)
    if problem is not None or leaf_bytes(entry) != inclusion.leaf:
        raise RegistryError("naming_leaf_malformed", problem or "not the canonical JSON of its members")
    keys = _keys(entry["keys"])
    entry["keys"] = [{"kid": k.kid, "use": k.use, "jwk": dict(k.jwk)} for k in keys]
    return dict(entry)


def verify_head(head: str, log_key: witness.VerifierKey, *, name: str, now_ms: int,
                max_age_ms: int = HEAD_MAX_AGE_MS) -> int:  # fmt: skip
    """The index of the current leaf of ``name``, when the log key signed that statement within ``max_age_ms``."""
    try:
        parsed = witness.parse_note(head)
        line = _log_line(parsed, log_key)
        if line is None:
            raise RegistryError("naming_head_unsigned", f"no signature by {log_key.name}")
        if not _log_signed(log_key, parsed.text, line):
            raise RegistryError("naming_head_invalid", f"the signature of {log_key.name} does not verify")
        fields = parsed.text.split("\n")
        if len(fields) != 6 or fields[0] != HEAD_FORMAT or fields[1] != log_key.name or fields[5]:
            raise RegistryError("naming_head_invalid", "not a naming-log head of this log")
        index, at_ms = witness.parse_decimal(fields[3], "index"), witness.parse_decimal(fields[4], "time")
    except witness.NoteError as exc:
        raise RegistryError("naming_head_invalid", str(exc)) from exc
    if fields[2] != name:
        raise RegistryError("naming_head_wrong_name", f"the head is for {fields[2]!r}")
    if not -HEAD_SKEW_MS <= now_ms - at_ms <= max_age_ms:
        raise RegistryError("naming_head_stale", f"signed at {at_ms}, now {now_ms}, at most {max_age_ms} ms old")
    return index


def bind_from_naming(inclusion: Inclusion, log_key: witness.VerifierKey, target: str, kid: str, use: str, *,
                     head: str, now_ms: int, tenant: str) -> KeyBinding:  # fmt: skip
    """A counterparty key published in the CURRENT naming entry of a name under the target's domain.

    ``head`` is the log's recent signed statement of that name's current leaf: a leaf the name has moved away from, or
    whose keys were replaced, binds nothing. ``tenant`` is the tenant whose record names this counterparty: a key
    published under another tenant's validation is grade I; one the asking tenant published under its own validation
    is grade W and labelled, because that tenant controls the domain and may hold the key."""
    entry = verify_entry(inclusion, log_key)
    if verify_head(head, log_key, name=entry["name"], now_ms=now_ms) != inclusion.index:
        raise RegistryError("naming_entry_superseded", f"{entry['name']} has a newer leaf than {inclusion.index}")
    if entry["domain"] != domain_name(target):
        raise RegistryError("naming_wrong_domain", f"the entry is under {entry['domain']}, the target is {target}")
    found = [published_key(k) for k in entry["keys"] if k["kid"] == kid]
    if len(found) != 1:
        raise RegistryError("domain_key_unknown", f"{entry['name']} publishes no key {kid!r}")
    if found[0].use != use:
        raise RegistryError("domain_key_wrong_use", f"{kid} is published for {found[0].use}, not {use}")
    evidence = {"log": log_key.name, "index": inclusion.index, "validation": entry["validation"]["digest"]}
    if entry["tenant"] == tenant:
        return KeyBinding(entry["domain"], kid, use, found[0].thumbprint, found[0].jwk, "naming-log", "W",
                          TENANT_DECLARED, (), evidence)  # fmt: skip
    return KeyBinding(entry["domain"], kid, use, found[0].thumbprint, found[0].jwk, "naming-log", "I", None,
                      ("tenant",), evidence)  # fmt: skip


# --- passports ---------------------------------------------------------------------------------------------------


def _digest(disclosure: str) -> str:
    return b64url(hashlib.sha256(disclosure.encode("ascii")).digest())


@dataclass(frozen=True)
class VerifiedPassport:
    issuer: str
    subject: str
    tenant: str
    epoch: int
    holder_jkt: str
    disclosed: Mapping[str, Any]
    nonce: str
    kb_iat: int
    expires_at: int
    jti: str


def _disclosed(payload: Mapping[str, Any], disclosures: list[str]) -> dict[str, Any]:
    if payload.get("_sd_alg") != SD_ALG:
        raise RegistryError("passport_sd_alg_unsupported", repr(payload.get("_sd_alg")))
    digests = payload.get("_sd", [])
    if (not isinstance(digests, list) or not all(isinstance(d, str) for d in digests)
            or len(set(digests)) != len(digests)):
        raise RegistryError("passport_malformed", "_sd is a list of distinct digests")
    out: dict[str, Any] = {}
    for disclosure in disclosures:
        digest = _digest(disclosure)
        if digest not in digests:
            raise RegistryError("passport_disclosure_unreferenced", "a disclosure the issuer signed no digest for")
        item = strict_json(unb64url(disclosure))
        if not isinstance(item, list) or len(item) != 3 or not isinstance(item[0], str) or not isinstance(item[1], str):
            raise RegistryError("passport_disclosure_malformed", "a disclosure is [salt, name, value]")
        salt, name, value = item
        if len(unb64url(salt)) < MIN_SALT_BYTES:
            raise RegistryError("passport_disclosure_malformed", "salt too short")
        if name in RESERVED or name in PLAIN or name in payload:
            raise RegistryError("passport_disclosure_reserved", name)
        if name in out:
            raise RegistryError("passport_disclosure_repeated", name)
        out[name] = value
    return out


def _key_binding(kb: str, holder: Mapping[str, Any], *, audience: str, prefix: str, now: int,
                 skew: int) -> tuple[str, int]:
    head, body, sig = split(kb)
    header = _object(head, "the key binding header")
    if header.get("typ") != KB_TYP:
        raise RegistryError("passport_kb_malformed", "a key binding JWT has typ kb+jwt")
    if set(header) & set(KEY_REFERENCES):
        raise RegistryError("passport_kb_names_a_key", "the holder key comes from cnf, never from the key binding")
    if "crit" in header:  # RFC 7515 section 4.1.11: no extension is understood, so none may be demanded
        raise RegistryError("passport_kb_critical", "the key binding JWT demands an extension through crit")
    signature = unb64url(sig)
    _one_spelling(header.get("alg"), signature)
    if not verify_signature(str(header.get("alg")), holder, f"{head}.{body}".encode("ascii"), signature):
        raise RegistryError("passport_possession_unproven", "the key binding JWT is not signed by the cnf key")
    claims = _object(body, "the key binding claims")
    if claims.get("aud") != audience:
        raise RegistryError("passport_kb_wrong_audience", f"bound to {claims.get('aud')!r}")
    if claims.get("sd_hash") != b64url(hashlib.sha256(prefix.encode("ascii")).digest()):
        raise RegistryError("passport_kb_sd_hash_mismatch", "the key binding covers another presentation")
    iat = int_claim(claims, "iat")
    if iat > now + skew or now - iat > KB_MAX_AGE_S:
        raise RegistryError("passport_kb_stale", f"iat {iat}, now {now}")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise RegistryError("passport_kb_malformed", "nonce")
    return nonce, iat


def verify_presentation(text: str, pins: Mapping[str, PinnedKeys], *, audience: str, now: int,
                        skew: int = 60) -> VerifiedPassport:  # fmt: skip
    """Every stateless check of one passport presentation; refused at the first that fails."""
    if not isinstance(text, str) or not text.isascii() or "~" not in text:
        raise RegistryError("passport_malformed", "a presentation is issuer JWT ~ disclosures ~ key binding JWT")
    parts = text.split("~")
    jwt, disclosures, kb = parts[0], parts[1:-1], parts[-1]
    if not kb:
        raise RegistryError("passport_no_possession", "a passport is never accepted without a key binding JWT")
    if any(not d for d in disclosures):
        raise RegistryError("passport_malformed", "an empty disclosure")
    payload = verify_jws(jwt, pins, typ=(PASSPORT_TYP,)).claims
    state, detail = _time_state(payload, now, MAX_LIFE_S, skew)
    if state == "lifetime":
        raise RegistryError("passport_lifetime_invalid", detail)
    if state == "early":
        raise RegistryError("passport_not_yet_valid", detail)
    if state == "late":
        raise RegistryError("passport_expired", detail)
    sub, tenant, epoch = payload.get("sub"), payload.get("tenant"), payload.get("epoch")
    if not isinstance(sub, str) or not ID_PATTERN.match(sub) or not isinstance(tenant, str):
        raise RegistryError("passport_malformed", "sub is a canonical id and tenant a string")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise RegistryError("passport_malformed", "epoch")
    cnf = payload.get("cnf")
    holder = cnf.get("jwk") if isinstance(cnf, dict) and set(cnf) == {"jwk"} else None
    if not isinstance(holder, dict) or _alg_of(holder) is None:
        raise RegistryError("passport_holder_invalid", "cnf is {jwk: <public key>}")
    disclosed = _disclosed(payload, disclosures)
    nonce, kb_iat = _key_binding(kb, holder, audience=audience, prefix=text[: len(text) - len(kb)], now=now,
                                 skew=skew)  # fmt: skip
    return VerifiedPassport(str(payload["iss"]), sub, tenant, epoch, jwk_thumbprint(holder), disclosed, nonce, kb_iat,
                            int_claim(payload, "exp"), str(payload.get("jti", "")))  # fmt: skip
