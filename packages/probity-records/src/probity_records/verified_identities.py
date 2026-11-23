"""The verified identities of one request: credentials in, canonical identities out, under a trust bundle the service pins.

A service that receives requests from agents asks one question of each, "who is this", and this module answers it as a
pure function: ``verified_identities(tokens, bundle, at, transport)`` returns the canonical identities
(``canonical_identity``) of the request and the transport identity beside them. It decides nothing: there is no allow
or deny here, so the same answer feeds an access list, a policy engine or a log.

Two kinds of credential arrive:

- the identity provider's tokens, when an agent calls the service directly: the user's token (``user``), the agent
  client's own access token (``agent``), and the sponsor's ID token (``sponsor``) for an agent acting for no user;
- the agent stamp (``stamp``, ``stamp.py``), when the call comes through a gateway, which verified the principals and
  forwards the stamp instead of their tokens. The two are never mixed in one request.

The verifying key never comes from the presented data. The trust bundle pins, per issuer, its public keys and, by RFC
7638 thumbprint, which roles each key may sign for and in which tenants; a token's ``iss`` picks among the pinned
issuers and its ``kid`` among that issuer's pinned keys. A header that names a key (``jku``, ``jwk``, ``x5u``,
``x5c``) is refused, never followed, and so is one that marks an extension critical (``crit``), which this verifier
implements none of.

A token the identity provider bound to a key (RFC 7800 ``cnf``) is accepted only with a proof of possession for this
request (``possession.check_possession``): a DPoP proof for this method and URL, or the client certificate, so the
token cannot be replayed on another route. This function remembers nothing; ``verify_request`` returns the proof and
the stamp's ``jti`` so a service that keeps state spends them once.

Absence of an agent never means a human acted: a user's token with no agent token is kind ``unknown``, which the
strict profile refuses. The format of the bundle, every check in order and the reasons are in
``docs/verified-identities.md``; ``vectors/shared/verified_identities.json`` holds every implementation to them.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .canonical_identity import PROFILES, CanonicalIdentity, IdentityStringError, Ref
from .clock import from_datetime
from .core import sha256_hex
from .digests import IdentityDigestError, act_chain_digest
from .grants import ts
from .identity import _verify_jws, jwk_thumbprint, unb64url
from .possession import CertificateProof, DpopProof, check_possession
from .stamp import (
    StampRefused,
    VerifiedStamp,
    stamp_header,
    stamp_issuer,
    stamp_key_id,
    verify_stamp_token,
)

VERSION: Final = 1
#: The roles a request credential may sign for, and the stamp a gateway signs.
TOKEN_ROLES: Final = ("user", "agent", "sponsor")
PIN_ROLES: Final = (*TOKEN_ROLES, "stamp")
#: The JOSE ``typ`` each role's credential carries (``application/`` prefix and case ignored, RFC 7515 section 4.1.9):
#: an RFC 9068 access token or an identity assertion grant for the user, an access token for the agent, an ID token
#: (no ``typ``, or ``JWT``) for the sponsor.
ROLE_TYPES: Final = {"user": ("at+jwt", "oauth-id-jag+jwt"), "agent": ("at+jwt",), "sponsor": (None, "jwt")}
#: Header members that point at a key; a verifier that follows one lets the token choose its own key.
KEY_REFERENCES: Final = ("jku", "jwk", "x5u", "x5c")
BUNDLE_MEMBERS: Final = frozenset({"version", "environment", "tenant", "audience", "profile", "issuers"})
MIN_RSA_BITS: Final = 2048
PRIVATE_JWK_MEMBERS: Final = frozenset({"d", "p", "q", "dp", "dq", "qi", "k", "oth"})


class VerifiedIdentitiesRefused(ValueError):
    """A request whose identities cannot be established; ``code`` is the registered reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _refuse(code: str, detail: str = "") -> VerifiedIdentitiesRefused:
    return VerifiedIdentitiesRefused(code, detail)


# --- the trust bundle ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PinnedKey:
    jwk: Mapping[str, Any]
    thumbprint: str
    roles: frozenset[str]
    tenants: frozenset[str]


@dataclass(frozen=True)
class PinnedIssuer:
    url: str
    keys: tuple[PinnedKey, ...]


@dataclass(frozen=True)
class TrustBundle:
    """What a service pins: its environment, tenant and audience, the profile it requires, and each issuer's keys
    with the roles and tenants each key may sign for. Made only by ``TrustBundle.parse``."""

    environment: str
    tenant: str
    audience: str
    profile: str
    issuers: Mapping[str, PinnedIssuer] = field(repr=False)

    @classmethod
    def parse(cls, doc: Any) -> TrustBundle:
        """The bundle a document states; ``trust_bundle_malformed`` unless it is exactly the format."""
        if not isinstance(doc, Mapping) or set(doc) != BUNDLE_MEMBERS:
            raise _refuse("trust_bundle_malformed", "a bundle has exactly " + ", ".join(sorted(BUNDLE_MEMBERS)))
        if doc["version"] != VERSION or isinstance(doc["version"], bool):
            raise _refuse("trust_bundle_malformed", "version is 1")
        try:
            Ref(type="service", environment=doc["environment"], domain="bundle", subject="probe")
        except IdentityStringError as exc:
            raise _refuse("trust_bundle_malformed", "environment is an identity environment") from exc
        for name in ("tenant", "audience"):
            if not isinstance(doc[name], str) or not doc[name]:
                raise _refuse("trust_bundle_malformed", f"{name} is a non-empty string")
        if doc["profile"] not in PROFILES:
            raise _refuse("trust_bundle_malformed", "profile is basic or strict")
        issuers = doc["issuers"]
        if not isinstance(issuers, Mapping) or not issuers:
            raise _refuse("trust_bundle_malformed", "issuers is a non-empty object")
        parsed = {str(url): _issuer(url, entry) for url, entry in issuers.items()}
        return cls(doc["environment"], doc["tenant"], doc["audience"], doc["profile"], parsed)

    def key(self, issuer: str, role: str, kid: Any) -> PinnedKey:
        """The one pinned key of ``issuer`` the header's ``kid`` selects, when it may sign for ``role`` here."""
        pinned = self.issuers.get(issuer)
        if pinned is None:
            raise _refuse("principal_issuer_untrusted", repr(issuer)[:80])
        if role == "stamp":
            matches = [k for k in pinned.keys if _is_stamp_key(k.jwk) and stamp_key_id(_raw(k.jwk)) == kid]
        else:
            matches = [k for k in pinned.keys if isinstance(kid, str) and k.jwk.get("kid") == kid]
        if len(matches) != 1:
            raise _refuse("stamp_key_mismatch" if role == "stamp" else "token_kid_unknown",
                          f"kid {str(kid)[:80]!r} selects no single pinned key of {issuer}")  # fmt: skip
        key = matches[0]
        if role not in key.roles or self.tenant not in key.tenants:
            raise _refuse("principal_key_not_pinned", f"the key is not pinned for {role} in tenant {self.tenant}")
        return key


def _issuer(url: Any, entry: Any) -> PinnedIssuer:
    if not isinstance(url, str) or not url or not url.isascii():
        raise _refuse("trust_bundle_malformed", "an issuer is a non-empty ASCII string")
    if not isinstance(entry, Mapping) or set(entry) != {"keys", "pins"}:
        raise _refuse("trust_bundle_malformed", f"issuer {url}: exactly keys and pins")
    keys, pins = entry["keys"], entry["pins"]
    if not isinstance(keys, list) or not keys or not isinstance(pins, list) or not pins:
        raise _refuse("trust_bundle_malformed", f"issuer {url}: keys and pins are non-empty lists")
    by_thumbprint: dict[str, Mapping[str, Any]] = {}
    for jwk in keys:
        if not isinstance(jwk, Mapping) or set(jwk) & PRIVATE_JWK_MEMBERS:
            raise _refuse("trust_bundle_malformed", f"issuer {url}: a key is a public JWK")
        try:
            thumbprint = jwk_thumbprint(jwk)
            short_rsa = jwk["kty"] == "RSA" and len(unb64url(str(jwk["n"])).lstrip(b"\0")) * 8 < MIN_RSA_BITS
        except (ValueError, binascii.Error) as exc:
            raise _refuse("trust_bundle_malformed", f"issuer {url}: a key has no RFC 7638 thumbprint") from exc
        if short_rsa:
            raise _refuse("trust_bundle_malformed", f"issuer {url}: an RSA key shorter than {MIN_RSA_BITS} bits")
        if thumbprint in by_thumbprint:
            raise _refuse("trust_bundle_malformed", f"issuer {url}: a key is listed twice")
        by_thumbprint[thumbprint] = dict(jwk)
    pinned: list[PinnedKey] = []
    for pin in pins:
        if not isinstance(pin, Mapping) or set(pin) != {"thumbprint", "roles", "tenants"}:
            raise _refuse("trust_bundle_malformed", f"issuer {url}: a pin has exactly thumbprint, roles, tenants")
        jwk = by_thumbprint.get(pin["thumbprint"]) if isinstance(pin["thumbprint"], str) else None
        if jwk is None or any(p.thumbprint == pin["thumbprint"] for p in pinned):
            raise _refuse("trust_bundle_malformed", f"issuer {url}: a pin names no listed key, or one pinned twice")
        roles, tenants = pin["roles"], pin["tenants"]
        if (not isinstance(roles, list) or not roles or not set(roles) <= set(PIN_ROLES) or len(set(roles)) != len(roles)
                or not isinstance(tenants, list) or not tenants
                or not all(isinstance(t, str) and t for t in tenants) or len(set(tenants)) != len(tenants)):  # fmt: skip
            raise _refuse("trust_bundle_malformed", f"issuer {url}: roles and tenants are lists of distinct names")
        if "stamp" in roles and (len(roles) != 1 or not _is_stamp_key(jwk)):
            raise _refuse("trust_bundle_malformed", f"issuer {url}: a stamp key is an Ed25519 key pinned for stamp only")
        if "stamp" not in roles and (not url.startswith("https://") or not isinstance(jwk.get("kid"), str)):
            raise _refuse("trust_bundle_malformed", f"issuer {url}: a token issuer is https and its keys carry kid")
        pinned.append(PinnedKey(jwk, pin["thumbprint"], frozenset(roles), frozenset(tenants)))
    return PinnedIssuer(url, tuple(pinned))


def _is_stamp_key(jwk: Mapping[str, Any]) -> bool:
    return jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and isinstance(jwk.get("x"), str)


def _raw(jwk: Mapping[str, Any]) -> bytes:
    return unb64url(str(jwk["x"]))


# --- the request --------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RequestFacts:
    """What the service itself knows about the request: its method, its own external URL for the route (never one
    built from the client's Host header), the body bytes (None for no body), and the possession proof presented: the
    DPoP proof header, or the DER client certificate the TLS layer verified."""

    method: str
    url: str
    content: bytes | None = None
    dpop: str | None = None
    client_certificate: bytes | None = None


@dataclass(frozen=True)
class VerifiedRequest:
    """The identities of a request, and what a service that keeps state spends once: the possession proof and the
    stamp's ``jti``."""

    identities: tuple[CanonicalIdentity, ...]
    proof: DpopProof | CertificateProof | None
    stamp: VerifiedStamp | None


def _segment(text: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate member")
            out[key] = value
        return out

    try:
        value = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)), object_pairs_hook=pairs)
    except (ValueError, binascii.Error) as exc:
        raise _refuse("token_malformed", "a segment is not base64url JSON") from exc
    if not isinstance(value, dict):
        raise _refuse("token_malformed", "header and claims are JSON objects")
    return value


def _seconds(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _refuse("token_malformed", f"{name} is not an integer")
    return value


@dataclass(frozen=True)
class _Token:
    role: str
    raw: str
    issuer: str
    subject: str
    client: str
    claims: Mapping[str, Any]


def _token(role: str, token: Any, bundle: TrustBundle, when: float) -> _Token:
    """One identity-provider token, verified for ``role`` under the bundle; VerifiedIdentitiesRefused otherwise."""
    parts = token.split(".") if isinstance(token, str) and token.isascii() else []
    if len(parts) != 3 or not all(parts):
        raise _refuse("token_malformed", f"the {role} credential is not a compact JWS")
    header, claims = _segment(parts[0]), _segment(parts[1])
    named = sorted(set(header) & set(KEY_REFERENCES))
    if named:
        raise _refuse("token_header_names_a_key", ", ".join(named))
    if "crit" in header:
        raise _refuse("token_critical_unsupported", "crit names an extension this verifier does not implement")
    iss = claims.get("iss")
    if not isinstance(iss, str) or iss not in bundle.issuers:
        raise _refuse("principal_issuer_untrusted", repr(iss)[:80])
    key = bundle.key(iss, role, header.get("kid"))
    typ = header.get("typ")
    typ = typ.lower().removeprefix("application/") if isinstance(typ, str) else typ
    if typ not in ROLE_TYPES[role]:
        raise _refuse("token_type_mismatch", f"a {role} credential with typ {header.get('typ')!r}")
    if not _verify_jws(str(header.get("alg")), key.jwk, f"{parts[0]}.{parts[1]}".encode("ascii"),
                       _signature(parts[2])):  # fmt: skip
        raise _refuse("token_signature_unverified", f"the {role} credential")
    client = claims.get("client_id") if role != "sponsor" else claims.get("azp", claims.get("client_id"))
    if not isinstance(claims.get("sub"), str) or not claims["sub"] or not isinstance(client, str) or not client:
        raise _refuse("token_malformed", f"the {role} credential's sub and client are non-empty strings")
    iat, exp = _seconds(claims, "iat"), _seconds(claims, "exp")
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if bundle.audience not in audiences:
        raise _refuse("token_wrong_audience", f"the {role} credential is not for {bundle.audience}")
    if exp <= iat:
        raise _refuse("token_malformed", "exp is not after iat")
    if when < iat:
        raise _refuse("principal_not_yet_valid", f"the {role} credential's iat")
    if "nbf" in claims and _seconds(claims, "nbf") > when:
        raise _refuse("token_not_yet_valid", f"the {role} credential's nbf")
    if when >= exp:
        raise _refuse("principal_expired", f"the {role} credential")
    return _Token(role, token, iss, claims["sub"], client, claims)


def _signature(segment: str) -> bytes:
    try:
        return unb64url(segment)
    except (ValueError, binascii.Error) as exc:
        raise _refuse("token_malformed", "the signature is not base64url") from exc


def _actors(act: Any) -> list[Mapping[str, Any]]:
    """The actors of an RFC 8693 ``act`` claim, the current actor first."""
    out: list[Mapping[str, Any]] = []
    while act is not None:
        if not isinstance(act, Mapping) or not isinstance(act.get("sub"), str) or not act["sub"]:
            raise _refuse("principal_act_malformed", "every actor of act is an object with a sub")
        if "iss" in act and (not isinstance(act["iss"], str) or not act["iss"]):
            raise _refuse("principal_act_malformed", "an actor's iss is a non-empty string")
        out.append(act)
        act = act.get("act")
    return out


def _possession(tokens: list[_Token], request: RequestFacts | None,
                at: str) -> DpopProof | CertificateProof | None:  # fmt: skip
    """The proof that the presenter holds the key every key-bound token names; None when no token is key-bound."""
    bound = [t for t in tokens if "cnf" in t.claims]
    if not bound:
        return None
    cnf = bound[0].claims["cnf"]
    if any(t.claims["cnf"] != cnf for t in bound) or not isinstance(cnf, Mapping):
        raise _refuse("possession_not_the_grant_key", "the presented tokens are bound to different keys")
    facts = request or RequestFacts(method="", url="")
    # the DPoP proof's ath binds one token: the agent's when it is key-bound, else the user's, else the sponsor's
    presented = min(bound, key=lambda t: ("agent", "user", "sponsor").index(t.role))
    proof, reason = check_possession(cnf, method=facts.method, url=facts.url, at=at, access_token=presented.raw,
                                     dpop=facts.dpop, client_certificate=facts.client_certificate,
                                     content=facts.content or b"")  # fmt: skip
    if proof is None:
        raise _refuse(reason, "the key-bound credential is not proven held for this request")
    return proof


def _identity_from_tokens(found: Mapping[str, _Token], bundle: TrustBundle) -> CanonicalIdentity:
    env = bundle.environment
    user, agent, sponsor = found.get("user"), found.get("agent"), found.get("sponsor")
    if sponsor is not None and agent is None:
        raise _refuse("principals_need_agent", "a sponsor answers for an agent")
    if user is None:
        assert agent is not None  # a request with no credential was refused before this
        return CanonicalIdentity(kind="agent", chain=(Ref("agent", env, agent.issuer, agent.subject),),
                                 sponsor=None if sponsor is None else Ref("sponsor", env, sponsor.issuer,
                                                                          sponsor.subject))  # fmt: skip
    user_ref = Ref("user", env, user.issuer, user.subject)
    actors = _actors(user.claims["act"]) if "act" in user.claims else []
    if agent is None:
        if actors:
            raise _refuse("principal_credential_missing", "the user's credential names an agent that presented none")
        return CanonicalIdentity(kind="unknown", user=user_ref)
    if actors and actors[0]["sub"] not in (agent.subject, agent.client):
        raise _refuse("principal_act_names_another_agent", "the user's act claim names another agent")
    if user.client != agent.client:
        raise _refuse("principal_user_token_not_issued_to_agent", "the user's credential was issued to another client")
    parents = [Ref("agent", env, str(a.get("iss", user.issuer)), a["sub"]) for a in actors[1:]]
    try:
        act = act_chain_digest(user.claims["act"]) if "act" in user.claims else None
    except IdentityDigestError as exc:
        raise _refuse(exc.code, str(exc)) from exc
    return CanonicalIdentity(kind="agent", user=user_ref,
                             chain=(*reversed(parents), Ref("agent", env, agent.issuer, agent.subject)),
                             sponsor=None if sponsor is None else Ref("sponsor", env, sponsor.issuer, sponsor.subject),
                             act=act)  # fmt: skip


def _stamp(token: Any, bundle: TrustBundle, request: RequestFacts | None, at: str) -> VerifiedStamp:
    try:
        issuer = stamp_issuer(token)
        if not isinstance(issuer, str) or issuer not in bundle.issuers:
            raise _refuse("stamp_wrong_issuer", repr(issuer)[:80])
        key = bundle.key(issuer, "stamp", stamp_header(token)["kid"])
        content = None if request is None else request.content
        return verify_stamp_token(token, public_raw=_raw(key.jwk), issuer=issuer, audience=bundle.audience,
                                  request_sha256=None if content is None else sha256_hex(content),
                                  now=from_datetime(ts(at)))  # fmt: skip
    except StampRefused as exc:
        raise _refuse(exc.code, str(exc)) from exc


def _environment(identity: CanonicalIdentity, bundle: TrustBundle) -> None:
    refs = [identity.user, *identity.chain, identity.sponsor, identity.approver, identity.service]
    if any(ref is not None and ref.environment != bundle.environment for ref in refs):
        raise _refuse("identity_environment_mismatch", f"an identity outside environment {bundle.environment}")


def verify_request(tokens: Mapping[str, str], bundle: TrustBundle | Mapping[str, Any], at: str,
                   transport: CanonicalIdentity | None = None, *,
                   request: RequestFacts | None = None) -> VerifiedRequest:  # fmt: skip
    """The identities of one request and the single-use values it presented; VerifiedIdentitiesRefused otherwise.

    ``tokens`` maps a role (``user``, ``agent``, ``sponsor``) or ``stamp`` to the compact JWS presented for it.
    ``at`` is the verifier's time (ISO 8601). ``transport`` is the identity a terminating TLS layer verified for the
    peer under a trust root it pins; it is never read from the request."""
    trust = bundle if isinstance(bundle, TrustBundle) else TrustBundle.parse(bundle)
    if transport is not None and (not isinstance(transport, CanonicalIdentity) or transport.kind != "transport"):
        raise TypeError("transport is a CanonicalIdentity of kind transport")
    if not isinstance(tokens, Mapping) or not tokens:
        raise _refuse("principal_credential_missing", "the request presents no credential")
    unknown = sorted(str(role) for role in tokens if role not in (*TOKEN_ROLES, "stamp"))
    if unknown:
        raise _refuse("principal_role_not_configured", ", ".join(unknown)[:80])
    try:
        when = ts(at).timestamp()
    except (TypeError, ValueError) as exc:
        raise TypeError("at is an ISO 8601 time") from exc
    stamp: VerifiedStamp | None = None
    proof: DpopProof | CertificateProof | None = None
    if "stamp" in tokens:
        if len(tokens) != 1:
            raise _refuse("identity_sources_mixed", "a stamp is presented alone, never beside the tokens it replaces")
        stamp = _stamp(tokens["stamp"], trust, request, at)
        identity = stamp.stamp.canonical_identity()
    else:
        found = {role: _token(role, tokens[role], trust, when) for role in TOKEN_ROLES if role in tokens}
        identity = _identity_from_tokens(found, trust)
        proof = _possession([found[r] for r in TOKEN_ROLES if r in found], request, at)
    _environment(identity, trust)
    try:
        identity.check(trust.profile)
    except IdentityStringError as exc:
        raise _refuse(exc.code, str(exc)) from exc
    identities = [identity]
    if transport is not None:
        _environment(transport, trust)
        identities.append(transport)
    return VerifiedRequest(tuple(identities), proof, stamp)


def verified_identities(tokens: Mapping[str, str], bundle: TrustBundle | Mapping[str, Any], at: str,
                        transport: CanonicalIdentity | None = None, *,
                        request: RequestFacts | None = None) -> list[CanonicalIdentity]:  # fmt: skip
    """The canonical identities of one request: the request identity, then the transport identity when given."""
    return list(verify_request(tokens, bundle, at, transport, request=request).identities)
