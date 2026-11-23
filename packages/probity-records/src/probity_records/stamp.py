"""The agent stamp: the token a service behind a gateway reads to learn who acts for whom on one request.

A gateway that verified a request's principals forwards it upstream with one stamp (``Probity-Agent-Stamp``, a compact
JWS, EdDSA, ``typ`` ``probity-agent-stamp+jwt``) instead of the inbound credentials, which it never forwards. The
stamp names the user, the agent, the identity digests that join them (``digests``: the principals block, the user
credential's RFC 8693 ``act`` claim and the capability grant chain) and the canonical identity string of the request
(``canonical_identity``), and it is bound to one upstream audience, to the SHA-256 of the exact bytes forwarded, to a
lifetime of at most ``MAX_TTL_SECONDS`` and to a ``jti``.

``verify_stamp_token`` is every check of one stamp that needs no memory of earlier stamps. The verifying key is the
one the service pins for the stamp issuer; the token's ``kid`` is compared with it and never used to find one. The
stamp is single-use: a service that keeps state spends ``(jti, exp)`` in its own store after this check passes, and
one that keeps none relies on the request binding.

Refusal codes, in the order the checks run: ``stamp_malformed``, ``stamp_header_invalid``, ``stamp_key_mismatch``,
``stamp_forged``, ``stamp_malformed`` (claims), ``stamp_wrong_issuer``, ``stamp_wrong_audience``,
``stamp_request_mismatch``, ``stamp_lifetime_too_long``, ``stamp_not_yet_valid``, ``stamp_expired``, then the
stamp claim itself (``stamp_malformed``, ``stamp_downgraded``, ``stamp_identity_mismatch``). The format and its
reasons are in ``docs/verified-identities.md``.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical_identity import CanonicalIdentity, IdentityStringError
from .clock import NS_PER_S
from .core import sha256_hex
from .digests import is_digest, stamp_digest

#: The request header the stamp travels in (lower case: header names compare case-insensitively).
STAMP_HEADER: Final = "probity-agent-stamp"
STAMP_TYP: Final = "probity-agent-stamp+jwt"
#: The longest lifetime a stamp may carry; a stamp names one request, so it is never a standing credential.
MAX_TTL_SECONDS: Final = 300
HEADER_MEMBERS: Final = frozenset({"alg", "typ", "kid"})
CLAIM_MEMBERS: Final = frozenset({"iss", "aud", "iat", "exp", "jti", "request_sha256", "stamp"})
STAMP_MEMBERS: Final = frozenset({"user", "agent", "principals", "act", "grants", "identity"})
MAX_JTI_BYTES: Final = 128


class StampRefused(ValueError):
    """A stamp a verifier will not accept; ``code`` is the registered reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise StampRefused("stamp_malformed", "a stamp field is not a non-empty string")
    return value


@dataclass(frozen=True)
class Stamp:
    """Who acts for whom on one request.

    ``principals`` is the digest of the verified principals block, ``act`` the digest of the user credential's act
    claim (None when it carries none), ``grants`` the digest of the capability grant chain (None when the request runs
    under no grants) and ``identity`` the canonical identity string of the request, which names the same user, agent,
    act claim and grant chain."""

    user_issuer: str
    user_subject: str
    agent_issuer: str
    agent_subject: str
    agent_client: str
    principals: str
    act: str | None
    grants: str | None
    identity: str

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

    def claims(self) -> dict[str, Any]:
        """The ``stamp`` claim of a stamp token."""
        return {"user": {"iss": self.user_issuer, "sub": self.user_subject},
                "agent": {"iss": self.agent_issuer, "sub": self.agent_subject, "client_id": self.agent_client},
                "principals": self.principals, "act": self.act, "grants": self.grants,
                "identity": self.identity}  # fmt: skip

    def canonical_identity(self) -> CanonicalIdentity:
        """The identity the stamp names, refused unless it names this stamp's user, agent, act claim and grants."""
        try:
            found = CanonicalIdentity.parse(self.identity)
        except IdentityStringError as exc:
            raise StampRefused("stamp_identity_mismatch", f"{exc.code}: the identity is not a canonical string") from exc
        agent, user = found.agent, found.user
        if (found.kind != "agent" or agent is None or user is None
                or (user.domain, user.subject) != self.user or (agent.domain, agent.subject) != self.agent[:2]
                or found.act != self.act or found.grants != self.grants):  # fmt: skip
            raise StampRefused("stamp_identity_mismatch", "the identity names another user, agent, act or grants")
        return found

    @classmethod
    def from_claims(cls, doc: Any) -> Stamp:
        """The stamp a ``stamp`` claim states; StampRefused unless it is exactly the format and names an agent."""
        if not isinstance(doc, Mapping) or set(doc) != STAMP_MEMBERS:
            raise StampRefused("stamp_malformed", "the stamp claim has other members")
        user, agent = doc["user"], doc["agent"]
        if not isinstance(user, Mapping) or set(user) != {"iss", "sub"}:
            raise StampRefused("stamp_malformed", "the stamp's user has other members")
        if not isinstance(agent, Mapping) or set(agent) != {"iss", "sub", "client_id"}:
            raise StampRefused("stamp_malformed", "the stamp's agent has other members")
        principals = _text(doc["principals"])
        if not is_digest(principals):
            raise StampRefused("stamp_malformed", "principals is not a sha256: identity digest")
        for name in ("act", "grants"):
            if doc[name] is not None and not is_digest(doc[name]):
                raise StampRefused("stamp_malformed", f"{name} is neither null nor a sha256: identity digest")
        stamp = cls(_text(user["iss"]), _text(user["sub"]), _text(agent["iss"]), _text(agent["sub"]),
                    _text(agent["client_id"]), principals, doc["act"], doc["grants"], _text(doc["identity"]))  # fmt: skip
        if stamp.alone:
            raise StampRefused("stamp_downgraded", "the stamp names the user acting alone")
        stamp.canonical_identity()
        return stamp


@dataclass(frozen=True)
class VerifiedStamp:
    """A stamp token that passed every stateless check: the stamp, and the ``jti`` and ``exp`` a store spends."""

    stamp: Stamp
    jti: str
    exp: int


def stamp_key_id(public_raw: bytes) -> str:
    """The key id a stamp names: the lowercase hex SHA-256 of the raw Ed25519 public key."""
    return sha256_hex(public_raw)


def _strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate member {key!r}")
            out[key] = value
        return out

    def constant(name: str) -> Any:
        raise ValueError(f"non-finite number {name}")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _segment(text: str) -> Any:
    try:
        return _strict_json(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    except (ValueError, binascii.Error) as exc:
        raise StampRefused("stamp_malformed", f"a segment is not base64url JSON: {exc}") from exc


def _seconds(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise StampRefused("stamp_malformed", f"{name} is not an integer")
    return value


def stamp_header(token: str) -> dict[str, Any]:
    """The protected header of a stamp token, unverified: what a verifier reads to pick among the keys it pins."""
    parts = token.split(".") if isinstance(token, str) and token.isascii() else []
    if len(parts) != 3 or not all(parts):
        raise StampRefused("stamp_malformed", "a stamp is a compact JWS of three segments")
    header = _segment(parts[0])
    if not isinstance(header, dict) or set(header) != HEADER_MEMBERS:
        raise StampRefused("stamp_header_invalid", "the header carries exactly alg, typ and kid")
    if header["alg"] != "EdDSA" or header["typ"] != STAMP_TYP:
        raise StampRefused("stamp_header_invalid", f"alg {header['alg']!r} typ {header['typ']!r}")
    return header


def stamp_issuer(token: str) -> Any:
    """The ``iss`` a stamp token states, unverified: what a verifier reads to pick the issuer whose keys it pins."""
    stamp_header(token)
    claims = _segment(token.split(".")[1])
    return claims.get("iss") if isinstance(claims, dict) else None


def verify_stamp_token(token: str, *, public_raw: bytes, issuer: str, audience: str, request_sha256: str | None,
                       now: int) -> VerifiedStamp:  # fmt: skip
    """The stamp a token carries, checked under the pinned key ``public_raw``; StampRefused otherwise.

    ``request_sha256`` is the lowercase hex SHA-256 of the request bytes the verifier received (None for a request
    with no body); ``now`` is the verifier's time in nanoseconds since the epoch."""
    header = stamp_header(token)
    head, body, sig = token.split(".")
    if header["kid"] != stamp_key_id(public_raw):
        raise StampRefused("stamp_key_mismatch", "the stamp names a key other than the pinned one")
    try:
        signature = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, f"{head}.{body}".encode("ascii"))
    except (InvalidSignature, ValueError, binascii.Error) as exc:
        raise StampRefused("stamp_forged", "the signature does not verify under the pinned key") from exc
    claims = _segment(body)
    if not isinstance(claims, dict) or set(claims) != CLAIM_MEMBERS:
        raise StampRefused("stamp_malformed", "the claims carry exactly " + ", ".join(sorted(CLAIM_MEMBERS)))
    if claims["iss"] != issuer:
        raise StampRefused("stamp_wrong_issuer", repr(claims["iss"])[:80])
    if claims["aud"] != audience:
        raise StampRefused("stamp_wrong_audience", f"the stamp is for {claims['aud']!r}, not {audience!r}")
    if claims["request_sha256"] != request_sha256:
        raise StampRefused("stamp_request_mismatch", "the stamp is bound to other request bytes")
    iat, exp = _seconds(claims, "iat"), _seconds(claims, "exp")
    moment = now / NS_PER_S
    if exp <= iat:
        raise StampRefused("stamp_malformed", "exp is not after iat")
    if exp - iat > MAX_TTL_SECONDS:
        raise StampRefused("stamp_lifetime_too_long", f"{exp - iat} s")
    if iat > moment:
        raise StampRefused("stamp_not_yet_valid", "iat is in the future")
    if moment >= exp:
        raise StampRefused("stamp_expired", "exp has passed")
    jti = claims["jti"]
    if not isinstance(jti, str) or not jti or len(jti.encode("utf-8")) > MAX_JTI_BYTES:
        raise StampRefused("stamp_malformed", "jti is not a string of at most 128 bytes")
    return VerifiedStamp(Stamp.from_claims(claims["stamp"]), jti, exp)
