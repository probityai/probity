"""One definition of every identity digest: what a record, a permit, a stamp or a canonical identity string cites when it
names who acted for whom.

Every digest is ``sha256:`` followed by 64 lowercase hex digits: SHA-256 over the RFC 8785 (JCS) bytes ``core.canonical``
gives, after one admission check, the identity domain. Version 1 defines four digests:

- ``principals_digest(block)``: the verified principals block of one request (``user``, ``agent``, ``sponsor``,
  ``approver``, each the principal member ``identity`` checks; ``approver`` may be a list of at least two), as
  recorded, except that an approver list is a set: its members are hashed sorted by their RFC 8785 bytes, so one set
  of approvers has one digest whatever order the writer listed them in.
- ``act_chain_digest(act)``: the RFC 8693 ``act`` claim of the user's credential, as its identity provider signed it.
- ``grant_chain_digest(links)``: the capability grant chain a request runs under, root first. It is the digest of the
  list of the links' grant digests (``grants.grant_digest`` of each body), so whoever holds the grant digests (a
  revocation list, the ``chain`` of ``verify_grant_allow``) computes it without the bodies (``grant_chain_digest_of``).
- ``stamp_digest(principals, act, grants)``: what crosses one hop, the digest of ``{"act", "grants", "principals"}``
  where an absent act claim or grant chain is null. ``stamp_digest_of`` derives all three from a block and its links.

The identity domain is null, booleans, strings of Unicode scalar values, integers within +-(2**53 - 1), arrays, and
objects whose member names are printable ASCII, nested at most 64 deep. Anything else is refused before it is hashed,
with the one code ``identity_out_of_domain`` and a reason, so a value one implementation would print differently from
another never reaches a digest. Grant bodies are outside this rule: they may hold floats (spend limits, range bounds)
and are named by their grant digests, which are in the domain. ``docs/identity-digests.md`` states the definitions,
the order of the checks and the reasons; ``vectors/shared/identity_digests.json`` holds every implementation to them.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any, Final, NoReturn

from .core import canonical
from .grants import grant_digest
from .identity import APPROVER_LIST_MIN, ROLES

VERSION: Final = 1
PREFIX: Final = "sha256:"
MAX_SAFE_INT: Final = 2**53 - 1
#: Containers deeper than this are refused; an act claim of 32 actors inside a principals block is 35 deep.
MAX_DEPTH: Final = 64
#: The most actors an ``act`` claim may name (the canonical identity string's chain limit).
MAX_ACTORS: Final = 32

OUT_OF_DOMAIN: Final = "identity_out_of_domain"
REASONS: Final = ("unsupported_type", "float", "integer_out_of_range", "member_name_not_ascii", "lone_surrogate",
                  "too_deep", "no_canonical_form")  # fmt: skip
CODES: Final = (OUT_OF_DOMAIN, "identity_principals_malformed", "identity_act_missing", "identity_act_malformed",
                "identity_grant_chain_empty", "identity_grant_chain_malformed", "identity_digest_malformed")  # fmt: skip
_HEX: Final = frozenset("0123456789abcdef")


class IdentityDigestError(ValueError):
    """A value with no identity digest. ``code`` is one of ``CODES``; ``reason`` (one of ``REASONS``) says why a value
    is outside the identity domain and is None for every other code."""

    def __init__(self, code: str, reason: str | None = None, detail: str = "") -> None:
        super().__init__(":".join(part for part in (code, reason or "", detail) if part))
        self.code = code
        self.reason = reason


def _out(reason: str) -> NoReturn:
    raise IdentityDigestError(OUT_OF_DOMAIN, reason)


def _printable_ascii(name: str) -> bool:
    return all(" " <= ch <= "~" for ch in name)


def admit(value: Any) -> Any:
    """``value`` as plain JSON (dicts and lists) when it lies in the identity domain; ``identity_out_of_domain`` otherwise.

    The walk is fixed so every implementation reports the same reason: a container's depth first, then at an object
    every member name, then its values in sorted member order; an array's items in order."""
    return _admit(value, 0)


def _admit(value: Any, depth: int) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            _out("lone_surrogate")
        return str(value)
    if isinstance(value, int):
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            _out("integer_out_of_range")
        return int(value)
    if isinstance(value, float):
        _out("float")
    if isinstance(value, Mapping):
        if depth >= MAX_DEPTH:
            _out("too_deep")
        for name in value:
            if not isinstance(name, str):
                _out("unsupported_type")
            if not _printable_ascii(name):
                _out("member_name_not_ascii")
        return {name: _admit(value[name], depth + 1) for name in sorted(value)}
    if isinstance(value, (list, tuple)):
        if depth >= MAX_DEPTH:
            _out("too_deep")
        return [_admit(item, depth + 1) for item in value]
    _out("unsupported_type")


def _digest(admitted: Any) -> str:
    try:
        data = canonical(admitted)
    except ValueError as exc:
        raise IdentityDigestError(OUT_OF_DOMAIN, "no_canonical_form", str(exc)) from exc
    return PREFIX + hashlib.sha256(data).hexdigest()


def _hex64(text: Any) -> bool:
    return isinstance(text, str) and len(text) == 64 and set(text) <= _HEX


def is_digest(text: Any) -> bool:
    """Whether ``text`` has the form of an identity digest: ``sha256:`` and 64 lowercase hex digits."""
    return isinstance(text, str) and text.startswith(PREFIX) and _hex64(text[len(PREFIX):])


def _principals(block: Any) -> dict[str, Any]:
    doc = admit(block)
    if not isinstance(doc, dict) or not doc:
        raise IdentityDigestError("identity_principals_malformed", detail="a principals block is a non-empty object")
    for role, member in doc.items():
        if role not in ROLES:
            raise IdentityDigestError("identity_principals_malformed", detail=f"{role!r} is not a role")
        if role == "approver" and isinstance(member, list):
            if len(member) < APPROVER_LIST_MIN or not all(isinstance(m, dict) for m in member):
                raise IdentityDigestError("identity_principals_malformed",
                                          detail="an approver list is at least two principal objects")
            # A set, not a sequence: the verdict never depends on the order, so neither does the digest.
            doc[role] = sorted(member, key=canonical)
        elif not isinstance(member, dict):
            raise IdentityDigestError("identity_principals_malformed", detail=f"the {role} principal is not an object")
    return doc


def principals_digest(block: Mapping[str, Any]) -> str:
    """The digest of a principals block: its members among ``user``, ``agent``, ``sponsor`` and ``approver`` (one
    principal, or a list of at least two, hashed as a set: sorted by each member's RFC 8785 bytes)."""
    return _digest(_principals(block))


def act_chain_digest(act: Mapping[str, Any] | None) -> str:
    """The digest of an RFC 8693 ``act`` claim: an object naming the current actor in ``sub``, its ``act`` the prior
    actor, at most ``MAX_ACTORS`` deep. A missing claim (None) is refused: it has no digest, and a stamp says null."""
    if act is None:
        raise IdentityDigestError("identity_act_missing", detail="the credential carries no act claim")
    doc = admit(act)
    level, actors = doc, 0
    while True:
        if not isinstance(level, dict) or not isinstance(level.get("sub"), str) or not level["sub"]:
            raise IdentityDigestError("identity_act_malformed", detail="every actor is an object with a non-empty sub")
        actors += 1
        if actors > MAX_ACTORS:
            raise IdentityDigestError("identity_act_malformed", detail=f"more than {MAX_ACTORS} actors")
        if "act" not in level:
            return _digest(doc)
        level = level["act"]


def grant_chain_digest_of(grant_digests: Sequence[str]) -> str:
    """The digest of a capability grant chain from its links' grant digests (64 lowercase hex each), root first."""
    doc = admit(grant_digests)
    if not isinstance(doc, list):
        raise IdentityDigestError("identity_grant_chain_malformed", detail="a grant chain is an array")
    if not doc:
        raise IdentityDigestError("identity_grant_chain_empty", detail="a grant chain has a root")
    if not all(_hex64(item) for item in doc):
        raise IdentityDigestError("identity_grant_chain_malformed", detail="a grant digest is 64 lowercase hex digits")
    return _digest(doc)


def grant_chain_digest(links: Sequence[Mapping[str, Any]]) -> str:
    """The digest of a capability grant chain, root first: ``grant_chain_digest_of`` the grant digest of each body."""
    if not isinstance(links, (list, tuple)):
        raise IdentityDigestError("identity_grant_chain_malformed", detail="a grant chain is an array")
    if not links:
        raise IdentityDigestError("identity_grant_chain_empty", detail="a grant chain has a root")
    digests = []
    for link in links:
        body = link.get("body") if isinstance(link, Mapping) else None
        if not isinstance(body, Mapping):
            raise IdentityDigestError("identity_grant_chain_malformed", detail="every link is an object with a body")
        try:
            digests.append(grant_digest(body))
        except ValueError as exc:
            raise IdentityDigestError("identity_grant_chain_malformed", detail=f"a body has no grant digest: {exc}") from exc
    return grant_chain_digest_of(digests)


def stamp_digest(principals: str, act: str | None, grants: str | None) -> str:
    """The digest of what crosses one hop: the principals digest, the act chain digest (None when the credential
    carries no act claim) and the grant chain digest (None when the request runs under no grants)."""
    for name, value, optional in (("principals", principals, False), ("act", act, True), ("grants", grants, True)):
        if not (is_digest(value) or (optional and value is None)):
            raise IdentityDigestError("identity_digest_malformed", detail=f"{name} is not a sha256: digest")
    return _digest({"act": act, "grants": grants, "principals": principals})


def stamp_digest_of(block: Mapping[str, Any], links: Sequence[Mapping[str, Any]] | None = None) -> str:
    """``stamp_digest`` of a principals block and the grant links the request runs under (None for none). The act
    chain is the user principal's ``act`` member; a present but null member is refused as missing."""
    doc = _principals(block)
    user = doc.get("user", {})
    act = act_chain_digest(user["act"]) if "act" in user else None
    grants = None if links is None else grant_chain_digest(links)
    return stamp_digest(_digest(doc), act, grants)


FUNCTIONS: Final = {
    "principals_digest": principals_digest,
    "act_chain_digest": act_chain_digest,
    "grant_chain_digest": grant_chain_digest,
    "grant_chain_digest_of": grant_chain_digest_of,
    "stamp_digest": stamp_digest,
    "stamp_digest_of": stamp_digest_of,
}


def judge(function: str, args: Sequence[Any]) -> dict[str, Any]:
    """What a conforming implementation reports for ``function`` called with ``args``: ``{"digest"}`` or
    ``{"refused", "reason"}``. The shared vectors hold every implementation to this."""
    try:
        return {"digest": FUNCTIONS[function](*args)}
    except IdentityDigestError as exc:
        return {"refused": exc.code, "reason": exc.reason}


__all__ = ["CODES", "FUNCTIONS", "MAX_ACTORS", "MAX_DEPTH", "MAX_SAFE_INT", "OUT_OF_DOMAIN", "PREFIX", "REASONS",
           "VERSION", "IdentityDigestError", "act_chain_digest", "admit", "grant_chain_digest", "grant_chain_digest_of",
           "is_digest", "judge", "principals_digest", "stamp_digest", "stamp_digest_of"]  # fmt: skip
