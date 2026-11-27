"""Signing anchors in the trust bundle, and the reader that verifies a statement under one.

A trust bundle (``verified_identities.TrustBundle``, version 2) pins two kinds of key: the issuers of request
credentials (``issuers``) and the anchors that sign evidence (``anchors``). This module owns the second. An anchor is
a public Ed25519 key with a role, a status (``active``, ``retired``, ``revoked``), a window in which its signatures
may have been made (``notBefore``, ``notAfter``) and the in-toto predicate types it may sign. The format and the
reasons are in ``docs/trust-bundle.md``; the decision that made the anchor manifest and the bundle one document is
``docs/one-name.md``.

The time a statement was signed is never read from the statement: the signer chose it. ``verify_anchored`` trusts
only an upper bound a witness quorum gives, the latest cosignature time on a c2sp.org tlog checkpoint whose tree holds
the statement (``WitnessedTime``, an RFC 9162 inclusion proof). An anchor that is retired, whose window has an end,
or whose key the signed revocation list names, verifies a statement only with such a bound inside its window and
before the revocation.
"""

from __future__ import annotations

import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import witness as w
from .core import JsonRefused, admitted_loads, key_id, open_envelope
from .grants import ts
from .identity import has_private_member, jwk_thumbprint, public_jwk
from .revocation import RevocationState

ANCHOR_MEMBERS: Final = frozenset({"jwk", "thumbprint", "role", "status", "notBefore", "notAfter", "predicateTypes"})
ANCHOR_STATUSES: Final = ("active", "retired", "revoked")


class AnchorRefused(ValueError):
    """A statement no pinned anchor may have signed, or an anchor list that is not the format; ``code`` is the
    registered reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def _malformed(detail: str) -> AnchorRefused:
    return AnchorRefused("trust_bundle_malformed", detail)


@dataclass(frozen=True)
class Anchor:
    """One pinned signing key. ``key_id`` (SHA-256 of the raw key) and ``thumbprint`` (RFC 7638) are both computed
    from ``jwk``: the first is the name DSSE signatures and revocation lists use, the second the bundle's own."""

    jwk: Mapping[str, Any]
    thumbprint: str
    key_id: str
    public: Ed25519PublicKey
    role: str
    status: str
    not_before: str
    not_after: str | None
    predicate_types: frozenset[str]


def _time(value: Any, what: str) -> str:
    try:
        ts(value)
    except ValueError as exc:
        raise _malformed(f"anchor {what} is an RFC 3339 time with an offset") from exc
    return str(value)


def _public(jwk: Any) -> Ed25519PublicKey:
    if not isinstance(jwk, Mapping) or has_private_member(jwk):
        raise _malformed("an anchor key is a public JWK")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str):
        raise _malformed("an anchor key is an Ed25519 OKP key")
    try:
        return Ed25519PublicKey.from_public_bytes(public_jwk(jwk)["x"])  # canonical, 32 bytes, nothing private
    except (ValueError, binascii.Error) as exc:
        raise _malformed("an anchor key's x is 32 base64url bytes") from exc


def _predicate_types(value: Any) -> frozenset[str]:
    if (not isinstance(value, list) or not value or len(set(map(str, value))) != len(value)
            or not all(isinstance(t, str) and t.startswith("https://") and t.isascii() and " " not in t
                       for t in value)):  # fmt: skip
        raise _malformed("predicateTypes is a non-empty list of distinct https URIs")
    return frozenset(value)


def parse_anchor(entry: Any) -> Anchor:
    """One anchor of a bundle; ``trust_bundle_malformed`` unless it is exactly the format."""
    if not isinstance(entry, Mapping) or set(entry) != ANCHOR_MEMBERS:
        raise _malformed("an anchor has exactly " + ", ".join(sorted(ANCHOR_MEMBERS)))
    public = _public(entry["jwk"])
    thumbprint = jwk_thumbprint(entry["jwk"])
    if entry["thumbprint"] != thumbprint:
        raise _malformed("an anchor's thumbprint is the RFC 7638 thumbprint of its key")
    if not isinstance(entry["role"], str) or not entry["role"] or not entry["role"].isascii():
        raise _malformed("an anchor's role is a non-empty ASCII name")
    status = entry["status"]
    if status not in ANCHOR_STATUSES:
        raise _malformed("an anchor's status is active, retired or revoked")
    not_before = _time(entry["notBefore"], "notBefore")
    not_after = None if entry["notAfter"] is None else _time(entry["notAfter"], "notAfter")
    if not_after is None and status != "active":
        raise _malformed("a retired or revoked anchor names the end of its window (notAfter)")
    if not_after is not None and not ts(not_before) < ts(not_after):
        raise _malformed("an anchor's notAfter is after its notBefore")
    return Anchor(dict(entry["jwk"]), thumbprint, key_id(public), public, entry["role"], status, not_before,
                  not_after, _predicate_types(entry["predicateTypes"]))


def parse_anchors(entries: Any) -> tuple[Anchor, ...]:
    """The bundle's ``anchors`` member: a list of anchors, each key listed once."""
    if not isinstance(entries, list):
        raise _malformed("anchors is a list")
    anchors = tuple(parse_anchor(e) for e in entries)
    if len({a.key_id for a in anchors}) != len(anchors):
        raise _malformed("an anchor key is listed twice")
    return anchors


# --- RFC 9162 inclusion -------------------------------------------------------------------------------------------


# RFC 9162 inclusion is ``witness.inclusion_proof`` and ``witness.verify_inclusion``, the package's one implementation,
# which refuses an index or size that is not an int (a float or a bool in a received document is not a position).


# --- the signing time a witness quorum gives ----------------------------------------------------------------------


@dataclass(frozen=True)
class WitnessedTime:
    """A cosigned checkpoint (``note``), the c2sp.org/tlog-policy the verifier pins for it, and the inclusion proof
    of the statement's envelope at ``index``. The leaf is the envelope as one journal line: its JSON with sorted keys
    and no spaces."""

    note: str
    policy: w.Policy
    index: int
    proof: tuple[bytes, ...]


def envelope_leaf(envelope: Mapping[str, Any]) -> bytes:
    """The bytes a log holds for an envelope: the journal's line form."""
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def witnessed_bound(envelope: Mapping[str, Any], witnessed: WitnessedTime) -> int | None:
    """The latest cosignature time, in seconds, of the counted witnesses on a checkpoint that holds ``envelope``;
    None when the note, the quorum or the inclusion proof does not hold, or the policy requires no witness."""
    if witnessed.policy.quorum in ("", "none"):
        return None
    try:
        checked = w.verify_note(witnessed.note, witnessed.policy)
    except w.NoteError:
        return None
    cp = checked.checkpoint
    leaf = w.leaf_hash(envelope_leaf(envelope))
    if not checked.cosigned_at or not w.verify_inclusion(witnessed.index, cp.size, leaf, witnessed.proof, cp.root):
        return None
    return max(checked.cosigned_at.values())


def _rfc3339(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- verifying a statement ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AnchoredStatement:
    """A statement a pinned anchor signed. ``signed_no_later_than`` is the witnessed bound when one was given and
    held, None otherwise."""

    statement: Mapping[str, Any]
    anchor: Anchor
    signed_no_later_than: str | None


def verify_anchored(envelope: Any, bundle: Any, *, revocations: RevocationState | None = None,
                    witnessed: WitnessedTime | None = None) -> AnchoredStatement:
    """The statement of a DSSE ``envelope`` when an anchor of ``bundle`` signed it for its predicate type, within
    the anchor's window and before any revocation of its key; ``AnchorRefused`` otherwise.

    The key is found by trying every listed anchor key, never by the envelope's unsigned ``keyid``."""
    anchors: tuple[Anchor, ...] = bundle.anchors
    try:
        payload, signer = open_envelope(envelope, [a.public for a in anchors])
    except ValueError as exc:
        raise AnchorRefused("anchor_unknown", "no anchor of the bundle signed the envelope") from exc
    anchor = next(a for a in anchors if a.key_id == signer)
    if anchor.status == "revoked":
        raise AnchorRefused("key_revoked", f"anchor {anchor.thumbprint} is revoked in the bundle")
    try:
        statement = admitted_loads(payload)
    except JsonRefused as exc:
        raise AnchorRefused("anchor_statement_malformed", f"the signed payload is not admissible JSON: {exc.variant}") \
            from exc
    if not isinstance(statement, Mapping) or statement.get("predicateType") not in anchor.predicate_types:
        raise AnchorRefused("anchor_predicate_not_authorized", f"anchor {anchor.role} may not sign this type")
    revoked_at = None
    if revocations is not None and revocations.revoked("key", anchor.key_id):
        revoked_at = str(revocations.entries[("key", anchor.key_id)]["revokedAt"])
    bound = None if witnessed is None else witnessed_bound(envelope, witnessed)
    if bound is None:
        if anchor.status == "retired" or anchor.not_after is not None or revoked_at is not None:
            raise AnchorRefused("anchor_signing_time_unbound",
                                "no witnessed tree head bounds when this anchor signed the statement")
        return AnchoredStatement(statement, anchor, None)
    at = datetime.fromtimestamp(bound, UTC)
    if at < ts(anchor.not_before) or (anchor.not_after is not None and at > ts(anchor.not_after)):
        raise AnchorRefused("anchor_signed_outside_window", f"witnessed at {_rfc3339(bound)}")
    if revoked_at is not None and ts(revoked_at) <= at:
        raise AnchorRefused("key_revoked", f"revoked at {revoked_at}, witnessed at {_rfc3339(bound)}")
    return AnchoredStatement(statement, anchor, _rfc3339(bound))
