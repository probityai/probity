"""The one signed revocation list: keys, identity provider keys, permits, grants, agents, streams, sponsors, builds.

A revocation root signs a chain of lists. ``seq`` rises by one (it is the list's epoch), ``previous`` is the digest
of the prior body, and each list is a delta: its ``entries`` are only the subjects that list newly revokes, and the
revocations in force after list n are the union of lists 1 to n. An entry is published once and never again: a list
naming a subject an earlier list of its chain revoked is refused (``revocation_entry_repeated``), so an entry's
``revokedAt`` never moves, and since no list can drop what an earlier one holds, nobody can quietly un-revoke. An
empty ``entries`` is a freshness list (a new seq and issue time, nothing newly revoked). Signing a list and folding
it into a state both cost what the delta holds, not what the chain has revoked so far. Every reader of revocations reads this format and only this format: the records
audit (``Trust``), the TypeScript twin and the Go reader in agent-evidence-vectors; the shared vectors
(``vectors/shared/revocation.json``) hold them, and any other reader, to the same verdicts. A signed list is::

    {"body": {"type": REVOCATION_LIST, "listId": id, "seq": n, "previous": "sha256:<hex>" | None,
              "issuedAt": "YYYY-MM-DDTHH:MM:SSZ", "issuerKey": b64 raw Ed25519,
              "entries": [{"kind": kind, "id": id, "revokedAt": time, "reason": str (optional),
                           "successor": b64 raw Ed25519 (optional, key kind only)}, ...]},
     "sig": b64 Ed25519 over REVOCATION_DOMAIN || JCS(body)}

The verifier pins root key ids and never reads one from a list: a list is checked under its presented key only
once that key's id is a pinned root. Revoking a root with a ``successor`` rotates it: the roots after a list are
the roots held plus the successors of the roots it revokes (less any successor an earlier list revoked), minus every
key id it revokes (a revoked key is never a root, in whatever order the entries come or in whichever list it was
revoked). Revoking a grant revokes every
grant delegated under it (the chain check refuses any chain containing it); revoking an agent or a sponsor reaches
every piece of work answering to it wherever the enforcement point derives that from a chain it verified.

An identity provider's token-signing key is kind ``idp-key``, named by its RFC 7638 JWK thumbprint (SHA-256,
base64url, no padding: one spelling per key). It is never kind ``key``, whose ids are this format's own 64-hex key ids,
and it carries no ``successor``: an identity provider rotates through its JWKS, not through this list. A token it
signed is refused from the entry's ``revokedAt`` on (``RevocationState.idp_key_revoked``).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any, cast

from cryptography.exceptions import InvalidSignature

from .core import (
    MAX_EXACT_INT,
    Signer,
    _b64,
    canonical,
    key_id,
    load_public,
    sha256_hex,
    unb64,
    verify_approval,
)
from .grants import raw_public, ts
from .identifiers import identifier, same_identifier

REVOCATION_DOMAIN = b"probity-revocation-v1\x00"
REVOCATION_LIST = identifier("agent-evidence-vectors/predicate/v2/revocation-list")
#: Every subject kind a list names. A digest kind's id is 64 lowercase hex, an ``idp-key`` id is an RFC 7638
#: thumbprint, the rest are identifiers.
REVOCATION_KINDS = ("agent", "build", "grant", "idp-key", "key", "permit", "sponsor", "stream")
DIGEST_KINDS = frozenset({"grant", "key", "permit"})
#: Every refusal ``RevocationState.apply`` reports, in the order it checks them.
REFUSAL_CODES = (
    "revocation_list_shape",
    "revocation_list_signer_not_a_root",
    "revocation_list_signature_unverified",
    "revocation_list_other_chain",
    "revocation_list_rollback",
    "revocation_list_gap",
    "revocation_list_previous_mismatch",
    "revocation_list_time_reversed",
    "revocation_entry_from_future",
    "revocation_entry_repeated",
)

_BODY_MEMBERS = frozenset({"type", "listId", "seq", "previous", "issuedAt", "issuerKey", "entries"})
_ENTRY_REQUIRED = frozenset({"kind", "id", "revokedAt"})
_ENTRY_OPTIONAL = frozenset({"reason", "successor"})
_IDENTIFIER = re.compile(r"[\x21-\x7e]{1,512}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: A SHA-256 thumbprint in base64url without padding: 43 digits, the last carrying two zero bits, so each key has one
#: spelling and a lookup by the thumbprint a reader computes cannot miss an entry written another way.
_THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")
_ID_FORMS = {**dict.fromkeys(DIGEST_KINDS, _HEX64), "idp-key": _THUMBPRINT}
_LIST_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class RevocationError(ValueError):
    """A list that is malformed, forged, out of order, or repeats an entry; the message starts with the code."""


def _shape(why: str) -> RevocationError:
    return RevocationError(f"revocation_list_shape:{why}")


def list_digest(body: Mapping[str, Any]) -> str:
    """The digest a list's successor names as ``previous`` and a permit names as the list it was minted under."""
    return "sha256:" + sha256_hex(canonical(dict(body)))


def _time(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise _shape(f"{what}_not_a_utc_second")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise _shape(f"{what}_not_a_calendar_instant") from None
    return value


def _raw_key(value: Any, what: str) -> bytes:
    try:
        raw = unb64(value)
    except ValueError:
        raise _shape(f"{what}_not_base64") from None
    if len(raw) != 32:
        raise _shape(f"{what}_not_an_ed25519_key")
    if _b64(raw) != value:
        raise _shape(f"{what}_not_canonical_base64")
    return raw


def check_subject_id(kind: Any, ident: Any) -> None:
    """Raise ``revocation_list_shape`` unless a list entry can name ``ident`` under ``kind``.

    An enforcement point admits work only under subjects some list could revoke; this is the entry check a list
    reader applies, so the two can never disagree. A digest kind's id is 64 lowercase hex, an ``idp-key`` id is a
    canonical RFC 7638 thumbprint (43 base64url digits), any other kind's is 1 to 512 printable ASCII characters.
    """
    if kind not in REVOCATION_KINDS:
        raise _shape("entry_kind_unknown")
    pattern = _ID_FORMS.get(kind, _IDENTIFIER)
    if not isinstance(ident, str) or not pattern.fullmatch(ident):
        raise _shape(f"entry_id_form:{kind}")


def _check_entry(entry: Any) -> tuple[str, str]:
    if not isinstance(entry, dict):
        raise _shape("entry_not_an_object")
    members = set(entry)
    if not _ENTRY_REQUIRED <= members or not members <= _ENTRY_REQUIRED | _ENTRY_OPTIONAL:
        raise _shape("entry_members")
    kind, ident = entry["kind"], entry["id"]
    check_subject_id(kind, ident)
    _time(entry["revokedAt"], "revokedAt")
    if "reason" in entry and not isinstance(entry["reason"], str):
        raise _shape("entry_reason_not_text")
    if "successor" in entry:
        if kind != "key":
            raise _shape("successor_on_non_key_entry")
        _raw_key(entry["successor"], "successor")
    return kind, ident


def _check_body(body: Any) -> None:
    """Raise ``revocation_list_shape`` unless ``body`` is exactly the format (signature and order not checked)."""
    if not isinstance(body, dict) or set(body) != _BODY_MEMBERS:
        raise _shape("body_members")
    if not same_identifier(body["type"], REVOCATION_LIST):
        raise _shape("type")
    if not isinstance(body["listId"], str) or not _IDENTIFIER.fullmatch(body["listId"]):
        raise _shape("list_id_form")
    seq = body["seq"]
    if type(seq) is not int or not 1 <= seq <= MAX_EXACT_INT:
        raise _shape("seq_not_a_positive_exact_integer")
    previous = body["previous"]
    if (seq == 1) != (previous is None) or (previous is not None and not (
            isinstance(previous, str) and _LIST_DIGEST.fullmatch(previous))):
        raise _shape("previous_form")
    _time(body["issuedAt"], "issuedAt")
    _raw_key(body["issuerKey"], "issuerKey")
    entries = body["entries"]
    if not isinstance(entries, list):
        raise _shape("entries_not_a_list")
    order = [_check_entry(e) for e in entries]
    if any(a >= b for a, b in pairwise(order)):
        raise _shape("entries_not_strictly_ascending")


def sign_revocations(signer: Signer, *, list_id: str, seq: int, issued_at: str,
                     entries: Iterable[Mapping[str, Any]], previous: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Sign list ``seq`` holding ``entries``: only the subjects this list newly revokes (lists are deltas).

    ``previous`` is the prior signed list, ``None`` for seq 1. The body is held to the format before it is signed, so
    an issuer cannot publish a list its own readers refuse for its shape. The cost is that of the delta and of the
    previous body's canonical form, itself a delta, never of the entries the chain revoked before.
    """
    rows = sorted((dict(e) for e in entries), key=lambda e: (str(e.get("kind")), str(e.get("id"))))
    body = {"entries": rows, "issuedAt": issued_at, "issuerKey": raw_public(signer), "listId": list_id,
            "previous": list_digest(previous["body"]) if previous is not None else None, "seq": seq,
            "type": REVOCATION_LIST}
    _check_body(body)
    return {"body": body, "sig": _b64(signer.sign(REVOCATION_DOMAIN + canonical(body)))}


class _ChainStore:
    """The entries of one chain of lists, each key with the seq of the list that added it.

    Only the state at the store's tip extends it, in place and under the lock; every state is a view of the keys added
    at or before its own seq, so a later list's keys are invisible to it. ``order`` holds the keys in the order they
    were added, so the first ``n`` keys are exactly those of the view holding ``n``.
    """

    __slots__ = ("added", "lock", "order", "tip")

    def __init__(self, tip: int) -> None:
        self.lock = threading.Lock()
        self.added: dict[tuple[str, str], tuple[int, Mapping[str, Any]]] = {}
        self.order: list[tuple[str, str]] = []
        self.tip = tip

    def __reduce__(self) -> tuple[Any, ...]:
        """Copy and pickle the keys, never the lock: a copied store is a store of its own."""
        with self.lock:
            return _restore_store, (self.tip, dict(self.added), list(self.order))


def _restore_store(tip: int, added: dict[tuple[str, str], tuple[int, Mapping[str, Any]]],
                   order: list[tuple[str, str]]) -> _ChainStore:
    store = _ChainStore(tip)
    store.added, store.order = added, order
    return store


class _EntriesView(Mapping[tuple[str, str], Mapping[str, Any]]):
    """A read-only view of a chain store as of one seq: lookups are O(1), iteration snapshots the keys under the lock."""

    __slots__ = ("_count", "_seq", "_store")

    def __init__(self, store: _ChainStore, seq: int, count: int) -> None:
        self._store, self._seq, self._count = store, seq, count

    @classmethod
    def of(cls, entries: Mapping[tuple[str, str], Mapping[str, Any]], seq: int) -> _EntriesView:
        """A view of its own store holding ``entries`` as of ``seq`` (a copy: the caller's mapping is never read again)."""
        store = _ChainStore(seq)
        for key, entry in entries.items():
            store.added[key] = (seq, dict(entry))
            store.order.append(key)
        return cls(store, seq, len(store.order))

    def __getitem__(self, key: tuple[str, str]) -> Mapping[str, Any]:
        held = self._store.added.get(key)
        if held is None or held[0] > self._seq:
            raise KeyError(key)
        return held[1]

    def __contains__(self, key: object) -> bool:
        held = self._store.added.get(key) if isinstance(key, tuple) else None
        return held is not None and held[0] <= self._seq

    def __len__(self) -> int:
        return self._count

    def __iter__(self) -> Iterator[tuple[str, str]]:
        with self._store.lock:
            keys = self._store.order[:self._count]
        return iter(keys)

    def __repr__(self) -> str:
        return f"_EntriesView(seq={self._seq}, entries={self._count})"

    def extended(self, seq: int, delta: Mapping[tuple[str, str], Mapping[str, Any]]) -> _EntriesView:
        """The view as of ``seq`` holding this view's keys and ``delta``'s: in place at the tip, else on a copy.

        At the tip the store grows by the delta alone. A view that is not the tip (an older state, or a sibling list
        applied to the same state) copies the keys it sees into a store of its own once, then extends that.
        """
        store = self._store
        with store.lock:
            if store.tip == self._seq:
                for key, entry in delta.items():
                    store.added[key] = (seq, entry)
                    store.order.append(key)
                store.tip = seq
                return _EntriesView(store, seq, len(store.order))
            keys = store.order[:self._count]
            held = {key: store.added[key][1] for key in keys}
        branch = _ChainStore(seq)
        branch.order = [*keys, *delta]
        branch.added = {key: (self._seq, entry) for key, entry in held.items()}
        branch.added.update((key, (seq, entry)) for key, entry in delta.items())
        return _EntriesView(branch, seq, len(branch.order))


@dataclass(frozen=True)
class RevocationState:
    """The verifier's side: pinned roots and the list in force (none: ``seq`` 0, nothing revoked).

    ``entries`` is every entry the chain has published up to ``seq``, as a read-only mapping keyed (kind, id). Every
    state is an immutable snapshot: applying a list never changes the state it is applied to, an older state never sees
    a later list's entries, and two lists applied to one state give two independent states, from any number of threads.
    A state built with a plain mapping copies it once.
    """

    roots: frozenset[str] = frozenset()
    list_id: str | None = None
    seq: int = 0
    head: str | None = None
    issued_at: str | None = None
    entries: Mapping[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        entries = self.entries
        if not (isinstance(entries, _EntriesView) and entries._seq == self.seq):
            object.__setattr__(self, "entries", _EntriesView.of(entries, self.seq))

    @classmethod
    def from_lists(cls, lists: Iterable[Mapping[str, Any]], root_key_ids: Iterable[str]) -> RevocationState:
        """Verify a whole chain from seq 1 and fold it. Raises RevocationError on any defect."""
        def seq_of(signed: Any) -> int:
            body = signed.get("body") if isinstance(signed, Mapping) else None
            seq = body.get("seq") if isinstance(body, Mapping) else None
            return seq if type(seq) is int else 0

        state = cls(roots=frozenset(root_key_ids))
        for signed in sorted(lists, key=seq_of):
            state = state.apply(signed)
        return state

    def apply(self, signed: Any) -> RevocationState:
        """The state with ``signed`` as the list in force, or RevocationError (this state is never changed)."""
        if not isinstance(signed, dict) or set(signed) != {"body", "sig"}:
            raise _shape("signed_list_members")
        body = signed["body"]
        _check_body(body)
        key = load_public(unb64(body["issuerKey"]))
        if key_id(key) not in self.roots:
            raise RevocationError("revocation_list_signer_not_a_root")
        try:
            sig = unb64(signed["sig"])
            if len(sig) != 64 or _b64(sig) != signed["sig"]:
                raise ValueError("signature is not the canonical base64 of 64 bytes")
            key.verify(sig, REVOCATION_DOMAIN + canonical(body))
        except (InvalidSignature, ValueError) as exc:
            raise RevocationError("revocation_list_signature_unverified") from exc
        seq = body["seq"]
        if self.list_id is not None and body["listId"] != self.list_id:
            raise RevocationError("revocation_list_other_chain")
        if seq <= self.seq:
            raise RevocationError(f"revocation_list_rollback:{seq}<={self.seq}")
        if seq > self.seq + 1:
            raise RevocationError(f"revocation_list_gap:{seq}>{self.seq + 1}")
        if body["previous"] != self.head:
            raise RevocationError("revocation_list_previous_mismatch")
        if self.issued_at is not None and body["issuedAt"] < self.issued_at:
            raise RevocationError("revocation_list_time_reversed")
        delta = {(e["kind"], e["id"]): dict(e) for e in body["entries"]}
        if any(e["revokedAt"] > body["issuedAt"] for e in delta.values()):
            raise RevocationError("revocation_entry_from_future")
        held = cast(_EntriesView, self.entries)  # __post_init__ made it a view
        for kind, ident in delta:
            if (kind, ident) in held:
                raise RevocationError(f"revocation_entry_repeated:{kind}:{ident[:12]}")
        # A revoked key is never a root, whatever the order of the entries and whichever list revoked it: the
        # successors of the roots this list revokes join unless an earlier list revoked them, then every key id this
        # list revokes leaves, so a successor the same list revokes does not stay either.
        revoked_keys = {ident for kind, ident in delta if kind == "key"}
        successors = {key_id(load_public(unb64(e["successor"]))) for (kind, ident), e in delta.items()
                      if kind == "key" and ident in self.roots and "successor" in e}
        successors = {kid for kid in successors if ("key", kid) not in held}
        roots = (self.roots | successors) - revoked_keys
        return RevocationState(frozenset(roots), body["listId"], seq, list_digest(body), body["issuedAt"],
                               held.extended(seq, delta))

    def revoked(self, kind: str, ident: str) -> bool:
        """Whether the list in force names ``ident`` under ``kind`` (in force from install)."""
        if kind not in REVOCATION_KINDS:
            raise ValueError(f"unknown_revocation_kind:{kind}")
        return (kind, ident) in self.entries

    def revoked_at(self, kind: str, ident: str, at: str) -> bool:
        """Whether ``ident`` was revoked at or before ``at``: anything it signs or authorises from then on is refused."""
        if not self.revoked(kind, ident):
            return False
        return ts(str(self.entries[(kind, ident)]["revokedAt"])) <= ts(at)

    def revokes(self, subjects: Iterable[tuple[str, str]]) -> bool:
        """Whether the list in force names any of the (kind, id) pairs."""
        return any(self.revoked(kind, ident) for kind, ident in subjects)

    def revoked_ids(self, kind: str) -> frozenset[str]:
        if kind not in REVOCATION_KINDS:
            raise ValueError(f"unknown_revocation_kind:{kind}")
        return frozenset(ident for k, ident in self.entries if k == kind)

    def key_revoked(self, kid: str, at: str) -> bool:
        return self.revoked_at("key", kid, at)

    def idp_key_revoked(self, thumbprint: str, at: str) -> bool:
        """Whether the identity provider key with RFC 7638 ``thumbprint`` was revoked at or before ``at``."""
        return self.revoked_at("idp-key", thumbprint, at)

    def permit_revoked(self, pid: str, at: str) -> bool:
        return self.revoked_at("permit", pid, at)

    def revoked_grants(self) -> frozenset[str]:
        """Every revoked grant digest; a chain containing one is refused, so descendants fall with it."""
        return self.revoked_ids("grant")

    def summary(self) -> dict[str, Any]:
        """The state as the shared vectors state it."""
        return {"head": self.head, "issuedAt": self.issued_at, "listId": self.list_id,
                "revoked": {kind: sorted(self.revoked_ids(kind)) for kind in REVOCATION_KINDS},
                "roots": sorted(self.roots), "seq": self.seq}


def verify_approval_live(signed: Any, approver_pems: dict[str, bytes], state: RevocationState,
                         at: str) -> dict[str, Any] | None:
    """``verify_approval`` that also refuses an approval whose approver key was revoked by ``at``."""
    body = verify_approval(signed, approver_pems)
    if body is None:
        return None
    pem = approver_pems[str(body.get("approver", ""))]
    return None if state.key_revoked(key_id(load_public(pem)), at) else body
