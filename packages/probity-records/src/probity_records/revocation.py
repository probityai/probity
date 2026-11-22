"""The one signed revocation list: keys, permits, grants, agents, streams, sponsors and builds.

A revocation root signs a chain of lists. ``seq`` rises by one (it is the list's epoch), ``previous`` is the digest
of the prior body, and the list is cumulative: an entry, once published, stays in every later list byte for byte,
so nobody can quietly un-revoke. Every reader of revocations reads this format and only this format: the records
audit (``Trust``), the TypeScript twin and the Go reader in agent-evidence-vectors; the shared vectors
(``vectors/shared/revocation.json``) hold them, and any other reader, to the same verdicts. A signed list is::

    {"body": {"type": REVOCATION_LIST, "listId": id, "seq": n, "previous": "sha256:<hex>" | None,
              "issuedAt": "YYYY-MM-DDTHH:MM:SSZ", "issuerKey": b64 raw Ed25519,
              "entries": [{"kind": kind, "id": id, "revokedAt": time, "reason": str (optional),
                           "successor": b64 raw Ed25519 (optional, key kind only)}, ...]},
     "sig": b64 Ed25519 over REVOCATION_DOMAIN || JCS(body)}

The verifier pins root key ids and never reads one from a list: a list is checked under its presented key only
once that key's id is a pinned root. Revoking a root with a ``successor`` rotates it: the roots after a list are
the roots held plus the successors of the roots it revokes, minus every key id it revokes (a revoked key is never a
root, in whatever order the entries come). Revoking a grant revokes every
grant delegated under it (the chain check refuses any chain containing it); revoking an agent or a sponsor reaches
every piece of work answering to it wherever the enforcement point derives that from a chain it verified.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any

from cryptography.exceptions import InvalidSignature

from .core import (
    MAX_EXACT_INT,
    Signer,
    _b64,
    _unb64,
    canonical,
    key_id,
    load_public,
    sha256_hex,
    verify_approval,
)
from .grants import raw_public, ts

REVOCATION_DOMAIN = b"probity-revocation-v1\x00"
REVOCATION_LIST = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-list"
#: Every subject kind a list names. A digest kind's id is 64 lowercase hex; the rest are identifiers.
REVOCATION_KINDS = ("agent", "build", "grant", "key", "permit", "sponsor", "stream")
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
    "revocation_list_drops_entry",
)

_BODY_MEMBERS = frozenset({"type", "listId", "seq", "previous", "issuedAt", "issuerKey", "entries"})
_ENTRY_REQUIRED = frozenset({"kind", "id", "revokedAt"})
_ENTRY_OPTIONAL = frozenset({"reason", "successor"})
_IDENTIFIER = re.compile(r"[\x21-\x7e]{1,512}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_LIST_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class RevocationError(ValueError):
    """A list that is malformed, forged, out of order, or un-revokes an entry; the message starts with the code."""


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
        raw = _unb64(value)
    except ValueError:
        raise _shape(f"{what}_not_base64") from None
    if len(raw) != 32:
        raise _shape(f"{what}_not_an_ed25519_key")
    if _b64(raw) != value:
        raise _shape(f"{what}_not_canonical_base64")
    return raw


def _check_entry(entry: Any) -> tuple[str, str]:
    if not isinstance(entry, dict):
        raise _shape("entry_not_an_object")
    members = set(entry)
    if not _ENTRY_REQUIRED <= members or not members <= _ENTRY_REQUIRED | _ENTRY_OPTIONAL:
        raise _shape("entry_members")
    kind, ident = entry["kind"], entry["id"]
    if kind not in REVOCATION_KINDS:
        raise _shape("entry_kind_unknown")
    pattern = _HEX64 if kind in DIGEST_KINDS else _IDENTIFIER
    if not isinstance(ident, str) or not pattern.fullmatch(ident):
        raise _shape(f"entry_id_form:{kind}")
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
    if body["type"] != REVOCATION_LIST:
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
    """Sign list ``seq`` holding ``entries`` (every entry still in force: lists are cumulative).

    ``previous`` is the prior signed list, ``None`` for seq 1. The body is held to the format before it is signed, so
    an issuer cannot publish a list its own readers refuse for its shape.
    """
    rows = sorted((dict(e) for e in entries), key=lambda e: (str(e.get("kind")), str(e.get("id"))))
    body = {"entries": rows, "issuedAt": issued_at, "issuerKey": raw_public(signer), "listId": list_id,
            "previous": list_digest(previous["body"]) if previous is not None else None, "seq": seq,
            "type": REVOCATION_LIST}
    _check_body(body)
    return {"body": body, "sig": _b64(signer.sign(REVOCATION_DOMAIN + canonical(body)))}


@dataclass(frozen=True)
class RevocationState:
    """The verifier's side: pinned roots and the list in force (none: ``seq`` 0, nothing revoked)."""

    roots: frozenset[str] = frozenset()
    list_id: str | None = None
    seq: int = 0
    head: str | None = None
    issued_at: str | None = None
    entries: Mapping[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)

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
        key = load_public(_unb64(body["issuerKey"]))
        if key_id(key) not in self.roots:
            raise RevocationError("revocation_list_signer_not_a_root")
        try:
            sig = _unb64(signed["sig"])
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
        entries = {(e["kind"], e["id"]): e for e in body["entries"]}
        if any(e["revokedAt"] > body["issuedAt"] for e in entries.values()):
            raise RevocationError("revocation_entry_from_future")
        for (kind, ident), held in self.entries.items():
            if entries.get((kind, ident)) != held:
                raise RevocationError(f"revocation_list_drops_entry:{kind}:{ident[:12]}")
        # A revoked key is never a root, whatever the order of the entries: the successors of the roots this list
        # revokes join, then every key id it revokes leaves, so a successor the same list revokes does not stay.
        revoked_keys = {ident for kind, ident in entries if kind == "key"}
        successors = {key_id(load_public(_unb64(e["successor"]))) for (kind, ident), e in entries.items()
                      if kind == "key" and ident in self.roots and "successor" in e}
        roots = (self.roots | successors) - revoked_keys
        return RevocationState(frozenset(roots), body["listId"], seq, list_digest(body), body["issuedAt"],
                               {k: dict(v) for k, v in entries.items()})

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
