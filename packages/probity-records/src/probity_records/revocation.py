"""Signed revocation lists for approver and signer keys, permits and grants, with root rotation and a
last-known-good cache.

A revocation list is signed by a revocation root. Lists form a chain (``seq`` rises by one,
``previous`` is the digest of the prior body) and only grow: an entry, once published, stays in
every later list unchanged, so nobody can quietly un-revoke. Entries::

    {"kind": "key" | "permit" | "grant", "id": key id | permit id | grant digest,
     "revokedAt": iso, "reason": str, "successor": b64 raw Ed25519 (optional, key kind only)}

Revoking a grant revokes every grant delegated under it (the chain check refuses any chain that
contains it). Revoking a root key with a ``successor`` rotates the root: later lists are accepted
from the successor and no longer from the revoked key.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature

from .core import _b64, _unb64, canonical, key_id, load_public, sha256_hex, verify_approval, Signer
from .grants import raw_public, ts

REVOCATION_DOMAIN = b"probity-revocation-v1\x00"
REVOCATION_LIST = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-list"
KINDS = ("key", "permit", "grant")


def list_digest(body: Mapping[str, Any]) -> str:
    return sha256_hex(canonical(dict(body)))


def sign_revocations(signer: Signer, *, list_id: str, seq: int, issued_at: str,
                     entries: Iterable[Mapping[str, Any]], previous: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Sign list ``seq``. ``previous`` is the prior signed list (None for seq 1)."""
    rows = [dict(e) for e in entries]
    for e in rows:
        if e.get("kind") not in KINDS or not e.get("id") or not e.get("revokedAt"):
            raise ValueError(f"revocation_entry_shape:{e}")
    body = {"entries": sorted(rows, key=lambda e: (e["kind"], e["id"])), "issuedAt": issued_at,
            "issuerKey": raw_public(signer), "listId": list_id,
            "previous": list_digest(previous["body"]) if previous else None, "seq": seq}
    return {"body": body, "sig": _b64(signer.sign(REVOCATION_DOMAIN + canonical(body)))}


class RevocationError(ValueError):
    """A revocation list that is forged, out of order, or un-revokes an entry."""


@dataclass(frozen=True)
class RevocationState:
    keys: Mapping[str, str] = field(default_factory=dict)
    permits: Mapping[str, str] = field(default_factory=dict)
    grants: Mapping[str, str] = field(default_factory=dict)
    roots: frozenset[str] = frozenset()
    seq: int = 0
    head: str | None = None

    @classmethod
    def from_lists(cls, lists: Iterable[Mapping[str, Any]], root_key_ids: Iterable[str]) -> RevocationState:
        """Verify every list in order and fold them. Raises RevocationError on any defect."""
        state = cls(roots=frozenset(root_key_ids))
        for signed in sorted(lists, key=lambda s: s.get("body", {}).get("seq", 0)):
            state = state.apply(signed)
        return state

    def apply(self, signed: Mapping[str, Any]) -> RevocationState:
        body = signed.get("body")
        if not isinstance(body, dict):
            raise RevocationError("revocation_list_shape")
        try:
            key = load_public(_unb64(body["issuerKey"]))
            key.verify(_unb64(signed.get("sig")), REVOCATION_DOMAIN + canonical(body))
        except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
            raise RevocationError("revocation_list_signature_unverified") from exc
        if key_id(key) not in self.roots:
            raise RevocationError("revocation_list_signer_not_a_root")
        if body.get("seq") != self.seq + 1 or body.get("previous") != self.head:
            raise RevocationError(f"revocation_list_out_of_order:{body.get('seq')}")
        entries = {(e["kind"], e["id"]): e for e in body.get("entries", [])}
        for kind, table in (("key", self.keys), ("permit", self.permits), ("grant", self.grants)):
            for ident, at in table.items():
                kept = entries.get((kind, ident))
                if kept is None or kept["revokedAt"] != at:
                    raise RevocationError(f"revocation_list_drops_entry:{kind}:{ident[:12]}")
        keys, permits, grants_ = dict(self.keys), dict(self.permits), dict(self.grants)
        roots = set(self.roots)
        for (kind, ident), e in entries.items():
            {"key": keys, "permit": permits, "grant": grants_}[kind][ident] = e["revokedAt"]
            if kind == "key" and ident in roots:
                roots.discard(ident)
                if e.get("successor"):
                    roots.add(key_id(load_public(_unb64(e["successor"]))))
        return RevocationState(keys, permits, grants_, frozenset(roots), body["seq"], list_digest(body))

    def key_revoked(self, kid: str, at: str) -> bool:
        """True when ``kid`` was revoked at or before ``at``: anything it signs from then on is refused."""
        when = self.keys.get(kid)
        return when is not None and ts(when) <= ts(at)

    def permit_revoked(self, pid: str, at: str) -> bool:
        when = self.permits.get(pid)
        return when is not None and ts(when) <= ts(at)

    def revoked_grants(self) -> frozenset[str]:
        """Every revoked grant digest; a chain containing one is refused, so descendants fall with it."""
        return frozenset(self.grants)


def verify_approval_live(signed: Any, approver_pems: dict[str, bytes], state: RevocationState,
                         at: str) -> dict[str, Any] | None:
    """``verify_approval`` that also refuses an approval whose approver key was revoked by ``at``."""
    body = verify_approval(signed, approver_pems)
    if body is None:
        return None
    pem = approver_pems[str(body.get("approver", ""))]
    return None if state.key_revoked(key_id(load_public(pem)), at) else body
