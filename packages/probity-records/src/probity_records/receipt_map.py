"""The receipt map: a sparse Merkle map keyed on (issuer key, permit id, stage), committed inside a log.

An append-only Merkle log proves that a receipt is included; it cannot prove that no second receipt for the
same (permit id, stage) is also included. The map turns uniqueness into something a single record bundle can
carry: a proof that, as of a root the log committed into its own tree, the key holds exactly one receipt (the
one at this leaf index with this leaf hash), or none.

Keyed per issuer: the issuer is the SHA-256 of the record's raw Ed25519 signing key, so a record one party
signs never occupies the slot of a record another party signs.

Shape: a binary tree of depth 256 over SHA-256 keys in compact form (a subtree holding one entry is that
entry's hash; an empty subtree is 32 zero bytes), so each set of entries has exactly one root and a proof is
as long as the key's distance to the nearest branching point, about log2(n) siblings:

    key        = SHA-256("probity-receipt-map/v1 key" || issuer key id || u16 len || permit id || u16 len || stage)
    entry      = SHA-256(0x00 || key || u64 leaf index || leaf hash)
    node(L, R) = SHA-256(0x01 || L || R)
    empty      = 32 zero bytes

A proof lists the siblings from the root down and ends in one entry or none. It proves membership when the
entry's key is the key asked about, and non-membership when the path ends empty or in another key's entry
that shares the path. The domain bytes keep an entry from passing as a node, and the compact form keeps the
representation canonical, so a proof that stops at another depth than the true tree cannot reproduce the
root. Vectors: vectors/shared/receipt-map.json (membership, both kinds of non-membership, and refusals).
"""

from __future__ import annotations

import base64
import binascii
import bisect
import hashlib
from dataclasses import dataclass
from typing import Any

DEPTH = 256
EMPTY = bytes(32)
STAGES = ("accept", "execute", "settle", "final")
_KEY_DOMAIN = b"probity-receipt-map/v1 key"
MAX_PERMIT_BYTES = 256


class MapError(ValueError):
    """A key, entry or proof that is refused."""


def _u16(data: bytes) -> bytes:
    if len(data) > 0xFFFF:
        raise MapError("field longer than 65535 bytes")
    return len(data).to_bytes(2, "big") + data


def check_key(permit_id: Any, stage: Any) -> tuple[str, str]:
    """A (permit id, stage) the map accepts: a non-empty permit id of at most 256 bytes, one of the four stages."""
    # This module loads by file path for the vector generator, so it imports nothing from the package.
    try:
        size = len(permit_id.encode()) if isinstance(permit_id, str) else 0
    except UnicodeEncodeError:  # a lone surrogate has no UTF-8 spelling
        size = 0
    if not 0 < size <= MAX_PERMIT_BYTES:
        raise MapError("a permit id is a non-empty UTF-8 string of at most 256 bytes")
    if any(ord(ch) < 0x20 for ch in permit_id):
        raise MapError("a permit id may hold no control character")
    if stage not in STAGES:
        raise MapError(f"stage must be one of {STAGES}")
    return permit_id, stage


def map_key(issuer: str, permit_id: str, stage: str) -> bytes:
    """The map key; `issuer` is the hex SHA-256 of the record's raw Ed25519 public key (its DSSE key id)."""
    check_key(permit_id, stage)
    try:
        issuer_raw = bytes.fromhex(issuer)
    except (TypeError, ValueError) as exc:
        raise MapError("the issuer is a hex SHA-256 key id") from exc
    if len(issuer_raw) != 32:
        raise MapError("the issuer is a hex SHA-256 key id")
    return hashlib.sha256(_KEY_DOMAIN + issuer_raw + _u16(permit_id.encode()) + _u16(stage.encode())).digest()


def entry_hash(key: bytes, index: int, leaf: bytes) -> bytes:
    if len(key) != 32 or len(leaf) != 32 or not 0 <= index < 2**64:
        raise MapError("an entry is a 32-byte key, a leaf index under 2**64 and a 32-byte leaf hash")
    return hashlib.sha256(b"\x00" + key + index.to_bytes(8, "big") + leaf).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _bit(key: int, depth: int) -> int:
    return (key >> (DEPTH - 1 - depth)) & 1


@dataclass(frozen=True)
class Entry:
    key: bytes
    index: int  # the receipt's leaf index in the log
    leaf: bytes  # the receipt's RFC 9162 leaf hash

    @property
    def hash(self) -> bytes:
        return entry_hash(self.key, self.index, self.leaf)


class ReceiptMap:
    """Insert-only map; a key is set once. Roots are cached per subtree and invalidated along an insert's path."""

    def __init__(self) -> None:
        self._keys: list[int] = []  # sorted
        self._entries: dict[int, Entry] = {}
        self._cache: dict[tuple[int, int], bytes] = {}  # (depth, prefix) -> hash, subtrees of 2+ entries

    def __len__(self) -> int:
        return len(self._keys)

    def get(self, key: bytes) -> Entry | None:
        return self._entries.get(int.from_bytes(key, "big"))

    def insert(self, key: bytes, index: int, leaf: bytes) -> Entry:
        k = int.from_bytes(key, "big")
        if k in self._entries:
            raise MapError("the key already holds a receipt")
        entry = Entry(key, index, leaf)
        entry_hash(key, index, leaf)  # validates the shape
        bisect.insort(self._keys, k)
        self._entries[k] = entry
        # every subtree on the new key's path changed; a proof may have cached a deep one without its parent,
        # so the whole path is cleared rather than stopping at the first uncached depth
        for depth in range(DEPTH):
            self._cache.pop((depth, k >> (DEPTH - depth)), None)
        return entry

    def _range(self, depth: int, prefix: int) -> tuple[int, int]:
        lo = prefix << (DEPTH - depth)
        hi = (prefix + 1) << (DEPTH - depth)
        return bisect.bisect_left(self._keys, lo), bisect.bisect_left(self._keys, hi)

    def _hash(self, depth: int, prefix: int, lo: int, hi: int) -> bytes:
        if hi == lo:
            return EMPTY
        if hi - lo == 1:
            return self._entries[self._keys[lo]].hash
        cached = self._cache.get((depth, prefix))
        if cached is not None:
            return cached
        mid = bisect.bisect_left(self._keys, ((prefix << 1) | 1) << (DEPTH - depth - 1), lo, hi)
        value = _node(self._hash(depth + 1, prefix << 1, lo, mid), self._hash(depth + 1, (prefix << 1) | 1, mid, hi))
        self._cache[(depth, prefix)] = value
        return value

    def root(self) -> bytes:
        return self._hash(0, 0, 0, len(self._keys))

    def prove(self, key: bytes) -> Proof:
        """Siblings from the root down to where the key's path holds at most one entry."""
        k = int.from_bytes(key, "big")
        siblings: list[bytes] = []
        prefix, lo, hi = 0, 0, len(self._keys)
        for depth in range(DEPTH):
            if hi - lo <= 1:
                break
            mid = bisect.bisect_left(self._keys, ((prefix << 1) | 1) << (DEPTH - depth - 1), lo, hi)
            if _bit(k, depth):
                siblings.append(self._hash(depth + 1, prefix << 1, lo, mid))
                prefix, lo = (prefix << 1) | 1, mid
            else:
                siblings.append(self._hash(depth + 1, (prefix << 1) | 1, mid, hi))
                prefix, hi = prefix << 1, mid
        terminal = None if hi == lo else self._entries[self._keys[lo]]
        return Proof(key, tuple(siblings), terminal)


@dataclass(frozen=True)
class Proof:
    """A path for `key`: the siblings top-down, then the one entry (or none) at the end of the path."""

    key: bytes
    siblings: tuple[bytes, ...]
    terminal: Entry | None

    def root(self) -> bytes:
        if len(self.siblings) > DEPTH:
            raise MapError("a proof is at most 256 siblings")
        k = int.from_bytes(self.key, "big")
        if self.terminal is None:
            h = EMPTY
        else:
            t = int.from_bytes(self.terminal.key, "big")
            depth = len(self.siblings)
            if depth and (t ^ k) >> (DEPTH - depth):
                raise MapError("the terminal entry is not on the key's path")
            h = self.terminal.hash
        for depth in range(len(self.siblings) - 1, -1, -1):
            sibling = self.siblings[depth]
            h = _node(sibling, h) if _bit(k, depth) else _node(h, sibling)
        return h

    def holds(self, root: bytes) -> Entry | None:
        """The entry the map holds for `key` under `root` (None: the key is absent); MapError if the proof is
        not a proof for that root."""
        if self.root() != root:
            raise MapError("the map proof does not reproduce the committed root")
        if self.terminal is None or self.terminal.key != self.key:
            return None
        return self.terminal

    def to_doc(self) -> dict[str, Any]:
        terminal = None if self.terminal is None else {
            "key": self.terminal.key.hex(), "index": self.terminal.index, "leafHash": self.terminal.leaf.hex()}  # fmt: skip
        return {"key": self.key.hex(), "siblings": [None if s == EMPTY else base64.b64encode(s).decode()
                                                    for s in self.siblings], "terminal": terminal}  # fmt: skip

    @classmethod
    def from_doc(cls, doc: Any) -> Proof:
        try:
            key = bytes.fromhex(doc["key"])
            siblings = tuple(EMPTY if s is None else base64.b64decode(s, validate=True) for s in doc["siblings"])
            t = doc["terminal"]
            terminal = None if t is None else Entry(bytes.fromhex(t["key"]), t["index"], bytes.fromhex(t["leafHash"]))
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise MapError(f"map proof malformed: {type(exc).__name__}") from exc
        if len(key) != 32 or any(len(s) != 32 for s in siblings) or len(siblings) > DEPTH:
            raise MapError("map proof malformed: lengths")
        if terminal is not None:
            if type(terminal.index) is not int:
                raise MapError("map proof malformed: index")
            entry_hash(terminal.key, terminal.index, terminal.leaf)
        return cls(key, siblings, terminal)
