"""The C2SP transparency-log witness surface, whole: signed notes, checkpoints, cosignatures, policies, proofs and the
witness protocol, with a journal feed cosigned by witness keys the customer holds.

Specifications implemented, each to the letter and each refusing rather than repairing:

- c2sp.org/signed-note: the envelope, vkeys, and every assigned signature type: 0x01 Ed25519, 0x02 ECDSA (as
  github.com/transparency-dev/witness and Sigstore Rekor sign: SHA-256, ASN.1, key ID = SHA-256 of the SPKI), 0x04
  timestamped Ed25519 cosignatures, 0x05 RFC 6962 ``TreeHeadSignature`` (c2sp.org/static-ct-api) and 0x06 timestamped
  ML-DSA-44 cosignatures. ``open_note`` is the generic verifier: unknown keys ignored, a known key that fails rejects
  the note, no verified known key rejects it.
- c2sp.org/tlog-checkpoint: origin, size, root and extension lines. A log may authenticate with 0x01, 0x02, 0x05 or
  0x06. Extension lines are carried, and a checkpoint whose extension lines no log signature covers is refused
  (``checkpoint_extensions_unsigned``): an ML-DSA-44 line does not sign them and a 0x05 line forbids them.
- c2sp.org/tlog-cosignature: Ed25519 ``cosignature/v1`` checkpoint cosignatures, and ML-DSA-44 ``subtree/v1``
  cosignatures in both forms, a checkpoint cosignature (start 0, end = size, timestamped) and a subtree cosignature
  (any valid subtree, timestamp zero), with draft-ietf-plants-merkle-tree-certs subtree hashes and subtree consistency
  proofs.
- c2sp.org/tlog-policy: logs and witnesses with their optional URLs, groups, one quorum; read from text or octets.
- c2sp.org/tlog-witness: ``add-checkpoint``, the optional ``sign-subtree``, and monitor retrieval of the latest
  cosigned checkpoint at ``<origin hash>/checkpoint``; a witness may hold ML-DSA-44 and Ed25519 keys at once.
- c2sp.org/tlog-proof: the offline proof of logging (index, inclusion proof, checkpoint), parsed, written and verified
  under a policy.

The tree is RFC 9162: leaf ``i`` of a journal is the bytes of journal line ``i`` (no newline), ``SHA-256(0x00 ||
line)``. Every refusal is a ``NoteError`` or ``WitnessRefused`` whose ``code`` is registered in ``refusal_codes.json``;
the text after the first ``:`` is detail for the producer's log and never part of the code.
``vectors/shared/c2sp-conformance.json`` holds the specifications' examples and notes from live logs
(Sigstore Rekor, a Static CT log) that independent implementations verify; ``vectors/shared/mldsa44-xcheck.json``
holds both directions of a cross-check against filippo.io/torchwood on Go's crypto/mldsa.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import http.client
import os
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA44PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from .clock import NS_PER_S, Clock

SIG_ED25519 = 0x01
SIG_ECDSA = 0x02
SIG_COSIGNATURE_V1 = 0x04
SIG_RFC6962 = 0x05
SIG_MLDSA44 = 0x06
#: The public key length of each fixed-length type; 0x02 and 0x05 carry a DER SubjectPublicKeyInfo.
PUBLIC_LEN = {SIG_ED25519: 32, SIG_COSIGNATURE_V1: 32, SIG_MLDSA44: 1312}
SPKI_TYPES = (SIG_ECDSA, SIG_RFC6962)
KNOWN_TYPES = (SIG_ED25519, SIG_ECDSA, SIG_COSIGNATURE_V1, SIG_RFC6962, SIG_MLDSA44)
#: Types a log authenticates its checkpoint with (c2sp.org/tlog-checkpoint, static-ct-api, Rekor).
LOG_TYPES = (SIG_ED25519, SIG_ECDSA, SIG_RFC6962, SIG_MLDSA44)
#: Types a witness cosigns with (c2sp.org/tlog-cosignature).
WITNESS_TYPES = (SIG_COSIGNATURE_V1, SIG_MLDSA44)
#: Log signature types that sign the whole note text, extension lines included.
COVERS_EXTENSIONS = (SIG_ED25519, SIG_ECDSA)
ECDSA_CURVES = ("secp256r1", "secp384r1", "secp521r1")
MLDSA44_SIG_LEN = 2420
SUBTREE_LABEL = b"subtree/v1\n\x00"  # 12 bytes (c2sp.org/tlog-cosignature, CosignedSubtree)
PROOF_HEADER = "c2sp.org/tlog-proof@v1"
EM_DASH = "—"
MAX_SIGNATURES = 64
MAX_PROOF_LINES = 63
MAX_TIMESTAMP = 2**63 - 1
MAX_SUBTREE = 1 << 62
EMPTY_ROOT = hashlib.sha256(b"").digest()
_DECIMAL = re.compile(r"(0|[1-9][0-9]*)\Z")


class NoteError(ValueError):
    """A note, vkey, checkpoint, cosignature, proof or policy that is refused: ``code[:detail]``."""

    @property
    def code(self) -> str:
        return str(self.args[0]).split(":", 1)[0] if self.args else ""


# ---- RFC 9162 tree --------------------------------------------------------------------------------
def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than ``n`` (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(leaves: Sequence[bytes]) -> bytes:
    """Root over leaf HASHES (already ``leaf_hash``ed)."""
    if not leaves:
        return EMPTY_ROOT
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """RFC 9162 section 2.1.3.1: the audit path of leaf ``index`` in the tree of ``leaves``."""
    if not 0 <= index < len(leaves):
        raise NoteError(f"proof_inclusion_invalid:index {index} outside a tree of {len(leaves)}")
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return [*inclusion_proof(index, leaves[:k]), root(leaves[k:])]
    return [*inclusion_proof(index - k, leaves[k:]), root(leaves[:k])]


def verify_inclusion(index: int, size: int, leaf: bytes, proof: Sequence[bytes], root_hash: bytes) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root_hash


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root(leaves[:k])]


def consistency_proof(old: int, leaves: Sequence[bytes]) -> list[bytes]:
    """RFC 9162 section 2.1.4 proof that the first ``old`` leaves are a prefix of ``leaves``."""
    if not 0 < old <= len(leaves):
        return []
    return _subproof(old, leaves, True)


def verify_consistency(old: int, new: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if old > new:
        return False
    if old == new:
        return not proof and old_root == new_root
    if old == 0:
        return not proof
    path = list(proof)
    if old & (old - 1) == 0:  # old is a power of two: the old root is the first node
        path = [old_root, *path]
    if not path:
        return False
    fn, sn = old - 1, new - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


def is_empty_root(root_hash: bytes) -> bool:
    """Whether ``root_hash`` is the RFC 6962 hash of the empty tree, the only root a size-zero checkpoint carries."""
    return root_hash == EMPTY_ROOT


# ---- subtrees (draft-ietf-plants-merkle-tree-certs-07 section 4) --------------------------------------
def valid_subtree(start: int, end: int) -> bool:
    """``[start, end)`` is a subtree: empty, or ``start`` a multiple of the smallest power of two >= its width."""
    if start < 0 or end < start or end - start > MAX_SUBTREE:
        return False
    return start == end or start & ((1 << (end - start - 1).bit_length()) - 1) == 0


def subtree_hash(leaves: Sequence[bytes], start: int, end: int) -> bytes:
    """The Merkle tree hash of the subtree ``[start, end)`` of a tree of leaf hashes."""
    if not valid_subtree(start, end) or end > len(leaves):
        raise NoteError(f"subtree_invalid:[{start}, {end}) of a tree of {len(leaves)}")
    return root(leaves[start:end])


def _sub_rec(lo: int, hi: int, start: int, end: int, own: bool, leaves: Sequence[bytes]) -> list[bytes]:
    if lo == start and hi == end:
        return [] if own else [root(leaves[lo:hi])]
    k = _split(hi - lo)
    if end <= lo + k:
        return [*_sub_rec(lo, lo + k, start, end, own, leaves), root(leaves[lo + k:hi])]
    if lo + k <= start:
        return [*_sub_rec(lo + k, hi, start, end, own, leaves), root(leaves[lo:lo + k])]
    return [*_sub_rec(lo + k, hi, lo + k, end, False, leaves), root(leaves[lo:lo + k])]


def subtree_consistency_proof(start: int, end: int, leaves: Sequence[bytes]) -> list[bytes]:
    """The subtree consistency proof (draft section 4.4) from ``[start, end)`` to the tree of ``leaves``."""
    if not valid_subtree(start, end) or end > len(leaves):
        raise NoteError(f"subtree_invalid:[{start}, {end}) of a tree of {len(leaves)}")
    return [] if start == end else _sub_rec(0, len(leaves), start, end, True, leaves)


def _run_sub(p: list[bytes], lo: int, hi: int, start: int, end: int, own: bool,
             sh: bytes) -> tuple[bytes, bytes] | None:
    if lo == start and hi == end:
        if own:
            return (sh, sh) if not p else None
        return (p[0], p[0]) if len(p) == 1 else None
    if not p:
        return None
    k = _split(hi - lo)
    last = p[-1]
    if end <= lo + k:
        got = _run_sub(p[:-1], lo, lo + k, start, end, own, sh)
        return None if got is None else (got[0], node_hash(got[1], last))
    if lo + k <= start:
        got = _run_sub(p[:-1], lo + k, hi, start, end, own, sh)
        return None if got is None else (got[0], node_hash(last, got[1]))
    got = _run_sub(p[:-1], lo + k, hi, lo + k, end, False, sh)
    return None if got is None else (node_hash(last, got[0]), node_hash(last, got[1]))


def verify_subtree_consistency(proof: Sequence[bytes], size: int, root_hash: bytes, start: int, end: int,
                               sub_hash: bytes) -> bool:
    """Whether ``proof`` shows the subtree ``[start, end)`` with hash ``sub_hash`` inside the tree of ``size``."""
    if size < 0 or end > size or not valid_subtree(start, end):
        return False
    if start == end:
        return not proof and sub_hash == EMPTY_ROOT
    got = _run_sub(list(proof), 0, size, start, end, True, sub_hash)
    return got is not None and got == (sub_hash, root_hash)


# ---- signed notes ---------------------------------------------------------------------------------
def b64decode_canonical(text: str) -> bytes:
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise NoteError(f"note_base64_invalid:{text!r}") from exc
    if base64.b64encode(raw).decode() != text:
        raise NoteError(f"note_base64_noncanonical:{text!r}")
    return raw


def parse_decimal(text: str, what: str) -> int:
    if len(text) > 19 or not _DECIMAL.match(text) or int(text) > MAX_TIMESTAMP:
        raise NoteError(f"note_decimal_invalid:{what} must be an ASCII decimal with no leading zeros")
    return int(text)


def valid_name(name: str) -> bool:
    """A key, cosigner or origin name: 1 to 255 bytes, no Unicode space, no '+', no control character."""
    try:
        size = len(name.encode())
    except UnicodeEncodeError:
        return False
    return bool(name) and size <= 255 and "+" not in name and not any(ch.isspace() or ord(ch) < 0x20 for ch in name)


def valid_key_name(name: str) -> bool:
    """A signed-note key name: non-empty, no Unicode space, no '+'. The 255-byte limit is a cosigner name's."""
    return bool(name) and "+" not in name and not any(ch.isspace() for ch in name)


def note_key_id(name: str, sig_type: int, public: bytes) -> bytes:
    """``SHA-256(name || 0x0A || type || public)[:4]``; ``public`` is the 32-byte RFC 6962 LogID for type 0x05."""
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + public).digest()[:4]


def _raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _spki(public: Any) -> bytes:
    return bytes(public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def _public_of(sig_type: int, public: bytes) -> Any:
    """The key object a vkey wraps, refusing a key that is not exactly its type's encoding."""
    if sig_type in PUBLIC_LEN:
        if len(public) != PUBLIC_LEN[sig_type]:
            raise NoteError(f"vkey_key_length:type {sig_type:#04x} carries a {PUBLIC_LEN[sig_type]}-byte key")
        if sig_type == SIG_MLDSA44:
            return MLDSA44PublicKey.from_public_bytes(public)
        return Ed25519PublicKey.from_public_bytes(public)
    try:
        key = load_der_public_key(public)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise NoteError(f"vkey_key_length:type {sig_type:#04x} carries a DER SubjectPublicKeyInfo") from exc
    if _spki(key) != public:
        raise NoteError("vkey_key_length:the SubjectPublicKeyInfo is not in its canonical DER form")
    _check_spki_key(sig_type, key)
    return key


def _check_spki_key(sig_type: int, key: Any) -> None:
    if isinstance(key, ec.EllipticCurvePublicKey):
        curves = ECDSA_CURVES if sig_type == SIG_ECDSA else ("secp256r1",)
        if key.curve.name not in curves:
            raise NoteError(f"vkey_curve_unsupported:{key.curve.name} for type {sig_type:#04x}")
        return
    if sig_type == SIG_RFC6962 and isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise NoteError("vkey_curve_unsupported:an RFC 6962 RSA key is at least 2048 bits")
        return
    raise NoteError(f"vkey_type_mismatch:type {sig_type:#04x} does not take a {type(key).__name__}")


@dataclass(frozen=True)
class VerifierKey:
    """A vkey ``<name>+<hex key id>+<base64(type || public key)>``; ``public`` is the raw key for 0x01, 0x04 and
    0x06 and the DER SubjectPublicKeyInfo for 0x02 and 0x05."""

    name: str
    sig_type: int
    public: bytes

    @property
    def id(self) -> bytes:
        if self.sig_type == SIG_ECDSA:
            return hashlib.sha256(self.public).digest()[:4]
        if self.sig_type == SIG_RFC6962:
            return note_key_id(self.name, SIG_RFC6962, hashlib.sha256(self.public).digest())
        return note_key_id(self.name, self.sig_type, self.public)

    def encode(self) -> str:
        return f"{self.name}+{self.id.hex()}+{base64.b64encode(bytes([self.sig_type]) + self.public).decode()}"

    @property
    def post_quantum(self) -> bool:
        return self.sig_type == SIG_MLDSA44

    def public_key(self) -> Any:
        """The key object: Ed25519, ML-DSA-44, or an EC or RSA public key for the DER types."""
        return _public_of(self.sig_type, self.public)

    def verify(self, sig: bytes, message: bytes) -> bool:
        """The raw signature check of this key's algorithm over ``message`` (0x05 lines go through ``verify_line``)."""
        try:
            key = self.public_key()
            if self.sig_type == SIG_ECDSA:
                key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
            else:
                key.verify(sig, message)
        except (InvalidSignature, ValueError, TypeError, NoteError):
            return False
        return True

    @classmethod
    def _make(cls, name: str, sig_type: int, public: bytes) -> VerifierKey:
        if not valid_name(name):
            raise NoteError(f"note_name_invalid:{name!r}")
        _public_of(sig_type, public)
        return cls(name, sig_type, public)

    @classmethod
    def ed25519(cls, name: str, public: Ed25519PublicKey) -> VerifierKey:
        """A log's Ed25519 note key (type 0x01)."""
        if not isinstance(public, Ed25519PublicKey):
            raise NoteError("vkey_type_mismatch:type 0x01 takes an Ed25519 key")
        return cls._make(name, SIG_ED25519, _raw(public))

    @classmethod
    def cosignature_v1(cls, name: str, public: Ed25519PublicKey) -> VerifierKey:
        """A cosigner's timestamped Ed25519 key (type 0x04)."""
        if not isinstance(public, Ed25519PublicKey):
            raise NoteError("vkey_type_mismatch:type 0x04 takes an Ed25519 key")
        return cls._make(name, SIG_COSIGNATURE_V1, _raw(public))

    @classmethod
    def mldsa44(cls, name: str, public: MLDSA44PublicKey) -> VerifierKey:
        """A cosigner's (or a log's own) ML-DSA-44 key (type 0x06)."""
        if not isinstance(public, MLDSA44PublicKey):
            raise NoteError("vkey_type_mismatch:type 0x06 takes an ML-DSA-44 key")
        return cls._make(name, SIG_MLDSA44, public.public_bytes_raw())

    @classmethod
    def ecdsa(cls, name: str, public: ec.EllipticCurvePublicKey) -> VerifierKey:
        """An ECDSA note key (type 0x02) on P-256, P-384 or P-521."""
        if not isinstance(public, ec.EllipticCurvePublicKey):
            raise NoteError("vkey_type_mismatch:type 0x02 takes an ECDSA key")
        return cls._make(name, SIG_ECDSA, _spki(public))

    @classmethod
    def rfc6962(cls, name: str, public: ec.EllipticCurvePublicKey | rsa.RSAPublicKey) -> VerifierKey:
        """A Static CT log key (type 0x05): ECDSA P-256 or RSA, named after the log's origin."""
        if not isinstance(public, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
            raise NoteError("vkey_type_mismatch:type 0x05 takes an ECDSA P-256 or RSA key")
        return cls._make(name, SIG_RFC6962, _spki(public))


def vkey(name: str, sig_type: int, public: Any) -> VerifierKey:
    """A vkey in one role: an ML-DSA-44 key only as type 0x06, an Ed25519 key only as 0x01 or 0x04, an EC or RSA
    key only as 0x02 or 0x05."""
    makers: dict[int, Callable[[str, Any], VerifierKey]] = {
        SIG_ED25519: VerifierKey.ed25519, SIG_COSIGNATURE_V1: VerifierKey.cosignature_v1,
        SIG_MLDSA44: VerifierKey.mldsa44, SIG_ECDSA: VerifierKey.ecdsa, SIG_RFC6962: VerifierKey.rfc6962}
    if sig_type not in makers:
        raise NoteError(f"vkey_type_unknown:{sig_type:#04x}")
    return makers[sig_type](name, public)


def parse_vkey(text: str) -> VerifierKey:
    parts = text.split("+", 2)
    if len(parts) != 3 or not valid_name(parts[0]):
        raise NoteError(f"vkey_malformed:{text!r}")
    blob = b64decode_canonical(parts[2])
    if not blob or blob[0] not in KNOWN_TYPES:
        raise NoteError(f"vkey_type_unknown:{blob[:1].hex()}")
    key = VerifierKey(parts[0], blob[0], blob[1:])
    _public_of(key.sig_type, key.public)
    if not re.fullmatch(r"[0-9a-f]{8}", parts[1]) or bytes.fromhex(parts[1]) != key.id:
        raise NoteError(f"vkey_id_mismatch:{text!r}")
    return key


@dataclass(frozen=True)
class SigLine:
    name: str
    key_id: bytes
    sig: bytes

    def encode(self) -> str:
        return f"{EM_DASH} {self.name} {base64.b64encode(self.key_id + self.sig).decode()}\n"


@dataclass(frozen=True)
class Note:
    text: str
    sigs: tuple[SigLine, ...]

    def encode(self) -> str:
        return self.text + "\n" + "".join(s.encode() for s in self.sigs)


def parse_note(note: str) -> Note:
    if any(ord(ch) < 0x20 and ch != "\n" for ch in note):
        raise NoteError("note_control_character")
    try:
        note.encode()
    except UnicodeEncodeError as exc:
        raise NoteError("note_malformed:not UTF-8") from exc
    split = note.rfind("\n\n")
    if split < 0 or not note.endswith("\n"):
        raise NoteError("note_malformed:a signed note is text, a blank line, then signature lines")
    text, tail = note[: split + 1], note[split + 2:]
    lines = tail[:-1].split("\n") if tail else []
    if not lines or len(lines) > MAX_SIGNATURES:
        raise NoteError(f"note_signature_count:{len(lines)} lines, 1 to {MAX_SIGNATURES} allowed")
    sigs = []
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != EM_DASH or not valid_key_name(parts[1]):
            raise NoteError(f"note_signature_line_malformed:{line!r}")
        blob = b64decode_canonical(parts[2])
        if len(blob) < 5:
            raise NoteError("note_signature_length:a signature is a 4-byte key id and the signature")
        sigs.append(SigLine(parts[1], blob[:4], blob[4:]))
    if len({(s.name, s.key_id) for s in sigs}) != len(sigs):
        raise NoteError("note_signature_duplicate:two signature lines share key name and key id")
    return Note(text, tuple(sigs))


@dataclass(frozen=True)
class OpenedNote:
    """A note ``open_note`` accepted: its text, the lines it verified (with their keys and timestamps, None for an
    untimestamped log signature), and the lines from keys it does not know."""

    text: str
    verified: tuple[tuple[SigLine, int | None], ...]
    unknown: tuple[SigLine, ...]


def open_note(note: str, keys: Iterable[VerifierKey]) -> OpenedNote:
    """c2sp.org/signed-note verification: lines from unknown (name, key id) pairs are ignored, a known key whose
    line fails rejects the note, and a note with no verified line from a known key is rejected."""
    parsed = parse_note(note)
    known = {(k.name, k.id): k for k in keys}
    verified, unknown = [], []
    for line in parsed.sigs:
        key = known.get((line.name, line.key_id))
        if key is None:
            unknown.append(line)
            continue
        verified.append((line, verify_line(key, parsed.text, line)))
    if not verified:
        raise NoteError("note_unverified:no signature from a known key")
    return OpenedNote(parsed.text, tuple(verified), tuple(unknown))


# ---- checkpoints ----------------------------------------------------------------------------------
@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    #: c2sp.org/tlog-checkpoint extension lines: opaque, non-empty, and signed only by 0x01, 0x02 and 0x04 lines.
    extensions: tuple[str, ...] = ()

    def text(self) -> str:
        lines = [self.origin, str(self.size), base64.b64encode(self.root).decode(), *self.extensions]
        return "\n".join(lines) + "\n"


def parse_checkpoint(text: str) -> Checkpoint:
    if not text.endswith("\n"):
        raise NoteError("checkpoint_malformed:checkpoint text ends in a newline")
    lines = text[:-1].split("\n")
    if len(lines) < 3 or any(not line for line in lines):
        raise NoteError("checkpoint_malformed:a checkpoint is origin, size, root and non-empty extension lines")
    if any(ord(ch) < 0x20 for line in lines for ch in line):
        raise NoteError("note_control_character")
    if not valid_name(lines[0]):
        raise NoteError(f"note_name_invalid:origin {lines[0]!r}")
    raw = b64decode_canonical(lines[2])
    if len(raw) != 32:
        raise NoteError("checkpoint_root_length:checkpoint root is 32 bytes")
    return Checkpoint(lines[0], parse_decimal(lines[1], "tree size"), raw, tuple(lines[3:]))


# ---- signing: one function per signature type --------------------------------------------------------
def _ed25519_public(signer: Any) -> Ed25519PublicKey:
    """The public half of an Ed25519 private key or of any ``SigningKey`` backend (local, Vault, KMS, delegated)."""
    public = signer.public_key() if isinstance(signer, Ed25519PrivateKey) else signer.public
    if not isinstance(public, Ed25519PublicKey):
        raise NoteError("vkey_type_mismatch:an Ed25519 log signature needs an Ed25519 key")
    return public


def log_signature(text: str, name: str, signer: Any) -> SigLine:
    """An Ed25519 log signature (type 0x01) over the note text; ``signer`` is an Ed25519 private key or any
    ``SigningKey`` (``sign(bytes)`` and ``public``)."""
    if not valid_name(name):
        raise NoteError(f"note_name_invalid:{name!r}")
    public = _ed25519_public(signer)
    return SigLine(name, note_key_id(name, SIG_ED25519, _raw(public)), signer.sign(text.encode()))


def ecdsa_signature(text: str, name: str, key: ec.EllipticCurvePrivateKey) -> SigLine:
    """An ECDSA note signature (type 0x02): ASN.1 ECDSA over SHA-256 of the note text, as Rekor signs."""
    vk = VerifierKey.ecdsa(name, key.public_key())
    return SigLine(name, vk.id, key.sign(text.encode(), ec.ECDSA(hashes.SHA256())))


def _tree_head(timestamp_ms: int, size: int, root_hash: bytes) -> bytes:
    """RFC 6962 section 3.5 ``TreeHeadSignature``: v1, tree_hash, timestamp, tree size, SHA-256 root."""
    return b"\x00\x01" + timestamp_ms.to_bytes(8, "big") + size.to_bytes(8, "big") + root_hash


def rfc6962_signature(cp: Checkpoint, key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey,
                      timestamp_ms: int) -> SigLine:
    """A Static CT checkpoint signature (type 0x05): timestamp || TLS ``DigitallySigned`` TreeHeadSignature, named
    after the origin. A checkpoint signed this way carries no extension lines."""
    if cp.extensions:
        raise NoteError("checkpoint_extensions_unsigned:an RFC 6962 signature forbids extension lines")
    if not 0 <= timestamp_ms <= MAX_TIMESTAMP:
        raise NoteError("cosignature_timestamp_range")
    vk = VerifierKey.rfc6962(cp.origin, key.public_key())
    message = _tree_head(timestamp_ms, cp.size, cp.root)
    if isinstance(key, rsa.RSAPrivateKey):
        alg, sig = 1, key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    else:
        alg, sig = 3, key.sign(message, ec.ECDSA(hashes.SHA256()))
    return SigLine(cp.origin, vk.id, timestamp_ms.to_bytes(8, "big") + bytes([4, alg]) + len(sig).to_bytes(2, "big")
                   + sig)


def rfc6962_timestamp(line: SigLine) -> int:
    """The millisecond timestamp of a 0x05 line."""
    if len(line.sig) < 13:
        raise NoteError("note_signature_length:an RFC 6962 note signature is too short")
    return int.from_bytes(line.sig[:8], "big")


def cosignature_message(timestamp: int, text: str) -> bytes:
    if not 0 <= timestamp <= MAX_TIMESTAMP:
        raise NoteError("cosignature_timestamp_range")
    return f"cosignature/v1\ntime {timestamp}\n{text}".encode()


def _signable(text: str) -> Checkpoint:
    """The checkpoint a signer may sign: a tree of size 0 carries the RFC 6962 hash of the empty string."""
    cp = parse_checkpoint(text)
    if cp.size == 0 and not is_empty_root(cp.root):
        raise NoteError("checkpoint_malformed:a tree of size 0 has the root of the empty tree")
    return cp


def cosign(text: str, name: str, key: Ed25519PrivateKey, timestamp: int) -> SigLine:
    """An Ed25519 checkpoint cosignature (type 0x04): timestamp || signature, covering extension lines."""
    _signable(text)
    sig = key.sign(cosignature_message(timestamp, text))
    return SigLine(name, VerifierKey.cosignature_v1(name, key.public_key()).id, timestamp.to_bytes(8, "big") + sig)


def subtree_message(cosigner: str, timestamp: int, origin: str, start: int, end: int, root_hash: bytes) -> bytes:
    """The CosignedSubtree an ML-DSA-44 cosignature signs, in TLS presentation: the 12-byte label, the cosigner name
    and the log origin each with a one-byte length, the timestamp, start and end as big-endian uint64, the 32-byte
    hash. A checkpoint cosignature has start 0 and end = tree size; a subtree with a non-zero start has timestamp 0."""
    name, log = cosigner.encode(), origin.encode()
    if not (1 <= len(name) <= 255 and 1 <= len(log) <= 255):
        raise NoteError("cosignature_input_range:cosigner name and log origin are 1 to 255 bytes")
    if not (0 <= timestamp <= MAX_TIMESTAMP and 0 <= start <= end <= MAX_TIMESTAMP and len(root_hash) == 32):
        raise NoteError("cosignature_input_range:timestamp, bounds or hash out of range")
    if start and timestamp:
        raise NoteError("cosignature_input_range:a subtree with a non-zero start carries timestamp 0")
    if start == end and root_hash != EMPTY_ROOT:
        raise NoteError("cosignature_input_range:an empty subtree carries the hash of the empty string")
    return b"".join([SUBTREE_LABEL, bytes([len(name)]), name, timestamp.to_bytes(8, "big"), bytes([len(log)]), log,
                     start.to_bytes(8, "big"), end.to_bytes(8, "big"), root_hash])


def cosign_mldsa(text: str, name: str, key: MLDSA44PrivateKey, timestamp: int) -> SigLine:
    """An ML-DSA-44 checkpoint cosignature (type 0x06): timestamp || FIPS 204 signature, empty context. It does not
    cover extension lines, so a checkpoint that carries any is refused rather than half-signed."""
    cp = _signable(text)
    if cp.extensions:
        raise NoteError("checkpoint_extensions_unsigned:an ML-DSA-44 cosignature does not cover extension lines")
    return _mldsa_checkpoint_line(name, key, cp, timestamp)


def _mldsa_checkpoint_line(name: str, key: MLDSA44PrivateKey, cp: Checkpoint, timestamp: int) -> SigLine:
    """The one maker of ML-DSA-44 checkpoint cosignature lines. Its timestamp is never 0: the same bytes with
    timestamp 0 are a subtree cosignature of ``[0, size)`` (c2sp.org/tlog-cosignature), which says nothing about
    the latest checkpoint, so ``verify_line`` refuses a 0x06 line dated 0 and this refuses to make one."""
    if timestamp == 0:
        raise NoteError("cosignature_timestamp_range:a checkpoint cosignature is dated; 0 marks a subtree cosignature")
    sig = key.sign(subtree_message(name, timestamp, cp.origin, 0, cp.size, cp.root))
    return SigLine(name, VerifierKey.mldsa44(name, key.public_key()).id, timestamp.to_bytes(8, "big") + sig)


def cosign_subtree(name: str, key: MLDSA44PrivateKey, origin: str, start: int, end: int, sub_hash: bytes) -> bytes:
    """An ML-DSA-44 subtree cosignature: the bare FIPS 204 signature over the subtree, no timestamp."""
    if not valid_subtree(start, end):
        raise NoteError(f"subtree_invalid:[{start}, {end})")
    return key.sign(subtree_message(name, 0, origin, start, end, sub_hash))


def verify_subtree_cosignature(key: VerifierKey, origin: str, start: int, end: int, sub_hash: bytes,
                               sig: bytes) -> bool:
    """Whether ``sig`` is ``key``'s ML-DSA-44 subtree cosignature of ``[start, end)`` with hash ``sub_hash``."""
    if key.sig_type != SIG_MLDSA44 or len(sig) != MLDSA44_SIG_LEN or not valid_subtree(start, end):
        return False
    try:
        return key.verify(sig, subtree_message(key.name, 0, origin, start, end, sub_hash))
    except NoteError:
        return False


def sign_checkpoint(cp: Checkpoint, signer: Any, *, name: str | None = None, pq: MLDSA44PrivateKey | None = None,
                    timestamp: int = 0) -> str:
    """The log's signed note: an Ed25519 log signature by ``signer`` (a private key or any ``SigningKey``) under
    ``name`` (the origin by default), plus the log's own ML-DSA-44 checkpoint cosignature dated ``timestamp`` when
    it holds a post-quantum key ``pq``."""
    text = cp.text()
    _signable(text)
    key_name = cp.origin if name is None else name
    lines = [log_signature(text, key_name, signer)]
    if pq is not None:
        lines.append(cosign_mldsa(text, key_name, pq, timestamp))
    return Note(text, tuple(lines)).encode()


def log_vkey(origin: str, signer: Any) -> str:
    return VerifierKey.ed25519(origin, _ed25519_public(signer)).encode()


def _verify_rfc6962(key: VerifierKey, text: str, line: SigLine) -> None:
    cp = parse_checkpoint(text)
    if cp.extensions:
        raise NoteError("checkpoint_extensions_unsigned:an RFC 6962 signature forbids extension lines")
    sig = line.sig
    if len(sig) < 13 or int.from_bytes(sig[10:12], "big") != len(sig) - 12 or sig[8] != 4:
        raise NoteError(f"note_signature_length:RFC 6962 signature from {key.name} is malformed")
    timestamp, alg, raw = int.from_bytes(sig[:8], "big"), sig[9], sig[12:]
    public = key.public_key()
    if timestamp > MAX_TIMESTAMP or cp.origin != key.name:
        raise NoteError(f"note_signature_invalid:RFC 6962 signature from {key.name}")
    message = _tree_head(timestamp, cp.size, cp.root)
    try:
        if alg == 3 and isinstance(public, ec.EllipticCurvePublicKey):
            public.verify(raw, message, ec.ECDSA(hashes.SHA256()))
        elif alg == 1 and isinstance(public, rsa.RSAPublicKey):
            public.verify(raw, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise InvalidSignature
    except (InvalidSignature, ValueError) as exc:
        raise NoteError(f"note_signature_invalid:RFC 6962 signature from {key.name}") from exc


def verify_line(key: VerifierKey, text: str, line: SigLine) -> int | None:
    """One signature line from a known key: None for a valid log signature (0x01, 0x02, 0x05), the timestamp for a
    valid cosignature (0x04, 0x06, a log's own ML-DSA-44 line included); ``NoteError`` when it does not verify."""
    if key.sig_type == SIG_MLDSA44:
        if len(line.sig) != 8 + MLDSA44_SIG_LEN:
            raise NoteError(f"note_signature_length:ML-DSA-44 cosignature from {key.name}")
        timestamp = int.from_bytes(line.sig[:8], "big")
        cp = parse_checkpoint(text)
        if timestamp == 0:  # a subtree cosignature of [0, size): never a statement about the latest checkpoint
            raise NoteError(f"note_signature_invalid:ML-DSA-44 line from {key.name} is dated 0, a subtree cosignature")
        if timestamp > MAX_TIMESTAMP or not key.verify(
                line.sig[8:], subtree_message(key.name, timestamp, cp.origin, 0, cp.size, cp.root)):  # fmt: skip
            raise NoteError(f"note_signature_invalid:ML-DSA-44 cosignature from {key.name}")
        return timestamp
    if key.sig_type == SIG_RFC6962:
        _verify_rfc6962(key, text, line)
        return None
    if key.sig_type in (SIG_ED25519, SIG_ECDSA):
        if key.sig_type == SIG_ED25519 and len(line.sig) != 64:
            raise NoteError(f"note_signature_length:Ed25519 signature from {key.name}")
        if not key.verify(line.sig, text.encode()):
            raise NoteError(f"note_signature_invalid:signature from {key.name}")
        return None
    if len(line.sig) != 72:
        raise NoteError(f"note_signature_length:cosignature from {key.name}")
    timestamp = int.from_bytes(line.sig[:8], "big")
    if timestamp > MAX_TIMESTAMP or not key.verify(line.sig[8:], cosignature_message(timestamp, text)):
        raise NoteError(f"note_signature_invalid:cosignature from {key.name}")
    return timestamp


# ---- tlog-proof ---------------------------------------------------------------------------------
@dataclass(frozen=True)
class TlogProof:
    """c2sp.org/tlog-proof@v1: an offline proof that a leaf is in a log, checkable without contacting the log."""

    index: int
    proof: tuple[bytes, ...]
    checkpoint: str
    extra: bytes | None = None

    def encode(self) -> str:
        head = [PROOF_HEADER]
        if self.extra is not None:
            head.append(f"extra {base64.b64encode(self.extra).decode()}")
        head.append(f"index {self.index}")
        head.extend(base64.b64encode(h).decode() for h in self.proof)
        return "\n".join(head) + "\n\n" + self.checkpoint


def parse_tlog_proof(text: str) -> TlogProof:
    head, sep, checkpoint = text.partition("\n\n")
    lines = head.split("\n")
    if not sep or lines[0] != PROOF_HEADER or len(lines) < 2:
        raise NoteError("proof_malformed:a tlog-proof starts with the c2sp.org/tlog-proof@v1 line")
    extra = None
    rest = lines[1:]
    if rest[0].startswith("extra "):
        extra, rest = b64decode_canonical(rest[0][6:]), rest[1:]
    if not rest or not rest[0].startswith("index "):
        raise NoteError("proof_malformed:the index line is missing")
    index = parse_decimal(rest[0][6:], "leaf index")
    if len(rest) - 1 > MAX_PROOF_LINES:
        raise NoteError("proof_malformed:more than 63 proof lines")
    proof = tuple(b64decode_canonical(line) for line in rest[1:])
    if any(len(h) != 32 for h in proof):
        raise NoteError("proof_malformed:each proof line is one 32-byte hash")
    parse_note(checkpoint)
    return TlogProof(index, proof, checkpoint, extra)


def verify_tlog_proof(text: str, leaf: bytes, policy: Policy, now: int | None = None,
                      max_age: int | None = None) -> VerifiedCheckpoint:
    """Accept a tlog-proof when its checkpoint passes ``verify_note`` and ``leaf`` (a leaf hash) is included."""
    proof = parse_tlog_proof(text)
    verified = verify_note(proof.checkpoint, policy, now=now, max_age=max_age)
    cp = verified.checkpoint
    if not verify_inclusion(proof.index, cp.size, leaf, proof.proof, cp.root):
        raise NoteError(f"proof_inclusion_invalid:leaf {proof.index} of {cp.size}")
    return verified


# ---- tlog-policy ----------------------------------------------------------------------------------
@dataclass
class Policy:
    """c2sp.org/tlog-policy: log keys, named witnesses, groups, one quorum, and the optional URLs."""

    logs: list[VerifierKey] = field(default_factory=list)
    witnesses: dict[str, VerifierKey] = field(default_factory=dict)
    groups: dict[str, tuple[int, tuple[str, ...]]] = field(default_factory=dict)
    quorum: str = ""
    #: the URL a ``log`` line names, keyed by its vkey text
    log_urls: dict[str, str] = field(default_factory=dict)
    #: the URL a ``witness`` line names, keyed by the witness name
    witness_urls: dict[str, str] = field(default_factory=dict)

    def satisfied(self, cosigned: set[str], name: str | None = None) -> bool:
        name = self.quorum if name is None else name
        if name == "none":
            return True
        if name in self.witnesses:
            return name in cosigned
        k, members = self.groups[name]
        return sum(self.satisfied(cosigned, m) for m in members) >= k


_POLICY_BYTES = re.compile(rb"[\t\n\x20-\x7e\x80-\xff]*\Z")


class _PolicyReader:
    def __init__(self) -> None:
        self.policy, self.keys, self.members = Policy(), set[bytes](), set[str]()

    def key(self, text: str, sig_types: tuple[int, ...]) -> VerifierKey:
        k = parse_vkey(text)
        if k.sig_type not in sig_types:
            raise NoteError(f"policy_key_type:{k.name} has type {k.sig_type:#04x}")
        if k.public in self.keys:
            raise NoteError(f"policy_key_repeated:{k.name}")
        self.keys.add(k.public)
        return k

    def fresh(self, name: str) -> str:
        if name == "none" or name in self.policy.witnesses or name in self.policy.groups:
            raise NoteError(f"policy_name_reserved:{name!r}")
        return name

    def group(self, name: str, threshold: str, members: tuple[str, ...]) -> None:
        known = set(self.policy.witnesses) | set(self.policy.groups)
        if len(set(members)) != len(members) or not set(members) <= known or self.members & set(members):
            raise NoteError("policy_group_members:members are earlier-defined names, each listed in one group only")
        self.members |= set(members)
        k = {"all": len(members), "any": 1}.get(threshold) or parse_decimal(threshold, "group threshold")
        if not 1 <= k <= len(members):
            raise NoteError("policy_group_threshold:a group threshold is 1 to n")
        self.policy.groups[self.fresh(name)] = (k, members)

    def line(self, raw: str) -> None:
        words = [w for w in re.split(r"[ \t]+", raw) if w]
        if not words or words[0].startswith("#"):
            return
        kind, args, policy = words[0], words[1:], self.policy
        if kind == "log" and len(args) in (1, 2):
            policy.logs.append(self.key(args[0], LOG_TYPES))
            if len(args) == 2:
                policy.log_urls[args[0]] = args[1]
        elif kind == "witness" and len(args) in (2, 3):
            policy.witnesses[self.fresh(args[0])] = self.key(args[1], WITNESS_TYPES)
            if len(args) == 3:
                policy.witness_urls[args[0]] = args[2]
        elif kind == "group" and len(args) >= 3:
            self.group(args[0], args[1], tuple(args[2:]))
        elif kind == "quorum" and len(args) == 1:
            if policy.quorum:
                raise NoteError("policy_quorum_count:a policy has exactly one quorum line")
            if args[0] != "none" and args[0] not in policy.witnesses and args[0] not in policy.groups:
                raise NoteError(f"policy_quorum_undefined:{args[0]!r}")
            policy.quorum = args[0]
        else:
            raise NoteError(f"policy_line_malformed:{raw!r}")


def parse_policy(text: str | bytes) -> Policy:
    """Read a policy from text or octets; names are opaque octets, so non-UTF-8 bytes survive as surrogates."""
    raw = text if isinstance(text, bytes) else text.encode("utf-8", "surrogateescape")
    if not _POLICY_BYTES.match(raw):
        raise NoteError("policy_control_character")
    reader = _PolicyReader()
    for line in raw.decode("utf-8", "surrogateescape").split("\n"):
        reader.line(line)
    if not reader.policy.quorum:
        raise NoteError("policy_quorum_count:a policy has exactly one quorum line")
    return reader.policy


@dataclass(frozen=True)
class VerifiedCheckpoint:
    checkpoint: Checkpoint
    cosigned_at: dict[str, int]
    #: the types of the log's own valid signatures (0x01, 0x02, 0x05, and 0x06 when it also signs post-quantum)
    log_types: frozenset[int] = frozenset()

    def post_quantum(self, policy: Policy) -> set[str]:
        """The counted witnesses whose policy key is ML-DSA-44 (type 0x06)."""
        return {w for w in self.cosigned_at if policy.witnesses[w].post_quantum}


def verify_note(note: str, policy: Policy, now: int | None = None, max_age: int | None = None,
                max_skew: int = 300) -> VerifiedCheckpoint:
    """Accept a checkpoint only when a policy log signed it and the witness quorum cosigned it.

    Offline (``now`` None) every valid cosignature counts; with ``now`` and ``max_age`` only fresh ones do, and one
    dated more than ``max_skew`` seconds after ``now`` is not counted: a witness whose clock runs ahead can neither
    veto a quorum the other witnesses meet nor complete one. A known key whose signature fails rejects the note;
    unknown keys are ignored. A log's own ML-DSA-44 line authenticates the log like its other lines, is reported in
    ``log_types``, and never counts as a witness. A checkpoint with extension lines needs a verified log line that
    signs them (0x01 or 0x02): no ML-DSA-44 line signs them and a 0x05 line forbids them.
    """
    parsed = parse_note(note)
    cp = parse_checkpoint(parsed.text)
    if cp.size == 0 and not is_empty_root(cp.root):
        raise NoteError("checkpoint_malformed:a tree of size 0 has the root of the empty tree")
    known: dict[tuple[str, bytes], tuple[str, VerifierKey]] = {}
    for k in policy.logs:
        if k.name == cp.origin:
            known[(k.name, k.id)] = ("", k)
    for wname, k in policy.witnesses.items():
        known[(k.name, k.id)] = (wname, k)
    log_types: set[int] = set()
    cosigned: dict[str, int] = {}
    for line in parsed.sigs:
        entry = known.get((line.name, line.key_id))
        if entry is None:
            continue
        wname, k = entry
        ts = verify_line(k, parsed.text, line)
        if not wname:
            log_types.add(k.sig_type)
        elif ts is None:  # unreachable: a policy witness key is a cosignature type
            raise NoteError(f"policy_key_type:witness {wname} key is not a cosignature key")
        elif now is not None and ts > now + max_skew:
            continue  # dated ahead of our clock: not counted, so it neither vetoes nor completes the quorum
        elif now is None or max_age is None or now - ts <= max_age:
            cosigned[wname] = ts
    if not log_types:
        raise NoteError("checkpoint_log_signature_missing")
    if cp.extensions and not log_types & set(COVERS_EXTENSIONS):
        raise NoteError("checkpoint_extensions_unsigned:no verified log signature covers the extension lines")
    if not policy.satisfied(set(cosigned)):
        raise NoteError(f"witness_quorum_not_met:{policy.quorum}:cosigned_by_{sorted(cosigned) or 'none'}")
    return VerifiedCheckpoint(cp, cosigned, frozenset(log_types))


# ---- tlog-witness protocol ------------------------------------------------------------------------
class WitnessRefused(Exception):
    """A witness refusal: the HTTP status, ``code[:detail]``, and the response body (the size for a 409)."""

    def __init__(self, status: int, message: str, body: str = "") -> None:
        super().__init__(f"{status}: {message}")
        self.status, self.message, self.body = status, message, body

    @property
    def code(self) -> str:
        return self.message.split(":", 1)[0]


def encode_add_checkpoint(old: int, proof: Sequence[bytes], note: str) -> str:
    return "\n".join([f"old {old}", *(base64.b64encode(h).decode() for h in proof)]) + "\n\n" + note


def _proof_lines(lines: Sequence[str]) -> list[bytes]:
    if len(lines) > MAX_PROOF_LINES:
        raise WitnessRefused(400, "witness_proof_lines_excess:more than 63 proof lines")
    try:
        proof = [b64decode_canonical(line) for line in lines]
    except NoteError as exc:
        raise WitnessRefused(400, f"witness_request_malformed:{exc}") from exc
    if any(len(h) != 32 for h in proof):
        raise WitnessRefused(400, "witness_request_malformed:each proof line is one 32-byte hash")
    return proof


def parse_add_checkpoint(body: str) -> tuple[int, list[bytes], str]:
    head, sep, rest = body.partition("\n\n")
    lines = head.split("\n")
    if not sep or not lines[0].startswith("old "):
        raise WitnessRefused(400, "witness_request_malformed:an old size line, proof lines, a blank line")
    try:
        old = parse_decimal(lines[0][4:], "old size")
    except NoteError as exc:
        raise WitnessRefused(400, f"witness_request_malformed:{exc}") from exc
    return old, _proof_lines(lines[1:]), rest


def encode_sign_subtree(start: int, end: int, sub_hash: bytes, proof: Sequence[bytes], note: str) -> str:
    lines = [f"subtree {start} {end}", base64.b64encode(sub_hash).decode(),
             *(base64.b64encode(h).decode() for h in proof)]
    return "\n".join(lines) + "\n\n" + note


def parse_sign_subtree(body: str) -> tuple[int, int, bytes, list[bytes], str]:
    head, sep, rest = body.partition("\n\n")
    lines = head.split("\n")
    words = lines[0].split(" ")
    if not sep or len(lines) < 2 or len(words) != 3 or words[0] != "subtree":
        raise WitnessRefused(400, "witness_request_malformed:a subtree line, the hash, proof lines, a blank line")
    try:
        start, end = parse_decimal(words[1], "subtree start"), parse_decimal(words[2], "subtree end")
        sub_hash = b64decode_canonical(lines[1])
    except NoteError as exc:
        raise WitnessRefused(400, f"witness_request_malformed:{exc}") from exc
    if len(sub_hash) != 32:
        raise WitnessRefused(400, "witness_request_malformed:the subtree hash is 32 bytes")
    if not valid_subtree(start, end) or start == end:
        raise WitnessRefused(400, f"witness_subtree_invalid:[{start}, {end})")
    return start, end, sub_hash, _proof_lines(lines[2:]), rest


def _witness_line(text: str, name: str, key: Any, timestamp: int) -> SigLine:
    """A witness's cosignature with one of its keys. An ML-DSA-44 witness line signs origin, size and root; a witness
    attests consistency, so it cosigns a checkpoint that carries extension lines too."""
    if isinstance(key, MLDSA44PrivateKey):
        return _mldsa_checkpoint_line(name, key, _signable(text), timestamp)
    return cosign(text, name, key, timestamp)


def _origin_hash(origin: str) -> str:
    return hashlib.sha256(origin.encode()).hexdigest()


@dataclass
class Witness:
    """A cosigner: its name and keys (the customer's), the log keys it trusts, its per-origin state.

    ``key`` and each of ``more_keys`` is an ML-DSA-44 (preferred by c2sp.org/tlog-witness) or Ed25519 private key;
    the witness cosigns with every one. ``state_dir`` holds one file per origin, ``<hex SHA-256 of origin>.checkpoint``:
    the latest cosigned checkpoint, which is both the state and the monitor's copy. It is written whole and durably
    before the witness answers, and ``add_checkpoint`` re-reads it under an exclusive lock on the directory before it
    checks the old size, so neither a restart, a crash nor a second process on the same directory lets the witness
    forget what it signed (forgetting would let a log fork past it).
    """

    name: str
    key: MLDSA44PrivateKey | Ed25519PrivateKey
    logs: dict[str, list[VerifierKey]]
    state_dir: Path | None = None
    clock: Clock = field(kw_only=True)
    more_keys: tuple[MLDSA44PrivateKey | Ed25519PrivateKey, ...] = field(default=(), kw_only=True)
    _latest: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    _notes: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if not valid_name(self.name):
            raise NoteError(f"note_name_invalid:{self.name!r}")
        for origin, keys in self.logs.items():
            if len(keys) + len(self.keys) > MAX_SIGNATURES:  # the monitor copy holds the log lines and our own
                raise NoteError(f"note_signature_count:{origin!r} would carry {len(keys) + len(self.keys)} lines")
        if self.state_dir is None:
            return
        self.state_dir = Path(self.state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with _dir_lock(self.state_dir):
            self._reload()

    def _reload(self) -> None:
        """Read every origin's latest cosigned checkpoint from its one file. A file that does not parse, or whose
        origin does not hash to its name, refuses: a witness never runs on state it cannot read.

        Release 0.12.0 kept ``<hex of origin>.state`` (size and root) instead. Such a file is read as the floor for
        its origin until that origin's checkpoint file exists, then removed: dropping it unread would be a restart
        that forgets what the witness signed, the one fault a witness exists to prevent, so this is the one place a
        former format is still read."""
        if self.state_dir is None:
            return
        directory = Path(self.state_dir)
        try:
            for f in directory.glob("*.state"):
                size, root_b64 = f.read_text().split()
                origin = bytes.fromhex(f.stem).decode()
                if not (directory / (_origin_hash(origin) + ".checkpoint")).exists():
                    self._latest[origin] = (parse_decimal(size, "tree size"), b64decode_canonical(root_b64))
            for f in directory.glob("*.checkpoint"):
                note = f.read_text()
                cp = parse_checkpoint(parse_note(note).text)
                if _origin_hash(cp.origin) != f.stem:
                    raise NoteError(f"checkpoint_malformed:{f.name} holds the checkpoint of {cp.origin!r}")
                self._notes[f.stem] = note
                self._latest[cp.origin] = (cp.size, cp.root)
        except (OSError, ValueError) as exc:
            raise WitnessRefused(500, f"witness_state_unreadable:{exc}") from exc

    @property
    def keys(self) -> tuple[MLDSA44PrivateKey | Ed25519PrivateKey, ...]:
        return (self.key, *self.more_keys)

    @property
    def vkeys(self) -> list[VerifierKey]:
        return [VerifierKey.mldsa44(self.name, k.public_key()) if isinstance(k, MLDSA44PrivateKey)
                else VerifierKey.cosignature_v1(self.name, k.public_key()) for k in self.keys]

    @property
    def vkey(self) -> VerifierKey:
        return self.vkeys[0]

    def _save(self, origin: str, size: int, root_hash: bytes, note: str) -> None:
        """Persist first, then remember: a write that fails leaves memory and disk at the old checkpoint, and the
        caller answers with a refusal, never a cosignature."""
        if self.state_dir is not None:
            directory = Path(self.state_dir)
            try:
                _write_whole(directory / (_origin_hash(origin) + ".checkpoint"), note)
                legacy = directory / (origin.encode().hex() + ".state")
                if len(legacy.name.encode()) <= 255:
                    legacy.unlink(missing_ok=True)
            except OSError as exc:
                raise WitnessRefused(500, f"witness_state_unwritable:{exc}") from exc
        self._latest[origin] = (size, root_hash)
        self._notes[_origin_hash(origin)] = note

    def _trusted_note(self, note_text: str) -> tuple[Note, Checkpoint]:
        parsed, cp, _ = self._trusted_lines(note_text)
        return parsed, cp

    def _trusted_lines(self, note_text: str) -> tuple[Note, Checkpoint, tuple[SigLine, ...]]:
        try:
            parsed = parse_note(note_text)
            cp = parse_checkpoint(parsed.text)
        except NoteError as exc:
            raise WitnessRefused(400, f"witness_request_malformed:{exc}") from exc
        trusted = {(k.name, k.id): k for k in self.logs.get(cp.origin, [])}
        if not trusted:
            raise WitnessRefused(404, f"witness_origin_unknown:{cp.origin!r}")
        signed: list[SigLine] = []
        for line in parsed.sigs:
            k = trusted.get((line.name, line.key_id))
            if k is None:
                continue
            try:
                verify_line(k, parsed.text, line)
            except NoteError as exc:
                raise WitnessRefused(403, f"witness_log_signature_invalid:{exc}") from exc
            signed.append(line)
        if not signed:
            raise WitnessRefused(403, "witness_log_signature_missing")
        return parsed, cp, tuple(signed)

    def add_checkpoint(self, body: str) -> str:
        old, proof, note_text = parse_add_checkpoint(body)
        parsed, cp, verified = self._trusted_lines(note_text)
        with self._lock, _dir_lock(self.state_dir):
            self._reload()
            size, stored = self._latest.get(cp.origin, (0, EMPTY_ROOT))
            if old > cp.size:
                raise WitnessRefused(400, "witness_old_size_beyond:old size is larger than the checkpoint size")
            if old != size:
                raise WitnessRefused(409, "witness_old_size_mismatch", f"{size}\n")
            if cp.size == 0 and not is_empty_root(cp.root):
                raise WitnessRefused(422, "witness_empty_root_required")
            if not verify_consistency(old, cp.size, stored, cp.root, proof):
                raise WitnessRefused(422, "witness_consistency_invalid")
            now = self.clock.now() // NS_PER_S
            lines = [_witness_line(parsed.text, self.name, k, now) for k in self.keys]
            self._save(cp.origin, cp.size, cp.root, Note(parsed.text, verified + tuple(lines)).encode())
        return "".join(line.encode() for line in lines)

    def sign_subtree(self, body: str) -> str:
        """c2sp.org/tlog-witness ``sign-subtree``: a base64 ML-DSA-44 subtree cosignature and a newline."""
        start, end, sub_hash, proof, note_text = parse_sign_subtree(body)
        pq = [k for k in self.keys if isinstance(k, MLDSA44PrivateKey)]
        if not pq:
            raise WitnessRefused(404, "witness_subtree_unsupported:this witness holds no ML-DSA-44 key")
        try:
            parsed = parse_note(note_text)
            cp = parse_checkpoint(parsed.text)
        except NoteError as exc:
            raise WitnessRefused(400, f"witness_request_malformed:{exc}") from exc
        own = {(k.name, k.id): (k, private) for k, private in zip(self.vkeys, self.keys, strict=True)}
        if len(parsed.sigs) != 1:
            raise WitnessRefused(400, "witness_request_malformed:the reference checkpoint carries exactly one signature")
        line = parsed.sigs[0]
        if (line.name, line.key_id) not in own:
            raise WitnessRefused(403, "witness_checkpoint_not_cosigned:the signature is not from this witness")
        own_key, private = own[(line.name, line.key_id)]
        if not isinstance(private, MLDSA44PrivateKey):
            raise WitnessRefused(403, "witness_subtree_unsupported:the key that cosigned the reference is Ed25519")
        try:
            verify_line(own_key, parsed.text, line)
        except NoteError as exc:
            raise WitnessRefused(403, f"witness_checkpoint_not_cosigned:{exc}") from exc
        if end > cp.size:
            raise WitnessRefused(400, f"witness_subtree_invalid:[{start}, {end}) beyond size {cp.size}")
        if not verify_subtree_consistency(proof, cp.size, cp.root, start, end, sub_hash):
            raise WitnessRefused(422, "witness_subtree_proof_invalid")
        return base64.b64encode(cosign_subtree(self.name, private, cp.origin, start, end, sub_hash)).decode() + "\n"

    def latest_checkpoint(self, origin_hash: str) -> str | None:
        """The latest checkpoint this witness cosigned for the origin whose SHA-256 is ``origin_hash`` (hex), read from
        the state file when there is one, so a second process on the directory serves what the first persisted."""
        if self.state_dir is not None and re.fullmatch(r"[0-9a-f]{64}", origin_hash):
            path = Path(self.state_dir) / (origin_hash + ".checkpoint")
            try:
                return path.read_text() if path.exists() else None
            except OSError:
                return None
        return self._notes.get(origin_hash)


class _dir_lock:
    """An exclusive lock on a state directory, so two witness processes check and persist one after the other."""

    def __init__(self, directory: Path | None) -> None:
        self.directory, self.fd = directory, -1

    def __enter__(self) -> None:
        if self.directory is not None:
            self.fd = os.open(Path(self.directory) / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(self.fd, fcntl.LOCK_EX)

    def __exit__(self, *_: object) -> None:
        if self.fd >= 0:
            os.close(self.fd)


_MAX_REQUEST = 1 << 16


def serve_witness(witness: Witness, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """c2sp.org/tlog-witness over HTTP: ``POST add-checkpoint``, ``POST sign-subtree`` and the monitor's
    ``GET <hex SHA-256 of origin>/checkpoint``. Returns the started server."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            return

        def do_GET(self) -> None:
            parts = self.path.rstrip("/").split("/")
            note = witness.latest_checkpoint(parts[-2]) if len(parts) >= 2 and parts[-1] == "checkpoint" else None
            if note is None:
                self._refuse(404, "witness_not_found")
                return
            self._reply(200, note)

        def do_POST(self) -> None:
            handlers = {"add-checkpoint": witness.add_checkpoint, "sign-subtree": witness.sign_subtree}
            handle = handlers.get(self.path.rstrip("/").split("/")[-1])
            if handle is None:
                self._refuse(404, "witness_not_found")
                return
            declared = self.headers.get("Content-Length", "0").strip()
            if not _DECIMAL.match(declared) or len(declared) > 19:
                self._refuse(400, "witness_request_malformed:Content-Length is not an ASCII decimal")
                return
            if int(declared) > _MAX_REQUEST:
                self._refuse(400, "witness_request_too_large")
                return
            try:
                out = handle(self.rfile.read(int(declared)).decode())
            except WitnessRefused as exc:
                self._reply(exc.status, exc.body or exc.message + "\n",
                            "text/x.tlog.size" if exc.status == 409 else "text/plain")
                return
            except UnicodeDecodeError:
                self._refuse(400, "witness_request_not_utf8")
                return
            except NoteError as exc:  # our own signing refused (a clock at 0, a key that cannot sign): never a crash
                self._refuse(500, exc.code)
                return
            self._reply(200, out)

        def _refuse(self, status: int, refusal: str) -> None:
            self._reply(status, refusal + "\n")

        def _reply(self, status: int, body: str, ctype: str = "text/plain") -> None:
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _request(req: urllib.request.Request, timeout: float, opener: Callable[..., Any]) -> str:
    try:
        with opener(req, timeout=timeout) as resp:
            data = resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise WitnessRefused(exc.code, f"witness_remote_refused:{body.strip() or exc.reason}", body) from exc
    try:
        return str(data.decode())
    except UnicodeDecodeError as exc:
        raise WitnessRefused(502, "witness_response_malformed:the witness answered with bytes that are not UTF-8") from exc


def add_checkpoint(url: str, body: str, timeout: float = 10.0,
                   opener: Callable[..., Any] = urllib.request.urlopen) -> str:
    """POST to a witness; the cosignature lines, or ``WitnessRefused`` with the status and body."""
    req = urllib.request.Request(url.rstrip("/") + "/add-checkpoint", data=body.encode(), method="POST")
    return _request(req, timeout, opener)


def sign_subtree(url: str, body: str, timeout: float = 10.0,
                 opener: Callable[..., Any] = urllib.request.urlopen) -> bytes:
    """POST ``sign-subtree`` to a witness; the raw subtree cosignature."""
    req = urllib.request.Request(url.rstrip("/") + "/sign-subtree", data=body.encode(), method="POST")
    return b64decode_canonical(_request(req, timeout, opener).rstrip("\n"))


def fetch_checkpoint(url: str, origin: str, timeout: float = 10.0,
                     opener: Callable[..., Any] = urllib.request.urlopen) -> str:
    """GET a witness's latest cosigned checkpoint for ``origin`` (the monitor retrieval endpoint)."""
    req = urllib.request.Request(f"{url.rstrip('/')}/{_origin_hash(origin)}/checkpoint", method="GET")
    return _request(req, timeout, opener)


def attach(note: str, response: str) -> str:
    """Append a witness's signature lines to a checkpoint note."""
    parsed = parse_note(note)
    extra = parse_note("x\n\n" + response).sigs
    return Note(parsed.text, parsed.sigs + extra).encode()


# ---- the authority's checkpoint feed ------------------------------------------------------------
def _write_whole(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` whole or not at all: a writer killed mid-write leaves the old file, never an
    empty or half-written one that the next reader cannot parse."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    with tmp.open("rb") as fh:
        os.fsync(fh.fileno())
    tmp.replace(path)
    fd = os.open(path.parent, os.O_RDONLY)  # the rename itself survives a crash only once the directory is synced
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


_SIGNATURE_LINE = f"{EM_DASH} ".encode()


def _whole_notes_end(data: bytes) -> int:
    """The end of the last whole entry of a checkpoint log: a note's last signature line, then the blank line."""
    end = pos = 0
    previous = b""
    for line in data.split(b"\n")[:-1]:
        pos += len(line) + 1
        if not line and previous.startswith(_SIGNATURE_LINE):
            end = pos
        previous = line
    return end


def _append_note(path: Path, note: str) -> None:
    """Append ``note`` and a blank line to the checkpoint log, durably, after cutting back any torn entry: bytes
    past the last whole entry are an append a killed writer never finished, and the next note must not be glued
    onto them."""
    data = path.read_bytes() if path.exists() else b""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        end = _whole_notes_end(data)
        if len(data) > end:
            os.ftruncate(fd, end)
            os.fsync(fd)
        os.write(fd, (note + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def journal_leaves(path: Path) -> list[bytes]:
    """Leaf hashes of a journal's complete lines (a torn tail is not a line)."""
    if not path.exists():
        return []
    data = path.read_bytes()
    end = data.rfind(b"\n") + 1
    return [leaf_hash(line) for line in data[:end].split(b"\n") if line.strip()]


@dataclass
class Feed:
    """Publishes a journal's checkpoint, cosigned by the customer's witnesses, at ``directory/checkpoint``.

    ``witnesses`` are ``(url, vkey)`` pairs: any c2sp.org/tlog-witness endpoint. With ``policy`` set,
    a checkpoint whose cosignatures do not meet its quorum is never published (fail closed), and
    ``publish`` raises.
    """

    journal: Any
    origin: str
    witnesses: Sequence[tuple[str, str]] = ()
    policy: Policy | None = None
    directory: Path | None = None
    poster: Callable[[str, str], str] = add_checkpoint

    def __post_init__(self) -> None:
        if not valid_name(self.origin):
            raise NoteError(f"note_name_invalid:origin {self.origin!r}")
        self.directory = Path(self.directory or Path(self.journal.directory) / "feed")
        self.directory.mkdir(parents=True, exist_ok=True)

    @property
    def _dir(self) -> Path:
        """The feed directory, which ``__post_init__`` always sets."""
        return cast(Path, self.directory)

    @property
    def log_key(self) -> Any:
        """The key that signs checkpoints: the root behind a delegated session key, so a witness pins
        one log key for the life of the deployment."""
        return getattr(self.journal.signer, "root", self.journal.signer)

    def vkey(self) -> str:
        return log_vkey(self.origin, self.log_key)

    def _state(self, wkey: VerifierKey) -> Path:
        return self._dir / f"witness-{wkey.id.hex()}.size"

    def _cosign(self, url: str, wkey: VerifierKey, note: str, leaves: list[bytes]) -> str:
        state = self._state(wkey)
        old = int(state.read_text()) if state.exists() else 0
        for _ in range(2):
            if old > len(leaves):
                raise WitnessRefused(409, f"witness_beyond_journal:{wkey.name} holds size {old}, past this journal's {len(leaves)}")
            body = encode_add_checkpoint(old, consistency_proof(old, leaves) if old else [], note)
            try:
                response = self.poster(url, body)
            except WitnessRefused as exc:
                if exc.status != 409:
                    raise
                old = parse_decimal(exc.body.strip(), "witness size")  # its own latest size: prove from there
                continue
            _write_whole(state, f"{len(leaves)}\n")
            return response
        raise WitnessRefused(409, f"witness_size_unstable:{wkey.name} kept moving its size")

    @staticmethod
    def _attach_verified(note: str, wkey: VerifierKey, response: str) -> str:
        """``note`` with the one line of ``response`` that is ``wkey``'s and verifies (c2sp.org/tlog-witness: the
        client MUST ignore signatures from unknown keys). A line under another witness's name and id is not this
        witness's to give, so a faulty witness can add nothing but its own cosignature, and a line the note already
        holds is not added twice."""
        parsed = parse_note(note)
        mine = [line for line in parse_note("x\n\n" + response).sigs if (line.name, line.key_id) == (wkey.name, wkey.id)]
        if not mine:
            raise NoteError(f"note_unverified:no cosignature from {wkey.name}")
        verify_line(wkey, parsed.text, mine[0])
        held = {(line.name, line.key_id) for line in parsed.sigs}
        return note if (wkey.name, wkey.id) in held else Note(parsed.text, (*parsed.sigs, mine[0])).encode()

    def publish(self) -> str:
        """Sign, gather cosignatures, check the policy, then publish; returns the published note."""
        leaves = journal_leaves(Path(self.journal.path))
        cp = Checkpoint(self.origin, len(leaves), root(leaves))
        note = sign_checkpoint(cp, self.log_key)
        errors = []
        for url, text in self.witnesses:
            wkey = parse_vkey(text)
            try:
                note = self._attach_verified(note, wkey, self._cosign(url, wkey, note, leaves))
            except (WitnessRefused, OSError, ValueError, http.client.HTTPException) as exc:
                errors.append(f"{wkey.name}: {exc}")  # one witness's fault is that witness's error, never the feed's
        if self.policy is not None:
            try:
                verify_note(note, self.policy)
            except NoteError as exc:
                raise WitnessRefused(503, f"feed_not_published:{exc}; witness errors: {errors}") from exc
        _write_whole(self._dir / "checkpoint", note)
        _append_note(self._dir / "checkpoints.log", note)
        return note

    def latest(self) -> str | None:
        path = self._dir / "checkpoint"
        return path.read_text() if path.exists() else None

    def witnessed_size(self) -> int:
        note = self.latest()
        return parse_checkpoint(parse_note(note).text).size if note else 0


@dataclass
class LagGate:
    """Stop issuing permits while more than ``max_unwitnessed`` journal lines wait for a cosigned
    checkpoint: a witness that goes dark halts the authority instead of leaving history unwitnessed."""

    feed: Feed
    max_unwitnessed: int

    def __call__(self, _request: Any = None) -> str | None:
        seq, _ = self.feed.journal._tail()
        return "witness_lag_exceeded" if seq - self.feed.witnessed_size() > self.max_unwitnessed else None
