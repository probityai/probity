"""A journal's checkpoints as C2SP tlog checkpoints, cosigned by witness keys the customer holds.

The authority signs; a witness the customer runs (this module's ``WitnessServer``, or any
c2sp.org/tlog-witness implementation such as litewitness or omniwitness) cosigns a checkpoint only
when an RFC 9162 consistency proof links it to the last one it cosigned. A verifier that pins the
customer's witness key (a c2sp.org/tlog-policy) then refuses, offline, any journal the authority
could have rewritten or shown in two versions, because the customer's key would have had to sign both.

The tree: leaf ``i`` is the bytes of journal line ``i`` (no newline), hashed per RFC 9162
(``SHA-256(0x00 || line)``). The checkpoint text is c2sp.org/tlog-checkpoint: origin, size, root.
The log signs it as a c2sp.org/signed-note Ed25519 note (type 0x01) with any ``SigningKey`` backend.
A witness adds a c2sp.org/tlog-cosignature ``cosignature/v1`` line (type 0x04).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SIG_ED25519 = 0x01
SIG_COSIGNATURE_V1 = 0x04
EM_DASH = "—"
MAX_SIGNATURES = 64
MAX_PROOF_LINES = 63
MAX_TIMESTAMP = 2**63 - 1
EMPTY_ROOT = hashlib.sha256(b"").digest()
_DECIMAL = re.compile(r"(0|[1-9][0-9]*)\Z")


class NoteError(ValueError):
    """A note, checkpoint, cosignature or policy that is refused."""


# ---- RFC 9162 tree --------------------------------------------------------------------------------
def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
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


# ---- signed notes ---------------------------------------------------------------------------------
def b64decode_canonical(text: str) -> bytes:
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise NoteError(f"not base64: {text!r}") from exc
    if base64.b64encode(raw).decode() != text:
        raise NoteError(f"non-canonical base64: {text!r}")
    return raw


def parse_decimal(text: str, what: str) -> int:
    if not _DECIMAL.match(text) or int(text) > MAX_TIMESTAMP:
        raise NoteError(f"{what} must be an ASCII decimal with no leading zeros")
    return int(text)


def valid_name(name: str) -> bool:
    return (bool(name) and len(name.encode()) <= 255 and "+" not in name
            and not any(ch.isspace() or ord(ch) < 0x20 for ch in name))


def note_key_id(name: str, sig_type: int, public: bytes) -> bytes:
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + public).digest()[:4]


def _raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class VerifierKey:
    """A vkey ``<name>+<hex key id>+<base64(type || public key)>``."""

    name: str
    sig_type: int
    public: bytes

    @property
    def id(self) -> bytes:
        return note_key_id(self.name, self.sig_type, self.public)

    def encode(self) -> str:
        return f"{self.name}+{self.id.hex()}+{base64.b64encode(bytes([self.sig_type]) + self.public).decode()}"

    def verify(self, sig: bytes, message: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.public).verify(sig, message)
        except InvalidSignature:
            return False
        return True


def vkey(name: str, sig_type: int, public: Ed25519PublicKey) -> VerifierKey:
    if not valid_name(name):
        raise NoteError(f"invalid key name {name!r}")
    return VerifierKey(name, sig_type, _raw(public))


def parse_vkey(text: str) -> VerifierKey:
    parts = text.split("+", 2)
    if len(parts) != 3 or not valid_name(parts[0]):
        raise NoteError(f"not a vkey: {text!r}")
    blob = b64decode_canonical(parts[2])
    if len(blob) != 33 or blob[0] not in (SIG_ED25519, SIG_COSIGNATURE_V1):
        raise NoteError("a vkey is type 0x01 or 0x04 and a 32-byte Ed25519 key")
    key = VerifierKey(parts[0], blob[0], blob[1:])
    if not re.fullmatch(r"[0-9a-f]{8}", parts[1]) or bytes.fromhex(parts[1]) != key.id:
        raise NoteError(f"vkey key id does not match its name and key: {text!r}")
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
        raise NoteError("a signed note holds no control character but newline")
    split = note.rfind("\n\n")
    if split < 0 or not note.endswith("\n"):
        raise NoteError("a signed note is text, a blank line, then signature lines")
    text, tail = note[: split + 1], note[split + 2:]
    lines = tail[:-1].split("\n") if tail else []
    if not lines or len(lines) > MAX_SIGNATURES:
        raise NoteError("a signed note carries 1 to 64 signature lines")
    sigs = []
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != EM_DASH or not valid_name(parts[1]):
            raise NoteError(f"malformed signature line {line!r}")
        blob = b64decode_canonical(parts[2])
        if len(blob) < 5:
            raise NoteError("a signature is a 4-byte key id and the signature")
        sigs.append(SigLine(parts[1], blob[:4], blob[4:]))
    if len({(s.name, s.key_id) for s in sigs}) != len(sigs):
        raise NoteError("two signature lines share key name and key id")
    return Note(text, tuple(sigs))


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes

    def text(self) -> str:
        return f"{self.origin}\n{self.size}\n{base64.b64encode(self.root).decode()}\n"


def parse_checkpoint(text: str) -> Checkpoint:
    if not text.endswith("\n"):
        raise NoteError("checkpoint text ends in a newline")
    lines = text[:-1].split("\n")
    if len(lines) < 3 or any(not line for line in lines) or not valid_name(lines[0]):
        raise NoteError("a checkpoint is origin, size, root (and extension lines)")
    raw = b64decode_canonical(lines[2])
    if len(raw) != 32:
        raise NoteError("checkpoint root is 32 bytes")
    return Checkpoint(lines[0], parse_decimal(lines[1], "tree size"), raw)


def cosignature_message(timestamp: int, text: str) -> bytes:
    return f"cosignature/v1\ntime {timestamp}\n{text}".encode()


def sign_checkpoint(cp: Checkpoint, signer: Any) -> str:
    """The log's signed note: ``signer`` is any ``SigningKey`` (local, Vault, KMS, delegated root)."""
    text = cp.text()
    sig = signer.sign(text.encode())
    line = SigLine(cp.origin, note_key_id(cp.origin, SIG_ED25519, _raw(signer.public)), sig)
    return Note(text, (line,)).encode()


def log_vkey(origin: str, signer: Any) -> str:
    return vkey(origin, SIG_ED25519, signer.public).encode()


def cosign(text: str, name: str, key: Ed25519PrivateKey, timestamp: int) -> SigLine:
    parse_checkpoint(text)
    sig = key.sign(cosignature_message(timestamp, text))
    return SigLine(name, note_key_id(name, SIG_COSIGNATURE_V1, _raw(key.public_key())),
                   timestamp.to_bytes(8, "big") + sig)


def _verify_line(key: VerifierKey, text: str, line: SigLine) -> int | None:
    if key.sig_type == SIG_ED25519:
        if len(line.sig) != 64 or not key.verify(line.sig, text.encode()):
            raise NoteError(f"signature from known key {key.name} does not verify")
        return None
    if len(line.sig) != 72:
        raise NoteError(f"cosignature from {key.name} has the wrong length")
    timestamp = int.from_bytes(line.sig[:8], "big")
    if timestamp > MAX_TIMESTAMP or not key.verify(line.sig[8:], cosignature_message(timestamp, text)):
        raise NoteError(f"cosignature from known key {key.name} does not verify")
    return timestamp


# ---- tlog-policy ----------------------------------------------------------------------------------
@dataclass
class Policy:
    """c2sp.org/tlog-policy: log keys, named witnesses, groups, one quorum."""

    logs: list[VerifierKey] = field(default_factory=list)
    witnesses: dict[str, VerifierKey] = field(default_factory=dict)
    groups: dict[str, tuple[int, tuple[str, ...]]] = field(default_factory=dict)
    quorum: str = ""

    def satisfied(self, cosigned: set[str], name: str | None = None) -> bool:
        name = self.quorum if name is None else name
        if name == "none":
            return True
        if name in self.witnesses:
            return name in cosigned
        k, members = self.groups[name]
        return sum(self.satisfied(cosigned, m) for m in members) >= k


def parse_policy(text: str) -> Policy:
    policy, keys = Policy(), set()

    def key(t: str, sig_type: int) -> VerifierKey:
        k = parse_vkey(t)
        if k.sig_type != sig_type or k.public in keys:
            raise NoteError(f"policy key {k.name} has the wrong type or repeats a key")
        keys.add(k.public)
        return k

    def fresh(name: str) -> str:
        if name == "none" or name in policy.witnesses or name in policy.groups:
            raise NoteError(f"policy name {name!r} is reserved or already defined")
        return name

    for raw in text.split("\n"):
        words = [w for w in re.split(r"[ \t]+", raw) if w]
        if not words or words[0].startswith("#"):
            continue
        kind, args = words[0], words[1:]
        if kind == "log" and len(args) in (1, 2):
            policy.logs.append(key(args[0], SIG_ED25519))
        elif kind == "witness" and len(args) in (2, 3):
            policy.witnesses[fresh(args[0])] = key(args[1], SIG_COSIGNATURE_V1)
        elif kind == "group" and len(args) >= 3:
            members = tuple(args[2:])
            known = set(policy.witnesses) | set(policy.groups)
            if len(set(members)) != len(members) or not set(members) <= known:
                raise NoteError("group members are distinct, earlier-defined names")
            k = {"all": len(members), "any": 1}.get(args[1]) or parse_decimal(args[1], "group threshold")
            if not 1 <= k <= len(members):
                raise NoteError("group threshold is 1..n")
            policy.groups[fresh(args[0])] = (k, members)
        elif kind == "quorum" and len(args) == 1 and not policy.quorum:
            if args[0] != "none" and args[0] not in policy.witnesses and args[0] not in policy.groups:
                raise NoteError("the quorum names an earlier-defined witness or group")
            policy.quorum = args[0]
        else:
            raise NoteError(f"unknown or malformed policy line {raw!r}")
    if not policy.quorum:
        raise NoteError("a policy has exactly one quorum line")
    return policy


@dataclass(frozen=True)
class VerifiedCheckpoint:
    checkpoint: Checkpoint
    cosigned_at: dict[str, int]


def verify_note(note: str, policy: Policy, now: int | None = None, max_age: int | None = None,
                max_skew: int = 300) -> VerifiedCheckpoint:
    """Accept a checkpoint only when a policy log signed it and the witness quorum cosigned it.

    Offline (``now`` None) every valid cosignature counts; with ``now`` and ``max_age`` only fresh
    ones do. A known key whose signature fails rejects the note; unknown keys are ignored.
    """
    parsed = parse_note(note)
    cp = parse_checkpoint(parsed.text)
    known: dict[tuple[str, bytes], tuple[str, VerifierKey]] = {}
    for k in policy.logs:
        if k.name == cp.origin:
            known[(k.name, k.id)] = ("", k)
    for wname, k in policy.witnesses.items():
        known[(k.name, k.id)] = (wname, k)
    logged, cosigned = False, {}
    for line in parsed.sigs:
        entry = known.get((line.name, line.key_id))
        if entry is None:
            continue
        wname, k = entry
        ts = _verify_line(k, parsed.text, line)
        if ts is None:
            logged = True
        elif now is not None and ts > now + max_skew:
            raise NoteError(f"cosignature from {wname} is dated in the future")
        elif now is None or max_age is None or now - ts <= max_age:
            cosigned[wname] = ts
    if not logged:
        raise NoteError("checkpoint_log_signature_missing")
    if not policy.satisfied(set(cosigned)):
        raise NoteError(f"witness_quorum_not_met:{policy.quorum}:cosigned_by_{sorted(cosigned) or 'none'}")
    return VerifiedCheckpoint(cp, cosigned)


# ---- tlog-witness protocol ------------------------------------------------------------------------
class WitnessRefused(Exception):  # noqa: N818 - carries the HTTP status the spec assigns
    def __init__(self, status: int, message: str, body: str = "") -> None:
        super().__init__(f"{status}: {message}")
        self.status, self.body = status, body


def encode_add_checkpoint(old: int, proof: Sequence[bytes], note: str) -> str:
    return "\n".join([f"old {old}", *(base64.b64encode(h).decode() for h in proof)]) + "\n\n" + note


def parse_add_checkpoint(body: str) -> tuple[int, list[bytes], str]:
    head, sep, rest = body.partition("\n\n")
    lines = head.split("\n")
    if not sep or not lines[0].startswith("old "):
        raise WitnessRefused(400, "request starts with an old size line and a blank line")
    if len(lines) - 1 > MAX_PROOF_LINES:
        raise WitnessRefused(400, "more than 63 proof lines")
    try:
        old = parse_decimal(lines[0][4:], "old size")
        proof = [b64decode_canonical(line) for line in lines[1:]]
    except NoteError as exc:
        raise WitnessRefused(400, str(exc)) from exc
    if any(len(h) != 32 for h in proof):
        raise WitnessRefused(400, "each proof line is one 32-byte hash")
    return old, proof, rest


@dataclass
class Witness:
    """A cosigner: its name and key (the customer's), the log keys it trusts, its per-origin state.

    ``state`` persists ``origin -> (size, root)`` in a directory so a restart never forgets what it
    signed (forgetting would let a log fork past it).
    """

    name: str
    key: Ed25519PrivateKey
    logs: dict[str, list[VerifierKey]]
    state_dir: Path | None = None
    clock: Callable[[], int] = lambda: int(time.time())
    _latest: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.state_dir is not None:
            self.state_dir = Path(self.state_dir)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            for f in self.state_dir.glob("*.state"):
                size, root_b64 = f.read_text().split()
                origin = bytes.fromhex(f.stem).decode()
                self._latest[origin] = (int(size), base64.b64decode(root_b64))

    @property
    def vkey(self) -> VerifierKey:
        return vkey(self.name, SIG_COSIGNATURE_V1, self.key.public_key())

    def _save(self, origin: str, size: int, root_hash: bytes) -> None:
        self._latest[origin] = (size, root_hash)
        if self.state_dir is None:
            return
        path = Path(self.state_dir) / (origin.encode().hex() + ".state")
        tmp = path.with_suffix(".tmp")
        tmp.write_text(f"{size} {base64.b64encode(root_hash).decode()}\n")
        with tmp.open("rb") as fh:
            os.fsync(fh.fileno())
        tmp.replace(path)

    def add_checkpoint(self, body: str) -> str:
        old, proof, note_text = parse_add_checkpoint(body)
        try:
            parsed = parse_note(note_text)
            cp = parse_checkpoint(parsed.text)
        except NoteError as exc:
            raise WitnessRefused(400, str(exc)) from exc
        trusted = {(k.name, k.id): k for k in self.logs.get(cp.origin, [])}
        if not trusted:
            raise WitnessRefused(404, f"unknown log origin {cp.origin!r}")
        signed = False
        for line in parsed.sigs:
            k = trusted.get((line.name, line.key_id))
            if k is None:
                continue
            try:
                _verify_line(k, parsed.text, line)
            except NoteError as exc:
                raise WitnessRefused(403, str(exc)) from exc
            signed = True
        if not signed:
            raise WitnessRefused(403, "no signature from a trusted log key")
        with self._lock:
            size, stored = self._latest.get(cp.origin, (0, EMPTY_ROOT))
            if old > cp.size:
                raise WitnessRefused(400, "old size is larger than the checkpoint size")
            if old != size:
                raise WitnessRefused(409, "old size is not the latest cosigned size", f"{size}\n")
            if cp.size == 0 and cp.root != EMPTY_ROOT:
                raise WitnessRefused(422, "a size-zero checkpoint carries the empty root")
            if not verify_consistency(old, cp.size, stored, cp.root, proof):
                raise WitnessRefused(422, "consistency proof does not verify")
            line = cosign(parsed.text, self.name, self.key, self.clock())
            self._save(cp.origin, cp.size, cp.root)
        return line.encode()


def serve_witness(witness: Witness, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """``POST /add-checkpoint`` per c2sp.org/tlog-witness. Returns the started server."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            if self.path.rstrip("/").split("/")[-1] != "add-checkpoint":
                self._reply(404, "not found\n")
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1 << 16:
                self._reply(400, "request too large\n")
                return
            try:
                out = witness.add_checkpoint(self.rfile.read(length).decode())
            except WitnessRefused as exc:
                self._reply(exc.status, exc.body or str(exc) + "\n",
                            "text/x.tlog.size" if exc.status == 409 else "text/plain")
                return
            except UnicodeDecodeError:
                self._reply(400, "not UTF-8\n")
                return
            self._reply(200, out)

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


def add_checkpoint(url: str, body: str, timeout: float = 10.0,
                   opener: Callable[..., Any] = urllib.request.urlopen) -> str:
    """POST to a witness; the cosignature lines, or ``WitnessRefused`` with the status and body."""
    req = urllib.request.Request(url.rstrip("/") + "/add-checkpoint", data=body.encode(), method="POST")
    try:
        with opener(req, timeout=timeout) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as exc:
        raise WitnessRefused(exc.code, exc.reason, exc.read().decode(errors="replace")) from exc


def attach(note: str, response: str) -> str:
    """Append a witness's signature lines to a checkpoint note."""
    parsed = parse_note(note)
    extra = parse_note("x\n\n" + response).sigs
    return Note(parsed.text, parsed.sigs + extra).encode()


# ---- the authority's checkpoint feed ------------------------------------------------------------
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
            raise NoteError(f"invalid origin {self.origin!r}")
        self.directory = Path(self.directory or Path(self.journal.directory) / "feed")
        self.directory.mkdir(parents=True, exist_ok=True)

    @property
    def log_key(self) -> Any:
        """The key that signs checkpoints: the root behind a delegated session key, so a witness pins
        one log key for the life of the deployment."""
        return getattr(self.journal.signer, "root", self.journal.signer)

    def vkey(self) -> str:
        return log_vkey(self.origin, self.log_key)

    def _state(self, wkey: VerifierKey) -> Path:
        return Path(self.directory) / f"witness-{wkey.id.hex()}.size"

    def _cosign(self, url: str, wkey: VerifierKey, note: str, leaves: list[bytes]) -> str:
        state = self._state(wkey)
        old = int(state.read_text()) if state.exists() else 0
        for _ in range(2):
            if old > len(leaves):
                raise WitnessRefused(409, f"witness {wkey.name} holds size {old}, past this journal's {len(leaves)}")
            body = encode_add_checkpoint(old, consistency_proof(old, leaves) if old else [], note)
            try:
                response = self.poster(url, body)
            except WitnessRefused as exc:
                if exc.status != 409 or not exc.body.strip().isdigit():
                    raise
                old = int(exc.body.strip())  # the witness's own latest size: prove from there
                continue
            state.write_text(f"{len(leaves)}\n")
            return response
        raise WitnessRefused(409, f"witness {wkey.name} kept moving its size")

    def publish(self) -> str:
        """Sign, gather cosignatures, check the policy, then publish; returns the published note."""
        leaves = journal_leaves(Path(self.journal.path))
        cp = Checkpoint(self.origin, len(leaves), root(leaves))
        note = sign_checkpoint(cp, self.log_key)
        errors = []
        for url, text in self.witnesses:
            wkey = parse_vkey(text)
            try:
                note = attach(note, self._cosign(url, wkey, note, leaves))
            except (WitnessRefused, OSError, NoteError) as exc:
                errors.append(f"{wkey.name}: {exc}")
        if self.policy is not None:
            try:
                verify_note(note, self.policy)
            except NoteError as exc:
                raise WitnessRefused(503, f"not published: {exc}; witness errors: {errors}") from exc
        tmp = Path(self.directory) / "checkpoint.tmp"
        tmp.write_text(note)
        with tmp.open("rb") as fh:
            os.fsync(fh.fileno())
        tmp.replace(Path(self.directory) / "checkpoint")
        with (Path(self.directory) / "checkpoints.log").open("a") as fh:
            fh.write(note + "\n")
        return note

    def latest(self) -> str | None:
        path = Path(self.directory) / "checkpoint"
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
        seq, _ = self.feed.journal._tail()  # noqa: SLF001 - O(new bytes)
        return "witness_lag_exceeded" if seq - self.feed.witnessed_size() > self.max_unwitnessed else None
