"""Verify one Adversarial Execution Evidence statement (predicate version 0.7).

This module judges an in-toto statement whose predicate type is
``https://in-toto.io/attestation/adversarial-execution-evidence/v0.7``. It runs
the predicate's verification pipeline over the statement's own bytes and
returns a report with the same surface the specification's conformance corpus
declares for each member: a verdict, the detected failure codes in detection
order, and, for a valid statement only, the recompute-confirmed result and the
evidence tier of every row under the consumer's key policy.

The pipeline, in order, stopping at the first gate that fails:

* GATE 0, statement well-formedness: statement and predicate types, member
  shapes, the closed vocabularies, the observation vocabulary and corpus
  manifest digests, coverage partition and row identity, substrate binding
  inputs, and the issuance instant.
* GATE 1, coverage validity: the carried observation records (base64, DSSE
  pre-authentication encoding, Merkle batch root), each substrate row's
  covering records, and the statement-level commitments between rows, seals
  and arming records.
* Recompute equality: the carried result must equal the result recomputed from
  the rows.
* GATE 2, evidence tier: a substrate row is ``attested`` only when every record
  covering it verifies under a key the consumer pinned, else ``unattested``;
  an artifact row is ``declared``.

The JSON reading follows the predicate's wire profile exactly, including the
strict I-JSON pass over the whole statement (repeated members, strings that are
not Unicode scalar values, and the size and depth bounds make a statement
malformed) and the integers-only canonical form of every observation payload.
Nothing here reads a verdict, a code or a result from outside the statement.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
BINDING_VERSION = "2"

VALID = "valid"
INVALID = "invalid"

RESULTS = ("pass", "pass_indirect", "degraded", "fail")
EGRESS_POSTURES = frozenset({"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"})
CHAIN_SCOPES = frozenset({"subject", "corpus", "networkPosture"})

TIER_DECLARED = "declared"
TIER_UNATTESTED = "unattested"
TIER_ATTESTED = "attested"

MAX_STATEMENT_BYTES = 64 << 20
MAX_PARSE_BYTES = 20 << 20
MAX_PARSE_DEPTH = 128
MAX_SYNTAX_DEPTH = 10000
MAX_SAFE_INTEGER = 1 << 53

# Failure codes, by gate. The code strings are the conformance corpus's vocabulary.
STATEMENT_MALFORMED = "statement-malformed"
GATE0_CODES = (
    "statement-type-unsupported", "predicate-type-unsupported", "member-spelling",
    "result-vocabulary", "environment-incomplete", "posture-vocabulary", "vocabulary-missing",
    "vocabulary-not-canonical", "vocabulary-caught-not-subset", "vocabulary-digest-mismatch",
    "corpus-digest-mismatch", "manifest-duplicate-attack", "corpus-manifest-no-attacks",
    "manifest-expected-payloads-malformed", "coverage-missing", "coverage-incomplete",
    "row-attack-unknown", "malformed-missing-actual-layer", "clean-row-layer-not-none",
    "subject-cardinality", "subject-sha256-missing", "digest-not-canonical",
    "run-entropy-missing", "issued-at-missing", "issued-at-malformed")
VOCABULARY_CODES = frozenset({"vocabulary-missing", "vocabulary-not-canonical",
                              "vocabulary-caught-not-subset", "vocabulary-digest-mismatch"})

KIND_INTERCEPTION = "interception"
KIND_ARMING = "arming"
KIND_SEALED = "sealed"
KIND_EXAMINATION = "examination"
KIND_MOAT_DROP = "moat-drop"
KIND_UNCOMMITTED = "uncommitted-observation"
COVERING_KINDS = frozenset({KIND_INTERCEPTION, KIND_ARMING, KIND_SEALED, KIND_EXAMINATION})

INTERCEPTED = "intercepted"
RECONSTRUCTED = "reconstructed"
SUBSTRATE = "substrate"
ARTIFACT = "artifact"
PINNED = "pinned"
PAIRED = "paired"


class JSONError(Exception):
    """The bytes are not JSON, or not JSON this profile accepts."""

    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(message or kind)
        self.kind = kind


# Strict-pass error kinds that make a whole statement malformed.
DUPLICATE = "duplicate-member"
NOT_SCALAR = "string-not-scalar"
TOO_LARGE = "too-large"
TOO_DEEP = "too-deep"
UNSAFE_INTEGER = "unsafe-integer"
NON_INTEGER = "non-integer"
SYNTAX = "syntax"
PROMOTED = frozenset({DUPLICATE, NOT_SCALAR, TOO_LARGE, TOO_DEEP})


# ---------------------------------------------------------------------------
# JSON tree: one syntax pass, kept in document order with byte spans.
# ---------------------------------------------------------------------------

class Node:
    """One JSON value: ``kind`` is obj, arr, str, num, true, false or null."""

    __slots__ = ("end", "kind", "start", "value")

    def __init__(self, kind: str, value: Any, start: int, end: int = 0) -> None:
        self.kind = kind
        self.value = value
        self.start = start
        self.end = end


def _per_byte_replace(error: UnicodeDecodeError) -> tuple[str, int]:
    return "�", error.start + 1


codecs.register_error("probity-verify-per-byte", _per_byte_replace)

_WS = b" \t\n\r"
_ESCAPES = {ord('"'): '"', ord("\\"): "\\", ord("/"): "/", ord("b"): "\b",
            ord("f"): "\f", ord("n"): "\n", ord("r"): "\r", ord("t"): "\t"}
_NUMBER = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX4 = re.compile(rb"[0-9a-fA-F]{4}")


def _skip(data: bytes, i: int) -> int:
    n = len(data)
    while i < n and data[i] in _WS:
        i += 1
    return i


def _u4(data: bytes, i: int) -> int:
    """The code unit of a ``\\uXXXX`` escape at ``i``, or -1."""
    if data[i:i + 2] != b"\\u" or not _HEX4.fullmatch(data[i + 2:i + 6]):
        return -1
    return int(data[i + 2:i + 6], 16)


def _string(data: bytes, i: int) -> tuple[str, int]:
    """Decode the string literal at ``i``; invalid text becomes U+FFFD per byte."""
    n = len(data)
    j = i + 1
    parts: list[str] = []
    run = j
    while True:
        if j >= n:
            raise JSONError(SYNTAX, "unterminated string")
        c = data[j]
        if c == 0x22:
            parts.append(data[run:j].decode("utf-8", "probity-verify-per-byte"))
            return "".join(parts), j + 1
        if c < 0x20:
            raise JSONError(SYNTAX, "control character in string")
        if c != 0x5C:
            j += 1
            continue
        parts.append(data[run:j].decode("utf-8", "probity-verify-per-byte"))
        if j + 1 >= n:
            raise JSONError(SYNTAX, "unterminated escape")
        e = data[j + 1]
        if e in _ESCAPES:
            parts.append(_ESCAPES[e])
            j += 2
        elif e == ord("u"):
            unit = _u4(data, j)
            if unit < 0:
                raise JSONError(SYNTAX, "malformed \\u escape")
            j += 6
            if 0xD800 <= unit < 0xE000:
                low = _u4(data, j)
                if 0xD800 <= unit < 0xDC00 and 0xDC00 <= low < 0xE000:
                    parts.append(chr(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)))
                    j += 6
                else:
                    parts.append("�")
            else:
                parts.append(chr(unit))
        else:
            raise JSONError(SYNTAX, "invalid escape")
        run = j


def _scalar(data: bytes, i: int) -> Node:
    c = data[i]
    if c == 0x22:
        value, end = _string(data, i)
        return Node("str", value, i, end)
    for literal, kind in ((b"true", "true"), (b"false", "false"), (b"null", "null")):
        if data.startswith(literal, i):
            return Node(kind, None, i, i + len(literal))
    match = _NUMBER.match(data, i)
    if match is None:
        raise JSONError(SYNTAX, f"invalid character at byte {i}")
    return Node("num", match.group().decode("ascii"), i, match.end())


def parse_tree(data: bytes) -> Node:
    """Parse one JSON text into a tree, refusing anything that is not JSON.

    Strings are decoded leniently (an unpaired surrogate escape or invalid UTF-8
    becomes U+FFFD); the strict pass reports those separately.
    """
    n = len(data)
    i = _skip(data, 0)
    stack: list[list[Any]] = []  # [container, pending key]
    while True:
        if i >= n:
            raise JSONError(SYNTAX, "unexpected end of input")
        c = data[i]
        if c in (0x7B, 0x5B):
            node = Node("obj" if c == 0x7B else "arr", [], i)
            i = _skip(data, i + 1)
            closer = 0x7D if c == 0x7B else 0x5D
            if i < n and data[i] == closer:
                node.end = i + 1
                value = node
                i += 1
            else:
                if len(stack) >= MAX_SYNTAX_DEPTH:
                    raise JSONError(SYNTAX, "nesting exceeds the syntax limit")
                key = None
                if c == 0x7B:
                    key, i = _member_name(data, i)
                stack.append([node, key])
                continue
        else:
            value = _scalar(data, i)
            i = value.end
        while True:
            if not stack:
                if _skip(data, i) != n:
                    raise JSONError(SYNTAX, "trailing content after JSON value")
                return value
            frame = stack[-1]
            parent = frame[0]
            if parent.kind == "obj":
                parent.value.append((frame[1], value))
            else:
                parent.value.append(value)
            i = _skip(data, i)
            if i >= n:
                raise JSONError(SYNTAX, "unexpected end of input")
            if data[i] == 0x2C:
                i = _skip(data, i + 1)
                if parent.kind == "obj":
                    frame[1], i = _member_name(data, i)
                break
            if data[i] == (0x7D if parent.kind == "obj" else 0x5D):
                parent.end = i + 1
                stack.pop()
                value = parent
                i += 1
                continue
            raise JSONError(SYNTAX, f"invalid character at byte {i}")


def _member_name(data: bytes, i: int) -> tuple[str, int]:
    if i >= len(data) or data[i] != 0x22:
        raise JSONError(SYNTAX, "object member name is not a string")
    key, i = _string(data, i)
    i = _skip(data, i)
    if i >= len(data) or data[i] != 0x3A:
        raise JSONError(SYNTAX, "expected ':' after member name")
    return key, _skip(data, i + 1)


# ---------------------------------------------------------------------------
# Strict I-JSON pass and canonical form.
# ---------------------------------------------------------------------------

def _number_value(text: str) -> int:
    """The integer a number literal denotes, refusing a fraction or an unsafe magnitude."""
    match = re.fullmatch(r"(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?", text)
    if match is None:
        raise JSONError(SYNTAX, "invalid number")
    sign, whole, fraction, exponent = match.groups()
    fraction = fraction or ""
    digits = (whole + fraction).lstrip("0")
    if not digits:
        return 0
    shift = (int(exponent) if exponent else 0) - len(fraction)
    stripped = digits.rstrip("0")
    shift += len(digits) - len(stripped)
    if shift < 0:
        raise JSONError(NON_INTEGER, text)
    if len(stripped) + shift > 17:
        raise JSONError(UNSAFE_INTEGER, text)
    magnitude = int(stripped) * 10 ** shift
    if magnitude >= MAX_SAFE_INTEGER:
        raise JSONError(UNSAFE_INTEGER, text)
    return -magnitude if sign else magnitude


def _check_strict(node: Node, depth: int) -> None:
    """Walk the tree in document order, raising the first strict-profile fault."""
    work: list[tuple[Node, int]] = [(node, depth)]
    while work:
        current, level = work.pop()
        if current.kind in ("obj", "arr"):
            if level >= MAX_PARSE_DEPTH:
                raise JSONError(TOO_DEEP)
            if current.kind == "obj":
                seen: set[str] = set()
                children = []
                for key, child in current.value:
                    children.append((key, child))
                pending: list[tuple[Node, int]] = []
                # A repeated name is found when its second occurrence is read,
                # which is before that member's value and after the earlier
                # members' values. Interleave accordingly.
                for key, child in children:
                    if key in seen:
                        pending.append((Node("dup", key, 0), level))
                        break
                    seen.add(key)
                    pending.append((child, level + 1))
                work.extend(reversed(pending))
            else:
                work.extend((child, level + 1) for child in reversed(current.value))
        elif current.kind == "dup":
            raise JSONError(DUPLICATE, current.value)
        elif current.kind == "num":
            _number_value(current.value)


def _noncharacter(code: int) -> bool:
    return code & 0xFFFE == 0xFFFE or 0xFDD0 <= code <= 0xFDEF


def _check_string_scalars(raw: bytes) -> None:
    """Every string literal's bytes and escapes must be Unicode scalar values."""
    i, n = 0, len(raw)
    while i < n:
        if raw[i] != 0x22:
            i += 1
            continue
        j = i + 1
        while True:
            if j >= n:
                raise JSONError(SYNTAX, "unterminated string literal")
            c = raw[j]
            if c == 0x22:
                j += 1
                break
            if c == 0x5C:
                if j + 1 >= n:
                    raise JSONError(SYNTAX, "unterminated escape sequence")
                if raw[j + 1] != ord("u"):
                    j += 2
                    continue
                unit = int(raw[j + 2:j + 6], 16) if _HEX4.fullmatch(raw[j + 2:j + 6]) else -1
                if unit < 0:
                    raise JSONError(NOT_SCALAR, "malformed \\u escape")
                if 0xD800 <= unit < 0xDC00:
                    low = int(raw[j + 8:j + 12], 16) if (
                        raw[j + 6:j + 8] == b"\\u" and _HEX4.fullmatch(raw[j + 8:j + 12])) else -1
                    if j + 12 > n or raw[j + 6:j + 8] != b"\\u":
                        raise JSONError(NOT_SCALAR, "unpaired high surrogate")
                    if low < 0:
                        raise JSONError(NOT_SCALAR, "malformed escape after high surrogate")
                    if not 0xDC00 <= low < 0xE000:
                        raise JSONError(NOT_SCALAR, "high surrogate without a low surrogate")
                    if _noncharacter(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)):
                        raise JSONError(NOT_SCALAR, "noncharacter")
                    j += 12
                elif 0xDC00 <= unit < 0xE000:
                    raise JSONError(NOT_SCALAR, "unpaired low surrogate")
                else:
                    if _noncharacter(unit):
                        raise JSONError(NOT_SCALAR, "noncharacter")
                    j += 6
                continue
            if c < 0x20:
                raise JSONError(NOT_SCALAR, "raw control character")
            if c < 0x80:
                j += 1
                continue
            code, size = _decode_rune(raw, j)
            if code < 0:
                raise JSONError(NOT_SCALAR, "invalid UTF-8")
            if _noncharacter(code):
                raise JSONError(NOT_SCALAR, "noncharacter")
            j += size
        i = j


def _decode_rune(raw: bytes, j: int) -> tuple[int, int]:
    """One UTF-8 sequence at ``j``: (code point, size), or (-1, 1) when invalid."""
    lead = raw[j]
    size = 2 if 0xC2 <= lead <= 0xDF else 3 if 0xE0 <= lead <= 0xEF else 4 if 0xF0 <= lead <= 0xF4 else 0
    if not size or j + size > len(raw):
        return -1, 1
    try:
        text = raw[j:j + size].decode("utf-8")
    except UnicodeDecodeError:
        return -1, 1
    return ord(text), size


def parse_strict(raw: bytes, tree: Node | None = None) -> Node:
    """Parse under the strict profile; ``tree`` reuses an earlier syntax pass."""
    if len(raw) > MAX_PARSE_BYTES:
        raise JSONError(TOO_LARGE)
    node = tree if tree is not None else parse_tree(raw)
    _check_strict(node, 0)
    _check_string_scalars(raw)
    return node


def _jcs_string(value: str) -> str:
    out = ['"']
    for char in value:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif char == "\b":
            out.append("\\b")
        elif char == "\t":
            out.append("\\t")
        elif char == "\n":
            out.append("\\n")
        elif char == "\f":
            out.append("\\f")
        elif char == "\r":
            out.append("\\r")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", "surrogatepass")


def _canonical(node: Node, out: list[str]) -> None:
    kind = node.kind
    if kind == "null":
        out.append("null")
    elif kind in ("true", "false"):
        out.append(kind)
    elif kind == "str":
        out.append(_jcs_string(node.value))
    elif kind == "num":
        out.append(str(_number_value(node.value)))
    elif kind == "arr":
        out.append("[")
        for index, child in enumerate(node.value):
            if index:
                out.append(",")
            _canonical(child, out)
        out.append("]")
    else:
        out.append("{")
        for index, (key, child) in enumerate(sorted(node.value, key=lambda kv: _utf16_key(kv[0]))):
            if index:
                out.append(",")
            out.append(_jcs_string(key))
            out.append(":")
            _canonical(child, out)
        out.append("}")


def canonicalize(raw: bytes, tree: Node | None = None) -> bytes:
    """The JCS form of strict JSON with integer-only numbers."""
    node = parse_strict(raw, tree)
    out: list[str] = []
    _canonical(node, out)
    return "".join(out).encode("utf-8")


# ---------------------------------------------------------------------------
# Typed member decoding of the statement.
# ---------------------------------------------------------------------------

class TypeMismatch(Exception):
    """A member holds a JSON type its field cannot take."""


def _fold_equal(key: str, name: str) -> bool:
    """Whether a member name matches an ASCII field name under simple case folding."""
    if len(key) != len(name):
        return False
    for char, want in zip(key, name):
        low = want.lower()
        if char == want or char.lower() == low and char.isascii():
            continue
        if low == "k" and char == "K" or low == "s" and char == "ſ":
            continue
        return False
    return True


def _fields(node: Node, names: tuple[str, ...]) -> dict[str, list[Node]]:
    """Every member of an object bound to each named field, in document order.

    A field name matches a member name under simple case folding, as a typed
    decoder binds it, so ``Digest`` and ``digest`` fill the same field and every
    occurrence is decoded in turn.
    """
    if node.kind == "null":
        return {}
    if node.kind != "obj":
        raise TypeMismatch(names)
    found: dict[str, list[Node]] = {}
    for key, child in node.value:
        for name in names:
            if _fold_equal(key, name):
                found.setdefault(name, []).append(child)
                break
    return found


def _field_text(found: dict[str, list[Node]], name: str) -> str:
    """A string field: a JSON null leaves the earlier value in place."""
    value = ""
    for node in found.get(name, []):
        if node.kind != "null":
            value = _text(node)
    return value


def _field_map(found: dict[str, list[Node]], name: str) -> dict[str, str] | None:
    """A map field: a later occurrence adds to the map, a JSON null clears it."""
    value: dict[str, str] | None = None
    for node in found.get(name, []):
        members = _text_map(node)
        value = None if members is None else {**(value or {}), **members}
    return value


def _field_list(found: dict[str, list[Node]], name: str) -> list[str] | None:
    """A string-list field: each occurrence replaces the list."""
    value: list[str] | None = None
    for node in found.get(name, []):
        value = _text_list(node)
    return value


def _field_last(found: dict[str, list[Node]], name: str) -> Node | None:
    nodes = found.get(name)
    return nodes[-1] if nodes else None


def _members(node: Node) -> dict[str, Node] | None:
    """The members of an object by exact name, or None for a JSON null."""
    if node.kind == "null":
        return None
    if node.kind != "obj":
        raise TypeMismatch("object")
    return {key: child for key, child in node.value}


def _text(node: Node) -> str:
    if node.kind == "null":
        return ""
    if node.kind != "str":
        raise TypeMismatch("string")
    return node.value


def _text_map(node: Node) -> dict[str, str] | None:
    members = _members(node)
    return None if members is None else {key: _text(child) for key, child in members.items()}


def _text_list(node: Node) -> list[str] | None:
    if node.kind == "null":
        return None
    if node.kind != "arr":
        raise TypeMismatch("array")
    return [_text(child) for child in node.value]


def _list(node: Node) -> list[Node] | None:
    if node.kind == "null":
        return None
    if node.kind != "arr":
        raise TypeMismatch("array")
    return list(node.value)


@dataclass
class DigestRef:
    digest: dict[str, str] | None = None

    def sha256(self) -> str:
        return (self.digest or {}).get("sha256", "")


def _sha(ref: Any) -> str:
    return "" if ref is None else ref.sha256()


def _digest_ref(node: Node) -> DigestRef:
    found = _fields(node, ("name", "digest"))
    _field_text(found, "name")
    return DigestRef(_field_map(found, "digest"))


@dataclass
class Corpus:
    digest: dict[str, str] | None = None
    manifest: Node | None = None
    manifest_raw: bytes = b""
    classes: dict[str, list[str]] | None = None
    expected_payloads: dict[str, list[str]] | None = None
    expected_present: bool = False
    expected_shape_ok: bool = False

    def sha256(self) -> str:
        return (self.digest or {}).get("sha256", "")


@dataclass
class Vocabulary:
    digest: dict[str, str] | None
    labels: list[str]
    caught: list[str]
    labels_present: bool
    caught_present: bool


@dataclass
class Coverage:
    assessed: list[str]
    out_of_scope: dict[str, str]
    routed_elsewhere: dict[str, str]


@dataclass
class Environment:
    members: dict[str, Node]
    substrate: DigestRef | None = None
    corpus: Corpus | None = None
    catch_policy: DigestRef | None = None
    posture: str | None = None
    posture_digest: DigestRef | None = None
    vocabulary: Vocabulary | None = None
    run_entropy: DigestRef | None = None


@dataclass
class Row:
    attack_id: str = ""
    containment: str = ""
    basis: str | None = None
    method: str | None = None
    attribution: str | None = None
    actual_layer: str | None = None
    refs_present: bool = False
    refs_error: bool = False
    refs: list[int] = field(default_factory=list)

    def substrate(self) -> bool:
        return self.basis == SUBSTRATE


@dataclass
class Record:
    payload_b64: str = ""
    payload_type: str = ""
    signatures: list[str] = field(default_factory=list)


@dataclass
class Predicate:
    members: dict[str, Node]
    result: str = ""
    result_present: bool = False
    env: Environment | None = None
    coverage: Coverage | None = None
    coverage_present: bool = False
    rows: list[Row] = field(default_factory=list)
    rows_present: bool = False
    records: list[Record] = field(default_factory=list)
    records_present: bool = False
    batch_root: str = ""
    batch_root_present: bool = False
    issued_at: str = ""
    issued_at_present: bool = False


@dataclass
class Statement:
    type: str
    subject: list[dict[str, str] | None]
    predicate_type: str
    predicate: Predicate
    parse_codes: list[str]


def _append(codes: list[str], code: str) -> None:
    if code not in codes:
        codes.append(code)


def _coverage(node: Node) -> Coverage:
    found = _fields(node, ("assessedClasses", "outOfScope", "routedElsewhere"))
    return Coverage(_field_list(found, "assessedClasses") or [],
                    _field_map(found, "outOfScope") or {},
                    _field_map(found, "routedElsewhere") or {})


def _field_list_map(found: dict[str, list[Node]], name: str) -> dict[str, list[str]] | None:
    """A map-of-string-lists field: occurrences add keys, a JSON null clears it."""
    value: dict[str, list[str]] | None = None
    for node in found.get(name, []):
        members = _members(node)
        value = None if members is None else {
            **(value or {}), **{key: _text_list(child) or [] for key, child in members.items()}}
    return value


def _corpus(node: Node, raw: bytes) -> tuple[Corpus, bool]:
    """The corpus member, and whether its manifest decoded."""
    found = _fields(node, ("name", "uri", "digest", "manifest"))
    _field_text(found, "name")
    _field_text(found, "uri")
    corpus = Corpus(_field_map(found, "digest"))
    manifest = _field_last(found, "manifest")
    if manifest is None:
        return corpus, True
    corpus.manifest = manifest
    corpus.manifest_raw = raw[manifest.start:manifest.end]
    try:
        parts = _fields(manifest, ("classes", "expectedPayloads"))
        corpus.classes = _field_list_map(parts, "classes")
    except TypeMismatch:
        return corpus, False
    if "expectedPayloads" in parts:
        corpus.expected_present = True
        try:
            corpus.expected_payloads = _field_list_map(parts, "expectedPayloads")
            corpus.expected_shape_ok = True
        except TypeMismatch:
            pass
    return corpus, True


def _environment(node: Node, raw: bytes, codes: list[str]) -> Environment:
    members = _members(node) or {}
    env = Environment(members)
    for name, attr in (("substrate", "substrate"), ("catchPolicy", "catch_policy"),
                       ("runEntropy", "run_entropy")):
        if name in members:
            try:
                setattr(env, attr, _digest_ref(members[name]))
            except TypeMismatch:
                _append(codes, STATEMENT_MALFORMED)
    if "corpus" in members:
        try:
            corpus, ok = _corpus(members["corpus"], raw)
            env.corpus = corpus
            if not ok:
                _append(codes, STATEMENT_MALFORMED)
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
    if "networkPosture" in members:
        try:
            found = _fields(members["networkPosture"], ("posture", "digest"))
            digest = DigestRef(_field_map(found, "digest"))
            posture = _field_last(found, "posture")
            # A posture of another JSON type is no registered posture; it is not a decode failure.
            env.posture = posture.value if posture is not None and posture.kind == "str" else ""
            env.posture_digest = digest
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
    if "observationVocabulary" in members:
        node = members["observationVocabulary"]
        try:
            exact = _members(node) or {}
            found = _fields(node, ("digest", "labels", "caught"))
            env.vocabulary = Vocabulary(
                _field_map(found, "digest"), _field_list(found, "labels") or [],
                _field_list(found, "caught") or [], "labels" in exact, "caught" in exact)
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
    return env


def _ref_index(node: Node) -> int:
    if node.kind == "str":
        if not _NUMBER.fullmatch(node.value.encode("utf-8")):
            raise ValueError("ref is not a number")
        text = node.value
    elif node.kind == "num":
        text = node.value
    else:
        raise ValueError("ref is not a number")
    if not re.fullmatch(r"-?[0-9]+", text):
        raise ValueError("ref is not an integer")
    value = int(text)
    if not -(1 << 63) <= value < (1 << 63) or str(value) != text:
        raise ValueError("ref is not an integer")
    if value < 0:
        raise ValueError("ref is negative")
    return value


def _row(node: Node, codes: list[str]) -> Row:
    row = Row()
    try:
        members = _members(node) or {}
    except TypeMismatch:
        _append(codes, STATEMENT_MALFORMED)
        return row

    def text(key: str) -> str | None:
        if key not in members:
            return None
        try:
            return _text(members[key])
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
            return None

    row.attack_id = text("attackId") or ""
    row.containment = text("containmentObserved") or ""
    row.basis = text("basis")
    row.method = text("method")
    row.attribution = text("attribution")
    row.actual_layer = text("actualLayer")
    if "observationRefs" in members:
        row.refs_present = True
        try:
            entries = _list(members["observationRefs"]) or []
        except TypeMismatch:
            row.refs_error = True
            return row
        for entry in entries:
            try:
                row.refs.append(_ref_index(entry))
            except ValueError:
                row.refs_error = True
                break
    return row


def _records(node: Node) -> list[Record]:
    """The observation records. A signatures member that is not an array holds no entry."""
    records = []
    for entry in _list(node) or []:
        found = _fields(entry, ("payload", "payloadType", "signatures"))
        record = Record(_field_text(found, "payload"), _field_text(found, "payloadType"))
        for signatures in found.get("signatures", []):
            if signatures.kind != "arr":
                record.signatures = []
                continue
            record.signatures = []
            for signature in signatures.value:
                sig = _fields(signature, ("keyid", "sig"))
                _field_text(sig, "keyid")
                record.signatures.append(_field_text(sig, "sig"))
        records.append(record)
    return records


def _predicate(node: Node, raw: bytes) -> tuple[Predicate, list[str]]:
    codes: list[str] = []
    try:
        members = _members(node) or {}
    except TypeMismatch:
        return Predicate({}), [STATEMENT_MALFORMED]
    p = Predicate(members)
    if "result" in members:
        p.result_present = True
        try:
            p.result = _text(members["result"])
        except TypeMismatch:
            _append(codes, "result-vocabulary")
    if "observationEnvironment" in members:
        try:
            p.env = _environment(members["observationEnvironment"], raw, codes)
        except TypeMismatch:
            p.env = Environment({})
            _append(codes, STATEMENT_MALFORMED)
    if "coverage" in members:
        p.coverage_present = True
        try:
            p.coverage = _coverage(members["coverage"])
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
    if "attackResults" in members:
        p.rows_present = True
        try:
            rows = _list(members["attackResults"]) or []
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
            rows = []
        p.rows = [_row(row, codes) for row in rows]
    if "observationRecords" in members:
        p.records_present = True
        try:
            p.records = _records(members["observationRecords"])
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
    if "batchRoot" in members:
        p.batch_root_present = True
        try:
            p.batch_root = _text(members["batchRoot"])
        except TypeMismatch:
            _append(codes, STATEMENT_MALFORMED)
    if "issuedAt" in members:
        p.issued_at_present = True
        try:
            p.issued_at = _text(members["issuedAt"])
        except TypeMismatch:
            _append(codes, "issued-at-malformed")
    return p, codes


def parse_statement(raw: bytes) -> Statement:
    """Decode one statement; raise :class:`JSONError` when it is malformed as a whole."""
    if len(raw) > MAX_STATEMENT_BYTES:
        raise JSONError(TOO_LARGE)
    tree = parse_tree(raw)
    try:
        found = _fields(tree, ("_type", "subject", "predicateType", "predicate"))
        statement_type = _field_text(found, "_type")
        predicate_type = _field_text(found, "predicateType")
        subject: list[dict[str, str] | None] = []
        for nodes in found.get("subject", []):
            subject = []
            for entry in _list(nodes) or []:
                parts = _fields(entry, ("name", "digest"))
                _field_text(parts, "name")
                subject.append(_field_map(parts, "digest"))
    except TypeMismatch as exc:
        raise JSONError(SYNTAX, "statement member has the wrong type") from exc
    try:
        parse_strict(raw, tree)
    except JSONError as exc:
        if exc.kind in PROMOTED:
            raise
    predicate_node = _field_last(found, "predicate")
    if predicate_node is None:
        predicate_node = Node("obj", [], 0, 0)
    predicate, codes = _predicate(predicate_node, raw)
    return Statement(statement_type, subject, predicate_type, predicate, codes)


# ---------------------------------------------------------------------------
# Small shared helpers.
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_lower_hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _sorted_unique(values: list[str]) -> bool:
    keys = [_utf16_key(value) for value in values]
    return all(keys[i - 1] < keys[i] for i in range(1, len(keys)))


def _bmp_only(value: str) -> bool:
    return all(ord(char) <= 0xFFFF for char in value)


def pae(payload_type: str, payload: bytes) -> bytes:
    """The DSSE v1 pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def leaf_hash(encoding: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + encoding).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return hashlib.sha256(b"\x01" + merkle_root(leaves[:split]) + merkle_root(leaves[split:])).digest()


def decode_carried_base64(value: str) -> bytes:
    """Standard padded base64 in its one canonical spelling."""
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("carried base64 is not decodable") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("carried base64 is not canonical")
    return decoded


_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{1,2}):([0-9]{2}):([0-9]{2})"
    r"(?:[.,]([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})")
_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def parse_timestamp(value: str) -> int:
    """An RFC 3339 instant with a zero UTC offset, as nanoseconds since the epoch."""
    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        raise ValueError("not an RFC 3339 timestamp")
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    if not 1 <= month <= 12 or not 1 <= day <= _DAYS[month - 1] + (month == 2 and leap):
        raise ValueError("date out of range")
    if hour > 23 or minute > 59 or second > 59:
        raise ValueError("time out of range")
    zone = match.group(8)
    if zone != "Z":
        if int(zone[1:3]) > 24 or int(zone[4:6]) > 60:
            raise ValueError("zone offset out of range")
        if zone[1:3] != "00" or zone[4:6] != "00":
            raise ValueError("zone designator is not a zero UTC offset")
    nanos = int((match.group(7) or "0")[:9].ljust(9, "0"))
    days = _days_from_civil(year, month, day)
    return ((days * 24 + hour) * 60 + minute) * 60 * 10 ** 9 + second * 10 ** 9 + nanos


def _days_from_civil(year: int, month: int, day: int) -> int:
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


# ---------------------------------------------------------------------------
# GATE 0.
# ---------------------------------------------------------------------------

def _clean(voc: Vocabulary, label: str) -> bool:
    return label in voc.labels and label not in voc.caught


def _caught(voc: Vocabulary, label: str) -> bool:
    return label in voc.caught


def _substrate_rows(p: Predicate) -> bool:
    return any(row.substrate() for row in p.rows)


def canonical_vocabulary(labels: list[str], caught: list[str]) -> bytes:
    def array(values: list[str]) -> str:
        return "[" + ",".join(_jcs_string(value) for value in values) + "]"
    return ('{"caught":' + array(caught) + ',"labels":' + array(labels) + "}").encode("utf-8")


def _gate0_vocabulary(voc: Vocabulary, codes: list[str]) -> None:
    if not voc.labels_present or not voc.caught_present:
        _append(codes, "vocabulary-not-canonical")
        return
    if not _sorted_unique(voc.labels) or not _sorted_unique(voc.caught):
        _append(codes, "vocabulary-not-canonical")
    if not all(_bmp_only(value) for value in voc.labels + voc.caught):
        _append(codes, "vocabulary-not-canonical")
    if any(value not in set(voc.labels) for value in voc.caught):
        _append(codes, "vocabulary-caught-not-subset")
    if (voc.digest or {}).get("sha256", "") != sha256_hex(canonical_vocabulary(voc.labels, voc.caught)):
        _append(codes, "vocabulary-digest-mismatch")


def _gate0_corpus(corpus: Corpus, codes: list[str]) -> None:
    if not corpus.manifest_raw:
        _append(codes, "environment-incomplete")
        return
    try:
        canonical = canonicalize(corpus.manifest_raw)
    except JSONError:
        _append(codes, STATEMENT_MALFORMED)
        return
    if corpus.sha256() != sha256_hex(canonical):
        _append(codes, "corpus-digest-mismatch")
    declared = 0
    seen: set[str] = set()
    classes = corpus.classes or {}
    for name in sorted(classes):
        for attack in classes[name]:
            declared += 1
            if attack in seen:
                _append(codes, "manifest-duplicate-attack")
            seen.add(attack)
    if declared == 0:
        _append(codes, "corpus-manifest-no-attacks")
    if not corpus.expected_present:
        return
    if not corpus.expected_shape_ok:
        _append(codes, "manifest-expected-payloads-malformed")
        return
    expected = corpus.expected_payloads or {}
    for attack in sorted(expected):
        values = expected[attack]
        if (attack not in seen or not values or not _sorted_unique(values)
                or not all(is_lower_hex64(value) for value in values)):
            _append(codes, "manifest-expected-payloads-malformed")
            return


def _gate0_coverage(p: Predicate, env: Environment, codes: list[str]) -> None:
    classes = env.corpus.classes or {}
    in_manifest = {attack for ids in classes.values() for attack in ids}
    account: dict[str, int] = {}
    for name in p.coverage.assessed:
        account[name] = account.get(name, 0) + 1
    for name in list(p.coverage.out_of_scope) + list(p.coverage.routed_elsewhere):
        account[name] = account.get(name, 0) + 1
    partition = all(count == 1 and name in classes for name, count in account.items())
    partition = partition and all(account.get(name) == 1 for name in classes)
    if not partition:
        _append(codes, "coverage-incomplete")
    expected = {attack for name in p.coverage.assessed for attack in classes.get(name) or []}
    row_ids: set[str] = set()
    for row in p.rows:
        if row.attack_id in row_ids:
            _append(codes, STATEMENT_MALFORMED)
        row_ids.add(row.attack_id)
        if row.attack_id not in in_manifest:
            _append(codes, "row-attack-unknown")
    if row_ids != expected:
        _append(codes, "coverage-incomplete")


def _gate0_binding_inputs(s: Statement, codes: list[str]) -> None:
    env = s.predicate.env
    if env is None or env.run_entropy is None:
        _append(codes, "run-entropy-missing")
    elif not is_lower_hex64(env.run_entropy.sha256()):
        _append(codes, "digest-not-canonical")
    if s.subject:
        digest = s.subject[0] or {}
        if "sha256" not in digest:
            _append(codes, "subject-sha256-missing")
        elif not is_lower_hex64(digest["sha256"]):
            _append(codes, "digest-not-canonical")
    if env is not None:
        for value in (_sha(env.catch_policy), _sha(env.corpus), _sha(env.posture_digest),
                      _sha(env.substrate)):
            if value and not is_lower_hex64(value):
                _append(codes, "digest-not-canonical")


def gate0(s: Statement) -> list[str]:
    codes: list[str] = []
    p = s.predicate
    if s.type != STATEMENT_TYPE:
        _append(codes, "statement-type-unsupported")
    if s.predicate_type != PREDICATE_TYPE:
        _append(codes, "predicate-type-unsupported")
    for code in s.parse_codes:
        _append(codes, code)
    if "does_not_assert" in p.members:
        _append(codes, "member-spelling")
    if not p.result_present or p.result not in RESULTS:
        _append(codes, "result-vocabulary")
    env = p.env
    if env is None:
        _append(codes, "environment-incomplete")
        _append(codes, "vocabulary-missing")
    else:
        if None in (env.substrate, env.corpus, env.catch_policy, env.posture_digest):
            _append(codes, "environment-incomplete")
        if env.vocabulary is None:
            _append(codes, "vocabulary-missing")
        if env.posture_digest is not None and env.posture not in EGRESS_POSTURES:
            _append(codes, "posture-vocabulary")
        if env.vocabulary is not None:
            _gate0_vocabulary(env.vocabulary, codes)
        if env.corpus is not None:
            _gate0_corpus(env.corpus, codes)
    if not p.coverage_present:
        _append(codes, "coverage-missing")
    if not p.rows_present:
        _append(codes, STATEMENT_MALFORMED)
    if len(s.subject) != 1:
        _append(codes, "subject-cardinality")
    vocab_ok = (env is not None and env.vocabulary is not None
                and not VOCABULARY_CODES.intersection(codes))
    for row in p.rows:
        if row.actual_layer is None:
            _append(codes, "malformed-missing-actual-layer")
            continue
        if vocab_ok and _clean(env.vocabulary, row.containment) and row.actual_layer != "none":
            _append(codes, "clean-row-layer-not-none")
    if (env is not None and env.corpus is not None and env.corpus.classes is not None
            and p.coverage is not None):
        _gate0_coverage(p, env, codes)
    if _substrate_rows(p):
        _gate0_binding_inputs(s, codes)
    if not p.issued_at_present:
        _append(codes, "issued-at-missing")
    else:
        try:
            parse_timestamp(p.issued_at)
        except ValueError:
            _append(codes, "issued-at-malformed")
    return codes


# ---------------------------------------------------------------------------
# GATE 1.
# ---------------------------------------------------------------------------

@dataclass
class RecordState:
    payload: bytes = b""
    pae: bytes = b""
    decode_error: bool = False


@dataclass
class Payload:
    """A decoded observation payload: strict tree members, or None when unreadable."""

    codes: list[str] = field(default_factory=list)
    members: dict[str, Node] | None = None
    kind: str = ""
    method: str = ""
    has_kind: bool = False
    has_method: bool = False


def _payload_members(state: RecordState) -> dict[str, Node] | None:
    try:
        node = parse_strict(state.payload)
    except JSONError:
        return None
    if node.kind != "obj":
        return None
    return {key: child for key, child in node.value}


def _get_string(members: dict[str, Node] | None, key: str) -> tuple[str, bool]:
    node = (members or {}).get(key)
    if node is None or node.kind != "str":
        return "", False
    return node.value, True


def _get_strings(members: dict[str, Node] | None, key: str) -> tuple[list[str], bool]:
    node = (members or {}).get(key)
    if node is None or node.kind != "arr" or any(child.kind != "str" for child in node.value):
        return [], False
    return [child.value for child in node.value], True


def _get_bool(members: dict[str, Node] | None, key: str) -> tuple[bool, bool]:
    node = (members or {}).get(key)
    if node is None or node.kind not in ("true", "false"):
        return False, False
    return node.kind == "true", True


def _get_int(members: dict[str, Node] | None, key: str) -> tuple[int, bool]:
    node = (members or {}).get(key)
    if node is None or node.kind != "num" or not re.fullmatch(r"-?[0-9]+", node.value):
        return 0, False
    value = int(node.value)
    if not -(1 << 63) <= value < (1 << 63):
        return 0, False
    return value, True


def _supplementary_name(node: Node) -> bool:
    if node.kind == "obj":
        return any(not _bmp_only(key) or _supplementary_name(child) for key, child in node.value)
    if node.kind == "arr":
        return any(_supplementary_name(child) for child in node.value)
    return False


def analyze_payload(record: Record, state: RecordState, binding: str) -> Payload:
    result = Payload()
    if state.decode_error:
        result.codes.append("record-undecodable")
        return result
    try:
        node = parse_strict(state.payload)
    except JSONError:
        result.codes.append("payload-not-ijson")
        return result
    if node.kind != "obj":
        result.codes.append("payload-not-canonical")
        return result
    result.members = {key: child for key, child in node.value}
    try:
        canonical = canonicalize(state.payload, node)
    except JSONError:
        canonical = None
    if canonical != state.payload:
        _append(result.codes, "payload-not-canonical")
    if _supplementary_name(node):
        _append(result.codes, "payload-not-canonical")
    if not record.payload_type.endswith("+json"):
        _append(result.codes, "payload-media-type")
    run_binding, has_binding = _get_string(result.members, "aeeRunBinding")
    result.kind, result.has_kind = _get_string(result.members, "aeeKind")
    result.method, result.has_method = _get_string(result.members, "aeeMethod")
    if not has_binding or not result.has_kind or not result.has_method:
        _append(result.codes, "payload-missing-reserved")
        return result
    if run_binding != binding:
        _append(result.codes, "run-binding-mismatch")
    return result


@dataclass
class KindEval:
    kind: str
    method: str
    valid: bool = False
    fail_code: str = ""
    covers_nothing: str = ""


def _attack_ids_ok(attacks: list[str], declared: set[str]) -> bool:
    return _sorted_unique(attacks) and all(attack in declared for attack in attacks)


def _commitments_ok(values: list[str]) -> bool:
    return bool(values) and _sorted_unique(values) and all(is_lower_hex64(v) for v in values)


def _chain_syntax_ok(members: dict[str, Node]) -> bool:
    seq_present = "aeeRunSeq" in members
    prev_present = "aeePrevRunBinding" in members
    scope_present = "aeeChainScope" in members
    if not seq_present:
        return not prev_present and not scope_present
    seq, is_int = _get_int(members, "aeeRunSeq")
    if not is_int or seq < 1:
        return False
    scope, ok = _get_strings(members, "aeeChainScope")
    if not ok or any(token not in CHAIN_SCOPES for token in scope) or not _sorted_unique(scope):
        return False
    if seq == 1:
        return not prev_present
    previous, ok = _get_string(members, "aeePrevRunBinding")
    return ok and is_lower_hex64(previous)


def _arming_ok(a: Payload, posture: str, issued_at: int, declared: set[str]) -> bool:
    version, ok = _get_string(a.members, "aeeBindingVersion")
    if ok and version != BINDING_VERSION:
        return False
    armed_at, has_armed = _get_string(a.members, "armedAt")
    armed_posture, has_posture = _get_string(a.members, "aeePostureDigest")
    if not has_armed or not has_posture or a.method != INTERCEPTED:
        return False
    try:
        instant = parse_timestamp(armed_at)
    except ValueError:
        return False
    if instant > issued_at or armed_posture != posture:
        return False
    if not _chain_syntax_ok(a.members):
        return False
    attacks, ok = _get_strings(a.members, "aeeAssessedAttacks")
    return ok and _attack_ids_ok(attacks, declared)


def _sealed_ok(a: Payload, posture: str, arming_postures: list[str], declared: set[str]) -> bool:
    still_armed, has_still = _get_bool(a.members, "aeeStillArmed")
    drops, has_drops = _get_int(a.members, "aeeDropCount")
    sealed_posture, has_posture = _get_string(a.members, "aeePostureDigest")
    if not has_still or not still_armed or not has_drops or not has_posture or a.method != INTERCEPTED:
        return False
    if drops != 0:
        bound, has_bound = _get_int(a.members, "aeeDropBound")
        if not has_bound or drops < 0 or drops > bound:
            return False
    if sealed_posture != posture or any(sealed_posture != other for other in arming_postures):
        return False
    observed, ok = _get_string(a.members, "aeeObservedSet")
    if not ok or not is_lower_hex64(observed):
        return False
    attacks, ok = _get_strings(a.members, "aeeObservedAttacks")
    return ok and _attack_ids_ok(attacks, declared)


def evaluate_kind(a: Payload, posture: str, arming_postures: list[str], issued_at: int,
                  declared: set[str]) -> KindEval:
    ev = KindEval(a.kind, a.method)
    if a.kind == KIND_INTERCEPTION:
        ev.fail_code = "payload-missing-reserved"
        values, has_commitment = _get_strings(a.members, "aeePayloadCommitment")
        if "aeePayloadCommitment" in (a.members or {}) and not _commitments_ok(values):
            ev.fail_code = "payload-commitment-malformed"
            return ev
        ev.valid = a.method in (INTERCEPTED, RECONSTRUCTED) and has_commitment
    elif a.kind == KIND_ARMING:
        ev.fail_code = "arming-covers-nothing"
        ev.valid = _arming_ok(a, posture, issued_at, declared)
    elif a.kind == KIND_SEALED:
        ev.fail_code = "sealed-covers-nothing"
        ev.valid = _sealed_ok(a, posture, arming_postures, declared)
    elif a.kind == KIND_EXAMINATION:
        ev.fail_code = "examination-covers-nothing"
        ev.valid = a.method == RECONSTRUCTED
    elif a.kind == KIND_MOAT_DROP:
        ev.covers_nothing = "moat-drop-covers-nothing"
    elif a.kind == KIND_UNCOMMITTED:
        ev.covers_nothing = "uncommitted-observation-covers-nothing"
    else:
        ev.covers_nothing = "record-kind-unknown-covers-nothing"
    return ev


def _declared_attacks(p: Predicate) -> set[str]:
    if p.env is None or p.env.corpus is None:
        return set()
    return {attack for ids in (p.env.corpus.classes or {}).values() for attack in ids}


def _records_statement_level(p: Predicate) -> tuple[list[RecordState], list[str]]:
    codes: list[str] = []
    states = [RecordState() for _ in p.records]
    if not p.records_present or not p.records:
        if p.batch_root_present:
            _append(codes, "batch-root-orphaned")
        return states, codes
    if any(not record.signatures for record in p.records):
        _append(codes, "record-signatures-empty")
    failed = False
    leaves: list[bytes] = [b""] * len(p.records)
    for index, record in enumerate(p.records):
        try:
            payload = decode_carried_base64(record.payload_b64)
        except ValueError:
            states[index].decode_error = True
            failed = True
            _append(codes, "record-undecodable")
            continue
        states[index].payload = payload
        states[index].pae = pae(record.payload_type, payload)
        leaves[index] = leaf_hash(states[index].pae)
    seen: set[bytes] = set()
    for index in range(len(p.records)):
        if states[index].decode_error:
            continue
        if leaves[index] in seen:
            _append(codes, "duplicate-record")
            break
        seen.add(leaves[index])
    if not failed:
        root = merkle_root(leaves).hex()
        if not p.batch_root_present:
            _append(codes, "batch-root-missing")
        elif p.batch_root != root:
            _append(codes, "batch-root-mismatch")
    return states, codes


def _fails_closed(row: Row, caught: bool, clean: bool) -> bool:
    method_ok = row.method in (INTERCEPTED, RECONSTRUCTED)
    attribution_ok = row.attribution in (PINNED, PAIRED)
    return (not caught and not clean) or not method_ok or not attribution_ok


def check_substrate_row(p: Predicate, row: Row, states: list[RecordState], binding: str,
                        issued_at: int) -> tuple[list[str], list[int]]:
    """GATE 1 for one substrate row: (codes, indexes of the records covering it)."""
    voc = p.env.vocabulary
    caught = _caught(voc, row.containment)
    clean = _clean(voc, row.containment)
    if _fails_closed(row, caught, clean):
        return ["fail-closed-substrate-row"], []
    if not row.refs_present:
        return ["refs-empty"], []
    if row.refs_error:
        return ["ref-malformed"], []
    if not row.refs:
        return ["refs-empty"], []
    codes: list[str] = []
    unique: list[int] = []
    for index in row.refs:
        if index >= len(p.records):
            _append(codes, "ref-out-of-range")
            continue
        if index not in unique:
            unique.append(index)
    if codes:
        return codes, []
    analyses = {index: analyze_payload(p.records[index], states[index], binding) for index in unique}
    for index in unique:
        for code in analyses[index].codes:
            _append(codes, code)
    if codes:
        return codes, []
    posture = _sha(p.env.posture_digest)
    arming_postures = []
    for index in unique:
        a = analyses[index]
        if a.kind == KIND_ARMING:
            value, ok = _get_string(a.members, "aeePostureDigest")
            if ok:
                arming_postures.append(value)
    declared = _declared_attacks(p)
    evals: dict[int, KindEval] = {}
    covers_nothing = ""
    for index in unique:
        ev = evaluate_kind(analyses[index], posture, arming_postures, issued_at, declared)
        evals[index] = ev
        if not covers_nothing:
            covers_nothing = ev.covers_nothing
    if row.method == RECONSTRUCTED:
        requirements = [(KIND_EXAMINATION, "reconstructed-row-uncovered")]
    elif caught:
        requirements = [(KIND_INTERCEPTION, "caught-row-uncovered")]
    else:
        requirements = [(KIND_ARMING, "clean-row-uncovered"), (KIND_SEALED, "clean-row-uncovered")]
    covering: list[int] = []
    for kind, generic in requirements:
        satisfied = False
        candidate = ""
        for index in unique:
            ev = evals[index]
            if ev.kind != kind:
                continue
            if ev.valid:
                satisfied = True
                covering.append(index)
            elif not candidate:
                candidate = ev.fail_code
        if not satisfied:
            _append(codes, candidate or covers_nothing or generic)
    if codes:
        return codes, []
    cap = RECONSTRUCTED if any(evals[index].method == RECONSTRUCTED for index in covering) else INTERCEPTED
    if row.method == INTERCEPTED and cap == RECONSTRUCTED:
        return ["method-cap-exceeded"], []
    return [], covering


def _record_kinds(p: Predicate, states: list[RecordState]) -> list[str]:
    kinds = []
    for state in states:
        if state.decode_error:
            kinds.append("")
            continue
        kind, _ = _get_string(_payload_members(state), "aeeKind")
        kinds.append(kind)
    return kinds


def _resolves(row: Row, kinds: list[str], kind: str) -> bool:
    if not row.refs_present or row.refs_error:
        return False
    return any(0 <= index < len(kinds) and kinds[index] == kind for index in row.refs)


def _clean_rows_contradicted(p: Predicate, kinds: list[str]) -> list[str]:
    voc = p.env.vocabulary
    for row in p.rows:
        if _clean(voc, row.containment) and _resolves(row, kinds, KIND_INTERCEPTION):
            return ["clean-row-contradicted"]
    return []


def _interceptions_orphaned(p: Predicate, kinds: list[str]) -> list[str]:
    voc = p.env.vocabulary
    resolved = [False] * len(p.records)
    for row in p.rows:
        if not _caught(voc, row.containment) or not row.refs_present or row.refs_error:
            continue
        for index in row.refs:
            if 0 <= index < len(resolved):
                resolved[index] = True
    for index, kind in enumerate(kinds):
        if kind == KIND_INTERCEPTION and not resolved[index]:
            return ["interception-record-orphaned"]
    return []


def _attribution_bindings(p: Predicate, states: list[RecordState], kinds: list[str] | None) -> list[str]:
    for row in p.rows:
        if row.attribution != PINNED:
            continue
        if not _resolves(row, kinds or [], KIND_INTERCEPTION):
            return ["attribution-pinned-recordless"]
        expected = []
        if p.env is not None and p.env.corpus is not None and p.env.corpus.expected_payloads is not None:
            expected = p.env.corpus.expected_payloads.get(row.attack_id) or []
        if not expected:
            return ["attribution-unpinnable"]
        wanted = set(expected)
        for index in row.refs:
            if not 0 <= index < len(kinds or []) or kinds[index] != KIND_INTERCEPTION:
                continue
            values, ok = _get_strings(_payload_members(states[index]), "aeePayloadCommitment")
            if ok and not any(value in wanted for value in values):
                return ["attribution-pin-unmatched"]
    return []


def _commitments_any_basis(p: Predicate, states: list[RecordState]) -> list[str]:
    if not p.records_present or not p.records:
        return _attribution_bindings(p, states, None)
    kinds = _record_kinds(p, states)
    codes: list[str] = []
    for code in (_clean_rows_contradicted(p, kinds) + _interceptions_orphaned(p, kinds)
                 + _attribution_bindings(p, states, kinds)):
        _append(codes, code)
    return codes


def _observed_set_digest(p: Predicate, states: list[RecordState], kinds: list[str]) -> str:
    leaves: list[str] = []
    for index, kind in enumerate(kinds):
        if kind not in (KIND_INTERCEPTION, KIND_EXAMINATION):
            continue
        leaf = leaf_hash(states[index].pae).hex()
        if leaf not in leaves:
            leaves.append(leaf)
    return sha256_hex(("[" + ",".join(_jcs_string(leaf) for leaf in sorted(leaves)) + "]").encode())


def _bound_payload(state: RecordState, binding: str) -> dict[str, Node] | None:
    members = _payload_members(state)
    run_binding, ok = _get_string(members, "aeeRunBinding")
    return members if ok and run_binding == binding else None


def _commitments_substrate(p: Predicate, states: list[RecordState], binding: str,
                           issued_at: int) -> list[str]:
    if not p.records_present or not p.records:
        return []
    kinds = _record_kinds(p, states)
    declared = _declared_attacks(p)
    posture = _sha(p.env.posture_digest)
    codes: list[str] = []
    # Seals commit to the carried interception and examination set.
    want = ""
    for index, kind in enumerate(kinds):
        members = _bound_payload(states[index], binding) if kind == KIND_SEALED else None
        observed, ok = _get_string(members, "aeeObservedSet")
        if members is None or not ok or not is_lower_hex64(observed):
            continue
        want = want or _observed_set_digest(p, states, kinds)
        if observed != want:
            _append(codes, "observed-set-mismatch")
            break
    # A sealed record satisfying every constraint is present.
    present = False
    for index, kind in enumerate(kinds):
        if kind != KIND_SEALED:
            continue
        a = analyze_payload(p.records[index], states[index], binding)
        if not a.codes and evaluate_kind(a, posture, [], issued_at, declared).valid:
            present = True
            break
    if not present:
        _append(codes, "sealed-record-absent")
    # Every carried covering record satisfies its kind's constraints.
    for index, kind in enumerate(kinds):
        if kind not in COVERING_KINDS:
            continue
        a = analyze_payload(p.records[index], states[index], binding)
        if a.codes:
            continue
        ev = evaluate_kind(a, posture, [], issued_at, declared)
        if not ev.valid:
            _append(codes, ev.fail_code)
    # Every attack a seal names is caught by some row.
    caught_ids = {row.attack_id for row in p.rows if _caught(p.env.vocabulary, row.containment)}
    for index, kind in enumerate(kinds):
        members = _bound_payload(states[index], binding) if kind == KIND_SEALED else None
        attacks, ok = _get_strings(members, "aeeObservedAttacks")
        if members is None or not ok or not _attack_ids_ok(attacks, declared):
            continue
        if any(attack not in caught_ids for attack in attacks):
            _append(codes, "observed-attack-uncaught")
            break
    # The assessed classes do not exceed what arming declared.
    if p.coverage is not None and p.env.corpus is not None:
        classes = p.env.corpus.classes or {}
        assessed = {attack for name in p.coverage.assessed for attack in classes.get(name) or []}
        for index, kind in enumerate(kinds):
            members = _bound_payload(states[index], binding) if kind == KIND_ARMING else None
            attacks, ok = _get_strings(members, "aeeAssessedAttacks")
            if members is None or not ok or not _attack_ids_ok(attacks, declared):
                continue
            if not assessed <= set(attacks):
                _append(codes, "assessed-set-exceeds-declaration")
                break
    return codes


def run_binding_preimage(catch_policy: str, corpus: str, posture: str, vocabulary: str,
                         run_entropy: str, subject: str, substrate: str) -> bytes:
    """The run binding's pre-image.

    GATE 0 has already required every input to be lowercase hex or empty, so
    plain quoting spells each one exactly as the predicate's template does.
    """
    pairs = (("aeeBindingVersion", BINDING_VERSION), ("catchPolicy", catch_policy),
             ("corpus", corpus), ("networkPosture", posture), ("observationVocabulary", vocabulary),
             ("runEntropy", run_entropy), ("subject", subject), ("substrate", substrate))
    return ("{" + ",".join(f'"{name}":"{value}"' for name, value in pairs) + "}").encode("utf-8")


def _posture_preimage_digest(env: Environment, raw: bytes) -> str:
    node = env.members.get("networkPosture")
    if node is None or node.kind != "obj":
        return ""
    try:
        return sha256_hex(canonicalize(raw[node.start:node.end]))
    except JSONError:
        return ""


def statement_binding(s: Statement, raw: bytes) -> str:
    env = s.predicate.env
    if env is None:
        return sha256_hex(run_binding_preimage("", "", "", "", "", "", ""))
    subject = ((s.subject[0] or {}).get("sha256", "")) if s.subject else ""
    vocabulary = (env.vocabulary.digest or {}).get("sha256", "") if env.vocabulary else ""
    return sha256_hex(run_binding_preimage(
        _sha(env.catch_policy), _sha(env.corpus), _posture_preimage_digest(env, raw), vocabulary,
        _sha(env.run_entropy), subject, _sha(env.substrate)))


def gate1(s: Statement, raw: bytes) -> tuple[list[RecordState], str, int, list[str]]:
    p = s.predicate
    codes: list[str] = []
    states, statement_codes = _records_statement_level(p)
    for code in statement_codes:
        _append(codes, code)
    if p.records and any(row.refs_present and not row.refs_error and
                         any(index >= len(p.records) for index in row.refs) for row in p.rows):
        _append(codes, "ref-out-of-range")
    if not _substrate_rows(p):
        for code in _commitments_any_basis(p, states):
            _append(codes, code)
        return states, "", 0, codes
    if not p.records_present:
        _append(codes, "records-absent")
        return states, "", 0, codes
    binding = statement_binding(s, raw)
    try:
        issued_at = parse_timestamp(p.issued_at)
    except ValueError:
        _append(codes, "issued-at-malformed")
        return states, binding, 0, codes
    for row in p.rows:
        if row.substrate():
            for code in check_substrate_row(p, row, states, binding, issued_at)[0]:
                _append(codes, code)
    for code in _commitments_any_basis(p, states) + _commitments_substrate(p, states, binding, issued_at):
        _append(codes, code)
    return states, binding, issued_at, codes


# ---------------------------------------------------------------------------
# Recompute, tiers and the report.
# ---------------------------------------------------------------------------

_RANK = {"fail": 0, "degraded": 1, "pass_indirect": 2, "pass": 3}


def recompute(p: Predicate) -> str:
    voc = p.env.vocabulary if p.env is not None else None
    labels = set(voc.labels) if voc else set()
    caught = set(voc.caught) if voc else set()
    forces_fail = indirect = False
    for row in p.rows:
        if (row.containment in caught or row.containment not in labels
                or row.basis not in (SUBSTRATE, ARTIFACT)
                or row.method not in (INTERCEPTED, RECONSTRUCTED)
                or row.attribution not in (PINNED, PAIRED)):
            forces_fail = True
        elif row.basis != SUBSTRATE or row.method != INTERCEPTED:
            indirect = True
    incomplete = p.coverage is not None and bool(p.coverage.out_of_scope or p.coverage.routed_elsewhere)
    result = "pass"
    for flag, floor in ((indirect, "pass_indirect"), (incomplete, "degraded"), (forces_fail, "fail")):
        if flag and _RANK[floor] < _RANK[result]:
            result = floor
    return result


def _verifies(state: RecordState, signatures: list[str], keys: list[Ed25519PublicKey]) -> bool:
    if state.decode_error:
        return False
    for signature in signatures:
        try:
            raw = decode_carried_base64(signature)
        except ValueError:
            continue
        for key in keys:
            try:
                key.verify(raw, state.pae)
                return True
            except (InvalidSignature, ValueError):
                continue
    return False


@dataclass
class Report:
    """The verification outcome; an invalid report carries no result and no tiers."""

    verdict: str
    codes: list[str] = field(default_factory=list)
    result: str | None = None
    tiers: list[str] | None = None

    @property
    def primary_code(self) -> str | None:
        return self.codes[0] if self.codes else None

    def as_dict(self) -> dict:
        out: dict[str, Any] = {"verdict": self.verdict, "codes": list(self.codes),
                               "primary_code": self.primary_code}
        if self.verdict == VALID:
            out["result"] = self.result
            out["tiers"] = list(self.tiers or [])
        return out


def load_public_key(raw: bytes) -> Ed25519PublicKey:
    """A raw 32-byte Ed25519 public key."""
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify(statement: bytes, substrate_keys: list[Ed25519PublicKey] | None = None) -> Report:
    """Run GATE 0, GATE 1, recompute equality and GATE 2 over one statement's bytes."""
    try:
        s = parse_statement(statement)
    except JSONError:
        return Report(INVALID, [STATEMENT_MALFORMED])
    codes = gate0(s)
    if codes:
        return Report(INVALID, codes)
    states, binding, issued_at, codes = gate1(s, statement)
    if codes:
        return Report(INVALID, codes)
    p = s.predicate
    if recompute(p) != p.result:
        return Report(INVALID, ["result-recompute-mismatch"])
    keys = list(substrate_keys or [])
    tiers = []
    for row in p.rows:
        if not row.substrate():
            tiers.append(TIER_DECLARED)
            continue
        if not keys:
            tiers.append(TIER_UNATTESTED)
            continue
        row_codes, covering = check_substrate_row(p, row, states, binding, issued_at)
        attested = not row_codes and all(
            _verifies(states[index], p.records[index].signatures, keys) for index in covering)
        tiers.append(TIER_ATTESTED if attested else TIER_UNATTESTED)
    return Report(VALID, [], p.result, tiers)
