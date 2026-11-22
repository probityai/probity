"""Strict I-JSON (RFC 7493) parsing of a served document."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any, Final

MAX_DEPTH = 128
#: The largest document accepted when a caller names no bound: an Agent Card, a trust store or a vector file.
MAX_DOCUMENT_BYTES: Final = 32 * 1024 * 1024


class IJsonError(ValueError):
    """The text is not I-JSON, so it has no RFC 8785 canonical form."""


def nesting_depth(text: str) -> int:
    """Return the deepest bracket nesting of *text*, ignoring brackets inside strings."""
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "]}":
            depth -= 1
    return deepest


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        dup = sorted(n for n, seen in Counter(names).items() if seen > 1)
        msg = f"duplicate member name(s) {dup!r}: RFC 8785 requires I-JSON input"
        raise IJsonError(msg)
    return dict(pairs)


def _no_constants(name: str) -> Any:
    msg = f"{name} is not JSON and has no RFC 8785 form"
    raise IJsonError(msg)


def has_lone_surrogate(value: Any) -> bool:
    """True when any string or member name inside *value* holds an unpaired surrogate."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _bounded(text: str, *, max_bytes: int, max_depth: int) -> None:
    """Refuse *text* that is larger than *max_bytes* or nested past *max_depth*, before any parse."""
    size = len(text.encode("utf-8", "surrogatepass"))
    if size > max_bytes:
        msg = f"the document is {size} bytes; the limit is {max_bytes}"
        raise IJsonError(msg)
    if nesting_depth(text) > max_depth:
        msg = f"nesting deeper than {max_depth} levels"
        raise IJsonError(msg)


def parse_i_json(text: str, *, max_depth: int = MAX_DEPTH, max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """Parse *text* as I-JSON.

    Refused: a repeated member name, a non-finite literal, an unpaired surrogate, a document larger
    than *max_bytes* and nesting deeper than *max_depth* (both checked before parsing, so a bomb
    cannot exhaust memory or the stack).
    """
    _bounded(text, max_bytes=max_bytes, max_depth=max_depth)
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except RecursionError as exc:
        msg = "nesting too deep to parse"
        raise IJsonError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"not JSON: {exc}"
        raise IJsonError(msg) from exc
    if has_lone_surrogate(value):
        msg = "an unpaired surrogate has no well-formed UTF-8 encoding"
        raise IJsonError(msg)
    return value


def read_i_json(path: str | os.PathLike[str], *, max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """Read the file at *path* as I-JSON, never holding more than *max_bytes* of it.

    Raises:
        OSError: The file cannot be opened or read.
        IJsonError: The file is larger than *max_bytes*, not UTF-8, or not I-JSON; the message begins with *path*.
    """
    with open(path, "rb") as handle:  # noqa: PTH123 -- takes the str and PathLike forms its callers hold
        data = handle.read(max_bytes + 1)
    name = os.fspath(path)
    if len(data) > max_bytes:
        msg = f"{name}: the file is larger than the limit of {max_bytes} bytes"
        raise IJsonError(msg)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = f"{name}: the document is not UTF-8"
        raise IJsonError(msg) from exc
    try:
        return parse_i_json(text, max_bytes=max_bytes)
    except IJsonError as refusal:
        msg = f"{name}: {refusal}"
        raise IJsonError(msg) from refusal


def parse_vector_json(text: str, *, max_depth: int = MAX_DEPTH, max_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    """Parse a conformance vector's raw input, bounded but otherwise as the standard library reads it.

    A vector deliberately carries what I-JSON refuses (a non-finite literal, an unpaired surrogate),
    because the canonicaliser under test is what has to refuse it; reading the vector strictly
    would refuse it here and the implementation would never be asked.  Size and nesting are still
    bounded before the parse.

    Raises:
        IJsonError: The text is larger than *max_bytes* or nested past *max_depth*.
        json.JSONDecodeError: The text is not JSON.
    """
    _bounded(text, max_bytes=max_bytes, max_depth=max_depth)
    try:
        return json.loads(text)
    except RecursionError as exc:
        msg = "nesting too deep to parse"
        raise IJsonError(msg) from exc
