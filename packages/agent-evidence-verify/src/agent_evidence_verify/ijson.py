"""One strict I-JSON reader (RFC 7493) for every adapter, so no two adapters read one byte string apart.

Python's ``json`` module is lenient in five ways that let two readers of the same bytes disagree
about what a record says while both report a clean parse:

* a repeated member name keeps the last value silently (``{"a":1,"a":2}`` reads as ``{"a":2}``);
* an escaped lone surrogate (``"\\ud800"``) decodes to a string no UTF-8 text can carry, so the
  canonical form a signer hashed and the one a verifier rebuilds part ways;
* an integer outside +-(2**53 - 1) parses exactly in Python and rounds in every double-based reader,
  so ``9007199254740993`` names one number here and another in JavaScript;
* ``1e400`` parses to ``inf`` and ``NaN``, ``Infinity`` and ``-Infinity`` parse at all;
* nesting has no bound below the interpreter's recursion limit.

``parse_ijson`` refuses each of these, plus input that is not UTF-8 (including a UTF-8 encoded
surrogate and a byte-order mark), before any adapter reads a member. Duplicate detection runs on the
decoded names, so ``{"a":1,"\\u0061":2}`` is refused as a duplicate. Every refusal raises
:class:`IJSONError`, a ``ValueError`` whose ``code`` is one of :data:`CODES`; an adapter maps the
code to its own refusal vocabulary and never needs a second parser.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from typing import Any

#: Exact integers in an I-JSON number: RFC 7493 section 2.2.
MAX_SAFE_INTEGER = 2**53 - 1
#: Default nesting bound, objects and arrays together; the audit-record readers use the same.
MAX_DEPTH = 128

CODES = (
    "not-utf8",
    "not-parseable",
    "non-json-number",
    "duplicate-member",
    "lone-surrogate",
    "unsafe-integer",
    "value-not-representable",
    "nesting-too-deep",
)


class IJSONError(ValueError):
    """Bytes the strict reader refuses. ``code`` names the rule, ``detail`` says where."""

    def __init__(self, code: str, detail: str) -> None:
        if code not in CODES:
            raise AssertionError(f"unregistered I-JSON refusal code {code}")
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise IJSONError("duplicate-member", f"member {key!r} appears more than once")
        out[key] = value
    return out


def _safe_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:  # more digits than the interpreter converts
        raise IJSONError("unsafe-integer", f"integer token of {len(text)} digits") from exc
    if abs(value) > MAX_SAFE_INTEGER:
        raise IJSONError("unsafe-integer", f"{text} is outside +-(2**53 - 1)")
    return value


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise IJSONError("value-not-representable", f"{text} is not a finite double")
    return value


def _refuse_float(text: str) -> float:
    raise IJSONError("value-not-representable", f"non-integer number {text} is outside the profile")


def _refuse_constant(text: str) -> Any:
    raise IJSONError("non-json-number", f"{text} is not a JSON number")


def _depth_ok(text: str, max_depth: int) -> None:
    """Refuse nesting past ``max_depth`` before the recursive decoder sees it."""
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise IJSONError("nesting-too-deep", f"nesting deeper than {max_depth}")
        elif char in "]}":
            depth -= 1


def _surrogate_free(value: Any) -> None:
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in node):
                raise IJSONError("lone-surrogate", "a string escapes a lone surrogate")
        elif isinstance(node, dict):
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def decode_utf8(data: bytes | str) -> str:
    """The text of ``data``: strict UTF-8 with no byte-order mark."""
    if isinstance(data, str):
        text = data
    else:
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise IJSONError("not-utf8", f"invalid UTF-8 at byte {exc.start}") from exc
    if text.startswith("﻿"):
        raise IJSONError("not-utf8", "a byte-order mark precedes the text")
    return text


def parse_ijson(data: bytes | str, *, integers_only: bool = False, max_depth: int = MAX_DEPTH,
                parse_float: Callable[[str], Any] | None = None,
                parse_int: Callable[[str], Any] | None = None) -> Any:
    """Parse ``data`` under I-JSON, or raise :class:`IJSONError`.

    ``integers_only`` refuses every non-integer number (the integer-only profile of the receipt and
    claim corpora). ``parse_float`` replaces the default finite-double reader, for example with
    ``decimal.Decimal`` where an adapter compares decimal text exactly; a replacement still meets
    the finite check only if it enforces one itself. ``parse_int`` replaces the safe-integer check
    only for an adapter whose own later rule refuses an out-of-range number under a code its corpus
    pins (``observed_effect/v1``); every other check still runs.
    """
    text = decode_utf8(data)
    _depth_ok(text, max_depth)
    if integers_only:
        float_hook: Callable[[str], Any] = _refuse_float
    else:
        float_hook = parse_float or _finite_float
    try:
        value = json.loads(text, object_pairs_hook=_unique, parse_int=parse_int or _safe_int,
                           parse_float=float_hook, parse_constant=_refuse_constant)
    except IJSONError:
        raise
    except RecursionError as exc:
        raise IJSONError("nesting-too-deep", "nesting exceeds the interpreter's limit") from exc
    except ValueError as exc:
        raise IJSONError("not-parseable", str(exc)) from exc
    _surrogate_free(value)
    return value


#: The words the adapters' earlier private parsers used, so a caller's message stays the same.
LEGACY_WORDS = {"duplicate-member": "duplicate JSON key", "non-json-number": "non-JSON number"}


def describe(exc: IJSONError) -> str:
    """A one-line message for a case error: the legacy words where they exist, then the detail."""
    return f"{LEGACY_WORDS.get(exc.code, exc.code)}: {exc.detail}"


def parse_lines(data: bytes | str, **options: Any) -> list[Any]:
    """Newline-delimited I-JSON: each non-blank line under :func:`parse_ijson`."""
    text = decode_utf8(data)
    out = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(parse_ijson(line, **options))
        except IJSONError as exc:
            raise IJSONError(exc.code, f"line {number}: {exc.detail}") from exc
    return out
