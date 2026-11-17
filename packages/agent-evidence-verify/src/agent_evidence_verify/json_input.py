"""Bound JSON parsing before allocation, with no duplicate-member inference."""

from __future__ import annotations

from collections.abc import Callable

from .common import CaseError
from .ijson import IJSONError, describe, parse_ijson


def parse_json(raw: bytes, *, max_bytes: int, max_depth: int, max_nodes: int,
               parse_float: Callable | None = None, ascii_only: bool = False):
    if len(raw) > max_bytes:
        raise CaseError("JSON input exceeds byte budget")
    depth = nodes = 0
    quoted = escaped = token = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
            token = False
            nodes += 1
        elif byte in (91, 123):
            depth += 1
            nodes += 1
            token = False
        elif byte in (93, 125):
            depth -= 1
            token = False
        elif byte in (9, 10, 13, 32, 44, 58):
            token = False
        elif not token:
            nodes += 1
            token = True
        if depth > max_depth or nodes > max_nodes:
            raise CaseError("JSON input exceeds structure budget")

    if ascii_only and not raw.isascii():
        raise CaseError("invalid JSON input")
    try:
        # The shared strict reader: UTF-8 only (so no UTF-16/UTF-32 inference), no repeated member,
        # no lone surrogate, no integer outside +-(2**53 - 1), no NaN or Infinity.
        return parse_ijson(raw, max_depth=max_depth, parse_float=parse_float)
    except IJSONError as exc:
        raise CaseError(f"invalid JSON input ({describe(exc)})") from exc
