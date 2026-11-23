"""``jcs_canonical/v1``: are the claimed bytes the RFC 8785 canonical form of this JSON input?

Three targets. ``rfc8785`` canonicalizes one JSON value. ``card-signing-input`` is the A2A Agent Card
signing input: the card without its top-level ``signatures`` member, canonicalized (A2A
specification 8.4.1 rules 2 and 3). Numbers are IEEE 754 doubles written as ECMAScript
``Number::toString``; members sort by their UTF-16 code units; a lone surrogate, NaN, Infinity, a
duplicate member or an integer outside the double range, and any number token no double holds exactly (RFC 7493
section 2.2), has no canonical form. A third target, ``rfc8785-safe-integer``, is the bounded
profile for signing inputs: it also refuses a number whose double reaches 2**53
(``12345678901234567.5`` canonicalizes to the integer 12345678901234568, which the profile
refuses on input). The canonicalizer is
a port of probityai/agent-evidence-vectors at commit 317df600f9a1503f32bcc2742b9f111036bdee32,
``packaging/agent_evidence_vectors/a2ajcs.py``.

Decisions: equal bytes are ``supported`` / ``canonical_bytes_match``; input with no canonical form
is ``contradicted`` / ``no_canonical_form``; other bytes are ``contradicted`` /
``canonical_bytes_differ``.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from pathlib import Path
from typing import Any

from ..common import CaseError, _string
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "jcs_canonical/v1"
TARGETS = ("rfc8785", "card-signing-input", "rfc8785-safe-integer")
MAX_EXACT_INTEGER = 2**53 - 1
TWO_POW_53 = float(2**53)
LIMIT = ("Recomputes canonical bytes from the bound input. It says nothing about who produced the "
         "input or whether a signature over the bytes is valid.")


class Refusal(ValueError):
    """The input has no RFC 8785 canonical form."""


def _number(value: float) -> str:
    """ECMAScript Number::toString of a finite double (RFC 8785 section 3.2.2.3)."""
    if not math.isfinite(value):
        raise Refusal("NaN and Infinity have no JSON number form")
    if value == 0:
        return "0"
    if value < 0:
        return "-" + _number(-value)
    _, digit_tuple, exponent = Decimal(repr(value)).as_tuple()
    if not isinstance(exponent, int):
        raise Refusal("NaN and Infinity have no JSON number form")
    every = "".join(str(d) for d in digit_tuple)
    digits = every.rstrip("0")
    exponent += len(every) - len(digits)
    k = len(digits)
    n = k + exponent
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"


_CONTROL = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _string_form(text: str) -> str:
    """RFC 8785 section 3.2.2.2, refusing a lone surrogate (not Unicode text)."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        if 0xD800 <= code <= 0xDFFF:
            raise Refusal(f"lone surrogate U+{code:04X} is not a Unicode scalar value")
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append(_CONTROL.get(code, f"\\u{code:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _value(value: Any, bounded: bool = False) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_EXACT_INTEGER:
            raise Refusal("number_not_interoperable: integer outside the I-JSON exact range "
                          "+-(2**53 - 1)")
        try:
            return _number(float(value))
        except OverflowError as exc:
            raise Refusal("integer outside the IEEE 754 double range") from exc
    if isinstance(value, float):
        if bounded and math.isfinite(value) and abs(value) >= TWO_POW_53:
            raise Refusal("number_not_interoperable: number whose double is an integer outside "
                          "the I-JSON exact range")
        return _number(value)
    if isinstance(value, str):
        return _string_form(value)
    if isinstance(value, list):
        return "[" + ",".join(_value(item, bounded) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_string_form(key) + ":" + _value(value[key], bounded)
                         for key in keys) + "}"
    raise Refusal(f"{type(value).__name__} is not a JSON value")


def serialize(value: Any) -> bytes:
    """The RFC 8785 bytes of an already parsed JSON value; raises :class:`Refusal` when it has none."""
    return _value(value).encode("utf-8")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in pairs:
        if key in out:
            raise Refusal(f"duplicate member {key!r} is not I-JSON")
        out[key] = item
    return out


def _exact_integer(token: str) -> int:
    """An integer token a double holds exactly (RFC 7493 section 2.2), else :class:`Refusal`.

    ``9007199254740993`` would canonicalize as ``9007199254740992``: the bytes a signer signs and the
    number an exact reader reads would be two values.
    """
    value = int(token)
    if abs(value) > MAX_EXACT_INTEGER:
        raise Refusal("number_not_interoperable: integer outside the I-JSON exact range "
                      "+-(2**53 - 1)")
    try:
        exact = float(value) == value
    except OverflowError as exc:
        raise Refusal("integer outside the IEEE 754 double range") from exc
    if not exact:
        raise Refusal(f"integer {token} has more precision than a double holds")
    return value


def _exact_number(token: str) -> float:
    """A non-integer token whose double, written at its shortest, is the token's own number."""
    value = float(token)
    if not math.isfinite(value) or Decimal(token) != Decimal(repr(value)):
        raise Refusal(f"number {token} reads as the double {value!r}, another number")
    return value


def _no_constant(token: str) -> Any:
    raise Refusal("NaN and Infinity have no JSON number form")


def canonical(target: str, text: str) -> bytes:
    """The canonical bytes of ``text`` for ``target``; raises :class:`Refusal` when it has none."""
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_int=_exact_integer,
                           parse_float=_exact_number, parse_constant=_no_constant)
    except Refusal:
        raise
    except ValueError as exc:
        raise Refusal(f"not JSON text: {exc}") from exc
    if target == "card-signing-input" and isinstance(value, dict):
        value = {key: item for key, item in value.items() if key != "signatures"}
    if target == "rfc8785-safe-integer":
        return _value(value, True).encode("utf-8")
    return _value(value).encode("utf-8")


def canonical_bounded(text: str) -> bytes:
    """RFC 8785 bytes for a signing input under the safe-integer profile: one signature, one number."""
    return canonical("rfc8785-safe-integer", text)


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Recompute the canonical bytes of the bound input and compare them with the claimed bytes."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"target", "input", "claimed"})
    target = _string(assessment["target"], "assessment.target")
    if target not in TARGETS:
        raise CaseError(f"assessment.target: expected one of {list(TARGETS)}")
    source, input_binding = bound(artifacts, artifact_root, assessment["input"], "assessment.input")
    claimed, claimed_binding = bound(artifacts, artifact_root, assessment["claimed"],
                                     "assessment.claimed")
    scope = {"target": target, "input": input_binding, "claimed": claimed_binding, "limit": LIMIT}
    if source is None or claimed is None:
        role = "input" if source is None else "claimed"
        return decision(case_id, CLAIM_TYPE, scope, "not_established", role + "_unavailable")
    try:
        produced = canonical(target, source.decode("utf-8"))
    except (Refusal, UnicodeDecodeError) as exc:
        check = {"id": "canonical_form", "status": "fail", "refusal": str(exc)}
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", "no_canonical_form", [check])
    match = produced == claimed
    check = {"id": "canonical_form", "status": "pass" if match else "fail",
             "recomputed_utf8_hex": produced.hex(), "claimed_utf8_hex": claimed.hex()}
    if match:
        return decision(case_id, CLAIM_TYPE, scope, "supported", "canonical_bytes_match", [check])
    return decision(case_id, CLAIM_TYPE, scope, "contradicted", "canonical_bytes_differ", [check])
