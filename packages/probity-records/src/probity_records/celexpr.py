"""CEL (Common Expression Language) conditions for grants, evaluated by Google's cel-cpp runtime.

A CEL condition is a boolean expression over a fixed set of variables. It holds only when the
expression evaluates to exactly ``true``; an error, a non-boolean result or a compile failure is
``false``, so a malformed or surprising condition refuses rather than admits.

JSON values bind to CEL by one rule every verifier shares (the TypeScript verifier runs the same
rule over the same vectors): a number whose value is an integer in the signed 64-bit range binds as
``int``, any other number as ``double``; strings, booleans, null, arrays and objects bind as
``string``, ``bool``, ``null``, ``list`` and ``map``. RFC 8785 serialises ``1.0`` and ``1`` to the
same bytes, so a verifier that reads the canonical bytes cannot tell them apart, and neither may we.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from cel_expr_python import cel

#: The variables a condition may name: ``value`` (one argument, for an argument constraint),
#: ``args`` (every argument of the call), ``tool`` (the tool name) and ``ctx`` (the call context the
#: permit names: workflow, run, call, agent).
VARIABLES = ("value", "args", "tool", "ctx")
INT64 = 2**63


def to_cel(value: Any) -> Any:
    """The CEL binding of a JSON value, by the shared rule in the module docstring."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return value if -INT64 <= value < INT64 else float(value)
    if isinstance(value, float):
        return int(value) if value.is_integer() and -INT64 <= value < INT64 else value
    if isinstance(value, list):
        return [to_cel(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_cel(v) for k, v in value.items()}
    raise TypeError(f"not a JSON value: {type(value).__name__}")


@lru_cache(maxsize=1)
def _env() -> Any:
    return cel.NewEnv(variables={name: cel.Type.DYN for name in VARIABLES})


#: The whitespace CEL's grammar skips (WHITESPACE in the CEL language definition). An expression of nothing else
#: is empty; any other character goes to the parser.
_BLANK = re.compile(r"[ \t\n\r\f]*")


def syntax_problem(expr: Any) -> str | None:
    """None when ``expr`` is a CEL expression that parses; otherwise ``cel_expression_empty`` (not a string, or
    only whitespace) or ``cel_syntax_invalid``. This is the check a verifier runs on a grant: syntax only, because
    the TypeScript verifier's CEL engine has no type checker that agrees with cel-cpp's, and an expression that
    parses but does not type-check never holds at evaluation (``holds`` is false) in either verifier."""
    if not isinstance(expr, str) or _BLANK.fullmatch(expr):
        return "cel_expression_empty"
    try:
        _env().compile(expr, disable_check=True)
    except Exception:  # noqa: BLE001 - every parser refusal is the one defect, whatever its message
        return "cel_syntax_invalid"
    return None


@lru_cache(maxsize=4096)
def _compiled(expr: str) -> Any:
    return _env().compile(expr)


def compile_expr(expr: Any) -> Any:
    """The type-checked program; ValueError ``cel_expression_empty``, ``cel_syntax_invalid`` or
    ``cel_type_check_failed`` (it parses, but cel-cpp's type check refuses it). An issuer runs this on every
    expression it signs; a verifier runs ``syntax_problem``."""
    found = syntax_problem(expr)
    if found:
        raise ValueError(found)
    try:
        return _compiled(expr)
    except Exception as exc:
        raise ValueError("cel_type_check_failed") from exc


def holds(expr: str, bindings: dict[str, Any]) -> bool:
    """True only when ``expr`` evaluates to exactly ``true`` under ``bindings``."""
    try:
        program = compile_expr(expr)
        data = {name: to_cel(bindings.get(name)) for name in VARIABLES}
        result = program.eval(data=data).value()
    except Exception:  # noqa: BLE001 - any evaluation error refuses
        return False
    return result is True
