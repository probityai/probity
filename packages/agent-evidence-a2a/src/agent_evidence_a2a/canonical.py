"""The bytes an agent card signature covers, computed from the card as served (A2A section 8.4.3)."""

from __future__ import annotations

from typing import Any

import rfc8785

from agent_evidence_a2a._data import data_json
from agent_evidence_a2a._ijson import MAX_DEPTH, IJsonError, parse_i_json


class CardCanonicalizationError(ValueError):
    """The served card has no RFC 8785 canonical form."""


def _field_for(fields: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    return next((f for f in fields if key in (f["json_name"], f["name"])), None)


def _strip_defaults(obj: Any, message: str, messages: dict[str, Any]) -> Any:
    """Apply section 8.4.1 rule 1 to *obj*: drop default-valued fields that are optional and have no presence.

    REQUIRED fields stay even at their default, fields with explicit presence stay whenever
    present, and a member the schema does not know stays: it was signed and served, and
    dropping it would let anyone append members to a signed card.
    """
    if not isinstance(obj, dict):
        return obj
    fields = messages[message]
    out: dict[str, Any] = {}
    for key, value in obj.items():
        field = _field_for(fields, key)
        if field is None:
            out[key] = value
            continue
        value = _strip_nested(value, field, messages)
        if not _droppable(value, field):
            out[key] = value
    return out


def _strip_nested(value: Any, field: dict[str, Any], messages: dict[str, Any]) -> Any:
    """Strip defaults inside a message-typed field's value (one message or a list of them)."""
    sub = field["message"]
    if sub is None:
        return value
    if isinstance(value, list):
        return [_strip_defaults(v, sub, messages) for v in value]
    return _strip_defaults(value, sub, messages)


def _droppable(value: Any, field: dict[str, Any]) -> bool:
    """A default-valued member of an optional field without explicit presence drops out of the signed form."""
    is_default = value in ("", 0, False, [], {}) and value is not None
    return is_default and not field["presence"] and not field["required"]


def served_signing_bytes(served: str | bytes, *, max_depth: int = MAX_DEPTH) -> bytes:
    """Return the signing payload of the card exactly as served.

    Parse as I-JSON, drop ``signatures``, remove default-valued optional properties (rule 1),
    and canonicalize with RFC 8785.

    Raises:
        CardCanonicalizationError: The served card has no RFC 8785 form.
    """
    try:
        text = served.decode("utf-8") if isinstance(served, bytes) else served
        data = parse_i_json(text, max_depth=max_depth)
    except (IJsonError, UnicodeDecodeError) as exc:
        raise CardCanonicalizationError(str(exc)) from exc
    if not isinstance(data, dict):
        msg = "the served card is not a JSON object"
        raise CardCanonicalizationError(msg)
    data.pop("signatures", None)
    schema = data_json("agent_card_schema.json")
    try:
        return rfc8785.dumps(_strip_defaults(data, schema["root"], schema["messages"]))
    except (rfc8785.CanonicalizationError, rfc8785.IntegerDomainError, rfc8785.FloatDomainError, ValueError) as exc:
        raise CardCanonicalizationError(str(exc)) from exc
