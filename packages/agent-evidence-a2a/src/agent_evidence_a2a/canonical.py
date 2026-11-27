"""The bytes an agent card signature covers, computed from the card as served (A2A section 8.4.3)."""

from __future__ import annotations

import json
import math
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

import rfc8785

from agent_evidence_a2a._data import data_json
from agent_evidence_a2a._ijson import MAX_DEPTH, IJsonError, parse_i_json

#: The largest served card read (an Agent Card is KiBs; the bound refuses a padded document before any parse).
MAX_CARD_BYTES: Final = 10 * 1024 * 1024


class CardCanonicalizationError(ValueError):
    """The served card has no RFC 8785 canonical form."""


def _field_for(fields: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    return next((f for f in fields if key in (f["json_name"], f["name"])), None)


def _strip_defaults(obj: Any, message: str, messages: dict[str, Any], *, keep_required: bool = True) -> Any:
    """Apply section 8.4.1 rule 1 to *obj*: drop default-valued fields that are optional and have no presence.

    REQUIRED fields stay even at their default (unless *keep_required* is false, which builds the
    form a producer that dropped them would sign), fields with explicit presence stay whenever
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
        value = _strip_nested(value, field, messages, keep_required=keep_required)
        if not _droppable(value, field, keep_required=keep_required):
            out[key] = value
    return out


def _strip_nested(value: Any, field: dict[str, Any], messages: dict[str, Any], *, keep_required: bool) -> Any:
    """Strip defaults inside a message-typed field's value (one message or a list of them)."""
    sub = field["message"]
    if sub is None:
        return value
    if isinstance(value, list):
        return [_strip_defaults(v, sub, messages, keep_required=keep_required) for v in value]
    return _strip_defaults(value, sub, messages, keep_required=keep_required)


def _droppable(value: Any, field: dict[str, Any], *, keep_required: bool) -> bool:
    """A default-valued member of an optional field without explicit presence drops out of the signed form."""
    is_default = value in ("", 0, False, [], {}) and value is not None
    return is_default and not field["presence"] and not (keep_required and field["required"])


def _served_document(served: str | bytes, *, max_depth: int, max_bytes: int) -> tuple[dict[str, Any], object]:
    """The served card parsed as I-JSON with its ``signatures`` member removed, and that member (``None`` if absent)."""
    try:
        text = served.decode("utf-8") if isinstance(served, bytes) else served
        data = parse_i_json(text, max_depth=max_depth, max_bytes=max_bytes)
    except (IJsonError, UnicodeDecodeError) as exc:
        raise CardCanonicalizationError(str(exc)) from exc
    if not isinstance(data, dict):
        msg = "the served card is not a JSON object"
        raise CardCanonicalizationError(msg)
    return data, data.pop("signatures", None)


def _stripped(data: dict[str, Any], *, keep_required: bool = True) -> Any:
    schema = data_json("agent_card_schema.json")
    return _strip_defaults(data, schema["root"], schema["messages"], keep_required=keep_required)


def served_signing_bytes(served: str | bytes, *, max_depth: int = MAX_DEPTH, max_bytes: int = MAX_CARD_BYTES) -> bytes:
    """Return the signing payload of the card exactly as served.

    Parse as I-JSON, drop ``signatures``, remove default-valued optional properties (rule 1),
    and canonicalize with RFC 8785.

    Raises:
        CardCanonicalizationError: The served card has no RFC 8785 form.
    """
    return signed_parts(served, max_depth=max_depth, max_bytes=max_bytes).payload


@dataclass(frozen=True, slots=True)
class SignedParts:
    """A served card split the way a verifier reads it, from one parse of the served bytes.

    Attributes:
        payload: The section 8.4.3 signing payload (what :func:`served_signing_bytes` returns).
        signatures: The served ``signatures`` member exactly as parsed, or ``None`` when the card has none.
            It is not checked here: a verifier judges its shape signature by signature.
    """

    payload: bytes
    signatures: object


def signed_parts(served: str | bytes, *, max_depth: int = MAX_DEPTH, max_bytes: int = MAX_CARD_BYTES) -> SignedParts:
    """Return the signing payload and the ``signatures`` member of the card exactly as served.

    The payload and the signatures come from the same parse, so a verifier never judges signatures
    read from one document against a payload computed from another.

    Raises:
        CardCanonicalizationError: The served card has no RFC 8785 form.
    """
    data, signatures = _served_document(served, max_depth=max_depth, max_bytes=max_bytes)
    try:
        payload = rfc8785.dumps(_stripped(data))
    except (rfc8785.CanonicalizationError, rfc8785.IntegerDomainError, rfc8785.FloatDomainError, ValueError) as exc:
        raise CardCanonicalizationError(str(exc)) from exc
    return SignedParts(payload=payload, signatures=signatures)


def _map_scalars(value: Any, fn: Callable[[Any], Any]) -> Any:
    """Apply *fn* to every string (keys too) and number in a JSON value, rebuilding objects and arrays."""
    if isinstance(value, dict):
        return {_map_scalars(k, fn): _map_scalars(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [_map_scalars(v, fn) for v in value]
    return fn(value)


def _nfc(value: Any) -> Any:
    return unicodedata.normalize("NFC", value) if isinstance(value, str) else value


def _integral_float_as_int(value: Any) -> Any:
    return int(value) if isinstance(value, float) and math.isfinite(value) and value.is_integer() else value


def _without_empty(value: Any) -> Any:
    """Drop ``None``, empty strings, empty lists and empty objects, recursively (the reference signer's cleaning)."""
    if isinstance(value, dict):
        cleaned = {k: _without_empty(v) for k, v in value.items()}
        return {k: v for k, v in cleaned.items() if v not in (None, "", [], {})}
    if isinstance(value, list):
        items = [_without_empty(v) for v in value]
        return [v for v in items if v not in (None, "", [], {})]
    return value


#: The label of the form the A2A reference SDK's signer produced before it emitted RFC 8785.
REFERENCE_SIGNER_FORM: Final = "the A2A reference SDK's json.dumps(sort_keys=True) canonicalization"


def non_jcs_forms(served: str | bytes) -> list[tuple[str, bytes]]:
    """The signing payloads a producer would get by deviating from RFC 8785 in one known way, from the card as served.

    The first is the form the A2A reference signer produced before it emitted true JCS: the card
    without ``signatures`` and without empty values, dumped with sorted keys, compact separators and
    ASCII escaping.  Each of the others is the section 8.4.3 payload (defaults removed,
    ``signatures`` dropped) with exactly one deviation: keys ordered by code point rather than
    UTF-16 code units, integral numbers written as full digits rather than in ES6 form,
    default-valued fields kept, REQUIRED fields at their default dropped, or strings in Unicode
    normalization form NFC.  Every form is built from the served document, so a member the schema
    does not know stays in each and a member added after signing is never explained away as a
    canonicalization choice.  A signature that verifies over one of them, and not over the true
    payload, shows which rule the producer broke.  A form the deviation cannot be built for (a lone
    surrogate, a number out of range) is left out, and a card with no I-JSON form has none.
    """
    try:
        data, _signatures = _served_document(served, max_depth=MAX_DEPTH, max_bytes=MAX_CARD_BYTES)
    except CardCanonicalizationError:
        return []

    def plain(value: Any, *, ascii_only: bool = False) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=ascii_only).encode("utf-8")

    stripped = _stripped(data)
    builders: tuple[tuple[str, Callable[[], bytes]], ...] = (
        (REFERENCE_SIGNER_FORM, lambda: plain(_without_empty(data), ascii_only=True)),
        ("keys ordered by code point instead of UTF-16 code units", lambda: plain(stripped)),
        (
            "integral numbers written as full digits instead of the ES6 form",
            lambda: plain(_map_scalars(stripped, _integral_float_as_int)),
        ),
        ("default-valued fields kept in the signed bytes", lambda: rfc8785.dumps(data)),
        (
            "REQUIRED fields holding their default omitted from the signed bytes",
            lambda: rfc8785.dumps(_stripped(data, keep_required=False)),
        ),
        ("strings normalized to Unicode NFC before signing", lambda: rfc8785.dumps(_map_scalars(stripped, _nfc))),
    )
    forms = []
    for label, build in builders:
        try:
            forms.append((label, build()))
        except (ValueError, OverflowError, RecursionError, rfc8785.CanonicalizationError):
            continue
    return forms
