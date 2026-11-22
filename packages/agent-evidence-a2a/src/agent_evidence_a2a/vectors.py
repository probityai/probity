"""Run the a2a-jcs-v01 vectors against an implementation's canonicaliser (the canonicaliser-under-test mode)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

import rfc8785

from agent_evidence_a2a._data import data_json
from agent_evidence_a2a._ijson import MAX_DOCUMENT_BYTES, IJsonError, parse_i_json, parse_vector_json

#: The most one conformance vector's raw input may hold.
_MAX_VECTOR_BYTES: Final = MAX_DOCUMENT_BYTES

Canonicalize = Callable[[Any], bytes]
RULE_3 = "a2a-spec-8.4.1-rule-3"


def load_vectors() -> list[dict[str, Any]]:
    """Return the 57 a2a-jcs-v01 vectors shipped with the package."""
    vectors: list[dict[str, Any]] = data_json("jcs_vectors.json")["vectors"]
    return vectors


def _refuses(impl: Canonicalize, value: Any) -> bytes | None:
    try:
        return impl(value)
    except (ValueError, TypeError, RecursionError):
        return None


def reference_canonicalize(value: Any) -> bytes:
    """Canonicalize with the reference implementation (rfc8785 on PyPI)."""
    return rfc8785.dumps(value)


def reference_signing_bytes(card: dict[str, Any]) -> bytes:
    """The reference signing path: drop ``signatures`` (rule 3), then canonicalize."""
    return reference_canonicalize({k: v for k, v in card.items() if k != "signatures"})


def check_vector(
    vector: dict[str, Any], impl: Canonicalize, signing: Callable[[dict[str, Any]], bytes]
) -> tuple[bool, str]:
    """Judge one vector: ``(passed, detail)``.

    Accept vectors need the exact bytes; reject vectors need a refusal. Rule 3 vectors go through
    *signing* so an implementation that keeps ``signatures`` through canonicalization fails them.
    """
    if vector["disposition"] == "MUST-ACCEPT":
        rule3 = vector["clause"] == RULE_3
        out = _refuses(signing, vector["input"]) if rule3 else _refuses(impl, vector["input"])
        if out is None:
            return False, "canonicalization raised, expected success"
        want = bytes.fromhex(vector["canonical_utf8_hex"])
        return (True, "ok") if out == want else (False, f"byte mismatch: got {out!r} want {want!r}")
    return _check_reject(vector, impl, signing)


def _check_reject(
    vector: dict[str, Any], impl: Canonicalize, signing: Callable[[dict[str, Any]], bytes]
) -> tuple[bool, str]:
    """Judge one MUST-REJECT vector: the input has to be refused, by parsing or by canonicalization."""
    raw = vector["input_raw"].encode("utf-8")
    if vector["clause"] == RULE_3:
        try:
            card = parse_i_json(vector["input_raw"], max_bytes=_MAX_VECTOR_BYTES)
        except IJsonError:
            return False, "rule-3 input is not bounded I-JSON, expected well-formed input"
        out = _refuses(signing, card)
        if out is None:
            return False, "signing path raised on well-formed input"
        return (
            (True, "correctly refused")
            if out != raw
            else (False, "accepted claimed-canonical bytes that still carry 'signatures'")
        )
    try:
        parsed = parse_vector_json(vector["input_raw"], max_bytes=_MAX_VECTOR_BYTES)
    except (json.JSONDecodeError, IJsonError):
        return True, "correctly refused (parse level)"
    out = _refuses(impl, parsed)
    return (
        (True, "correctly refused")
        if out is None
        else (False, f"accepted input that should have been refused, produced {out!r}")
    )


@dataclass(frozen=True, kw_only=True, slots=True)
class CanonicaliserReport:
    """How many of the vectors an implementation's canonicaliser passes."""

    total: int
    failed_ids: tuple[str, ...]

    @property
    def passed(self) -> int:
        """The number of vectors that passed."""
        return self.total - len(self.failed_ids)


def check_canonicaliser(
    impl: Canonicalize,
    signing: Callable[[dict[str, Any]], bytes] | None = None,
) -> CanonicaliserReport:
    """Run all vectors against *impl*; *signing* defaults to dropping ``signatures`` then calling *impl*."""

    def default_signing(card: dict[str, Any]) -> bytes:
        return impl({k: v for k, v in card.items() if k != "signatures"})

    sign = signing or default_signing
    vectors = load_vectors()
    failed = tuple(v["id"] for v in vectors if not check_vector(v, impl, sign)[0])
    return CanonicaliserReport(total=len(vectors), failed_ids=failed)


def broken_code_point_order(value: Any) -> bytes:
    """Positive control m1: sorted compact ``json.dumps`` (code-point key order, Python float repr)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def broken_ascii_escaping(value: Any) -> bytes:
    """Positive control m2: m1 plus ASCII escaping, which RFC 8785 forbids."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
