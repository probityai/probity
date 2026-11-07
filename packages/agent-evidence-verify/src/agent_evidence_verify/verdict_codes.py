"""The closed set of receipt verdict codes, and the failure codes each one covers.

A report that is not clean carries one verdict code, so a reader holding only the
document learns what kind of refusal or limit it is without reading the failure-code
registry. The registry is ``receipt-verdict-codes.json``, a byte copy of
``docs/reference/receipt-verdict-codes.json`` in probityai/agent-evidence-vectors
(its gate holds it to the Go core and the corpus). This module only reads it.

A failure takes the code of the report's primary code. A valid report takes the code of
its worst row tier, ``unattested`` before ``declared``; an all-``attested`` report is
clean and has none. A code the registry does not classify raises :class:`UnknownCode`:
a caller that reads a code from a newer verifier refuses it, never passes it.
"""

from __future__ import annotations

import json
from enum import StrEnum
from functools import cache
from importlib import resources
from typing import Any


class VerdictCode(StrEnum):
    """The closed set. A value outside it is not a verdict code."""

    NOT_PUBLICLY_VERIFIABLE = "NOT_PUBLICLY_VERIFIABLE"
    LEAF_HASH_MISMATCH = "LEAF_HASH_MISMATCH"
    PROOF_BROKEN = "PROOF_BROKEN"
    CLAIM_NOT_BOUND = "CLAIM_NOT_BOUND"
    SUMMARY_MISMATCH = "SUMMARY_MISMATCH"
    MALFORMED = "MALFORMED"
    NOT_RECONSTRUCTIBLE = "NOT_RECONSTRUCTIBLE"

    @classmethod
    def parse(cls, text: str) -> VerdictCode:
        """The verdict code spelled ``text``; any other spelling raises UnknownCode."""
        try:
            return cls(text)
        except ValueError:
            raise UnknownCode(f"{text!r} is not a receipt verdict code") from None


class UnknownCode(ValueError):
    """A code the registry does not classify. The caller treats it as a refusal."""


TIER_CODES = {"unattested": VerdictCode.NOT_PUBLICLY_VERIFIABLE,
              "declared": VerdictCode.NOT_RECONSTRUCTIBLE}


@cache
def registry() -> dict[str, Any]:
    """The shipped registry, read once."""
    text = resources.files(__package__).joinpath("receipt-verdict-codes.json").read_text("utf-8")
    loaded: dict[str, Any] = json.loads(text)
    if sorted(e["code"] for e in loaded["codes"]) != sorted(v.value for v in VerdictCode):
        raise UnknownCode("the shipped registry does not name exactly the closed set")
    return loaded


@cache
def _table() -> dict[str, VerdictCode | None]:
    table: dict[str, VerdictCode | None] = {code: None for code in registry()["outside_receipt_axis"]}
    for entry in registry()["codes"]:
        for code in entry["validity_codes"] + entry["consumer_policy_codes"]:
            table[code] = VerdictCode(entry["code"])
    return table


def verdict_for_code(code: str) -> VerdictCode | None:
    """The verdict code of one failure code; None for a consumer-policy code outside the axis."""
    table = _table()
    if code not in table:
        raise UnknownCode(f"no verdict code classifies {code!r}")
    return table[code]


def verdict_for_report(verdict: str, codes: list[str], tiers: list[str] | None) -> VerdictCode | None:
    """The verdict code of one verification report, or None when the report is clean."""
    if verdict != "valid":
        if not codes:
            raise UnknownCode("an invalid report names no code")
        return verdict_for_code(codes[0])
    for tier in ("unattested", "declared"):
        if tier in (tiers or []):
            return TIER_CODES[tier]
    return None
