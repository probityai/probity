"""Overfitting screen: a change may not carry literals copied from the training traces.

A guard or procedure that names `ch_3MoK8`, `cus_mo41`, `T-1042`, `3200` cents or "Maya Okafor" fixes one
recorded case, not a mechanism. The screen collects every record id, money amount and personal name the
training traces contain (tool-call arguments, recorded state views and tool results; policy documents are
excluded, since a policy threshold is general knowledge, not a copied case detail) and reports each one the
candidate's new text contains.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any

from ratchet_cases.types import Trace

from ratchet.improve.failures import Literals, new_text
from ratchet.types import Harness

_ID = re.compile(r"\b[A-Za-z]{1,6}[_-][A-Za-z0-9_-]*\d[A-Za-z0-9_-]*\b")
_NAME_KEYS = {"name", "full_name", "customer_name", "email", "to", "from"}
_AMOUNT_KEY = re.compile(r"cents|amount|total|price", re.IGNORECASE)
_COMMON_AMOUNTS = {100, 1000}


def _walk(value: Any, key: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for k, v in value.items():
            if k == "policy":
                continue
            yield from _walk(v, str(k))
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, key)
    else:
        yield key, value


def training_literals(traces: Iterable[Trace]) -> Literals:
    lit = Literals()
    for t in traces:
        lit.ids.update({t.case_id, t.run_id})
        for e in t.events:
            if e.kind not in ("tool_call", "tool_result"):
                continue
            for key, value in _walk(e.payload):
                if isinstance(value, bool):
                    continue
                if isinstance(value, int) and _AMOUNT_KEY.search(key) and value >= 100:
                    lit.amounts.add(value)
                elif isinstance(value, str):
                    lit.ids.update(_ID.findall(value))
                    if key in _NAME_KEYS and len(value) >= 4 and (" " in value or "@" in value):
                        lit.names.add(value)
    lit.amounts -= _COMMON_AMOUNTS
    return lit


def lint(parent: Harness, candidate: Harness, literals: Literals) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for where, text in new_text(parent, candidate):
        lowered = text.lower()
        for ident in sorted(literals.ids):
            if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(ident)}(?![A-Za-z0-9_-])", text):
                hits.append({"where": where, "category": "id", "literal": ident})
        for amount in sorted(literals.amounts):
            dollars = f"{amount // 100}.{amount % 100:02d}"
            if re.search(rf"(?<![\d.]){amount}(?!\d)", text) or re.search(
                rf"(?<![\d.]){re.escape(dollars)}(?!\d)", text
            ):
                hits.append({"where": where, "category": "amount", "literal": str(amount)})
        for name in sorted(literals.names):
            if name.lower() in lowered:
                hits.append({"where": where, "category": "name", "literal": name})
    return hits
