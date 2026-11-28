"""A received DPoP proof that is not ASCII is ``dpop_malformed``, never a raise, on every shared row that carries one.

Each case is a shared vector row whose proof has one non-ASCII character added to its header or claims segment. An
earlier ``check_dpop`` built the signing input with ``.encode("ascii")`` after its size check and before it read the
claims, so these rows raised UnicodeEncodeError. The TypeScript twin gives the same code for the same rows (the
differential in tests/parity_r6c). This file imports only the vector judge, so it also runs against older code.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from probity_records.verified_identities_vectors import judge

ROWS = json.loads((Path(__file__).parents[1] / "vectors" / "shared" / "verified_identities.json").read_text())
CASES = [
    (f"{row['id']}/{segment}", row, segment)
    for row in ROWS
    if isinstance(dpop := (row.get("request") or {}).get("dpop"), str) and dpop.count(".") == 2
    for segment in (0, 1)
]


def test_the_cases_cover_every_row_with_a_proof() -> None:
    assert len(CASES) == 2 * sum(isinstance((r.get("request") or {}).get("dpop"), str) and
                                 r["request"]["dpop"].count(".") == 2 for r in ROWS) > 0


@pytest.mark.parametrize(("name", "row", "segment"), CASES, ids=[c[0] for c in CASES])
def test_a_dpop_segment_that_is_not_ascii_is_dpop_malformed(name: str, row: dict[str, Any], segment: int) -> None:
    r = copy.deepcopy(row)
    parts = r["request"]["dpop"].split(".")
    parts[segment] += "é"
    r["request"]["dpop"] = ".".join(parts)
    try:
        got = judge(r)
    except Exception as exc:  # noqa: BLE001 - a raise on received text is the defect this test names
        pytest.fail(f"{name}: a non-ASCII DPoP proof raised {type(exc).__name__} instead of being refused")
    assert got == {"refused": "dpop_malformed"}, name
