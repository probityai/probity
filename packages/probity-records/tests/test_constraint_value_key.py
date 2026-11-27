"""The two readers compare constraint values by one key: ``true`` is never ``1``, ``1.0`` is ``1``, member order is free.

Python's ``==`` calls ``True`` and ``1`` equal and its ``repr`` sets tell ``1`` from ``1.0``; the TypeScript twin could do
neither of those, so a ``not_one_of`` list, a ``subset`` or a narrowing proof gave different answers in the two readers.
Both now compare ``core.value_key`` (the TypeScript twin's ``valueKey``): RFC 8785 bytes with numbers read as doubles.

The Python half is this file: the committed fixture must equal this reader's answer on every case. The TypeScript half is
``node/probity-records-verify/test/constraint-value-key.test.ts``, which reads the same fixture and must answer each case
the same way. Regenerate after an intended change: ``uv run python packages/probity-records/tests/test_constraint_value_key.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from probity_records import check_constraint, narrows
from probity_records.constraints import ConstraintError, same

FIXTURE = (Path(__file__).resolve().parents[3] / "node" / "probity-records-verify" / "test" / "fixtures"
           / "constraint-value-key.json")

POOL: list[Any] = [True, False, 1, 0, 1.0, 0.0, -0.0, 3, 3.0, 1e16, 10**16, "1", "", None, [], [True], [1], [1.0], [0],
                   {}, {"a": 1, "b": True}, {"b": True, "a": 1}, {"a": 1.0, "b": True}, {"a": True, "b": True},
                   {"a": 1, "b": 1}]


def _answer(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except ConstraintError as exc:
        return f"error:{exc}"


def build() -> dict[str, Any]:
    checks, narrowing = [], []
    for kind, key in (("exact", "value"), ("one_of", "values"), ("not_one_of", "values"), ("contains", "values"),
                      ("subset", "values")):
        for member in POOL:
            constraint = {"type": kind, key: member if kind == "exact" else [member]}
            for value in POOL:
                for given in ([value] if kind in ("contains", "subset") else [value, [value]]):
                    checks.append({"constraint": constraint, "value": given,
                                   "expected": _answer(check_constraint, constraint, given)})
    for kind in ("not_one_of", "contains", "subset"):
        for a in POOL:
            for b in POOL:
                child, parent = {"type": kind, "values": [a]}, {"type": kind, "values": [b]}
                narrowing.append({"child": child, "parent": parent, "expected": _answer(narrows, child, parent)})
    for a in POOL:
        for b in POOL:
            child, parent = {"type": "exact", "value": a}, {"type": "not_one_of", "values": [b]}
            narrowing.append({"child": child, "parent": parent, "expected": _answer(narrows, child, parent)})
    return {"check": checks, "narrows": narrowing}


def test_the_fixture_is_this_readers_answer_on_every_case() -> None:
    assert json.loads(FIXTURE.read_text()) == build()


def test_the_cases_reach_both_answers() -> None:
    cases = json.loads(FIXTURE.read_text())
    assert {c["expected"] for c in cases["check"]} == {True, False}
    assert {c["expected"] for c in cases["narrows"]} == {True, False}


@pytest.mark.parametrize(("a", "b", "equal"), [
    (True, 1, False), (False, 0, False), (1, 1.0, True), (1e16, 10**16, True),
    ({"a": 1, "b": True}, {"b": True, "a": 1}, True), ({"a": 1}, {"a": True}, False), ([1], [True], False),
    (None, False, False), ("1", 1, False),
])
def test_same_reads_one_json_value(a: Any, b: Any, equal: bool) -> None:
    assert same(a, b) is equal and same(b, a) is equal


def test_a_deny_list_never_admits_a_value_jcs_admit_refuses() -> None:
    """A lone surrogate has no canonical form: it equals nothing, and not_one_of denies it rather than admit it."""
    lone = "\ud800"
    assert not same(lone, lone)
    assert check_constraint({"type": "not_one_of", "values": ["x"]}, lone) is False


def test_the_old_python_answers_are_gone() -> None:
    assert check_constraint({"type": "not_one_of", "values": [1]}, True) is True
    assert check_constraint({"type": "not_one_of", "values": [True]}, 1) is True
    assert check_constraint({"type": "subset", "values": [1]}, [True]) is False
    assert narrows({"type": "subset", "values": [True]}, {"type": "subset", "values": [1]}) is False
    assert narrows({"type": "subset", "values": [1.0]}, {"type": "subset", "values": [1]}) is True


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(build(), separators=(",", ":")) + "\n")
