"""Which sealed pytest ids the verifier counts itself: the proof read off the sealed source.

Each case is a sealed test body, never a candidate: a shape the replay counts, or a shape whose
outcome a child-served function, a gate on the candidate's answer, or an echo of the expected
value could decide, which the proof refuses so that only the worker counts it.
"""

from __future__ import annotations

import pytest
from probity_observer.done import pytest_proof

REMOTE = frozenset(["pkg"])
HEADER = ("import pytest\n\nimport pkg\nimport pkg.shapes\nimport pkg.shapes as shapes\n"
          "from pkg.shapes import area, solve, check, is_square\n"
          "from pkg.testing import assert_close, error\nfrom sealed_helpers import local\n\n\n")


def prove(body: str, name: str = "test_it", header: str = HEADER):
    return pytest_proof.Module(header + body, REMOTE).proof(name)


@pytest.mark.parametrize("body, callees", [
    ("def test_it():\n    \"\"\"Doc.\"\"\"\n    assert area(2, 3) == 6\n"
     "    assert 0 == area(0, 5)\n",
     ["pkg.shapes.area", "pkg.shapes.area"]),
    ("def test_it():\n    assert pkg.shapes.area(2, 3) == 6, 'six'\n    pass\n",
     ["pkg.shapes.area"]),
    ("def test_it():\n    assert shapes.area(w=2, h=3) == (6, [1.5, {'a': b'x'}])\n",
     ["pkg.shapes.area"]),
    ("@pytest.mark.parametrize('w, h, expected', [(2, 3, 6), (1, 1, 1)])\n"
     "@pytest.mark.parametrize('unused', [0], ids=['zero'])\n"
     "def test_it(w, h, expected, unused):\n    assert area(w, h) == expected\n",
     ["pkg.shapes.area"]),
    ("@pytest.mark.parametrize(argnames=['n'], argvalues=[1, 2])\n"
     "def test_it(n):\n    assert area(n, 1) == 1\n", ["pkg.shapes.area"]),
])
def test_a_sealed_comparison_against_one_call_is_proven(body, callees):
    proof = prove(body)
    assert not isinstance(proof, str), proof
    assert [site.callee for site in proof.sites] == callees


@pytest.mark.parametrize("body, reason", [
    # F1: the candidate's own helper decides, or transforms the expected side.
    ("def test_it():\n    assert_close(area(2, 3), 6)\n", "Expr"),
    ("def test_it():\n    assert error(area(2, 3), 6) < 0.1\n", "one == comparison"),
    ("def test_it():\n    assert area(2, 3) == error(6)\n", "one call against a sealed value"),
    ("def test_it():\n    assert area(2, 3)\n", "one == comparison"),
    # F2: the assertion is gated on what the candidate returned.
    ("def test_it():\n    for item in solve(1):\n        assert item == (1, 2, 3)\n", "For"),
    ("def test_it():\n    if check(1):\n        assert area(1, 1) == 1\n", "If"),
    ("def test_it():\n    assert all(item == 1 for item in solve(1))\n", "one == comparison"),
    ("def test_it():\n    try:\n        assert area(1, 1) == 1\n"
     "    except Exception:\n        pass\n",
     "Try"),
    ("def test_it():\n    with pytest.raises(ValueError):\n        area(-1, 1)\n", "With"),
    ("def test_it():\n    while check(1):\n        assert area(1, 1) == 1\n", "While"),
    ("def test_it():\n    if check(1):\n        return\n    assert area(1, 1) == 1\n", "If"),
    ("def test_it():\n    x = area(1, 1)\n    assert x == 1\n", "Assign"),
    # F4: a function the candidate returned is called, or one call feeds another.
    ("def test_it():\n    assert area(2)(3) == 6\n", "not a name"),
    ("def test_it():\n    assert area(area(1, 1), 2) == 2\n", "not a literal"),
    ("def test_it():\n    assert area(*[1, 2]) == 2\n", "unpacks"),
    # The expected value is degenerate, or would reach the child.
    ("def test_it():\n    assert area(1, 1) == None\n", "None"),
    ("def test_it():\n    assert area(1, 1) == (None,)\n", "None"),
    ("def test_it():\n    assert area(1, 1) == [None, (None, [None])]\n", "None"),
    ("@pytest.mark.parametrize('x, expected', [(2, 4)])\n"
     "def test_it(x, expected):\n    assert area(x, expected) == expected\n", "sent to the child"),
    ("@pytest.mark.parametrize('x, expected', [(2, None)])\n"
     "def test_it(x, expected):\n    assert area(x, 1) == expected\n", "None"),
    ("def test_it():\n    assert area(1, 1) == 1j\n", "plain data"),
    ("def test_it():\n    assert area(1, 1) == area\n", "is not sealed"),
    # The called name is not served from the candidate, or not bound once.
    ("def test_it():\n    assert local(1) == 1\n", "not imported from a module the child serves"),
    ("def test_it():\n    assert pytest.approx(1) == 1\n", "not a module the child serves"),
    ("def test_it():\n    assert pkg(1) == 1\n", "call is of a module"),
    ("@pytest.mark.parametrize('area', [1])\ndef test_it(area):\n    assert area(1, 1) == 1\n",
     "is a table name"),
    ("def test_it():\n    assert area.__call__(1, 1) == 1\n", "dunder"),
    ("def test_it():\n    assert area(1, 1) == 1\n\n\narea = None\n", "bound 2 times"),
    ("def test_it():\n    assert area(1, 1) == 1\n\n\ndef rebind():\n    global area\n",
     "bound 2 times"),
    # The test is not a plain module-level function of literal tables.
    ("def test_it(tmp_path):\n    assert area(1, 1) == 1\n", "fixture"),
    ("def test_it(n=1):\n    assert area(n, 1) == 1\n", "other than its table"),
    ("@pytest.mark.skipif(False, reason='x')\ndef test_it():\n    assert area(1, 1) == 1\n",
     "decorator"),
    ("@pytest.mark.parametrize('n', [pytest.param(1)])\n"
     "def test_it(n):\n    assert area(n, 1) == 1\n", "not a literal"),
    ("@pytest.mark.parametrize('n', [1], indirect=True)\n"
     "def test_it(n):\n    assert area(n, 1) == 1\n", "indirect"),
    ("@pytest.mark.parametrize('n', [])\ndef test_it(n):\n    assert area(n, 1) == 1\n", "no rows"),
    ("def test_it():\n    assert area(1, 1) == 1\n\n\ndef test_it():\n    pass\n", "bound 2"),
    ("def test_it():\n    \"\"\"Only a docstring.\"\"\"\n", "no sealed comparison"),
    ("async def test_it():\n    assert area(1, 1) == 1\n", "not a module-level function"),
    ("def test_it():\n    assert area(1, 1) == 1, area(0, 0)\n", "message is not a literal"),
])
def test_a_shape_the_candidate_could_decide_is_not_proven(body, reason):
    proof = prove(body)
    assert isinstance(proof, str) and reason in proof, proof


@pytest.mark.parametrize("header, reason", [
    ("from pkg.shapes import *\n\n\n", "star import"),
    ("from .shapes import area\n\n\n", "relative"),
    ("import pkg as area\n\n\n", "call is of a module"),
    ("try:\n    from pkg.shapes import area\nexcept ImportError:\n    area = None\n\n\n",
     "bound 2"),
    ("def test_it(:\n", "does not parse"),
])
def test_a_module_whose_bindings_are_not_plain_imports_proves_nothing(header, reason):
    proof = prove("def test_it():\n    assert area(1, 1) == 1\n", header=header)
    assert isinstance(proof, str) and reason in proof, proof


def test_a_class_method_or_a_file_id_is_never_counted(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text(
        HEADER + "class TestA:\n    def test_it(self):\n        assert area(1, 1) == 1\n\n\n"
        "def test_it():\n    assert area(1, 1) == 1\n")
    sources = pytest_proof.Sources([tmp_path], REMOTE)
    assert not isinstance(sources.proof("tests/test_a.py::test_it[1-2]"), str)
    for test_id in ("tests/test_a.py", "tests/test_a.py::TestA::test_it", "tests/test_a.py::TestA",
                    "tests/missing.py::test_it", "../x.py::test_it", "/etc/x.py::test_it"):
        assert isinstance(sources.proof(test_id), str), test_id


def test_a_boolean_comparison_needs_its_function_asserted_both_ways(tmp_path):
    (tmp_path / "test_b.py").write_text(
        HEADER + "def test_yes():\n    assert is_square(2, 2) == True\n\n\n"
        "def test_no():\n    assert is_square(2, 3) == False\n\n\n"
        "@pytest.mark.parametrize('n, expected', [(1, True), (2, False)])\n"
        "def test_table(n, expected):\n    assert check(n) == expected\n\n\n"
        "def test_only():\n    assert check(1) == True\n    assert area(1, 1) == 1\n")
    sources = pytest_proof.Sources([tmp_path], REMOTE)
    ids = [f"test_b.py::{name}" for name in ("test_yes", "test_no", "test_table", "test_only")]
    kept, reasons = pytest_proof.proven(sources, ids)
    assert kept == ids
    kept, reasons = pytest_proof.proven(sources, [ids[0], ids[3]])
    # is_square is asserted only True; check only True as well once the table is left out.
    assert kept == [] and set(reasons) == {ids[0], ids[3]}
    assert "boolean" in reasons[ids[0]]


def test_the_held_out_tree_is_read_before_the_issued_file(tmp_path):
    held, issued = tmp_path / "held", tmp_path / "issued"
    held.mkdir()
    issued.mkdir()
    (issued / "test_c.py").write_text(HEADER + "def test_it():\n    assert area(1, 1) == 1\n")
    (held / "test_c.py").write_text(HEADER + "def test_it():\n    assert_close(area(1, 1), 1)\n")
    assert not isinstance(pytest_proof.Sources([issued], REMOTE).proof("test_c.py::test_it"), str)
    assert isinstance(pytest_proof.Sources([held, issued], REMOTE).proof("test_c.py::test_it"), str)


def test_each_assertion_has_its_sealed_value_for_one_run():
    proof = prove("@pytest.mark.parametrize('w, expected', [(2, 6), (1, 3)])\n"
                  "def test_it(w, expected):\n    \"\"\"Doc.\"\"\"\n"
                  "    assert area(w, 3) == expected\n    pass\n"
                  "    assert (1, [2]) == area(1, 1)\n")
    assert not isinstance(proof, str)
    assert proof.expected({"w": 1, "expected": 3}) == [3, (1, [2])]


def test_a_boolean_inside_an_answer_needs_its_place_asserted_both_ways(tmp_path):
    (tmp_path / "test_d.py").write_text(
        HEADER + "def test_one():\n    assert is_square(2, 2) == [True]\n\n\n"
        "def test_yes():\n    assert check(1) == (True, 0)\n\n\n"
        "def test_no():\n    assert check(2) == (False, 1)\n\n\n"
        "def test_key():\n    assert area(1, 1) == {'ok': True}\n\n\n"
        "def test_other():\n    assert area(0, 1) == {'ok': [False]}\n")
    sources = pytest_proof.Sources([tmp_path], REMOTE)
    ids = [f"test_d.py::{name}" for name in ("test_one", "test_yes", "test_no", "test_key",
                                              "test_other")]
    proof = sources.proof(ids[1])
    assert not isinstance(proof, str) and proof.booleans() == {"pkg.shapes.check[0]": {True}}
    kept, reasons = pytest_proof.proven(sources, ids)
    # is_square gives only True at [0]; area gives True at ["ok"] and False at ["ok"][0], two
    # places each asserted one way; check is asserted both ways at [0].
    assert kept == ids[1:3] and set(reasons) == {ids[0], *ids[3:]}
    kept, reasons = pytest_proof.proven(sources, ids[1:2])
    assert kept == [] and "boolean" in reasons[ids[1]]
