"""Parent-compare replay of sealed pytest ids: the verifier runs and counts the sealed tests.

The candidates are honest modules, honest modules a replay cannot serve (a class instance, an
exception class of their own, a module alias), and the recorded replay adversaries of
``test_replay.py`` (a per-input call counter, a forger of the result file), each called from
a sealed pytest file instead of a LiveCodeBench check. No new forging candidate is written
here: where a rule needs one to show it holds end to end, the test drives the rule from the
parent's side instead, and the design document names the fixture an outside harness supplies.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from probity_observer.done import (contract, pytest_proof, pytest_replay, replay, runner,
                                   verify_run)
from probity_observer.done.runner import SubprocessRunner

from .test_replay import FORGER, PER_INPUT_COUNTER

PACKAGE = "probity_replay_shapes"
# Not ``tests``: the in-process replays import the sealed tests in this suite's own process.
TESTS = "probity_sealed_tests"
HONEST = ("UNITS = 'cm'\n\n\ndef area(w, h):\n    if w < 0:\n        raise ValueError('negative')\n"
          "    return w * h\n\n\ndef add(a, b):\n    return a + b\n")
# Every test here reduces to ``assert <one call> == <sealed literal>`` (pytest_proof).
TEST = (f"import os\n\nimport pytest\n\nimport {PACKAGE}\n"
        f"from {PACKAGE}.shapes import add, area\n\n\n"
        "def test_area():\n    assert area(2, 3) == 6\n\n\n"
        "@pytest.mark.parametrize('w, h, expected', [(2, 2, 4), (1, 5, 5)])\n"
        "def test_table(w, h, expected):\n    assert area(w, h) == expected\n\n\n"
        f"def test_dotted():\n    assert {PACKAGE}.shapes.area(3, 3) == 9\n\n\n"
        "def test_add():\n    assert add(1, 1) == 2\n    assert add(2, 3) == 5\n")
IDS = [f"{TESTS}/test_shapes.py::{name}" for name in ("test_area", "test_table", "test_dotted",
                                                     "test_add")]
# Shapes a replay does not count: a raise the candidate chooses, and a plain attribute read.
UNPROVEN = (f"import pytest\n\nimport {PACKAGE}\nfrom {PACKAGE}.shapes import area\n\n\n"
            "def test_raises():\n    with pytest.raises(ValueError, match='negative'):\n"
            "        area(-1, 1)\n\n\n"
            f"def test_units():\n    assert {PACKAGE}.shapes.UNITS == 'cm'\n\n\n"
            "def test_area():\n    assert area(2, 3) == 6\n")


def tree(base: Path, source: str, test: str = TEST) -> tuple[Path, Path]:
    """A state holding the candidate package, and a sealed directory with the test root."""
    state, held = base / "state", base / "held"
    (state / PACKAGE).mkdir(parents=True)
    (state / PACKAGE / "__init__.py").write_text("")
    (state / PACKAGE / "shapes.py").write_text(source)
    root = held / runner.PYTEST_ROOT / TESTS
    root.mkdir(parents=True)
    (root / "__init__.py").write_text("")
    (root / "test_shapes.py").write_text(test)
    (held / "config").mkdir()
    (held / "config" / "pytest.ini").write_text("[pytest]\n")
    shutil.copytree(held / runner.PYTEST_ROOT / TESTS, state / TESTS)
    return state, held


def argv(ids=IDS, overlay=None, remote=(PACKAGE,)):
    return runner.pytest_replay_argv("../heldout/config/pytest.ini", overlay, remote, 2, ids)


def run(base: Path, source: str, test: str = TEST, ids=IDS, python_bin=sys.executable,
        remote=(PACKAGE,)):
    state, held = tree(base, source, test)
    local = SubprocessRunner(python_bin)
    code = local.run(state, argv(ids, remote=remote), held, 120)
    return code, local.replays[-1] if local.replays else None


def request(base: Path, source: str, test: str = TEST, ids=IDS, remote=(PACKAGE,)) -> dict:
    """The parent's request, laid out by the runner, for an in-process :func:`pytest_replay`."""
    state, held = tree(base, source, test)
    scratch = base / "scratch"
    scratch.mkdir()
    runner.stage(state, held, scratch)
    found = runner._pytest_request(scratch, argv(ids, remote=remote),
                                   SubprocessRunner(sys.executable).child_argv)
    assert found is not None
    return {**found, "call_timeout": 30.0, "order_seed": "seed", "mode": "pytest"}


def test_an_honest_module_passes_and_the_parent_counts_every_test(tmp_path):
    code, report = run(tmp_path, HONEST)
    assert code == 0 and report["passed"], report
    assert set(report["items"]) == {*IDS[:1], *IDS[2:], f"{IDS[1]}[2-2-4]", f"{IDS[1]}[1-5-5]"}
    # Each test ran twice, and passed both times, in the verifier's own pytest.
    assert all(counts == {"passed": 2, "failed": 0, "skipped": 0}
               for counts in report["items"].values())
    assert report["calls_intercepted"] > 0 and not report["impure"]
    assert runner.pytest_plugins.passed(report["items"], IDS) == len(IDS)


def test_a_wrong_module_fails_and_the_count_shows_which_tests(tmp_path):
    code, report = run(tmp_path, HONEST.replace("return w * h", "return w + h"))
    assert code == 1 and not report["passed"]
    assert report["items"][IDS[0]]["failed"] == 2
    # Only test_add holds for w + h; one row of the table does too, so the table fails.
    assert runner.pytest_plugins.passed(report["items"], IDS) == 1
    assert report["items"][f"{IDS[1]}[2-2-4]"]["passed"] == 2


def test_the_candidates_module_code_runs_outside_the_parent(tmp_path):
    # Where the module is imported, no pytest is loaded and no sealed plugin either.
    source = HONEST + ("\nimport sys\nWITH_PYTEST = sorted(name for name in sys.modules\n"
                       "                     if name.split('.')[0] in ('_pytest', 'pytest',\n"
                       "                                               'probity_repeat'))\n\n\n"
                       "def where():\n    return WITH_PYTEST\n")
    test = TEST + (f"\n\ndef test_where():\n    assert {PACKAGE}.shapes.where() == []\n")
    ids = [*IDS, f"{TESTS}/test_shapes.py::test_where"]
    code, report = run(tmp_path, source, test, ids)
    assert code == 0, report
    assert report["items"][f"{TESTS}/test_shapes.py::test_where"]["passed"] == 2


def test_a_recorded_per_input_counter_fails_the_repeated_run(tmp_path):
    code, report = run(tmp_path, HONEST.split("def add")[0] + PER_INPUT_COUNTER)
    assert code == 1 and report["impure"], report
    assert report["items"][f"{TESTS}/test_shapes.py::test_add"]["failed"] >= 1


def test_the_recorded_result_forger_cannot_write_the_parents_result(tmp_path):
    code, report = run(tmp_path, HONEST.split("def add")[0] + FORGER)
    assert code == 1 and not report["passed"], report
    assert runner.pytest_plugins.passed(report["items"], IDS) == 0


@pytest.mark.parametrize("source, test, reason", [
    # An instance of the candidate's class cannot cross as plain data.
    ("class Box:\n    pass\n\n\ndef area(w, h):\n    return Box()\n",
     f"from {PACKAGE}.shapes import area\n\n\ndef test_area():\n    assert area(2, 3) == 6\n",
     "unplain"),
    # An exception class of the candidate's own is not re-raised in the parent.
    ("class Bad(Exception):\n    pass\n\n\ndef area(w, h):\n    raise Bad('no')\n",
     f"from {PACKAGE}.shapes import area\n\n\ndef test_area():\n    assert area(2, 3) == 6\n",
     "raised"),
    # A module alias of the standard library is never served from the parent's own modules.
    ("import os as helper\n",
     f"import {PACKAGE}.shapes as shapes\n\n\ndef test_area():\n"
     "    assert shapes.helper.getcwd() == '/'\n", "outside"),
    # An attribute the sealed module sets would never reach the child.
    ("def area(w, h):\n    return w * h\n",
     f"import {PACKAGE}.shapes as shapes\n\nshapes.UNITS = 'mm'\n\n\n"
     "def test_area():\n    assert shapes.area(2, 3) == 6\n", "set"),
    # A missing name is an import error in the test.
    ("def area(w, h):\n    return w * h\n",
     f"from {PACKAGE}.shapes import volume\n\n\ndef test_area():\n    assert volume(1) == 1\n",
     "import"),
    # A value of the right size but another builtin type is not the sealed value.
    ("def area(w, h):\n    return float(w * h)\n",
     f"from {PACKAGE}.shapes import area\n\n\ndef test_area():\n    assert area(2, 3) == 6\n",
     "type"),
    ("def area(w, h):\n    return 1\n",
     f"from {PACKAGE}.shapes import area\n\n\ndef test_area():\n    assert area(2, 3) == True\n"
     "\n\ndef test_other():\n    assert area(2, 2) == False\n", "bool"),
])
def test_what_a_replay_cannot_serve_fails_and_is_never_a_pass(tmp_path, source, test, reason):
    code, report = run(tmp_path, source, test, [f"{TESTS}/test_shapes.py::test_area"])
    assert code == 1 and not report["passed"], (reason, report)
    assert runner.pytest_plugins.passed(report["items"], [f"{TESTS}/test_shapes.py::test_area"]) == 0


def test_the_replay_runs_in_process_and_leaves_no_candidate_module(tmp_path):
    before = os.getcwd()
    result = pytest_replay.pytest_replay(request(tmp_path, HONEST))
    assert result["passed"], result
    assert os.getcwd() == before
    assert not any(name.split(".", 1)[0] == PACKAGE for name in sys.modules)
    assert result["fresh_order"] and not result["fresh_mismatch"]


def test_a_changing_answer_is_impure_in_process(tmp_path):
    result = pytest_replay.pytest_replay(request(tmp_path / "a", HONEST.split("def add")[0]
                                                 + PER_INPUT_COUNTER))
    assert not result["passed"] and result["failure"] == "pytest exit 1"
    assert result["impure"]


@pytest.mark.parametrize("remote", [("json",), (TESTS,), ("pytest",)])
def test_a_remote_name_the_parent_holds_is_refused(tmp_path, remote):
    result = pytest_replay.pytest_replay(request(tmp_path, HONEST, remote=remote))
    assert not result["passed"] and result["failure"].startswith("remote module name")


def test_replies_map_to_builtin_exceptions_or_to_a_candidate_failure():
    with pytest.raises(KeyError):
        pytest_replay.raise_for({"raised": ["builtins", "KeyError"], "args": ["tuple", [
            ["str", "k"]]]})
    with pytest.raises(pytest_replay.CandidateFailed):
        pytest_replay.raise_for({"raised": ["builtins", "KeyboardInterrupt"], "args": None})
    with pytest.raises(pytest_replay.CandidateFailed):
        # UnicodeDecodeError takes five arguments; a reply that cannot build one is no raise.
        pytest_replay.raise_for({"raised": ["builtins", "UnicodeDecodeError"], "args": None})
    for malformed in ({"raised": "ValueError"}, {"raised": ["builtins"]},
                      {"raised": ["builtins", "ValueError"], "args": ["list", []]}):
        with pytest.raises(pytest_replay.CandidateFailed):
            pytest_replay.raise_for(malformed)
    with pytest.raises(pytest_replay.CandidateFailed, match="child-timeout"):
        pytest_replay.raise_for({"error": "child-timeout"})
    with pytest.raises(pytest_replay.CandidateFailed, match="malformed"):
        pytest_replay.value(None, {"ok": ["nope"]}, "m", "n")


def test_a_call_with_an_argument_that_is_not_plain_fails():
    function = pytest_replay.RemoteFunction(None, "m", "f")
    assert repr(function) == "<remote m.f>"
    with pytest.raises(pytest_replay.CandidateFailed, match="not plain"):
        function(object())


@pytest.mark.parametrize("broken", [
    lambda items: items[:5],
    lambda items: [items[0], "--other", *items[2:]],
    lambda items: [*items[:9], "two", *items[10:]],
    lambda items: [*items[:7], "not a name", *items[8:]],
    lambda items: [*items[:10], "-", *items[11:]],
])
def test_a_malformed_pytest_replay_argv_is_refused(tmp_path, broken):
    bad = broken(list(argv()))
    assert runner.replay_mode(bad) is None
    state, held = tree(tmp_path, HONEST)
    assert SubprocessRunner().run(state, bad, held, 30) == 2


@pytest.mark.parametrize("config, overlay", [("../../etc/passwd", None),
                                             ("../heldout/config/pytest.ini", "../workspace")])
def test_a_path_outside_the_sealed_directory_is_refused(tmp_path, config, overlay):
    state, held = tree(tmp_path, HONEST)
    bad = runner.pytest_replay_argv(config, overlay, [PACKAGE], 2, IDS)
    assert SubprocessRunner().run(state, bad, held, 30) == 2


def test_the_heldout_overlay_replaces_the_issued_test(tmp_path):
    state, held = tree(tmp_path, HONEST, TEST.replace("== 6", "== 7"))
    (held / "tree" / TESTS).mkdir(parents=True)
    (held / "tree" / TESTS / "test_shapes.py").write_text(TEST)
    local = SubprocessRunner()
    assert local.run(state, argv(IDS[:1]), held, 120) == 1
    assert local.run(state, argv(IDS[:1], overlay="../heldout/tree"), held, 120) == 0


def test_replay_commands_with_ids_are_counted_and_cover_the_worker_commands():
    worker = {"id": "fail-to-pass", "argv": ["python", "-m", "pytest"], "ids": ["a", "b"]}
    hidden = {"id": "heldout-fail-to-pass", "argv": ["sh", "-c", "x"], "ids": ["a", "b"]}
    visible = {"id": "fail-to-pass-replay", "argv": list(runner.pytest_replay_argv(
        None, None, ["pkg"], 2, ["a", "b"])), "ids": ["a", "b"]}
    # A held-out command is covered only by a held-out replay.
    assert verify_run.worker_counted([worker, hidden, visible]) == ["heldout-fail-to-pass"]
    held = {**visible, "id": "heldout-fail-to-pass-replay"}
    assert verify_run.worker_counted([worker, hidden, visible, held]) == []
    partial = {**visible, "argv": list(runner.pytest_replay_argv(None, None, ["pkg"], 2, ["a"])),
               "ids": ["a"]}
    assert verify_run.worker_counted([worker, partial]) == ["fail-to-pass"]


def test_importable_names_are_top_level_modules_and_packages(tmp_path):
    (tmp_path / "pkg" / "sub").mkdir(parents=True)
    (tmp_path / "pkg" / "sub" / "m.py").write_text("")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "x.txt").write_text("")
    (tmp_path / "setup.py").write_text("")
    (tmp_path / "not-a-name.py").write_text("")
    (tmp_path / ".git").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "pkg")
    assert contract.importable_names(tmp_path) == {"pkg", "setup"}


def test_a_replay_request_round_trips_through_the_parent_main(tmp_path):
    found = request(tmp_path, HONEST)
    out = tmp_path / "out.json"
    path = tmp_path / "request.json"
    path.write_text(json.dumps({**found, "out": str(out), "run_timeout": 120}))
    assert replay.main([str(path)]) == 0
    assert json.loads(out.read_text())["mode"] == "pytest"


def test_a_replay_that_never_calls_the_candidate_fails(tmp_path):
    # pytest exits 0 when every test is skipped, and a skip never reaches the candidate.
    test = (f"import pytest\nimport {PACKAGE}.shapes\n\n\n@pytest.mark.skip\n"
            f"def test_area():\n    assert {PACKAGE}.shapes.area(2, 3) == 6\n")
    code, report = run(tmp_path, HONEST, test, [f"{TESTS}/test_shapes.py::test_area"])
    assert code == 1 and report["exit"] == 0, report
    assert report["failure"] == "no call reached the candidate", report
    assert report["items"][f"{TESTS}/test_shapes.py::test_area"]["skipped"] == 2


def test_a_replay_in_which_one_id_skipped_fails(tmp_path):
    test = TEST + "\n\n@pytest.mark.skip\ndef test_skipped():\n    assert area(2, 3) == 6\n"
    code, report = run(tmp_path, HONEST, test, [IDS[0], f"{TESTS}/test_shapes.py::test_skipped"])
    assert code == 1 and report["exit"] == 0 and report["failure"] == "a sealed id did not pass"


def test_a_src_layout_package_is_remote_and_served_from_src(tmp_path):
    start = tmp_path / "start"
    (start / "src" / PACKAGE).mkdir(parents=True)
    (start / "src" / PACKAGE / "__init__.py").write_text("")
    (start / "src" / PACKAGE / "shapes.py").write_text(HONEST)
    (start / TESTS).mkdir()
    (start / TESTS / "__init__.py").write_text("")
    (start / TESTS / "test_shapes.py").write_text(TEST)
    held = tmp_path / "held"
    (held / "config").mkdir(parents=True)
    (held / "config" / "pytest.ini").write_text("[pytest]\n")
    found = contract.pytest_replays(start, None, held, [contract.Protected(TESTS, "directory")],
                                    "../heldout/config/pytest.ini", 2, IDS, [])
    assert [command.id for command in found] == ["fail-to-pass-replay",
                                                 "heldout-fail-to-pass-replay"]
    assert runner.pytest_replay_fields(found[0].argv)["remote"] == [PACKAGE, "src"]
    local = SubprocessRunner()
    assert local.run(start, found[0].argv, held, 120) == 0, local.replays
    assert found[0].record()["ids"] == IDS


def test_an_unprotected_test_file_is_never_replayed(tmp_path):
    start = tmp_path / "start"
    (start / PACKAGE).mkdir(parents=True)
    (start / PACKAGE / "shapes.py").write_text(HONEST)
    (start / "tests").mkdir()
    for name in ("test_a.py", "test_b.py"):
        (start / "tests" / name).write_text(f"from {PACKAGE}.shapes import area\n\n\n"
                                            "def t():\n    assert area(1, 1) == 1\n\n\n"
                                            "def u():\n    assert area(1, 2) == 2\n")
    held = tmp_path / "held"
    held.mkdir()
    found = contract.pytest_replays(start, None, held, [contract.Protected("tests/test_a.py", "file")],
                                    "-", 2, ["tests/test_a.py::t", "tests/test_b.py::t"],
                                    ["tests/test_b.py::u"])
    assert [(command.id, runner.pytest_replay_fields(command.argv)["ids"]) for command in found] == [
        ("fail-to-pass-replay", ["tests/test_a.py::t"]),
        ("heldout-fail-to-pass-replay", ["tests/test_a.py::t"])]


def test_answers_that_differ_on_one_request_fail_even_when_every_test_passes(tmp_path,
                                                                            monkeypatch):
    # A sealed comparison refuses a changing value on its own; the purity check also covers
    # the answers no comparison reads (a handle). The recorded answer of one request is made
    # to differ between its repeats, as a changing answer of the child would.
    answer, handles = pytest_replay._answer, []

    def changing(reply):
        if reply.get("callable"):
            handles.append(reply)
            return answer(reply) + ("x" if len(handles) % 2 else "")
        return answer(reply)
    monkeypatch.setattr(pytest_replay, "_answer", changing)
    result = pytest_replay.pytest_replay(request(tmp_path, HONEST))
    assert result["exit"] == 0 and result["failure"] == "answers differ on one request", result


def test_a_recorded_answer_a_fresh_child_does_not_give_is_a_mismatch(tmp_path):
    found = request(tmp_path, HONEST)
    honest = pytest_replay.Session(None, frozenset([PACKAGE]))
    call = {"op": "call", "module": f"{PACKAGE}.shapes", "name": "add",
            "args": replay.plain((1, 1)), "kwargs": replay.plain({})}
    key = pytest_replay._key(call)
    honest.requests[key] = call
    # The session's own record says 3; a fresh child holding the module answers 2.
    honest.answers[key] = [pytest_replay._answer({"ok": replay.plain(3)})]
    assert pytest_replay.fresh_mismatches(found, honest, [key], 30.0) == [key]
    honest.answers[key] = [pytest_replay._answer({"ok": replay.plain(2)})]
    assert pytest_replay.fresh_mismatches(found, honest, [key], 30.0) == []


def test_a_fresh_mismatch_fails_the_replay(tmp_path, monkeypatch):
    monkeypatch.setattr(pytest_replay, "fresh_mismatches",
                        lambda request, session, order, timeout: order[:1])
    result = pytest_replay.pytest_replay(request(tmp_path, HONEST))
    assert result["exit"] == 0 and result["failure"] == "a fresh child answered differently"
    assert result["fresh_mismatch"] == result["fresh_order"][:1]


def test_a_reply_that_is_not_an_object_is_a_protocol_error():
    class Child:
        def ask(self, request):
            return ["raised", "ValueError"]
    session = pytest_replay.Session(Child(), frozenset([PACKAGE]))
    assert session.ask({"op": "import", "module": PACKAGE}) == {"error": "child-protocol"}


def unproven_ids(names):
    return [f"{TESTS}/test_shapes.py::{name}" for name in names]


def test_an_id_the_proof_refuses_fails_in_the_replay_with_its_reason(tmp_path):
    # Sealed as a replay by hand: the compiler never seals these two, and the parent refuses
    # them again rather than run them.
    ids = unproven_ids(["test_raises", "test_units", "test_area"])
    code, report = run(tmp_path, HONEST, UNPROVEN, ids)
    assert code == 1 and report["failure"] == "pytest exit 1", report
    assert set(report["unproven"]) == set(ids[:2])
    assert "With" in report["unproven"][ids[0]] and "one call" in report["unproven"][ids[1]]
    assert [report["items"][test_id]["passed"] for test_id in ids] == [0, 0, 2]


@pytest.mark.parametrize("setup", [
    # A plain value read at import, and a call a fixture makes, both reach the parent's code
    # outside any sealed comparison.
    f"UNITS = {PACKAGE}.shapes.UNITS\n",
    "@pytest.fixture(autouse=True)\ndef warm():\n    area(1, 1)\n",
    # The refusal is a BaseException: sealed code that catches Exception cannot carry on.
    f"try:\n    UNITS = {PACKAGE}.shapes.UNITS\nexcept Exception:\n    UNITS = 'cm'\n",
])
def test_candidate_data_outside_a_sealed_comparison_fails_the_replay(tmp_path, setup):
    test = TEST.replace("\n\n\ndef test_area", f"\n\n\n{setup}\n\ndef test_area", 1)
    code, report = run(tmp_path, HONEST, test)
    assert code == 1 and report["failure"] == "candidate data outside a sealed comparison", report
    assert report["outside"] and all(json.loads(key)[0] in ("attr", "call")
                                     for key in report["outside"])
    assert runner.pytest_plugins.passed(report["items"], IDS[:1]) == 0


def test_candidate_data_outside_a_sealed_comparison_never_reaches_the_sealed_code():
    class Child:
        def ask(self, request):
            return {"ok": ["str", "/etc/passwd"], "nonce": request["nonce"]}
    session = pytest_replay.Session(Child(), frozenset([PACKAGE]))
    read = {"op": "attr", "module": f"{PACKAGE}.shapes", "name": "CACHE"}
    reply = session.ask(read)
    assert reply == {"error": pytest_replay.OUTSIDE} and session.outside == [
        pytest_replay._key(read)]
    with pytest.raises(pytest_replay.CandidateFailed, match="outside a sealed comparison"):
        pytest_replay.value(session, reply, f"{PACKAGE}.shapes", "CACHE")
    # Inside a comparison the same answer goes to the comparison.
    session.site = 0
    assert session.ask(read) == {"ok": ["str", "/etc/passwd"]}


def test_a_passed_report_without_the_instrumented_run_counts_as_failed(tmp_path, monkeypatch):
    # Another implementation answers every call without running the sealed comparisons:
    # pytest reports each test passed, and the parent counts none of them.
    monkeypatch.setattr(pytest_replay.Count, "call", lambda self, item: True)
    result = pytest_replay.pytest_replay(request(tmp_path, HONEST, ids=IDS[:1]))
    assert result["exit"] == 0 and result["failure"] == "a sealed id did not pass", result
    assert result["items"][IDS[0]] == {"passed": 0, "failed": 2, "skipped": 0}


def comparison(source=TEST, name="test_area"):
    proof = pytest_proof.Module(source, frozenset([PACKAGE])).proof(name)
    assert not isinstance(proof, str), proof
    session = pytest_replay.Session(None, frozenset([PACKAGE]))
    return pytest_replay.Count(1, session=session), session, proof


def test_a_sealed_comparison_makes_exactly_one_call_and_compares_type_strictly():
    count, session, proof = comparison()

    def calls(number, result):
        def thunk():
            session.site_calls += number
            return result
        return thunk
    made: set[int] = set()
    count.compare(proof, 0, calls(1, 6), 6, made, {})
    assert made == {0} and session.site is None
    for number in (0, 2):
        with pytest.raises(pytest_replay.CandidateFailed, match="exactly one call"):
            count.compare(proof, 0, calls(number, 6), 6, set(), {})
    for wrong in (6.0, True, 7):
        with pytest.raises(AssertionError):
            count.compare(proof, 0, calls(1, wrong), 6, set(), {})


def test_a_boolean_comparison_counts_only_when_its_function_is_asserted_both_ways(tmp_path):
    source = "def is_square(w, h):\n    return w == h\n"
    test = (f"from {PACKAGE}.shapes import is_square\n\n\n"
            "def test_yes():\n    assert is_square(2, 2) == True\n\n\n"
            "def test_no():\n    assert is_square(2, 3) == False\n")
    ids = unproven_ids(["test_yes", "test_no"])
    code, report = run(tmp_path / "both", source, test, ids)
    assert code == 0, report
    code, report = run(tmp_path / "one", source, test, ids[:1])
    assert code == 1 and report["degenerate"] == ids[:1], report
    assert report["failure"] == "a boolean comparison its function never makes the other way"
    assert report["items"][ids[0]] == {"passed": 0, "failed": 2, "skipped": 0}


def test_a_reply_must_carry_its_request_nonce_back():
    class Child:
        def __init__(self, reply):
            self.reply, self.sent = reply, []

        def ask(self, request):
            self.sent.append(request)
            return self.reply(request) if callable(self.reply) else self.reply
    echo = Child(lambda request: {"ok": ["int", "2"], "nonce": request["nonce"]})
    assert pytest_replay.exchange(echo, {"op": "attr"}) == {"ok": ["int", "2"]}
    assert len(echo.sent[0]["nonce"]) == 32
    for reply in ({"ok": ["int", "2"]}, {"ok": ["int", "2"], "nonce": "0" * 32},
                  {"error": "child-timeout", "nonce": "x"}):
        assert pytest_replay.exchange(Child(reply), {"op": "attr"}) == {"error": "child-protocol"}
    # The client's own failures carry no nonce and keep their name.
    assert pytest_replay.exchange(Child({"error": "child-timeout"}), {"op": "attr"}) == {
        "error": "child-timeout"}
    session = pytest_replay.Session(Child({"ok": ["none"]}), frozenset([PACKAGE]))
    key = pytest_replay._key({"op": "import", "module": PACKAGE})
    session.ask({"op": "import", "module": PACKAGE})
    assert session.answers[key] == ['{"error":"child-protocol"}']


def test_a_call_that_answers_with_a_function_or_a_module_is_a_candidate_failure():
    # A returned function would come back as a handle named after the factory, so calling it
    # would call the factory again.
    for reply in ({"callable": True}, {"module": PACKAGE}):
        class Child:
            def ask(self, request, reply=reply):
                return {**reply, "nonce": request["nonce"]}
        session = pytest_replay.Session(Child(), frozenset([PACKAGE]))
        # Inside a sealed comparison, where a call is answered at all.
        session.site = 0
        with pytest.raises(pytest_replay.CandidateFailed):
            pytest_replay.RemoteFunction(session, f"{PACKAGE}.shapes", "make")(2)
        assert session.site_calls == 1 and not session.outside


def test_the_finder_serves_remote_modules_to_sealed_code_only(tmp_path):
    session = pytest_replay.Session(None, frozenset([PACKAGE]))
    finder = pytest_replay.RemoteFinder(session, str(tmp_path))
    # The verifier's own code (this file) asking for the name gets nothing from the child.
    assert finder.find_spec(PACKAGE) is None
    namespace = {"finder": finder}
    exec(compile(f"spec = finder.find_spec({PACKAGE!r})", str(tmp_path / "test_x.py"), "exec"),
         namespace)
    assert namespace["spec"].name == PACKAGE
    assert finder.find_spec("json") is None


@pytest.mark.parametrize("name", ["_pytest", "pluggy", "iniconfig"])
def test_pytest_is_imported_before_the_remote_names_are_checked(tmp_path, name):
    # In a fresh parent nothing of pytest is loaded yet, so the check must come after it is.
    code, report = run(tmp_path, HONEST, remote=(PACKAGE, name))
    assert code == 1 and report["failure"] == f"remote module name not allowed: {name}", report


def test_the_compiler_replays_only_ids_the_proof_counts(tmp_path):
    start, held = tmp_path / "start", tmp_path / "held"
    (start / PACKAGE).mkdir(parents=True)
    (start / PACKAGE / "shapes.py").write_text(HONEST)
    (start / "tests").mkdir()
    sealed = f"from {PACKAGE}.shapes import area\n\n\n"
    (start / "tests" / "test_a.py").write_text(
        sealed + "def t():\n    assert area(1, 1) == 1\n\n\n"
        "def gated():\n    for answer in [area(1, 1)]:\n        assert answer == 1\n\n\n"
        "def u():\n    assert area(1, 2) == 2\n\n\n"
        "def helper():\n    area(1, 2)\n")
    # The held-out copy of the file asks t through the candidate's own helper.
    (held / "tree" / "tests").mkdir(parents=True)
    (held / "tree" / "tests" / "test_a.py").write_text(
        sealed + f"from {PACKAGE}.shapes import add\n\n\n"
        "def t():\n    add(area(1, 1), 0)\n")
    found = contract.pytest_replays(start, None, held, [contract.Protected("tests", "directory")],
                                    "-", 2, ["tests/test_a.py::t", "tests/test_a.py::gated"],
                                    ["tests/test_a.py::u", "tests/test_a.py::helper"])
    assert [(command.id, runner.pytest_replay_fields(command.argv)["ids"])
            for command in found] == [("fail-to-pass-replay", ["tests/test_a.py::t"]),
                                      ("pass-to-pass-replay", ["tests/test_a.py::u"])]


def test_a_module_the_candidate_names_must_be_a_dotted_name_under_a_remote_one():
    session = pytest_replay.Session(None, frozenset([PACKAGE]))
    for found in (f"{PACKAGE}./etc", f"{PACKAGE}..x", "json", f"{PACKAGE}.a b"):
        with pytest.raises(pytest_replay.CandidateFailed, match="outside the candidate"):
            pytest_replay.value(session, {"module": found}, PACKAGE, "x")
