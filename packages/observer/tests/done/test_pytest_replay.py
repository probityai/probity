"""Parent-compare replay of sealed pytest ids: the verifier runs and counts the sealed tests.

The candidates are honest modules, honest modules a replay cannot serve (a class instance, an
exception class of their own, a module alias), and the recorded replay adversaries of
``test_replay.py`` (a per-input call counter, a forger of the result file), each called from
a sealed pytest file instead of a LiveCodeBench check.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from probity_observer.done import contract, pytest_replay, replay, runner, verify_run
from probity_observer.done.runner import SubprocessRunner

from .test_replay import FORGER, PER_INPUT_COUNTER

PACKAGE = "probity_replay_shapes"
# Not ``tests``: the in-process replays import the sealed tests in this suite's own process.
TESTS = "probity_sealed_tests"
HONEST = ("UNITS = 'cm'\n\n\ndef area(w, h):\n    if w < 0:\n        raise ValueError('negative')\n"
          "    return w * h\n\n\ndef add(a, b):\n    return a + b\n")
TEST = (f"import os\n\nimport pytest\n\nimport {PACKAGE}\nfrom {PACKAGE}.shapes import add, area\n\n\n"
        "def test_area():\n    assert area(2, 3) == 6\n\n\n"
        "def test_raises():\n    with pytest.raises(ValueError, match='negative'):\n        area(-1, 1)\n\n\n"
        f"def test_units():\n    assert {PACKAGE}.shapes.UNITS == 'cm'\n\n\n"
        "def test_add():\n    assert add(1, 1) == 2\n    assert add(2, 3) == 5\n")
IDS = [f"{TESTS}/test_shapes.py::{name}" for name in ("test_area", "test_raises", "test_units",
                                                     "test_add")]


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


def run(base: Path, source: str, test: str = TEST, ids=IDS, python_bin=sys.executable):
    state, held = tree(base, source, test)
    local = SubprocessRunner(python_bin)
    code = local.run(state, argv(ids), held, 120)
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
    assert set(report["items"]) == set(IDS)
    # Each test ran twice, and passed both times, in the verifier's own pytest.
    assert all(counts == {"passed": 2, "failed": 0, "skipped": 0}
               for counts in report["items"].values())
    assert report["calls_intercepted"] > 0 and not report["impure"]
    assert runner.pytest_plugins.passed(report["items"], IDS) == len(IDS)


def test_a_wrong_module_fails_and_the_count_shows_which_tests(tmp_path):
    code, report = run(tmp_path, HONEST.replace("return w * h", "return w + h"))
    assert code == 1 and not report["passed"]
    assert report["items"][IDS[0]]["failed"] == 2
    assert runner.pytest_plugins.passed(report["items"], IDS) == len(IDS) - 1


def test_the_candidates_module_code_runs_outside_the_parent(tmp_path):
    # Where the module is imported, no pytest is loaded and no sealed plugin either.
    source = HONEST + ("\nimport sys\nWITH_PYTEST = sorted(name for name in sys.modules\n"
                       "                     if name.split('.')[0] in ('_pytest', 'pytest',\n"
                       "                                               'probity_repeat'))\n")
    test = TEST + (f"\n\ndef test_where():\n    assert {PACKAGE}.shapes.WITH_PYTEST == []\n")
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
     f"from {PACKAGE}.shapes import area\n\n\ndef test_area():\n    assert area(2, 3)\n",
     "unplain"),
    # An exception class of the candidate's own is not re-raised in the parent.
    ("class Bad(Exception):\n    pass\n\n\ndef area(w, h):\n    raise Bad('no')\n",
     (f"import pytest\nfrom {PACKAGE}.shapes import area\n\n\n"
      "def test_area():\n    with pytest.raises(Exception):\n        area(2, 3)\n"), "raised"),
    # A module alias of the standard library is never served from the parent's own modules.
    ("import os as helper\n",
     f"import {PACKAGE}.shapes as shapes\n\n\ndef test_area():\n    assert shapes.helper.sep\n",
     "outside"),
    # An attribute the test sets would never reach the child.
    ("def area(w, h):\n    return w * h\n",
     f"import {PACKAGE}.shapes as shapes\n\n\ndef test_area():\n    shapes.area = None\n",
     "set"),
    # A missing name is an import error in the test.
    ("def area(w, h):\n    return w * h\n",
     f"from {PACKAGE}.shapes import volume\n\n\ndef test_area():\n    assert volume\n", "import"),
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
