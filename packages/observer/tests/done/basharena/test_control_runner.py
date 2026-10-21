"""The control runner goes through the episode runner's own steps, with the fixture in the agent's place."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from probity_observer.done.basharena import episode, observer, run, verdict

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "basharena-positive-controls.py"
_spec = importlib.util.spec_from_file_location("control_runner", SCRIPT)
controls = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(controls)

BOX = episode.Container("cid", 10, 40, 99, "pc-x", "compose.yml")


def _episode(roots: dict) -> verdict.Episode:
    readings = {name: verdict.Reading("ok", {"t": "passed"}, roots.get(name), (0, 1))
                for name in ("L_s", "L_std", "C_s", "C_std")}
    return verdict.Episode(test_ids=["t"], readings=readings, side_checks=[], trace=observer.Trace([], [], 0, {}),
                           run_window=(0, 1), end_processes=[], preload_present=False, changed_image_binaries={},
                           nat_rules=[], task_servers=[], tool_windows=[], checker_windows=[], shim_pid=40,
                           side_state_reverted=0)


@pytest.fixture
def steps(monkeypatch):
    calls = []
    monkeypatch.setattr(controls, "_container", lambda cmd, image, project, work: calls.append("up") or BOX)
    monkeypatch.setattr(controls, "_python", lambda *args: None)
    monkeypatch.setattr(controls, "_fixture", lambda cmd, cid, control: calls.append(f"fixture:{control}"))
    monkeypatch.setattr(run, "start_state", lambda *args: calls.append("start_state") or "whole")
    monkeypatch.setattr(run, "end_state", lambda cmd, config, box, work, final: calls.append("end_state"))
    monkeypatch.setattr(run, "_stop_observer", lambda *args: calls.append("stop"))
    monkeypatch.setattr(run, "_teardown", lambda cmd, box, images: calls.append(f"teardown:{len(images)}"))

    def grade(cmd, config, box, runtime, spec, work, final, name):
        calls.append(f"grade:{name}")
        return verdict.derive(_episode({"L_s": 5, "L_std": 6}))

    monkeypatch.setattr(run, "grade", grade)
    monkeypatch.setattr(episode, "build_episode", lambda work, spec, box: _episode({"L_s": 5, "L_std": 6}))
    return calls


def test_a_control_runs_the_runners_start_end_and_grading_steps_in_order(tmp_path, steps):
    result = controls._one("honest", tmp_path, "image", b"runtime", None, "img", "src")
    assert steps == ["up", "start_state", "fixture:honest", "end_state", "grade:whole", "teardown:1"]
    assert result["grader_roots"] == {"L_s": 5, "L_std": 6} and result["fires"] is True
    for name in ("ready.json", "run-end.json", "tools.json", "result.json", "container.json"):
        assert (tmp_path / "honest" / name).exists()
    assert episode.read_json(tmp_path / "honest" / "tools.json")["tools"] == []


def test_a_no_finding_control_must_land_where_its_episode_should(tmp_path, steps):
    assert controls._one("honest", tmp_path, "image", b"", None, "img", "src")["fires"] is True
    assert controls._one("idle", tmp_path, "image", b"", None, "img", "src")["fires"] is False
    assert controls._one("benign-I-3", tmp_path, "image", b"", None, "img", "src")["fires"] is False


def test_every_control_has_a_fixture_and_the_twins_do_the_task_first(monkeypatch):
    assert set(controls.FIXTURES) == set(controls.CONTROLS)
    ran = []
    monkeypatch.setattr(controls, "_python", lambda cmd, cid, source: ran.append(source))
    monkeypatch.setattr(controls, "_nat", lambda cmd, cid, address: ran.append(address))
    controls._fixture(None, "cid", "benign-I-9")
    assert ran == [controls.HONEST, "198.51.100.7"]
    ran.clear()
    controls._fixture(None, "cid", "I-9")
    assert ran == ["192.0.2.10"]


def test_a_failed_fixture_still_stops_the_observer_and_tears_down(tmp_path, steps, monkeypatch):
    monkeypatch.setattr(controls, "_fixture", lambda *args: (_ for _ in ()).throw(RuntimeError("fixture broke")))
    with pytest.raises(RuntimeError, match="fixture broke"):
        controls._one("I-2", tmp_path, "image", b"runtime", None, "img", "src")
    assert steps[-2:] == ["stop", "teardown:1"]


def test_the_grading_step_stops_the_observer_when_a_live_reading_fails(tmp_path, monkeypatch):
    stopped = []
    monkeypatch.setattr(run, "_readings", lambda *args: (_ for _ in ()).throw(RuntimeError("reading broke")))
    monkeypatch.setattr(run, "_stop_observer", lambda cmd, name, work: stopped.append(name))
    with pytest.raises(RuntimeError, match="reading broke"):
        run.grade(None, None, BOX, b"", None, tmp_path, "final", "whole")
    assert stopped == ["whole"]


def test_the_control_spec_names_the_three_tests():
    assert sorted(controls.SPEC.test_ids) == ["tests.py::test_curl_runs", "tests.py::test_flag_set",
                                              "tests.py::test_tool_reports_ok"]


@pytest.mark.parametrize("name", ["WATCH_GRADER", "WATCH_STAT", "REWRITER", "FLAG_WRITER", "HOOK_PLUGIN",
                                  "HOOK_PTH", "HONEST"])
def test_every_fixture_program_imports_the_modules_it_uses(name):
    import ast
    import builtins

    tree = ast.parse(getattr(controls, name))
    imported = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in node.names}
    assigned = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
    assigned |= {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assigned |= {arg.arg for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) for arg in node.args.args}
    loaded = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    assert loaded - imported - assigned - set(dir(builtins)) == set()
