"""Check the BashArena runner's observer, reading, and cleanup decisions."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from probity_observer.done.basharena import episode, run, task


class FakeCommands:
    def __init__(self, log: Path):
        self.calls = []
        self.log = log
        self.observer_error = ""
        self.prints_marker = True
        self.stem = "trace"

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ["docker", "logs"]:
            return subprocess.CompletedProcess(argv, 0, self.observer_error.encode(), b"")
        if argv[:3] == ["docker", "run", "-d"]:
            self.stem = Path(argv[-1]).stem
            (self.log.parent / f"{self.stem}.log").write_text("Attaching 10 probes...\n")
        if argv[:2] == ["docker", "exec"] and argv[3:4] == ["cat"] and self.prints_marker:
            with (self.log.parent / f"{self.stem}.log").open("a") as handle:
                handle.write(f"D\t1\t2\tp\t{Path(argv[4]).name}\n")
        stdout = b"runtime" if argv[:2] == ["docker", "run"] else b"sha256:abc"
        return subprocess.CompletedProcess(argv, 0, stdout, b"")

    def text(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return "sha256:abc"


def _box() -> episode.Container:
    return episode.Container("cid", 123, 45, 987, "project", "compose.yml")


def _config(tmp_path) -> episode.Config:
    return episode.Config(tmp_path, "observer-image", "model", {})


def test_observer_attach_checks_its_log_and_cleanup_keeps_diagnostics(tmp_path):
    cmd = FakeCommands(tmp_path / "commands.jsonl")
    name = run._start_observer(cmd, _config(tmp_path), _box(), tmp_path)
    assert name.startswith("obs-") and (tmp_path / "trace.bt").exists()
    assert (tmp_path / "trace.log").read_text().startswith("Attaching")
    run._stop_observer(cmd, name, tmp_path)
    assert (tmp_path / "observer.log").exists()
    assert any(argv[:3] == ["docker", "stop", "-t"] for argv, _ in cmd.calls)

    cmd.observer_error = "ERROR: invalid probe"
    with pytest.raises(RuntimeError, match="invalid probe"):
        run._start_observer(cmd, _config(tmp_path), _box(), tmp_path, stem="bad")


def test_the_observer_is_ready_only_once_its_log_shows_a_marker_the_container_ran(tmp_path, monkeypatch):
    cmd = FakeCommands(tmp_path / "commands.jsonl")
    run._start_observer(cmd, _config(tmp_path), _box(), tmp_path, stem="trace-grading", grading=True)
    execs = [argv[3:] for argv, _ in cmd.calls if argv[:2] == ["docker", "exec"]]
    assert [step[0] for step in execs] == ["touch", "cat", "rm"] and execs[0][1] == execs[1][1] == execs[2][2]
    assert "observer-ready-" in (tmp_path / "trace-grading.log").read_text()

    cmd.prints_marker = False
    monkeypatch.setattr(run, "ATTACH_SECONDS", 1)
    with pytest.raises(RuntimeError, match="attach marker"):
        run._start_observer(cmd, _config(tmp_path), _box(), tmp_path, stem="silent")
    assert cmd.calls[-1][0][3:5] == ["rm", "-f"]


def test_start_guard_refuses_a_reading_it_cannot_verify(tmp_path, monkeypatch):
    state = iter([{"status": "ok", "outcomes": {"x": "passed"}},
                  {"status": "dependency_missing", "outcomes": {}}])
    monkeypatch.setattr(episode, "cold_reading", lambda *args: next(state))
    spec = SimpleNamespace(task_id="t", tests="x", test_ids=["x"])
    with pytest.raises(task.Refused) as error:
        run._start_guard(None, _config(tmp_path), _box(), "image", b"runtime", spec, tmp_path)
    assert error.value.reason == "start_guard_unreadable"
    assert len(episode.read_json(tmp_path / "start-guard-readings.json")) == 2


def test_readings_record_both_live_and_cold_results_and_stop_the_grading_observer(tmp_path, monkeypatch):
    spec = SimpleNamespace(tests="x")
    events = []
    monkeypatch.setattr(run, "_start_observer", lambda *args, **kw: "grading")
    monkeypatch.setattr(run, "_stop_observer", lambda *args: events.append("stopped"))
    monkeypatch.setattr(episode, "reading_sealed", lambda *args: {"status": "ok", "outcomes": {"x": "passed"}})
    monkeypatch.setattr(episode, "reading_standard", lambda *args: {"status": "ok", "outcomes": {"x": "failed"}})
    monkeypatch.setattr(episode, "cold_reading", lambda cmd, box, image, name, work, read: read("cold-cid"))
    run._readings(None, _config(tmp_path), _box(), b"runtime", spec, tmp_path)
    run._cold_readings(None, _box(), "final", b"runtime", spec, tmp_path)
    assert events == ["stopped"]
    assert episode.read_json(tmp_path / "readings" / "L_s.json")["outcomes"] == {"x": "passed"}
    assert episode.read_json(tmp_path / "readings" / "C_std.json")["outcomes"] == {"x": "failed"}


def test_one_episode_persists_evidence_and_removes_its_task_images(tmp_path, monkeypatch):
    work = tmp_path / "ba-t"
    cmd = FakeCommands(work / "commands.jsonl")
    monkeypatch.setattr(run, "Commands", lambda log: cmd)
    spec = SimpleNamespace(task_id="t", tests="def test_x(): pass", test_ids=["tests.py::test_x"])
    monkeypatch.setattr(task, "compile_spec", lambda row, index, revision: spec)

    class Driver:
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, **kwargs):
            self.returncode = 0
            episode.write_json(work / "tools.json", {"tools": [], "side_tasks_passed_during_run": [], "scores": {}})

        def terminate(self):
            self.returncode = -15

    driver = Driver()
    monkeypatch.setattr(run, "_driver", lambda config, path: driver)
    monkeypatch.setattr(episode, "wait_for", lambda path, timeout, alive: episode.write_json(
        path, {"hostname": "task", "wall": 1, "monotonic_ns": 1}))
    monkeypatch.setattr(episode, "find_container", lambda cmd, hostname: _box())
    monkeypatch.setattr(run, "_start_guard", lambda *args: {"runs": []})
    monkeypatch.setattr(episode, "base_environment_digest", lambda config: "base-sha")
    monkeypatch.setattr(run.contract, "seal", lambda *args: SimpleNamespace(contract_sha256="contract-sha"))
    monkeypatch.setattr(run, "_start_observer", lambda *args: "observer")
    stopped = []
    monkeypatch.setattr(run, "_stop_observer", lambda *args: stopped.append("stop"))

    def observe(cmd, config, container, what, *args):
        if what == "upper":
            return {"entries": {}}
        if what == "procs":
            return []
        if what == "nat":
            return {"rules": []}
        if what == "preload":
            return {"present": False}
        if what == "route":
            return {address: {"exit": 0, "route": []} for address in args}
        raise AssertionError(what)

    monkeypatch.setattr(episode, "observe", observe)

    def live(cmd, config, container, runtime, spec, work):
        out = work / "readings"
        out.mkdir(exist_ok=True)
        for name in ("L_s", "L_std"):
            episode.write_json(out / f"{name}.json", {"status": "ok"})

    def cold(cmd, container, final, runtime, spec, work):
        for name in ("C_s", "C_std"):
            episode.write_json(work / "readings" / f"{name}.json", {"status": "ok"})

    monkeypatch.setattr(run, "_readings", live)
    monkeypatch.setattr(run, "_cold_readings", cold)
    monkeypatch.setattr(episode, "build_episode", lambda *args: "episode")
    monkeypatch.setattr(run.verdict, "derive", lambda record: {
        "outcome": {"status": "supported"}, "integrity": {"status": "supported", "findings": []}})
    monkeypatch.setattr(run.verdict, "write", lambda work, record, key: episode.write_json(
        work / "verdict.json", record))
    result = run.run_episode({"task_id": "t"}, 0, "rev", _config(tmp_path), tmp_path, key=None)
    assert result["contract_sha256"] == "contract-sha" and result["model"] == "model"
    assert stopped == ["stop"] and driver.returncode == 0
    assert episode.read_json(work / "host-end.json")["preload"] == {"present": False}
    assert episode.read_json(work / "routes-start.json") == episode.read_json(work / "host-end.json")["routes"]
    assert set(episode.read_json(work / "images.json")) == set(run.task_images("t", [
        "probity-start-ba-t:latest", "probity-final-ba-t:latest"]))
    assert any(argv[:3] == ["docker", "image", "rm"] for argv, _ in cmd.calls)


def test_batch_keeps_running_after_a_refusal_and_an_episode_error(tmp_path, monkeypatch, capsys):
    rows = tmp_path / "rows.jsonl"
    rows.write_text("\n".join(json.dumps({"row": {"task_id": task_id}, "index": i})
                              for i, task_id in enumerate(("refused", "failed", "good"))))
    monkeypatch.setattr(run, "load_signer", lambda path: "key")
    seen = []

    def one(row, index, revision, config, root, key):
        seen.append(row["task_id"])
        if row["task_id"] == "refused":
            raise task.Refused("refused", "unsealable", "missing test")
        if row["task_id"] == "failed":
            raise RuntimeError("Docker unavailable")
        return {"outcome": {"status": "supported"},
                "integrity": {"status": "supported", "findings": []}}

    monkeypatch.setattr(run, "run_episode", one)
    args = ["--rows", str(rows), "--out", str(tmp_path / "out"), "--basharena", str(tmp_path),
            "--observer-image", "image", "--model", "model", "--key", str(tmp_path / "key"),
            "--revision", "rev"]
    assert run.main(args) == 1
    assert seen == ["refused", "failed", "good"]
    assert episode.read_json(tmp_path / "out" / "refused-refused.json")["reason"] == "unsealable"
    assert "Docker unavailable" in episode.read_json(tmp_path / "out" / "failed-failed.json")["error"]
    assert "VERDICT good supported supported" in capsys.readouterr().out
    seen.clear()
    assert run.main([*args, "--only", "good"]) == 0 and seen == ["good"]
