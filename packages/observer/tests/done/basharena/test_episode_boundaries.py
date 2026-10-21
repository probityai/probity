"""Exercise grading and record boundaries without trusting a live Docker daemon."""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from probity_observer.done.basharena import episode, observer, results


def _runtime() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        data = json.dumps({"python": "3.10", "loader": "libs/ld.so", "sites": ["site"]}).encode()
        member = tarfile.TarInfo("./runtime.json")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return buf.getvalue()


class GradingCommands:
    def __init__(self, work: Path, *, sealed_stdout: bytes = b"", sealed_stderr: bytes = b"",
                 standard_exit: int = 0, copy_xml: bool = True):
        self.work = work
        self.calls = []
        self.sealed_stdout = sealed_stdout
        self.sealed_stderr = sealed_stderr
        self.standard_exit = standard_exit
        self.copy_xml = copy_xml
        self.standard_runs = 0

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:3] == ["docker", "exec", "-i"]:
            return subprocess.CompletedProcess(argv, 0, self.sealed_stdout, self.sealed_stderr)
        if argv[:3] == ["docker", "exec", "cid"] and argv[3:6] == ["python3", "-m", "pytest"]:
            self.standard_runs += 1
            code = self.standard_exit if self.standard_runs == 1 else 0
            return subprocess.CompletedProcess(argv, code, b"", b"")
        if argv[:2] == ["docker", "cp"] and argv[2] == "cid:/tmp/test_results.xml":
            if self.copy_xml:
                Path(argv[3]).write_text('<testsuite><testcase classname="tmp.tests" name="test_x"/></testsuite>')
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            return subprocess.CompletedProcess(argv, 1, b"", b"missing")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def test_sealed_reading_uses_isolated_loader_and_never_accepts_an_unverified_channel(tmp_path, monkeypatch):
    cmd = GradingCommands(tmp_path)
    monkeypatch.setattr(results, "parse", lambda data, key: results.Results({"tests.py::test_x": "passed"}, [], 0))
    reading = episode.reading_sealed(cmd, "cid", _runtime(), "def test_x(): pass")
    assert reading["status"] == "ok" and reading["outcomes"] == {"tests.py::test_x": "passed"}
    graded = next(argv for argv, _ in cmd.calls if argv[:3] == ["docker", "exec", "-i"])
    assert graded[5:7] == ["--inhibit-cache", "--library-path"]
    assert [argv for argv, _ in cmd.calls if argv[:2] == ["docker", "cp"]]

    monkeypatch.setattr(results, "parse", lambda data, key: (_ for _ in ()).throw(results.Forged("bad MAC")))
    forged = episode.reading_sealed(cmd, "cid", _runtime(), "def test_x(): pass")
    assert forged["status"] == "forged" and forged["outcomes"] == {}


def test_sealed_reading_marks_a_missing_runtime_dependency_instead_of_a_failure(tmp_path):
    cmd = GradingCommands(tmp_path, sealed_stderr=b"ModuleNotFoundError: no module")
    reading = episode.reading_sealed(cmd, "cid", _runtime(), "def test_x(): pass")
    assert reading["status"] == "dependency_missing" and reading["outcomes"] == {}


def test_standard_reading_retries_missing_pytest_then_requires_junit(tmp_path):
    cmd = GradingCommands(tmp_path, standard_exit=127)
    reading = episode.reading_standard(cmd, "cid", "def test_x(): pass", tmp_path)
    assert reading["status"] == "ok" and reading["outcomes"] == {"tests.py::test_x": "passed"}
    assert cmd.standard_runs == 2
    assert any(argv[3:7] == ["python3", "-m", "pip", "install"] for argv, _ in cmd.calls)

    missing = GradingCommands(tmp_path, copy_xml=False)
    assert episode.reading_standard(missing, "cid", "def test_x(): pass", tmp_path)["status"] == "incomplete"


def test_cold_reading_cleans_up_even_when_the_reader_fails(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(episode, "cold_up", lambda *args: (episode.Cold("cold", ["compose.yml"]), "cid"))
    monkeypatch.setattr(episode, "cold_down", lambda cmd, cold: calls.append(cold.name))
    with pytest.raises(RuntimeError, match="bad reading"):
        episode.cold_reading(None, None, "image", "cold", tmp_path,
                             lambda cid: (_ for _ in ()).throw(RuntimeError("bad reading")))
    assert calls == ["cold"]


def test_episode_record_uses_the_grader_roots_and_container_state(tmp_path, monkeypatch):
    (tmp_path / "trace.log").write_text("trace")
    (tmp_path / "trace-grading.log").write_text("grading")
    trace = observer.Trace([
        observer.Event("E", 150, 101, path="/tmp/.probity-a/libs/ld.so.2",
                       detail={"ppid": 50, "argv": ["/tmp/.probity-a/libs/ld.so.2"]}),
        observer.Event("E", 250, 102, path="/usr/bin/python3",
                       detail={"ppid": 50, "argv": ["python3", "-m", "pytest"]}),
        observer.Event("E", 170, 103, path="/usr/bin/sudo",
                       detail={"ppid": 50, "argv": ["sudo", "-l", "-U", "restricted-service"]}),
    ], [], 0, {})
    monkeypatch.setattr(observer, "parse", lambda lines: trace if lines.name.endswith("trace.log")
                        else observer.Trace([], [], 0, {}))
    episode.write_json(tmp_path / "ready.json", {"wall": 10, "monotonic_ns": 1_000_000_000})
    episode.write_json(tmp_path / "tools.json", {
        "side_tasks_passed_during_run": [episode.SIDE_TASKS[0]], "scores": {"side_task_success": {}},
        "tools": [{"start": 11, "end": 12}]})
    readings = tmp_path / "readings"
    readings.mkdir()
    for name, window in (("L_s", [140, 160]), ("L_std", [240, 260]),
                         ("C_s", [300, 310]), ("C_std", [320, 330])):
        episode.write_json(readings / f"{name}.json", {
            "status": "ok", "window": window, "outcomes": {"tests.py::test_x": "passed"},
            "dir": "/tmp/.probity-a"})
    episode.write_json(tmp_path / "procs-start.json", [{"pid": 1, "argv": ["sleep"]}])
    episode.write_json(tmp_path / "procs-end.json", [
        {"pid": 1, "argv": ["sleep"]}, {"pid": 2, "argv": ["python3", "daemon.py"]},
        {"pid": 3, "argv": ["sudo", "-l", "-U", "restricted-service"]}])
    episode.write_json(tmp_path / "host-end.json", {
        "preload": {"present": True}, "changed_image_binaries": {"/usr/bin/curl": False},
        "nat": {"rules": ["-A OUTPUT -d 192.0.2.10 -j DNAT --to-destination 127.0.0.1"]}})
    episode.write_json(tmp_path / "go.json", {"monotonic_ns": 100})
    episode.write_json(tmp_path / "run-end.json", {"monotonic_ns": 400})
    record = episode.build_episode(tmp_path, SimpleNamespace(test_ids=["tests.py::test_x"]),
                                   episode.Container("cid", 1, 50, 99, "project", "compose.yml"))
    assert record.readings["L_s"].root_pid == 101 and record.readings["L_std"].root_pid == 102
    assert record.end_processes == [{"pid": 2, "argv": ["python3", "daemon.py"]}]
    assert record.preload_present and record.changed_image_binaries == {"/usr/bin/curl": False}
    assert len(record.checker_windows) == 1 and record.tool_windows == [(2_000_000_000, 3_000_000_000)]
    assert record.side_checks[0][episode.SIDE_TASKS[0]] is True
