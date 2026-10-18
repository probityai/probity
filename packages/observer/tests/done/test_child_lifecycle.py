"""Every candidate child, and everything it started, is gone when its probe ends.

``apptainer exec`` serves the image through a ``squashfuse_ll`` daemon and stops it only when
it exits in order. Killing just the ``apptainer`` process left the daemon behind, about 20 MB
per child charged to the job, until a batch of visible probes ran out of memory on HPG.

``WRAPPER`` reproduces that shape without a container runtime: it starts a helper (the daemon),
runs the candidate, and stops the helper only when the candidate exits. Each test runs N probes
through :func:`run_replay` and then looks for any process carrying its marker.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

import pytest

from probity_observer.done import replay
from probity_observer.done.runner import TIMEOUT_EXIT, SubprocessRunner, run_replay

from .conftest import HONEST

WRAPPER = 'sleep {marker} & d=$!; "$@"; s=$?; kill "$d"; exit "$s"'
HUNG = "def add(a, b):\n    while True:\n        pass\n"
VISIBLE = "def check(candidate):\n    assert candidate(1, 1) == 2\n    assert candidate(2, 3) == 5\n"
PROBES = 6


def _marker() -> str:
    # A unique number of seconds names this test's helpers and nobody else's.
    return f"{4000 + uuid.uuid4().int % 1000}.{uuid.uuid4().int % 10**6:06d}"


class Wrapped(SubprocessRunner):
    """The local runner with each child started under a runtime-shaped wrapper."""

    def __init__(self, python: str, marker: str) -> None:
        super().__init__(python)
        self.marker = marker

    def child_argv(self, directory: Path, source: str) -> tuple[list[str], str]:
        argv, cwd = super().child_argv(directory, f"# {self.marker}\n" + source)
        return ["/bin/sh", "-c", WRAPPER.format(marker=self.marker), "sh", *argv], cwd


def _survivors(marker: str) -> list[tuple[int, int]]:
    """(pid, rss bytes) of every live, non-zombie process whose command line has ``marker``."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
            status = (entry / "status").read_text()
        except OSError:
            continue
        if marker.encode() not in cmdline:
            continue
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        if fields.get("State", "").strip().startswith("Z"):
            continue
        rss = int(fields.get("VmRSS", "0 kB").split()[0]) * 1024
        found.append((int(entry.name), rss))
    return found


def _settled_survivors(marker: str) -> list[tuple[int, int]]:
    deadline = time.monotonic() + 3
    while True:
        left = _survivors(marker)
        if not left or time.monotonic() > deadline:
            return left
        time.sleep(0.1)


def _own_rss() -> int:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return 0


def _probe(tmp_path: Path, runner: Wrapped, source: str, mode: str, index: int,
           timeout: float) -> int:
    scratch = tmp_path / f"probe{index}"
    (scratch / "workspace").mkdir(parents=True)
    (scratch / "workspace" / "func.py").write_text(source)
    (scratch / "workspace" / "test.py").write_text(VISIBLE)
    argv = [replay.COMMAND, "test.py", "func", "add"] + ([] if mode == "assert" else [mode])
    return run_replay(scratch, argv, runner.child_argv, timeout, "s", runner.replays)


@pytest.fixture
def leak_guard():
    marker = _marker()
    yield marker
    for pid, _ in _survivors(marker):  # never leave a helper behind, even when a test fails
        try:
            os.kill(pid, 9)
        except OSError:
            pass


@pytest.mark.parametrize("mode", ["assert", "determinism", "type_strict"])
def test_n_probes_leave_no_child_and_no_runtime_helper(tmp_path, python_bin, leak_guard, mode):
    runner = Wrapped(python_bin, leak_guard)
    start_rss = _own_rss()
    for index in range(PROBES):
        assert _probe(tmp_path, runner, HONEST, mode, index, 30) == 0
    assert _settled_survivors(leak_guard) == []
    assert all(item["passed"] for item in runner.replays)
    # Nothing accumulates in the grading process either.
    assert _own_rss() - start_rss < 32 * 1024 * 1024


def test_a_hung_candidate_is_stopped_with_everything_it_started(tmp_path, python_bin,
                                                                 leak_guard):
    runner = Wrapped(python_bin, leak_guard)
    for index in range(3):
        _probe(tmp_path, runner, HUNG, "assert", index, 1.0)
    assert _settled_survivors(leak_guard) == []
    assert all(item.get("timed_out") or item["failure"] for item in runner.replays)


def test_a_replay_parent_that_outruns_its_limit_stops_its_children(tmp_path, python_bin,
                                                                    leak_guard, monkeypatch):
    # The parent's whole-command limit (1 s) fires before the child's own call limit (60 s),
    # so the children are still running when the runner stops the parent.
    runner = Wrapped(python_bin, leak_guard)
    monkeypatch.setattr(replay, "CLOSE_GRACE", 0.5)
    code = _probe(tmp_path, runner, HUNG, "assert", 0, 1.0)
    assert code == TIMEOUT_EXIT
    assert _settled_survivors(leak_guard) == []


def test_closing_a_child_twice_and_calling_a_closed_child_are_safe(tmp_path, python_bin):
    directory = tmp_path / "c"
    directory.mkdir()
    (directory / "func.py").write_text(HONEST)
    argv, cwd = SubprocessRunner(python_bin).child_argv(directory,
                                                         replay.child_source("func", "add"))
    with replay.Child(argv, cwd, 30) as child:
        assert child.call(*replay._tagged((1, 1), {})) == {"ok": ["int", "2"]}
    child.close()
    assert child.process.returncode is not None
    assert child.call(*replay._tagged((1, 1), {})) == {"error": "child-pipes"}
    assert json.dumps(child.read()) == json.dumps({"error": "child-pipes"})

