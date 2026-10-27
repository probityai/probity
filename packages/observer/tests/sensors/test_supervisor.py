"""Integration tests using actual traced processes."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import pytest

from probity_observer.sensors import supervisor
from probity_observer.sensors.exec_supervisor import CaptureError


@pytest.fixture(autouse=True)
def ptrace_available():
    pid = os.fork()
    if pid == 0:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p,
                                ctypes.c_void_p)
        libc.ptrace.restype = ctypes.c_long
        os._exit(0 if libc.ptrace(0, 0, None, None) == 0 else 1)
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        pytest.skip("PTRACE_TRACEME denied")


def run_worker(argv, env=None, deadline=5):
    with tempfile.TemporaryFile(mode="w+b") as evidence:
        result = supervisor.Supervisor(
            argv, env if env is not None else {},
            deadline_seconds=deadline, evidence=evidence).run()
        evidence.seek(0)
        records = [json.loads(line) for line in evidence]
    return result, records


def test_true_captures_vectors_and_closes():
    code, records = run_worker(["/bin/true"], {"PROBITY_TEST": "present"})
    assert code == 0
    assert [record["seq"] for record in records] == list(range(len(records)))
    capture = next(record for record in records if record["type"] == "exec")
    assert capture["argv"] == {"encoding": "utf8", "items": ["/bin/true"]}
    assert capture["env"] == {
        "encoding": "utf8", "items": ["PROBITY_TEST=present"]}
    assert records[-1]["type"] == "closing"
    assert records[-1]["sensor"]["status"] == "complete"
    assert records[-1]["sensor"]["tasks_reaped"] is True
    assert records[-1]["exit"] == 0


def test_nonzero_exit_is_not_sensor_failure():
    code, records = run_worker(["/bin/sh", "-c", "exit 3"])
    assert code == records[-1]["exit"] == 3
    assert records[-1]["termination"] == "exited"
    assert records[-1]["sensor"]["status"] == "complete"


def test_fork_children_have_distinct_logical_ids_and_parent_links():
    _, records = run_worker(["/bin/sh", "-c", "/bin/true; /bin/true"])
    captures = [record for record in records if record["type"] == "exec"]
    assert len(captures) >= 3
    parent = next(record for record in captures
                  if record["argv"]["items"][0] == "/bin/sh")
    children = [record for record in captures
                if record["argv"]["items"][0] == "/bin/true"]
    assert len({record["logical_task_id"] for record in children}) >= 2
    assert all(record["parent_id"] == parent["logical_task_id"]
               for record in children)
    assert records[-1]["sensor"]["status"] == "complete"


def test_deadline_kills_and_reaps():
    started = time.monotonic()
    code, records = run_worker(["/bin/sleep", "30"], deadline=1)
    assert time.monotonic() - started < 10
    assert code == records[-1]["exit"] == 124
    assert records[-1]["termination"] == "timed_out"
    assert records[-1]["sensor"]["tasks_reaped"] is True


def test_failed_exec_has_diagnostic_but_no_capture():
    _, records = run_worker(["/no/such/probity-worker"])
    assert any(record["type"] == "exec_failed" for record in records)
    assert not any(record["type"] == "exec" for record in records)


def test_capture_failure_makes_collection_incomplete(monkeypatch):
    def fail(_tid):
        raise CaptureError("test capture failure")

    monkeypatch.setattr(supervisor, "read_initial_stack", fail)
    _, records = run_worker(["/bin/sleep", "30"])
    assert any(record["type"] == "capture_failed" for record in records)
    assert records[-1]["sensor"]["status"] == "incomplete"
    assert records[-1]["sensor"]["reason"] == "trace_incomplete"


def test_cli_evidence_fd():
    src = Path(__file__).resolve().parents[2] / "src"
    environment = dict(os.environ, PYTHONPATH=str(src))
    with tempfile.TemporaryFile(mode="w+b") as evidence:
        result = subprocess.run(
            [sys.executable, "-m", "probity_observer.sensors.supervisor",
             "--deadline", "5", "--evidence-fd", str(evidence.fileno()),
             "--env", "PROBITY_CLI=yes", "--", "/bin/true"],
            env=environment, pass_fds=(evidence.fileno(),), timeout=10,
            check=False)
        evidence.seek(0)
        records = [json.loads(line) for line in evidence]
    assert result.returncode == 0
    capture = next(record for record in records if record["type"] == "exec")
    assert capture["env"]["items"] == ["PROBITY_CLI=yes"]
    assert records[-1]["sensor"]["status"] == "complete"
