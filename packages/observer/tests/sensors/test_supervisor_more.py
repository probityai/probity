"""Additional parent-side paths and real ptrace integration."""
import io
import json
import os
import signal
import sys

import pytest

from probity_observer.sensors import supervisor


def more_supervisor():
    evidence = io.BytesIO()
    return supervisor.Supervisor(
        ["/bin/true"], {}, deadline_seconds=5, evidence=evidence), evidence


def more_records(evidence):
    return [json.loads(line) for line in evidence.getvalue().splitlines()]


def more_stopped(sig=signal.SIGSTOP):
    return (sig << 8) | 0x7f


def more_ptrace_or_skip():
    pid = os.fork()
    if pid == 0:
        os._exit(0 if supervisor._LIBC.ptrace(
            supervisor.PTRACE_TRACEME, 0, None, None) == 0 else 1)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status)
    if os.WEXITSTATUS(status) == 1:
        pytest.skip("PTRACE_TRACEME denied")
    assert os.WEXITSTATUS(status) == 0


@pytest.mark.parametrize(
    ("argv", "deadline", "uid", "gid", "message"),
    [([], 5, None, None, "argv"),
     (["/bin/true"], 0, None, None, "deadline"),
     (["/bin/true"], 5, 65534, None, "uid and gid"),
     (["/bin/true"], 5, None, 65534, "uid and gid")],
)
def test_more_constructor_rejects_invalid_inputs(argv, deadline, uid, gid, message):
    with pytest.raises(ValueError, match=message):
        supervisor.Supervisor(argv, {}, deadline_seconds=deadline,
                              evidence=io.BytesIO(), worker_uid=uid, worker_gid=gid)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [(ProcessLookupError, "shared_fs_unsupported"),
     (PermissionError, "trace_incomplete")],
)
def test_more_kill_all_ignores_gone_tasks_but_not_denied(monkeypatch, failure, expected):
    instance, _ = more_supervisor()
    instance._add_task(101, None)
    instance.reason = "shared_fs_unsupported"
    def fail(pid, sig):
        assert (pid, sig) == (101, signal.SIGKILL)
        raise failure("cannot kill")
    monkeypatch.setattr(supervisor.os, "kill", fail)
    instance._kill_all()
    assert instance.reason == expected


def test_more_capture_exec_loses_replaced_task_at_lookup(monkeypatch):
    instance, evidence = more_supervisor()
    old = instance._add_task(101, None)
    displaced = instance._add_task(100, None)
    class VanishingLookup(dict):
        def get(self, key, default=None):
            return None if key == 100 else super().get(key, default)
    instance.tasks = VanishingLookup(instance.tasks)
    monkeypatch.setattr(supervisor, "_event_message", lambda tid: 101)
    assert instance._capture_exec(100) == signal.SIGKILL
    assert instance.tasks[100] is old
    assert more_records(evidence)[0]["logical_task_id"] == displaced["id"]
    assert instance.reason == "trace_incomplete"


def test_more_observe_continued_status_is_incomplete():
    instance, evidence = more_supervisor()
    instance._add_task(100, None)
    instance._observe(100, 0xffff)
    assert instance.reason == "trace_incomplete"
    assert 100 in instance.tasks
    assert more_records(evidence)[0]["wait_status"] == 0xffff


def test_more_observe_unknown_task_failed_kill_cont(monkeypatch):
    instance, evidence = more_supervisor()
    def denied(request, tid, data=0):
        assert (request, tid, data) == (supervisor.PTRACE_CONT, 999, signal.SIGKILL)
        raise OSError("gone")
    monkeypatch.setattr(supervisor, "_ptrace", denied)
    instance._observe(999, more_stopped())
    assert instance.reason == "trace_incomplete"
    assert [r["type"] for r in more_records(evidence)] == ["observation"]


def test_more_observe_trace_error_then_failed_kill_cont(monkeypatch):
    instance, evidence = more_supervisor()
    instance._add_task(100, None)
    calls = []
    def denied(request, tid, data=0):
        calls.append((request, tid, data))
        raise OSError("cont unavailable")
    monkeypatch.setattr(supervisor, "_ptrace", denied)
    killed = []
    monkeypatch.setattr(instance, "_kill_all", lambda: killed.append(True))
    instance._observe(100, more_stopped())
    assert calls == [(supervisor.PTRACE_CONT, 100, 0),
                     (supervisor.PTRACE_CONT, 100, signal.SIGKILL)]
    assert killed == [True]
    assert [r["type"] for r in more_records(evidence)] == ["observation", "trace_error"]
    assert instance.reason == "trace_incomplete"


def test_more_run_setoptions_and_kill_cont_both_fail(monkeypatch):
    instance, evidence = more_supervisor()
    monkeypatch.setattr(supervisor.os, "fork", lambda: 123456)
    waits = iter([(123456, more_stopped()), (123456, signal.SIGKILL)])
    monkeypatch.setattr(supervisor.os, "waitpid", lambda pid, opts: next(waits))
    monkeypatch.setattr(supervisor.os, "kill", lambda pid, sig: None)
    requests = []
    def denied(request, tid, data=0):
        requests.append((request, tid, data))
        raise OSError("ptrace unavailable")
    monkeypatch.setattr(supervisor, "_ptrace", denied)
    assert instance.run() == 128 + signal.SIGKILL
    assert requests == [(supervisor.PTRACE_SETOPTIONS, 123456,
                         supervisor.PTRACE_OPTIONS),
                        (supervisor.PTRACE_CONT, 123456, signal.SIGKILL)]
    assert [r["type"] for r in more_records(evidence)] == [
        "observation", "trace_error", "observation", "closing"]
    assert more_records(evidence)[-1]["sensor"]["reason"] == "trace_incomplete"


@pytest.mark.parametrize(
    ("initial", "exit_code", "termination", "diagnostic"),
    [(signal.SIGTERM, 128 + signal.SIGTERM, "signaled", None),
     (97 << 8, 97, "exited", "child_setup_failed")],
)
def test_more_run_initial_terminal_status(monkeypatch, initial, exit_code,
                                          termination, diagnostic):
    instance, evidence = more_supervisor()
    monkeypatch.setattr(supervisor.os, "fork", lambda: 123456)
    monkeypatch.setattr(supervisor.os, "waitpid", lambda pid, opts: (123456, initial))
    assert instance.run() == exit_code
    lines = more_records(evidence)
    assert lines[-1]["termination"] == termination
    assert lines[-1]["sensor"]["reason"] == "trace_incomplete"
    assert lines[-1]["sensor"]["tasks_reaped"] is True
    assert ("child_setup_failed" in [r["type"] for r in lines]) == bool(diagnostic)


def test_more_run_deadline_grace_unreaped(monkeypatch):
    instance, evidence = more_supervisor()
    instance.deadline_seconds = 1
    monkeypatch.setattr(supervisor.os, "fork", lambda: 123456)
    waits = iter([(123456, more_stopped()), (0, 0)])
    monkeypatch.setattr(supervisor.os, "waitpid", lambda pid, opts: next(waits))
    monkeypatch.setattr(supervisor, "_ptrace", lambda *args: 0)
    clock = iter([0, 2, 8])
    monkeypatch.setattr(supervisor.time, "monotonic", lambda: next(clock, 8))
    monkeypatch.setattr(supervisor.time, "sleep", lambda _: None)
    killed = []
    monkeypatch.setattr(supervisor.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    assert instance.run() == 124
    assert killed == [(123456, signal.SIGKILL)]
    assert instance.unreaped is True
    closing = more_records(evidence)[-1]
    assert closing["termination"] == "timed_out"
    assert closing["sensor"]["tasks_reaped"] is False


@pytest.mark.parametrize(
    ("arguments", "message"),
    [(["--"], "a command is required"),
     (["--env", "A", "--", "/bin/true"], "--env requires KEY=VALUE")],
)
def test_more_main_rejects_invalid_arguments(arguments, message, capsys):
    with pytest.raises(SystemExit) as exit_info:
        supervisor.main(["--deadline", "5", "--evidence-fd", "1", *arguments])
    assert exit_info.value.code == 2
    assert message in capsys.readouterr().err


def test_more_main_runs_true_with_evidence_fd_and_env(tmp_path):
    more_ptrace_or_skip()
    destination = tmp_path / "supervisor-evidence.jsonl"
    with destination.open("wb") as evidence:
        assert supervisor.main([
            "--deadline", "10", "--evidence-fd", str(evidence.fileno()),
            "--env", "A=1", "--", "/bin/true"]) == 0
    lines = [json.loads(line) for line in destination.read_bytes().splitlines()]
    assert any(item["type"] == "exec" for item in lines)
    assert lines[-1]["sensor"]["status"] == "complete"


@pytest.mark.skipif(os.geteuid() != 0, reason="credential drop requires root")
def test_more_real_credentials_and_failed_exec():
    more_ptrace_or_skip()
    evidence = io.BytesIO()
    instance = supervisor.Supervisor(
        ["/bin/true"], {}, deadline_seconds=10, evidence=evidence,
        worker_uid=65534, worker_gid=65534)
    assert instance.run() == 0
    lines = more_records(evidence)
    capture = next(item for item in lines if item["type"] == "exec")
    assert capture["credentials"]["Uid"] == [65534] * 4
    assert capture["credentials"]["Gid"] == [65534] * 4
    assert capture["credentials"]["CapEff"] == "0000000000000000"
    assert lines[-1]["sensor"]["status"] == "complete"

    failed_evidence = io.BytesIO()
    failed = supervisor.Supervisor(
        ["/no-such-observer-worker-executable"], {}, deadline_seconds=10,
        evidence=failed_evidence, worker_uid=65534, worker_gid=65534)
    assert failed.run() == 98
    failed_lines = more_records(failed_evidence)
    assert any(item["type"] == "exec_failed" for item in failed_lines)
    assert failed_lines[-1]["sensor"]["status"] == "complete"


def test_more_real_clone_with_shared_fs_is_unsupported():
    more_ptrace_or_skip()
    # No CLONE_VM: the clone has its own address space and exits immediately.
    script = (
        "import ctypes, os, signal\n"
        "signal.signal(signal.SIGUSR1, signal.SIG_IGN)\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "libc.syscall.restype = ctypes.c_long\n"
        "pid = libc.syscall(56, 0x200 | signal.SIGUSR1, 0, 0, 0, 0)\n"
        "if pid == 0: os._exit(0)\n"
        "if pid < 0: raise OSError(ctypes.get_errno(), 'clone')\n"
        "libc.waitpid(pid, None, ctypes.c_int(-0x80000000).value)\n"
    )
    evidence = io.BytesIO()
    instance = supervisor.Supervisor(
        [sys.executable, "-c", script], {}, deadline_seconds=10,
        evidence=evidence)
    assert instance.run() == 0
    lines = more_records(evidence)
    assert any(item["type"] == "task" and item["event"] == 3
               and item["fs_sharing_unknown"] is True for item in lines)
    assert lines[-1]["sensor"]["reason"] == "shared_fs_unsupported"
