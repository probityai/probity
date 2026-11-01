"""Parent-side supervision paths not exercised by ordinary worker exits."""
import ctypes
import hashlib
import io
import json
import os
import signal
from types import SimpleNamespace

import pytest

from probity_observer.sensors import supervisor


def make_supervisor():
    evidence = io.BytesIO()
    instance = supervisor.Supervisor(
        ["/bin/true"], {}, deadline_seconds=5, evidence=evidence)
    return instance, evidence


def records(evidence):
    return [json.loads(line) for line in evidence.getvalue().splitlines()]


def stopped(sig=signal.SIGSTOP, event=0):
    return (event << 16) | (sig << 8) | 0x7f


def test_proc_helpers_and_event_message(monkeypatch):
    assert supervisor._tgid(os.getpid()) == os.getpid()
    with open("/proc/self/exe", "rb") as stream:
        expected = hashlib.sha256(stream.read()).hexdigest()
    assert supervisor._sha256_exe(os.getpid()) == expected

    def write_event(request, tid, data=0):
        assert request == supervisor.PTRACE_GETEVENTMSG
        assert tid == 123
        ctypes.cast(data, ctypes.POINTER(ctypes.c_ulonglong)).contents.value = 456

    monkeypatch.setattr(supervisor, "_ptrace", write_event)
    assert supervisor._event_message(123) == 456


def test_capture_exec_records_baseline_and_tid_replacement(monkeypatch):
    instance, evidence = make_supervisor()
    old = instance._add_task(101, None)
    displaced = instance._add_task(100, None)
    instance.baseline = object()
    monkeypatch.setattr(supervisor, "_event_message", lambda tid: 101)
    monkeypatch.setattr(supervisor, "read_initial_stack",
                        lambda tid: SimpleNamespace(argv=[b"/bin/true"],
                                                    envp=[b"A=1"]))
    monkeypatch.setattr(supervisor, "encode_vector",
                        lambda values: [value.decode() for value in values])
    monkeypatch.setattr(supervisor, "environment_reason",
                        lambda values, baseline: "baseline_checked")
    monkeypatch.setattr(supervisor, "_status", lambda tid: {
        "Tgid": "100", "Uid": "1000 1000 1000 1000",
        "Gid": "1000 1000 1000 1000", "CapEff": "00000000"})
    monkeypatch.setattr(supervisor.os, "readlink",
                        lambda path: "/bin/true" if path.endswith("/exe")
                        else "/tmp")
    monkeypatch.setattr(supervisor, "_sha256_exe", lambda tid: "digest")

    assert instance._capture_exec(100) == 0
    assert instance.tasks[100] is old
    assert 101 not in instance.tasks
    assert old["captured"] is True
    assert old["tgid"] == 100
    assert records(evidence)[0]["logical_task_id"] == displaced["id"]
    capture = records(evidence)[1]
    assert capture["type"] == "exec"
    assert capture["environment_reason"] == "baseline_checked"
    assert capture["credentials"]["Uid"] == [1000] * 4


def test_capture_exec_missing_task_and_read_failure(monkeypatch):
    instance, evidence = make_supervisor()
    monkeypatch.setattr(supervisor, "_event_message", lambda tid: 999)
    assert instance._capture_exec(100) == signal.SIGKILL
    assert instance.reason == "trace_incomplete"

    instance, evidence = make_supervisor()
    instance._add_task(100, None)
    monkeypatch.setattr(supervisor, "_event_message", lambda tid: tid)

    def fail(tid):
        raise OSError("stack disappeared")

    monkeypatch.setattr(supervisor, "read_initial_stack", fail)
    killed = []
    monkeypatch.setattr(instance, "_kill_all", lambda: killed.append(True))
    assert instance._capture_exec(100) == signal.SIGKILL
    assert killed == [True]
    assert records(evidence)[0]["type"] == "capture_failed"
    assert instance.reason == "trace_incomplete"


def test_observe_clone_tracks_cross_process_child(monkeypatch):
    instance, evidence = make_supervisor()
    instance.root_pid = 100
    parent = instance._add_task(100, None)
    monkeypatch.setattr(supervisor, "_event_message", lambda tid: 101)
    monkeypatch.setattr(supervisor, "_tgid",
                        lambda tid: 200 if tid == 101 else 100)
    continued = []
    monkeypatch.setattr(supervisor, "_ptrace",
                        lambda *args: continued.append(args))

    instance._observe(100, stopped(event=supervisor.PTRACE_EVENT_CLONE))
    child = instance.tasks[101]
    assert child["parent_id"] == parent["id"]
    assert child["tgid"] == 200
    assert records(evidence)[1]["fs_sharing_unknown"] is True
    assert instance.reason == "shared_fs_unsupported"
    assert continued == [(supervisor.PTRACE_CONT, 100, 0)]

    # A later trace failure takes precedence over the unsupported-FS reason.
    instance._incomplete("trace_incomplete")
    assert instance.reason == "trace_incomplete"


def test_observe_fork_duplicate_and_trace_failure(monkeypatch):
    instance, evidence = make_supervisor()
    instance._add_task(100, None)
    monkeypatch.setattr(supervisor, "_event_message", lambda tid: 101)
    monkeypatch.setattr(supervisor, "_tgid", lambda tid: tid)
    continued = []
    monkeypatch.setattr(supervisor, "_ptrace",
                        lambda *args: continued.append(args))
    instance._observe(100, stopped(event=supervisor.PTRACE_EVENT_FORK))
    assert records(evidence)[1]["fs_sharing_unknown"] is False
    assert instance.reason is None

    killed = []
    monkeypatch.setattr(instance, "_kill_all", lambda: killed.append(True))
    instance._observe(100, stopped(event=supervisor.PTRACE_EVENT_FORK))
    assert records(evidence)[-1]["type"] == "trace_error"
    assert killed == [True]
    assert continued[-1] == (supervisor.PTRACE_CONT, 100, signal.SIGKILL)


def test_observe_unknown_task_and_signal_delivery(monkeypatch):
    instance, evidence = make_supervisor()
    continued = []
    monkeypatch.setattr(supervisor, "_ptrace",
                        lambda *args: continued.append(args))
    instance._observe(999, stopped())
    assert instance.reason == "trace_incomplete"
    assert continued == [(supervisor.PTRACE_CONT, 999, signal.SIGKILL)]

    instance, evidence = make_supervisor()
    instance._add_task(100, None)
    instance.root_pid = 100
    instance._observe(100, stopped())
    instance._observe(100, stopped(signal.SIGUSR1))
    assert continued[-2:] == [(supervisor.PTRACE_CONT, 100, 0),
                              (supervisor.PTRACE_CONT, 100, signal.SIGUSR1)]
    instance._observe(100, signal.SIGTERM)
    assert instance.root_exit == 128 + signal.SIGTERM
    assert instance.root_termination == "signaled"
    assert not instance.tasks


@pytest.mark.parametrize(
    ("code", "diagnostic", "reason"),
    [(97, "child_setup_failed", "trace_incomplete"),
     (98, "exec_failed", None)],
)
def test_observe_uncaptured_child_exit(code, diagnostic, reason):
    instance, evidence = make_supervisor()
    instance.root_pid = 100
    instance._add_task(100, None)
    instance._observe(100, code << 8)
    assert instance.root_exit == code
    assert instance.root_termination == "exited"
    assert records(evidence)[1]["type"] == diagnostic
    assert instance.reason == reason


def test_run_handles_child_failure_before_initial_stop(monkeypatch):
    instance, evidence = make_supervisor()
    monkeypatch.setattr(supervisor.os, "fork", lambda: 123456)
    monkeypatch.setattr(supervisor.os, "waitpid",
                        lambda pid, options: (123456, 97 << 8))
    assert instance.run() == 97
    assert [item["type"] for item in records(evidence)] == [
        "observation", "child_setup_failed", "closing"]
    assert records(evidence)[-1]["sensor"]["reason"] == "trace_incomplete"


def test_run_handles_interrupted_wait_and_unreaped_tasks(monkeypatch):
    instance, evidence = make_supervisor()
    monkeypatch.setattr(supervisor.os, "fork", lambda: 123456)
    waits = iter([(123456, stopped()), InterruptedError(),
                  (123456, 0)])

    def waitpid(pid, options):
        result = next(waits)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(supervisor.os, "waitpid", waitpid)
    monkeypatch.setattr(supervisor, "_ptrace", lambda *args: 0)
    assert instance.run() == 0
    assert records(evidence)[-1]["sensor"]["tasks_reaped"] is True

    instance, evidence = make_supervisor()
    waits = iter([(123456, stopped()), ChildProcessError()])
    monkeypatch.setattr(supervisor.os, "waitpid", waitpid)
    assert instance.run() == 1
    assert instance.unreaped is True
    assert records(evidence)[-1]["sensor"]["tasks_reaped"] is False
    assert records(evidence)[-1]["sensor"]["reason"] == "trace_incomplete"


def test_run_handles_setoptions_error(monkeypatch):
    instance, evidence = make_supervisor()
    monkeypatch.setattr(supervisor.os, "fork", lambda: 123456)
    waits = iter([(123456, stopped()), (123456, signal.SIGKILL)])
    monkeypatch.setattr(supervisor.os, "waitpid",
                        lambda pid, options: next(waits))
    monkeypatch.setattr(supervisor.os, "kill", lambda pid, sig: None)

    def fail_options(request, tid, data=0):
        if request == supervisor.PTRACE_SETOPTIONS:
            raise OSError("options unavailable")
        return 0

    monkeypatch.setattr(supervisor, "_ptrace", fail_options)
    assert instance.run() == 128 + signal.SIGKILL
    assert any(item["type"] == "trace_error" for item in records(evidence))
    assert records(evidence)[-1]["sensor"]["reason"] == "trace_incomplete"


def test_real_signaled_worker_with_environment_baseline(monkeypatch):
    pid = os.fork()
    if pid == 0:
        os._exit(0 if supervisor._LIBC.ptrace(
            supervisor.PTRACE_TRACEME, 0, None, None) == 0 else 1)
    _, probe_status = os.waitpid(pid, 0)
    if not os.WIFEXITED(probe_status) or os.WEXITSTATUS(probe_status):
        pytest.skip("PTRACE_TRACEME denied")

    baseline = object()
    monkeypatch.setattr(supervisor, "environment_reason",
                        lambda env, value: "baseline_checked")
    evidence = io.BytesIO()
    instance = supervisor.Supervisor(
        ["/bin/sh", "-c", "kill -TERM $$"], {},
        deadline_seconds=5, evidence=evidence, baseline=baseline)
    assert instance.run() == 128 + signal.SIGTERM
    captured = next(item for item in records(evidence)
                    if item["type"] == "exec")
    assert captured["environment_reason"] == "baseline_checked"
    assert records(evidence)[-1]["termination"] == "signaled"
    assert records(evidence)[-1]["sensor"]["status"] == "complete"
