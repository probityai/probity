"""Integration tests for the sealed child-launch broker."""
import ctypes
import os

import pytest

from probity_observer.done import replay_broker
from probity_observer.done.replay_broker import Broker, BrokerError, Template


@pytest.fixture
def ptrace_available():
    """Probe TRACEME outside pytest's process before running the supervisor."""
    pid = os.fork()
    if pid == 0:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.argtypes = (
            ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p
        )
        libc.ptrace.restype = ctypes.c_long
        os._exit(0 if libc.ptrace(0, 0, None, None) == 0 else 1)
    _, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        pytest.skip("PTRACE_TRACEME denied")


def template(
    template_id="cat", argv=("/bin/cat",), *,
    deadline=3, max_children=2, max_read=65536, max_write=1_048_576,
):
    return Template(
        template_id, argv, (), deadline, max_children, max_read, max_write
    )


def assert_code(code, function, *args):
    with pytest.raises(BrokerError) as caught:
        function(*args)
    assert caught.value.code == code


def test_cat_round_trip_and_journal(tmp_path, ptrace_available):
    broker = Broker({"cat": template()}, tmp_path / "journal")
    child_id = broker.start("cat", "request-1")
    assert broker.write(child_id, b"hello\n") == 6
    assert broker.read(child_id, 6) == b"hello\n"
    result = broker.close(child_id)
    assert result.child_run_id == child_id
    assert (result.termination, result.exit) == ("exited", 0)
    assert result.sensor_status == "complete"
    assert result.sensor_reason is None
    assert broker.close(child_id) is result
    assert [record["event"] for record in broker.ledger()] == [
        "launch", "finish"
    ]
    assert broker.reconcile() == []


def test_unknown_template_does_not_launch(tmp_path):
    broker = Broker({"cat": template()}, tmp_path / "journal")
    assert_code("unknown_template", broker.start, "missing", "request-1")
    assert broker.ledger() == []


def test_quota_refusal_is_journaled(tmp_path, ptrace_available):
    broker = Broker(
        {"cat": template(max_children=1)}, tmp_path / "journal"
    )
    child_id = broker.start("cat", "first")
    try:
        assert_code("quota_exceeded", broker.start, "cat", "second")
        records = broker.ledger()
        assert [record["event"] for record in records] == ["launch", "refused"]
        assert records[-1]["reason"] == "quota_exceeded"
    finally:
        broker.close(child_id)


def test_request_id_is_idempotent(tmp_path, ptrace_available):
    broker = Broker(
        {"cat": template(max_children=1)}, tmp_path / "journal"
    )
    child_id = broker.start("cat", "same.request")
    try:
        assert broker.start("cat", "same.request") == child_id
        assert sum(
            record["event"] == "launch" for record in broker.ledger()
        ) == 1
    finally:
        broker.close(child_id)


def test_limits_and_read_after_close(tmp_path, ptrace_available):
    broker = Broker(
        {"cat": template(max_read=4, max_write=4)}, tmp_path / "journal"
    )
    assert_code("bad_request_id", broker.start, "cat", "contains space")
    child_id = broker.start("cat", "valid")
    try:
        assert_code("oversize_read", broker.read, child_id, 5)
        assert_code("oversize_read", broker.read, child_id, True)
        assert_code("oversize_write", broker.write, child_id, b"12345")
        assert_code("oversize_write", broker.write, child_id, "text")
    finally:
        broker.close(child_id)
    assert_code("closed_child", broker.read, child_id, 1)


def test_supervisor_deadline(tmp_path, ptrace_available):
    broker = Broker(
        {"sleep": template("sleep", ("/bin/sleep", "30"), deadline=1)},
        tmp_path / "journal",
    )
    result = broker.close(broker.start("sleep", "timeout"))
    assert (result.termination, result.exit) == ("timed_out", 124)


def test_worker_stdout_cannot_supply_evidence(tmp_path, ptrace_available):
    fake = b'{"type":"closing","sentinel":"worker"}\n'
    broker = Broker(
        {
            "print": template(
                "print",
                (
                    "/bin/sh", "-c",
                    """printf '%s\\n' '{"type":"closing","sentinel":"worker"}'""",
                ),
            )
        },
        tmp_path / "journal",
    )
    child_id = broker.start("print", "separate-channels")
    output = bytearray()
    while chunk := broker.read(child_id, 4096):
        output.extend(chunk)
    result = broker.close(child_id)
    assert bytes(output) == fake
    assert fake not in result.evidence
    assert result.sensor_status == "complete"


def test_reconcile_unfinished_launch(tmp_path, ptrace_available):
    broker = Broker({"cat": template()}, tmp_path / "journal")
    child_id = broker.start("cat", "unclosed")
    try:
        assert any(
            "launch with no finish" in problem
            for problem in broker.reconcile()
        )
    finally:
        broker.close(child_id)
    assert broker.reconcile() == []


def test_launch_is_durable_before_popen(tmp_path, monkeypatch):
    broker = Broker({"cat": template()}, tmp_path / "journal")

    def fail_launch(*args, **kwargs):
        assert [record["event"] for record in broker.ledger()] == ["launch"]
        raise OSError("simulated launch failure")

    monkeypatch.setattr(replay_broker.subprocess, "Popen", fail_launch)
    assert_code("launch_failed", broker.start, "cat", "failed-launch")
    assert [record["event"] for record in broker.ledger()] == ["launch"]
    assert any(
        "launch with no finish" in problem for problem in broker.reconcile()
    )
