"""Strict whole-vector parsing of exec arguments and environments (``strace.vector_arg``)."""

from __future__ import annotations

import pytest

from probity_observer.sensors import strace


def hx(data: bytes | str) -> str:
    raw = data.encode() if isinstance(data, str) else data
    return '"' + "".join(f"\\x{byte:02x}" for byte in raw) + '"'


def array(*items: bytes | str) -> str:
    return "[" + ", ".join(hx(item) for item in items) + "]"


def trace_exec(envp: str, argv: str | None = None, result: str = "0") -> strace.Effects:
    argv = argv if argv is not None else array("/usr/bin/git", "status")
    text = f"10 1.000000 execve({hx('/usr/bin/git')}, {argv}, {envp}) = {result}\n"
    return strace.effects(strace.parse(text), "/workspace")


def test_complete_vector_keeps_every_element_in_order():
    vector = strace.vector_arg(array("B=2", "A=1", "B=3"))
    assert vector.items == (b"B=2", b"A=1", b"B=3") and vector.complete


def test_empty_array_is_complete():
    assert strace.vector_arg("[]") == strace.Vector((), "complete")


def test_truncated_strace_env():
    """A string cut at the print limit (``"..."...``) is truncated, not complete."""
    found = trace_exec("[" + hx("PATH=/bin") + ", " + hx("BIG=xx") + "...]")
    (event,) = found.events
    assert event.envp_vector.status == "truncated" and not event.envp_vector.complete


def test_truncated_element_list():
    vector = strace.vector_arg("[" + hx("A=1") + ", ...]")
    assert vector.status == "truncated" and vector.items == (b"A=1",)


def test_abbreviated_environment_array():
    found = trace_exec("0x7ffc12345678 /* 6 vars */")
    (event,) = found.events
    assert event.envp_vector.status == "abbreviated" and event.envp_vector.items == ()


@pytest.mark.parametrize("text", [
    "[" + hx("A=1") + " junk " + hx("B=2") + "]",
    "[" + hx("A=1") + hx("B=2") + "]",
    "[" + hx("A=1") + ", ]",
    "[" + hx("A=1") + ", B=2]",
    "[" + hx("A=1") + "]x",
    hx("A=1"),
    "[" + hx("A=1") + "..., " + hx("B=2") + "]",
    "[" + '"\\x4"' + "]",
])
def test_array_fragment_not_accepted(text):
    """Quoted fragments with any other text between, before or after them are refused,
    where the old parser collected every quoted string it could find."""
    with pytest.raises(strace.TraceError):
        strace.vector_arg(text)


def test_array_fragment_in_a_trace_is_a_trace_error():
    with pytest.raises(strace.TraceError):
        trace_exec("[" + hx("A=1") + " " + hx("B=2") + "]")


def test_truncated_argv_not_accepted_as_complete():
    found = trace_exec(array("PATH=/bin"), argv="[" + hx("/usr/bin/git") + ", ...]")
    (event,) = found.events
    assert event.argv_vector.status == "truncated" and event.envp_vector.complete


def test_lossless_non_utf8_vector():
    raw = b"X=\xff\xfe\x00z"
    vector = strace.vector_arg(array(b"PATH=/bin", raw))
    assert vector.items[1] == raw


def test_duplicate_names_are_preserved_beside_the_projection():
    found = trace_exec(array("PYTHONPATH=/a", "HOME=/tmp", "PYTHONPATH=/b"))
    (event,) = found.events
    assert event.envp_vector.items == (b"PYTHONPATH=/a", b"HOME=/tmp", b"PYTHONPATH=/b")
    # The loader projection collapses the duplicate; it is never the complete environment.
    assert event.env == {"PYTHONPATH": "/b"}


def test_large_complete_exec_vector():
    """A value longer than the tracer's -s limit, printed in full, is complete."""
    value = "V=" + "a" * 70000
    vector = strace.vector_arg(array("PATH=/bin", value))
    assert vector.complete and vector.items[1] == value.encode()


def test_failed_exec_is_kept_as_a_diagnostic_and_is_no_exec_event():
    text = (f"10 1.000000 execve({hx('/nope')}, {array('/nope')}, {array('A=1')}) = "
            "-1 E2BIG (Argument list too long)\n"
            f"10 1.100000 execve({hx('/usr/bin/git')}, {array('git')}, {array('A=1')}) = 0\n")
    found = strace.effects(strace.parse(text), "/workspace")
    assert [event.argv for event in found.events] == [["git"]]
    assert found.failed_execs == [{"syscall": "execve", "pid": 10, "time": 1.0,
                                   "result": "-1 E2BIG (Argument list too long)"}]


def test_unparsed_required_trace_event_is_refused():
    """A cut-off exec line before the end of the trace is a trace error, never taken as a
    trace with nothing lost."""
    text = "10 1.000000 execve(garbage\n10 1.100000 +++ exited with 0 +++\n"
    with pytest.raises(strace.TraceError):
        strace.parse(text)
