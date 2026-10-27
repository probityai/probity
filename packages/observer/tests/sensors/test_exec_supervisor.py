"""Tests for stopped-exec initial-vector capture primitives."""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import signal

import pytest

from probity_observer.sensors.exec_supervisor import (encode_vector, environment_reason,
                                                      read_initial_stack)


def test_environment_reason_precedence() -> None:
    """Malformed names precede loader additions and ordinary changes."""
    baseline = {"PATH": "/usr/bin"}
    assert environment_reason((b"PATH=/usr/bin", b"PATH=x", b"LD_PRELOAD=x"),
                              baseline) == "launch_environment_invalid"
    assert environment_reason((b"PATH=/usr/bin", b"LD_PRELOAD=x", b"X=1"),
                              baseline) == "loader_injection"
    assert environment_reason((b"PATH=/usr/bin", b"X=1"),
                              baseline) == "launch_environment_changed"
    assert environment_reason((b"PATH=/usr/bin",), baseline) is None


def test_lossless_non_utf8_vector() -> None:
    """Invalid UTF-8 remains an exact base64 byte string."""
    assert encode_vector((b"X=\xff",)) == {"encoding": "base64", "items": ["WD3/"]}


@pytest.mark.skipif(platform.system() != "Linux" or platform.machine() != "x86_64",
                    reason="initial-stack decoder supports Linux x86-64 only")
def test_stopped_exec_initial_stack() -> None:
    """A real exec stop exposes the kernel's effective argv and all envp bytes."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
    libc.ptrace.restype = ctypes.c_long
    pid = os.fork()
    if pid == 0:
        if libc.ptrace(0, 0, None, None) == -1:
            os._exit(77 if ctypes.get_errno() in (errno.EPERM, errno.EACCES) else 78)
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execve(b"/bin/true", [b"not-the-path"], {b"NONUTF8": b"\xff"})
        os._exit(78)
    try:
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 77:
            pytest.skip("ptrace unavailable: TRACEME denied by kernel capability policy")
        assert os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP
        assert libc.ptrace(0x4200, pid, None, ctypes.c_void_p(0x100010)) == 0
        assert libc.ptrace(7, pid, None, None) == 0
        _, status = os.waitpid(pid, 0)
        assert os.WIFSTOPPED(status) and status >> 16 == 4
        vectors = read_initial_stack(pid)
        assert vectors.argv == (b"not-the-path",)
        assert vectors.envp == (b"NONUTF8=\xff",)
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
