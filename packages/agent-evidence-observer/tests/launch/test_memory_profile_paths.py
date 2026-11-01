"""Tests for worker-profile prerequisites and descriptor reconciliation."""
import builtins
import ctypes
import errno
import io
import os
import stat
from types import SimpleNamespace

import pytest

from probity_observer.launch import memory_profile as profile


def test_syscall_reports_kernel_error():
    with pytest.raises(OSError) as error:
        profile._syscall(999999)
    assert error.value.errno == errno.ENOSYS


def test_seccomp_install_builds_program_and_uses_expected_syscalls(monkeypatch):
    calls = []

    def record(number, *args):
        calls.append((number, args))

    monkeypatch.setattr(profile, "_syscall", record)
    profile._install_seccomp()  # No filter is installed: _syscall is replaced.

    assert [number for number, _ in calls] == [157, 317]
    assert [arg.value for arg in calls[0][1][:2]] == [38, 1]
    assert calls[1][1][0].value == 1
    program = ctypes.cast(
        calls[1][1][2], ctypes.POINTER(profile._SockFprog)
    ).contents
    assert program.length == len(profile.filter_instructions())
    assert (program.filter[0].code, program.filter[0].k) == (0x20, 4)


def test_worker_identity_reads_capabilities(monkeypatch):
    real_open = builtins.open
    status = "CapEff:\t00000000\nCapPrm:\t00000000\nCapAmb:\t00000000\n"

    def open_status(path, *args, **kwargs):
        if path == "/proc/self/status":
            return io.StringIO(status)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", open_status)
    monkeypatch.setattr(profile.os, "getresuid", lambda: (1000, 1000, 1000))
    monkeypatch.setattr(profile.os, "getresgid", lambda: (1000, 1000, 1000))
    monkeypatch.setattr(profile.os, "getgroups", lambda: [])
    assert profile._worker_identity() is True

    status = status.replace("CapAmb:\t00000000", "CapAmb:\t00000001")
    assert profile._worker_identity() is False
    status = "CapEff:\tinvalid\n"
    assert profile._worker_identity() is False


def test_apparmor_label_reads_and_handles_missing_attribute(monkeypatch):
    real_open = builtins.open

    def label_open(path, *args, **kwargs):
        if path == "/proc/self/attr/apparmor/current":
            return io.StringIO("  " + profile.APPARMOR_LABEL + "\n")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", label_open)
    assert profile._apparmor_label() == profile.APPARMOR_LABEL

    def missing(path, *args, **kwargs):
        if path == "/proc/self/attr/apparmor/current":
            raise FileNotFoundError(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", missing)
    assert profile._apparmor_label() is None


def test_proc_mem_requires_both_open_modes_to_be_denied(monkeypatch):
    flags_seen = []

    def denied(path, flags):
        assert path == "/proc/self/mem"
        flags_seen.append(flags)
        raise PermissionError(errno.EPERM, "denied")

    monkeypatch.setattr(profile.os, "open", denied)
    assert profile._proc_mem_denied() is True
    assert flags_seen == [os.O_RDONLY | os.O_CLOEXEC,
                          os.O_RDWR | os.O_CLOEXEC]

    closed = []
    monkeypatch.setattr(profile.os, "open", lambda path, flags: 42)
    monkeypatch.setattr(profile.os, "close", closed.append)
    assert profile._proc_mem_denied() is False
    assert closed == [42]

    def missing(path, flags):
        raise FileNotFoundError(errno.ENOENT, "missing")

    monkeypatch.setattr(profile.os, "open", missing)
    assert profile._proc_mem_denied() is False


class _OsProxy:
    """Stand-in for the os module that profile sees.

    Patching os.fstat or os.close on the real module also breaks pytest's own
    capture, which calls them while the test runs. Replacing profile's reference
    keeps the patch inside the code under test."""

    def __getattr__(self, name):
        return getattr(os, name)


def test_close_inherited_checks_channels_and_reconciles_fds(monkeypatch):
    null = SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=7)
    pipe = SimpleNamespace(st_mode=stat.S_IFIFO, st_rdev=0)
    closed = []
    fake_os = _OsProxy()
    monkeypatch.setattr(profile, "os", fake_os)
    monkeypatch.setattr(fake_os, "listdir",
                        lambda path: ["0", "1", "2", "8", "9"])
    monkeypatch.setattr(fake_os, "stat", lambda path: null)
    monkeypatch.setattr(fake_os, "fstat",
                        lambda fd: null if fd == 0 else pipe)

    def close(fd):
        closed.append(fd)
        if fd == 9:
            raise OSError(errno.EBADF, "already closed")

    monkeypatch.setattr(fake_os, "close", close)
    profile._close_inherited((0, 1, 2))
    assert closed == [8, 9]

    monkeypatch.setattr(fake_os, "fstat",
                        lambda fd: SimpleNamespace(st_mode=stat.S_IFREG,
                                                   st_rdev=0))
    with pytest.raises(profile.ProfileUnsupported, match="not a pipe"):
        profile._close_inherited((0,))
    with pytest.raises(profile.ProfileUnsupported, match="standard channels"):
        profile._close_inherited((0, 3))
    with pytest.raises(profile.ProfileUnsupported, match="standard channels"):
        profile._close_inherited((0, 0))

    def unavailable(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(fake_os, "listdir", unavailable)
    with pytest.raises(profile.ProfileUnsupported, match="cannot reconcile"):
        profile._close_inherited((0,))


def test_apply_worker_profile_success_and_install_failure(monkeypatch):
    monkeypatch.setattr(profile.platform, "system", lambda: "Linux")
    monkeypatch.setattr(profile.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(profile, "_apparmor_label",
                        lambda: profile.APPARMOR_LABEL)
    monkeypatch.setattr(profile, "_worker_identity", lambda: True)
    monkeypatch.setattr(profile, "_proc_mem_denied", lambda: True)
    preserved = []
    monkeypatch.setattr(profile, "_close_inherited", preserved.append)
    monkeypatch.setattr(profile, "_install_seccomp", lambda: None)

    assert profile.apply_worker_profile(
        approved_object_policy=True, preserve_fds=(0, 1)
    ) == profile.ProfileStatus(True, profile.APPARMOR_LABEL, True)
    assert preserved == [(0, 1)]

    def install_fails():
        raise OSError(errno.EPERM, "seccomp unavailable")

    monkeypatch.setattr(profile, "_install_seccomp", install_fails)
    with pytest.raises(profile.ProfileUnsupported) as error:
        profile.apply_worker_profile(approved_object_policy=True)
    assert isinstance(error.value.__cause__, OSError)


def test_apply_worker_profile_refuses_missing_prerequisites(monkeypatch):
    monkeypatch.setattr(profile.platform, "system", lambda: "Linux")
    monkeypatch.setattr(profile.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(profile, "_apparmor_label",
                        lambda: profile.APPARMOR_LABEL)
    monkeypatch.setattr(profile, "_worker_identity", lambda: True)
    monkeypatch.setattr(profile, "_proc_mem_denied", lambda: True)

    with pytest.raises(profile.ProfileUnsupported):
        profile.apply_worker_profile()
    monkeypatch.setattr(profile, "_worker_identity", lambda: False)
    with pytest.raises(profile.ProfileUnsupported):
        profile.apply_worker_profile(approved_object_policy=True)
    monkeypatch.setattr(profile, "_worker_identity", lambda: True)
    monkeypatch.setattr(profile, "_proc_mem_denied", lambda: False)
    with pytest.raises(profile.ProfileUnsupported):
        profile.apply_worker_profile(approved_object_policy=True)
    monkeypatch.setattr(profile.platform, "machine", lambda: "aarch64")
    with pytest.raises(profile.ProfileUnsupported):
        profile.apply_worker_profile(approved_object_policy=True)
