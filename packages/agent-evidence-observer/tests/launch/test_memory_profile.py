import errno
import os
import struct

import pytest

from probity_observer.launch import memory_profile as profile


def test_report_profile():
    missing = profile.report_profile(None)
    assert missing["status"] == "incomplete"
    assert missing["reason"] == profile.UNSUPPORTED
    assert missing["seccomp"] is False

    status = profile.ProfileStatus(True, profile.APPARMOR_LABEL, True)
    enforced = profile.report_profile(status)
    assert enforced["status"] == "enforced"
    assert enforced["reason"] is None
    assert enforced["seccomp"] is True

    breached = profile.report_profile(status, breach=True)
    assert breached["status"] == "incomplete"
    assert breached["reason"] == profile.BREACH


def test_filter_structure():
    program = profile.filter_instructions()
    assert len(program) < 4096
    assert program[:3] == (
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, profile._KILL),
    )
    assert program[3:6] == (
        (0x20, 0, 0, 0),
        (0x45, 0, 1, 0x40000000),
        (0x06, 0, 0, profile._KILL),
    )
    assert program[-1] == (0x06, 0, 0, profile._ALLOW)

    for number in profile._DENIED:
        assert any(
            instruction == (0x15, 0, 1, number)
            and program[index + 1] == (0x06, 0, 0, profile._ERRNO)
            for index, instruction in enumerate(program[:-1])
        )

    for index, (code, jt, jf, _) in enumerate(program):
        if code in (0x15, 0x45):
            assert index + 1 + jt < len(program)
            assert index + 1 + jf < len(program)


def _evaluate(program, number, arch=0xC000003E, flags=0):
    # seccomp_data: u32 nr, u32 arch, u64 instruction_pointer, u64 args[0].
    data = struct.pack("<IIQQ", number, arch, 0, flags)
    accumulator = 0
    pc = 0
    for _ in range(len(program)):
        code, jt, jf, k = program[pc]
        if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
            accumulator = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == 0x15:  # BPF_JMP | BPF_JEQ | BPF_K
            pc += 1 + (jt if accumulator == k else jf)
        elif code == 0x45:  # BPF_JMP | BPF_JSET | BPF_K
            pc += 1 + (jt if accumulator & k else jf)
        elif code == 0x06:  # BPF_RET | BPF_K
            return k
        else:
            raise AssertionError(f"unexpected BPF opcode: {code:#x}")
        assert 0 <= pc < len(program)
    raise AssertionError("BPF program did not return")


def test_filter_decisions():
    program = profile.filter_instructions()
    assert _evaluate(program, 101) == 0x00050000 | errno.EPERM
    assert _evaluate(program, 0) == profile._ALLOW
    assert _evaluate(program, 0, arch=0) == profile._KILL
    assert _evaluate(program, 0x40000000) == profile._KILL
    assert _evaluate(program, 56, flags=0x7E020080) == profile._ERRNO
    assert _evaluate(program, 56, flags=0x11) == profile._ALLOW


@pytest.fixture
def ready_profile(monkeypatch):
    monkeypatch.setattr(profile.platform, "system", lambda: "Linux")
    monkeypatch.setattr(profile.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(profile, "_apparmor_label", lambda: profile.APPARMOR_LABEL)
    monkeypatch.setattr(profile, "_worker_identity", lambda: True)
    monkeypatch.setattr(profile, "_proc_mem_denied", lambda: True)
    monkeypatch.setattr(profile, "_close_inherited", lambda preserve: None)


@pytest.mark.parametrize(
    "failure",
    ["architecture", "policy", "label", "identity", "proc_mem"],
)
def test_apply_refuses_before_install(monkeypatch, ready_profile, failure):
    calls = []

    def unexpected_install():
        calls.append(True)
        raise AssertionError("installed despite failed prerequisite")

    monkeypatch.setattr(profile, "_install_seccomp", unexpected_install)
    if failure == "architecture":
        monkeypatch.setattr(profile.platform, "machine", lambda: "aarch64")
    elif failure == "label":
        monkeypatch.setattr(profile, "_apparmor_label", lambda: "other")
    elif failure == "identity":
        monkeypatch.setattr(profile, "_worker_identity", lambda: False)
    elif failure == "proc_mem":
        monkeypatch.setattr(profile, "_proc_mem_denied", lambda: False)

    with pytest.raises(profile.ProfileUnsupported):
        profile.apply_worker_profile(approved_object_policy=failure != "policy")
    assert calls == []


def test_apply_installs_once(monkeypatch, ready_profile):
    calls = []
    monkeypatch.setattr(profile, "_install_seccomp", lambda: calls.append(True))

    assert profile.apply_worker_profile(approved_object_policy=True) == (
        profile.ProfileStatus(True, profile.APPARMOR_LABEL, True)
    )
    assert calls == [True]


def test_apply_converts_install_error(monkeypatch, ready_profile):
    calls = []

    def failed_install():
        calls.append(True)
        raise OSError(errno.EPERM, "seccomp unavailable")

    monkeypatch.setattr(profile, "_install_seccomp", failed_install)
    with pytest.raises(profile.ProfileUnsupported) as exc:
        profile.apply_worker_profile(approved_object_policy=True)
    assert isinstance(exc.value.__cause__, OSError)
    assert calls == [True]


@pytest.mark.parametrize("preserve", [(0, 1, 2, 3), (0, 0)])
def test_close_inherited_rejects_invalid_preserve(preserve):
    with pytest.raises(profile.ProfileUnsupported):
        profile._close_inherited(preserve)


def _fork_assert_success(check):
    pid = os.fork()
    if pid == 0:
        try:
            success = check()
        except BaseException:
            success = False
        os._exit(0 if success else 1)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0


def _replace_standard_channels():
    null_fd = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null_fd, fd)
    if null_fd not in (0, 1, 2):
        os.close(null_fd)


def test_close_inherited_closes_extra_file(tmp_path):
    path = tmp_path / "extra"
    path.write_bytes(b"extra")

    def check():
        _replace_standard_channels()
        file_fd = os.open(path, os.O_RDONLY)
        os.dup2(file_fd, 200)
        if file_fd != 200:
            os.close(file_fd)
        profile._close_inherited((0, 1, 2))
        try:
            os.fstat(200)
        except OSError as error:
            return error.errno == errno.EBADF
        return False

    _fork_assert_success(check)


def test_close_inherited_rejects_regular_standard_channel(tmp_path):
    path = tmp_path / "channel"
    path.write_bytes(b"not a pipe")

    def check():
        _replace_standard_channels()
        file_fd = os.open(path, os.O_RDONLY)
        os.dup2(file_fd, 0)
        os.close(file_fd)
        try:
            profile._close_inherited((0, 1, 2))
        except profile.ProfileUnsupported:
            return True
        return False

    _fork_assert_success(check)


def test_worker_identity_rejects_root_uid(monkeypatch):
    monkeypatch.setattr(profile.os, "getresuid", lambda: (0, 0, 0))
    assert profile._worker_identity() is False
