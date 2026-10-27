"""Worker remote-memory exclusion for the pinned Linux x86-64 sandbox.

The AppArmor label identifies a separately consumer-pinned policy. The host
must install and approve that policy, including exec inheritance, file-use
and file-receive mediation. A label and a syscall filter alone do not prove
the policy's contents.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import stat
from dataclasses import dataclass

PROFILE_ID = "grade-no-remote-memory-v1"
APPARMOR_LABEL = "probity-grade-no-remote-memory-v1 (enforce)"
UNSUPPORTED = "sensor_configuration_unsupported"
BREACH = "trace_incomplete"
_ARCH = 0xC000003E
_X32 = 0x40000000
_NAMESPACE_FLAGS = 0x7E020080
_DENIED = (
    101, 310, 311, 434, 438, 304, 303, 47, 299, 46, 307,
    425, 426, 427, 321, 298, 323, 300, 308, 272, 435,
    165, 166, 155, 428, 429, 430, 431, 432, 433, 442,
)
_ERRNO = 0x00050000 | errno.EPERM
_KILL = 0x80000000
_ALLOW = 0x7FFF0000


class ProfileUnsupported(RuntimeError):
    """The worker cannot exec under the required kernel configuration."""


@dataclass(frozen=True)
class ProfileStatus:
    """Observed pre-exec enforcement state, not a worker attestation.

    Attributes:
        enforced: Whether the required policy was installed and probed.
        object_guard: Measured object-policy label, if present.
        descriptors_closed: Whether inherited non-channel FDs were closed.
    """

    enforced: bool
    object_guard: str | None = None
    descriptors_closed: bool = False


def report_profile(status: ProfileStatus | None, *, breach: bool = False) -> dict[str, object]:
    """Return producer evidence and its local refusal reason.

    Args:
        status: Result from trusted pre-exec worker setup.
        breach: A detected bypass or possible unobserved interference.

    Returns:
        Evidence fields; missing status never defaults to success.
    """
    enforced = status is not None and status.enforced
    return {"profile_id": PROFILE_ID, "status": "enforced" if enforced and not breach
            else "incomplete", "seccomp": bool(enforced),
            "object_guard": status.object_guard if status else None,
            "descriptors_closed": status.descriptors_closed if status else False,
            "reason": BREACH if breach else None if enforced else UNSUPPORTED}


def _instruction(code: int, k: int, jt: int = 0, jf: int = 0) -> tuple[int, int, int, int]:
    return code, jt, jf, k


def filter_instructions() -> tuple[tuple[int, int, int, int], ...]:
    """Build the x86-64 BPF filter, including x32 and namespace exclusions.

    Syscall numbers and offsets are Linux x86-64 ABI constants. The filter
    does not inspect pathname strings: an approved LSM must mediate
    process-memory objects, including aliases and already-open descriptors.
    """
    ins = [_instruction(0x20, 4), _instruction(0x15, _ARCH, 1),
           _instruction(0x06, _KILL), _instruction(0x20, 0),
           _instruction(0x45, _X32, 0, 1), _instruction(0x06, _KILL)]
    for number in _DENIED:
        ins.extend((_instruction(0x15, number, 0, 1), _instruction(0x06, _ERRNO)))
    ins.extend((_instruction(0x15, 56, 0, 3), _instruction(0x20, 16),
                _instruction(0x45, _NAMESPACE_FLAGS, 0, 1),
                _instruction(0x06, _ERRNO), _instruction(0x06, _ALLOW)))
    return tuple(ins)


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort),
                ("filter", ctypes.POINTER(_SockFilter))]


def _syscall(number: int, *args: object) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(ctypes.c_long(number), *args) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _install_seccomp() -> None:
    instructions = filter_instructions()
    array = (_SockFilter * len(instructions))(*(_SockFilter(*item) for item in instructions))
    program = _SockFprog(len(array), array)
    _syscall(157, ctypes.c_long(38), ctypes.c_long(1),
             ctypes.c_long(0), ctypes.c_long(0), ctypes.c_long(0))
    _syscall(317, ctypes.c_long(1), ctypes.c_long(0), ctypes.byref(program))


def _worker_identity() -> bool:
    uids, gids = os.getresuid(), os.getresgid()
    if uids[0] == 0 or len(set(uids)) != 1 or len(set(gids)) != 1 or os.getgroups():
        return False
    try:
        with open("/proc/self/status", encoding="ascii") as stream:
            lines = dict(line.split(":", 1) for line in stream if ":" in line)
        return all(int(lines[key].strip(), 16) == 0
                   for key in ("CapEff", "CapPrm", "CapAmb"))
    except (OSError, KeyError, ValueError):
        return False


def _apparmor_label() -> str | None:
    try:
        with open("/proc/self/attr/apparmor/current", encoding="ascii") as stream:
            return stream.read().strip()
    except (OSError, UnicodeError):
        return None


def _proc_mem_denied() -> bool:
    for flags in (os.O_RDONLY, os.O_RDWR):
        try:
            descriptor = os.open("/proc/self/mem", flags | os.O_CLOEXEC)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EPERM):
                continue
            return False
        else:
            os.close(descriptor)
            return False
    return True


def _close_inherited(preserve: tuple[int, ...]) -> None:
    if any(fd not in (0, 1, 2) for fd in preserve) or len(set(preserve)) != len(preserve):
        raise ProfileUnsupported("only checked standard channels may survive exec")
    try:
        names = os.listdir("/proc/self/fd")
        null = os.stat("/dev/null")
        for name in names:
            fd = int(name)
            if fd in preserve:
                try:
                    info = os.fstat(fd)
                except OSError:
                    continue
                if stat.S_ISFIFO(info.st_mode) or (stat.S_ISCHR(info.st_mode)
                        and info.st_rdev == null.st_rdev):
                    continue
                raise ProfileUnsupported("preserved channel is not a pipe or /dev/null")
            try:
                os.close(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    except (OSError, ValueError) as error:
        raise ProfileUnsupported("cannot reconcile inherited descriptors") from error


def apply_worker_profile(*, approved_object_policy: bool = False,
                         preserve_fds: tuple[int, ...] = (0, 1, 2)) -> ProfileStatus:
    """Install worker restrictions immediately before exec, after credential drop.

    Args:
        approved_object_policy: Trusted supervisor's consumer-pinned confirmation
            that the exact AppArmor policy mediates inode aliases, proc-memory
            use, file_receive, and ix (not ux/px) exec transitions for the run.
            Do not obtain this value from worker data or infer it from the label.
        preserve_fds: Standard I/O channels; only pipes and /dev/null survive.

    Returns:
        Measured status for the evidence stream.

    Raises:
        ProfileUnsupported: A prerequisite is absent. The caller must refuse
            the launch with sensor_configuration_unsupported, not exec anyway.
    """
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ProfileUnsupported(UNSUPPORTED)
    if not approved_object_policy or _apparmor_label() != APPARMOR_LABEL:
        raise ProfileUnsupported(UNSUPPORTED)
    if not _worker_identity() or not _proc_mem_denied():
        raise ProfileUnsupported(UNSUPPORTED)
    _close_inherited(preserve_fds)
    try:
        _install_seccomp()
    except OSError as error:
        raise ProfileUnsupported(UNSUPPORTED) from error
    return ProfileStatus(True, APPARMOR_LABEL, True)
