"""Stopped-exec initial-vector capture primitives for Linux x86-64."""
from __future__ import annotations

import base64
import ctypes
import os
import platform
from dataclasses import dataclass

PTRACE_GETREGS = 12
MAX_ITEMS = 131072
MAX_BYTES = 16 * 1024 * 1024
_REGISTER_NAMES = ("r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8",
                   "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags",
                   "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs")


class CaptureError(RuntimeError):
    """Initial-stack capture failed; this exec must not be resumed as covered."""


class _Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in _REGISTER_NAMES]


_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
_LIBC.ptrace.restype = ctypes.c_long


def _registers(tid: int) -> _Registers:
    regs = _Registers()
    ctypes.set_errno(0)
    result = _LIBC.ptrace(PTRACE_GETREGS, tid, None, ctypes.cast(ctypes.byref(regs),
                                                                 ctypes.c_void_p))
    if result == -1:
        raise CaptureError(f"PTRACE_GETREGS: {os.strerror(ctypes.get_errno())}")
    return regs


def _read(fd: int, address: int, size: int) -> bytes:
    try:
        data = os.pread(fd, size, address)
    except (OSError, OverflowError) as error:
        raise CaptureError(f"initial stack inaccessible: {error}") from error
    if len(data) != size:
        raise CaptureError("short initial-stack read")
    return data


def _word(fd: int, address: int) -> int:
    return int.from_bytes(_read(fd, address, 8), "little")


def _string(fd: int, address: int, remaining: int) -> bytes:
    value = bytearray()
    while len(value) < remaining:
        # Do not cross a page boundary: the following page need not be mapped.
        size = min(4096 - (address % 4096), remaining - len(value))
        chunk = _read(fd, address, size)
        if b"\0" in chunk:
            value.extend(chunk.split(b"\0", 1)[0])
            return bytes(value)
        value.extend(chunk)
        address += size
    raise CaptureError("unterminated initial-stack string")


@dataclass(frozen=True)
class InitialVectors:
    """Complete ordered initial vectors from a stopped successful exec."""

    argv: tuple[bytes, ...]
    envp: tuple[bytes, ...]


def read_initial_stack(tid: int) -> InitialVectors:
    """Read a stopped Linux x86-64 exec image, before PTRACE_CONT.

    Args:
        tid: TID stopped at PTRACE_EVENT_EXEC, not a syscall-entry stop.

    Raises:
        CaptureError: ABI, memory access or vector bounds prevent full capture.
    """
    if os.name != "posix" or platform.machine() != "x86_64":
        raise CaptureError("sensor_configuration_unsupported")
    rsp = _registers(tid).rsp
    try:
        fd = os.open(f"/proc/{tid}/mem", os.O_RDONLY | os.O_CLOEXEC)
    except OSError as error:
        raise CaptureError(f"initial stack inaccessible: {error}") from error
    try:
        argc = _word(fd, rsp)
        if argc > MAX_ITEMS:
            raise CaptureError("argv pointer count exceeds limit")
        cursor = rsp + 8
        vectors: list[list[bytes]] = [[], []]
        remaining = MAX_BYTES
        for index in range(2):
            while True:
                pointer = _word(fd, cursor)
                cursor += 8
                if pointer == 0:
                    break
                if len(vectors[index]) >= MAX_ITEMS:
                    raise CaptureError("initial vector exceeds item limit")
                value = _string(fd, pointer, remaining)
                remaining -= len(value) + 1
                if remaining <= 0:
                    raise CaptureError("initial vectors exceed byte limit")
                vectors[index].append(value)
        if len(vectors[0]) != argc:
            raise CaptureError("argc disagrees with initial argv")
        return InitialVectors(tuple(vectors[0]), tuple(vectors[1]))
    finally:
        os.close(fd)


def encode_vector(items: tuple[bytes, ...]) -> dict[str, object]:
    """Encode strings without byte replacement or surrogate normalization."""
    try:
        return {"encoding": "utf8", "items": [item.decode("utf-8") for item in items]}
    except UnicodeDecodeError:
        return {"encoding": "base64",
                "items": [base64.b64encode(item).decode("ascii") for item in items]}


def environment_reason(envp: tuple[bytes, ...], baseline: dict[str, str],
                       admit: dict[str, str] | None = None) -> str | None:
    """Return the first E.2 refusal reason, or None for an exact environment."""
    found: dict[bytes, bytes] = {}
    for item in envp:
        if b"\0" in item or b"=" not in item:
            return "launch_environment_invalid"
        key, value = item.split(b"=", 1)
        if not key or key in found:
            return "launch_environment_invalid"
        found[key] = value
    required = {key.encode(): value.encode() for key, value in baseline.items()}
    required.update({key.encode(): value.encode() for key, value in (admit or {}).items()})
    if any(key.startswith(b"LD_") and key not in required for key in found):
        return "loader_injection"
    return None if found == required else "launch_environment_changed"
