"""Ptrace lifecycle supervision for a CI worker."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import signal
import time

from .exec_supervisor import (
    CaptureError,
    encode_vector,
    environment_reason,
    read_initial_stack,
)

PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_EVENT_FORK = 1
PTRACE_EVENT_VFORK = 2
PTRACE_EVENT_CLONE = 3
PTRACE_EVENT_EXEC = 4
PTRACE_OPTIONS = 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x100000
WALL = 0x40000000

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p,
                         ctypes.c_void_p)
_LIBC.ptrace.restype = ctypes.c_long
_LIBC.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_ulong, ctypes.c_ulong)
_LIBC.prctl.restype = ctypes.c_int


def _ptrace(request: int, tid: int, data: int | ctypes.c_void_p = 0) -> int:
    ctypes.set_errno(0)
    result = _LIBC.ptrace(request, tid, None, data)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, f"ptrace({request}, {tid}): {os.strerror(error)}")
    return result


def _event_message(tid: int) -> int:
    value = ctypes.c_ulonglong()
    _ptrace(PTRACE_GETEVENTMSG, tid, ctypes.cast(ctypes.byref(value),
                                                ctypes.c_void_p))
    return value.value


def _status(tid: int) -> dict[str, str]:
    with open(f"/proc/{tid}/status", encoding="ascii") as stream:
        return dict(line.split(":", 1) for line in stream if ":" in line)


def _tgid(tid: int) -> int:
    return int(_status(tid)["Tgid"].strip())


def _sha256_exe(tid: int) -> str:
    digest = hashlib.sha256()
    with open(f"/proc/{tid}/exe", "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Supervisor:
    def __init__(self, argv, env, *, deadline_seconds, evidence,
                 worker_uid=None, worker_gid=None, baseline=None):
        if not argv or deadline_seconds <= 0:
            raise ValueError("argv must be nonempty and deadline positive")
        if (worker_uid is None) != (worker_gid is None):
            raise ValueError("uid and gid must be supplied together")
        self.argv = list(argv)
        self.env = dict(env)
        self.deadline_seconds = deadline_seconds
        self.evidence = evidence
        self.worker_uid = worker_uid
        self.worker_gid = worker_gid
        self.baseline = baseline
        self.seq = 0
        self.next_task_id = 0
        self.tasks: dict[int, dict] = {}
        self.reason: str | None = None
        self.root_pid: int | None = None
        self.root_exit: int | None = None
        self.root_termination: str | None = None
        self.unreaped = False

    def _record(self, kind: str, **fields) -> None:
        record = {"seq": self.seq, "type": kind, **fields}
        self.evidence.write((json.dumps(record, ensure_ascii=False) + "\n")
                            .encode("utf-8"))
        self.evidence.flush()
        self.seq += 1

    def _incomplete(self, reason: str) -> None:
        # A failed capture is never downgraded to a filesystem warning.
        if self.reason is None or reason == "trace_incomplete":
            self.reason = reason

    def _add_task(self, tid: int, parent_id: int | None,
                  tgid: int | None = None) -> dict:
        task = {"id": self.next_task_id, "parent_id": parent_id,
                "tgid": tgid, "captured": False}
        self.next_task_id += 1
        self.tasks[tid] = task
        return task

    def _child(self) -> None:
        try:
            _ptrace(PTRACE_TRACEME, 0)
            if self.worker_uid is not None:
                os.setgroups([])
                os.setresgid(self.worker_gid, self.worker_gid, self.worker_gid)
                os.setresuid(self.worker_uid, self.worker_uid, self.worker_uid)
                if _LIBC.prctl(38, 1, 0, 0, 0) != 0:
                    os._exit(97)
                credentials = _status(os.getpid())
                if (os.getresuid() != (self.worker_uid,) * 3
                        or os.getresgid() != (self.worker_gid,) * 3
                        or os.getgroups()
                        or any(int(credentials[key].strip(), 16) != 0
                               for key in ("CapEff", "CapPrm", "CapAmb"))):
                    os._exit(97)
            os.kill(os.getpid(), signal.SIGSTOP)
        except (OSError, ValueError, KeyError):
            os._exit(97)
        try:
            os.execve(self.argv[0], self.argv, self.env)
        except (OSError, ValueError):
            os._exit(98)
        os._exit(98)

    def _kill_all(self) -> None:
        for tid in tuple(self.tasks):
            try:
                os.kill(tid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                self._incomplete("trace_incomplete")

    def _capture_exec(self, tid: int) -> int:
        former_tid = _event_message(tid)
        if former_tid != tid:
            task = self.tasks.pop(former_tid, None)
            displaced = self.tasks.pop(tid, None)
            if displaced is not None:
                self._record("observation", tid=tid,
                             logical_task_id=displaced["id"],
                             detail="leader_replaced_by_exec",
                             former_tid=former_tid)
            if task is None:
                self._incomplete("trace_incomplete")
                return signal.SIGKILL
            self.tasks[tid] = task
        task = self.tasks.get(tid)
        if task is None:
            self._incomplete("trace_incomplete")
            return signal.SIGKILL
        try:
            # Nothing that might resume the tracee precedes this read.
            vectors = read_initial_stack(tid)
            status = _status(tid)
            record = {
                "logical_task_id": task["id"],
                "parent_id": task["parent_id"],
                "tid": tid,
                "tgid": int(status["Tgid"].strip()),
                "argv": encode_vector(vectors.argv),
                "env": encode_vector(vectors.envp),
                "effective_executable": os.readlink(f"/proc/{tid}/exe"),
                "executable_sha256": _sha256_exe(tid),
                "cwd_at_capture": os.readlink(f"/proc/{tid}/cwd"),
                "credentials": {
                    "Uid": [int(item) for item in status["Uid"].split()],
                    "Gid": [int(item) for item in status["Gid"].split()],
                    "CapEff": status["CapEff"].strip(),
                },
            }
            if self.baseline is not None:
                record["environment_reason"] = environment_reason(
                    vectors.envp, self.baseline)
        except (CaptureError, OSError, KeyError, ValueError) as error:
            self._record("capture_failed", tid=tid,
                         logical_task_id=task["id"], error=str(error))
            self._incomplete("trace_incomplete")
            self._kill_all()
            return signal.SIGKILL
        task["tgid"] = record["tgid"]
        task["captured"] = True
        self._record("exec", **record)
        return 0

    def _observe(self, tid: int, status: int) -> None:
        task = self.tasks.get(tid)
        event = status >> 16
        self._record("observation", tid=tid, wait_status=status,
                     ptrace_event=event,
                     logical_task_id=task["id"] if task else None)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            if os.WIFEXITED(status):
                code = os.WEXITSTATUS(status)
                termination = "exited"
                if code == 98 and task is not None and not task["captured"]:
                    self._record("exec_failed", tid=tid,
                                 logical_task_id=task["id"], exit=code)
                elif code == 97 and task is not None and not task["captured"]:
                    self._record("child_setup_failed", tid=tid,
                                 logical_task_id=task["id"], exit=code)
                    self._incomplete("trace_incomplete")
            else:
                code = 128 + os.WTERMSIG(status)
                termination = "signaled"
            if tid == self.root_pid:
                self.root_exit = code
                self.root_termination = termination
            self.tasks.pop(tid, None)
            return
        if not os.WIFSTOPPED(status):
            self._incomplete("trace_incomplete")
            return
        if task is None:
            self._incomplete("trace_incomplete")
            try:
                _ptrace(PTRACE_CONT, tid, signal.SIGKILL)
            except OSError:
                pass
            return
        deliver = 0
        try:
            if event in (PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK,
                         PTRACE_EVENT_CLONE):
                child_tid = _event_message(tid)
                child_tgid = _tgid(child_tid)
                parent_tgid = _tgid(tid)
                if child_tid in self.tasks:
                    raise RuntimeError("duplicate live tid")
                child = self._add_task(child_tid, task["id"], child_tgid)
                unknown = (event == PTRACE_EVENT_CLONE
                           and child_tgid != parent_tgid)
                self._record("task", tid=child_tid, tgid=child_tgid,
                             logical_task_id=child["id"],
                             parent_id=task["id"],
                             event=event, fs_sharing_unknown=unknown)
                if unknown:
                    self._incomplete("shared_fs_unsupported")
            elif event == PTRACE_EVENT_EXEC:
                deliver = self._capture_exec(tid)
            elif event == 0:
                stopped_signal = os.WSTOPSIG(status)
                # New tracees' synthetic SIGSTOP is not a worker signal.
                deliver = 0 if stopped_signal == signal.SIGSTOP else stopped_signal
            _ptrace(PTRACE_CONT, tid, deliver)
        except (OSError, RuntimeError, ValueError) as error:
            self._record("trace_error", tid=tid, error=str(error))
            self._incomplete("trace_incomplete")
            self._kill_all()
            try:
                _ptrace(PTRACE_CONT, tid, signal.SIGKILL)
            except OSError:
                pass

    def run(self) -> int:
        started = time.monotonic()
        pid = os.fork()
        if pid == 0:
            self._child()
            os._exit(97)
        self.root_pid = pid
        self._add_task(pid, None, pid)
        timed_out = False
        grace_end = None
        # The initial TRACEME stop must be consumed before setting options.
        _, initial = os.waitpid(pid, 0)
        self._record("observation", tid=pid, wait_status=initial,
                     ptrace_event=initial >> 16, logical_task_id=0)
        if os.WIFSTOPPED(initial):
            try:
                _ptrace(PTRACE_SETOPTIONS, pid, PTRACE_OPTIONS)
                _ptrace(PTRACE_CONT, pid)
            except OSError as error:
                self._record("trace_error", tid=pid, error=str(error))
                self._incomplete("trace_incomplete")
                self._kill_all()
                try:
                    _ptrace(PTRACE_CONT, pid, signal.SIGKILL)
                except OSError:
                    pass
        else:
            # Setup can fail before the deliberate SIGSTOP.
            if os.WIFEXITED(initial):
                self.root_exit = os.WEXITSTATUS(initial)
                self.root_termination = "exited"
                if self.root_exit == 97:
                    self._record("child_setup_failed", tid=pid, exit=97)
            elif os.WIFSIGNALED(initial):
                self.root_exit = 128 + os.WTERMSIG(initial)
                self.root_termination = "signaled"
            self.tasks.pop(pid, None)
            self._incomplete("trace_incomplete")

        while self.tasks:
            now = time.monotonic()
            if not timed_out and now - started >= self.deadline_seconds:
                timed_out = True
                grace_end = now + 5
                self._kill_all()
            if timed_out and now >= grace_end:
                self.unreaped = True
                break
            try:
                tid, status = os.waitpid(-1, WALL | os.WNOHANG)
            except ChildProcessError:
                self.unreaped = True
                self._incomplete("trace_incomplete")
                break
            except InterruptedError:
                continue
            if tid:
                self._observe(tid, status)
            else:
                time.sleep(0.01)

        if self.root_exit is None and not timed_out:
            self._incomplete("trace_incomplete")
        exit_code = 124 if timed_out else (
            self.root_exit if self.root_exit is not None else 1)
        self._record(
            "closing",
            sensor={"status": "incomplete" if self.reason else "complete",
                    "reason": self.reason, "collection_closed": True,
                    "tasks_reaped": not self.tasks and not self.unreaped},
            termination="timed_out" if timed_out else (
                self.root_termination or "signaled"),
            exit=exit_code,
        )
        return exit_code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument("--evidence-fd", type=int, required=True)
    parser.add_argument("--uid", type=int)
    parser.add_argument("--gid", type=int)
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    env = {}
    for entry in args.env:
        key, separator, value = entry.partition("=")
        if not separator or not key:
            parser.error("--env requires KEY=VALUE")
        env[key] = value
    with os.fdopen(os.dup(args.evidence_fd), "wb") as evidence:
        return Supervisor(command, env, deadline_seconds=args.deadline,
                          evidence=evidence, worker_uid=args.uid,
                          worker_gid=args.gid).run()


if __name__ == "__main__":
    raise SystemExit(main())
