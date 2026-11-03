"""The open guard runtime: one `python -I -S` child per guard (per batch shard), resource limits only.

THIS IS NOT AN ISOLATION BOUNDARY. The child runs with an empty environment, `/` as its working directory
and RLIMIT_CPU, RLIMIT_AS, NPROC=0, FSIZE=0 and CORE=0, under a CPU-time alarm and a parent wall clock. It
has no network namespace, no syscall filter and no filesystem ruleset: a guard can read any file the user
can and open sockets. It exists so the public engine runs, replays and verifies guards with the same
decisions an enforcing runtime gives a well-behaved guard. It provides the layer `rlimits` and nothing
else, and it refuses to start when `GuardLimits.require` names any other layer, so a caller that demands
isolation gets the refusal, never a silent downgrade. Install an enforcing runtime under the
`ratchet.guards` entry-point group to get isolation (`ratchet.agent.guard_api`).

The child's code is read once, when this module is imported (`CHILD_SOURCE`), so a parent and its children
always speak one protocol version.

Decisions follow `guard_api`: a guard that does not compile, does not define `check`, raises, returns a
non-string, runs past its time limit or kills its process gets a fail-closed `guard_error`. Two clocks keep
machine load out of guard verdicts: before the child's start marker the item is in transport
(`transport_timeout_s`, `startup_timeout_s`), and a failure there is an `infrastructure_error`, retried
once on a fresh child and then raised; after the marker the guard has `call_timeout_s` of CPU time and
`call_timeout_s + guard_wall_grace_s` of wall time.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import TracebackType
from typing import Any

from ratchet_cases.types import Event, ToolCall

from ratchet.agent.guard_api import (
    GuardDecision,
    GuardInfrastructureError,
    GuardItem,
    GuardLimits,
    GuardSourceError,
    SandboxUnavailableError,
    compile_guard,
    error_decision,
    infrastructure_decision,
)
from ratchet.types import Guard

PROVIDES = ("rlimits",)
CHILD_PATH = Path(__file__).with_name("_guard_open_child.py")
CHILD_SOURCE = CHILD_PATH.read_text(encoding="utf-8")


class _ChildDiedError(Exception):
    pass


class OpenGuardProcess:
    """One child running one guard: one request line and its replies at a time, with hard deadlines."""

    def __init__(self, guard: Guard, limits: GuardLimits) -> None:
        self.guard = guard
        self.limits = limits
        self.isolation: dict[str, str] = {}
        self._buffer = b""
        self._sent: list[Event] = []
        self._next = 0
        self._proc = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", CHILD_SOURCE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={},
            cwd="/",
            close_fds=True,
            start_new_session=True,
        )
        try:
            self._start()
        except BaseException:
            self.close()
            raise

    @property
    def guard_bound(self) -> float:
        return self.limits.call_timeout_s + self.limits.guard_wall_grace_s

    def _start(self) -> None:
        setup = {
            "source": self.guard.source,
            "cpu_s": self.limits.cpu_s,
            "memory_mb": self.limits.memory_mb,
            "timeout_s": self.limits.call_timeout_s,
            "require": list(self.limits.require),
        }
        try:
            self._write(setup, time.monotonic() + self.limits.transport_timeout_s)
            reply = self._read(time.monotonic() + self.limits.startup_timeout_s)
        except (TimeoutError, _ChildDiedError, ValueError) as exc:
            raise GuardInfrastructureError(f"guard child failed to start: {exc}") from exc
        if reply.get("loading") is True:
            try:
                reply = self._read(time.monotonic() + self.guard_bound)
            except (TimeoutError, _ChildDiedError, ValueError) as exc:
                raise GuardSourceError(f"guard failed to load: {exc}") from exc
        isolation = reply.get("isolation")
        self.isolation = dict(isolation) if isinstance(isolation, dict) else {}
        if reply.get("ready") is True:
            return
        error = reply.get("error")
        if reply.get("ready") is not False or not isinstance(error, str) or not error.strip():
            excerpt = json.dumps(reply, sort_keys=True, default=str)[:300]
            raise GuardInfrastructureError(f"guard child sent an out-of-protocol startup reply: {excerpt}")
        if error.startswith("isolation unavailable"):
            raise SandboxUnavailableError(f"{error}; layers: {self.isolation}")
        raise GuardSourceError(error)

    @property
    def alive(self) -> bool:
        return self._proc.poll() is None

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.kill()
        self._proc.wait()
        for stream in (self._proc.stdin, self._proc.stdout):
            if stream is not None:
                stream.close()

    def _write(self, obj: Any, deadline: float) -> None:
        stdin = self._proc.stdin
        assert stdin is not None
        data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
        fd = stdin.fileno()
        os.set_blocking(fd, False)
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                raise TimeoutError("timeout")
            try:
                data = data[os.write(fd, data) :]
            except BrokenPipeError as exc:
                raise _ChildDiedError("guard process exited") from exc

    def _read(self, deadline: float) -> dict[str, Any]:
        stdout = self._proc.stdout
        assert stdout is not None
        fd = stdout.fileno()
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise TimeoutError("timeout")
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                raise _ChildDiedError(f"guard process exited with status {self._proc.wait()}")
            self._buffer += chunk
        line, self._buffer = self._buffer.split(b"\n", 1)
        reply = json.loads(line)
        if not isinstance(reply, dict):
            raise ValueError("guard process sent a malformed reply")
        return reply

    def _request(self, item: GuardItem, index: int) -> dict[str, Any]:
        sent, history = self._sent, item.history
        keep, limit = 0, min(len(sent), len(history))
        while keep < limit and sent[keep] is history[keep]:
            keep += 1
        add = list(history[keep:])
        self._sent = sent[:keep] + add
        call = item.call
        return {
            "i": index,
            "call": {"name": call.name, "args": call.args, "call_id": call.call_id},
            "view": item.view,
            "h_keep": keep,
            "h_add": [{"seq": e.seq, "kind": e.kind, "payload": e.payload, "ts": e.ts} for e in add],
        }

    def evaluate(self, item: GuardItem) -> GuardDecision:
        """Evaluate once. Raises nothing: every failure becomes a decision, and the child is closed."""
        guard_id = self.guard.id
        if not self.alive:
            return infrastructure_decision(guard_id, "guard process is not running")
        index = self._next
        self._next += 1
        try:
            deadline = time.monotonic() + self.limits.transport_timeout_s
            self._write(self._request(item, index), deadline)
            marker = self._read(deadline)
        except (TimeoutError, _ChildDiedError, ValueError) as exc:
            self.close()
            return infrastructure_decision(guard_id, f"{exc} before the guard started")
        started = time.monotonic()
        try:
            if marker.get("s") != index:
                raise ValueError("guard process sent a malformed reply")
            reply = self._read(started + self.guard_bound)
            if reply.get("i") != index:
                raise ValueError("guard process sent a malformed reply")
        except (TimeoutError, _ChildDiedError, ValueError) as exc:
            self.close()
            return error_decision(guard_id, str(exc), time.monotonic() - started)
        elapsed = float(reply.get("guard_s") or 0.0)
        if reply.get("error"):
            return error_decision(guard_id, str(reply["error"]), elapsed)
        block = reply.get("block")
        if block is None:
            return GuardDecision(guard_id, False, None, elapsed_s=elapsed)
        return GuardDecision(guard_id, True, str(block), elapsed_s=elapsed)


def _guard_key(guard: Guard) -> str:
    return guard.id + ":" + hashlib.sha256(guard.source.encode("utf-8")).hexdigest()


class OpenGuardRuntime:
    """The open `GuardRuntime` (module docstring). Refuses at construction when the limits require a layer
    other than `rlimits`."""

    def __init__(self, limits: GuardLimits | None = None, *, workers: int | None = None) -> None:
        self.limits = limits or GuardLimits()
        missing = [x for x in self.limits.require if x not in PROVIDES]
        if missing:
            raise SandboxUnavailableError(
                f"the open guard runtime provides only {', '.join(PROVIDES)} and is not an isolation "
                f"boundary; the limits require {', '.join(missing)}. Install a guard runtime that provides "
                "them under the ratchet.guards entry-point group, or stop requiring them"
            )
        self.workers = max(1, workers or (os.cpu_count() or 1))
        self._live: dict[str, OpenGuardProcess] = {}
        self._rejected: dict[str, str] = {}

    def __enter__(self) -> OpenGuardRuntime:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()

    def close(self) -> None:
        for proc in self._live.values():
            proc.close()
        self._live.clear()

    def validate(self, guard: Guard) -> dict[str, str]:
        compile_guard(guard.source)
        proc = OpenGuardProcess(guard, self.limits)
        try:
            return dict(proc.isolation)
        finally:
            proc.close()

    def _process(self, guard: Guard) -> OpenGuardProcess | str:
        key = _guard_key(guard)
        if key in self._rejected:
            return self._rejected[key]
        proc = self._live.get(key)
        if proc is not None and proc.alive:
            return proc
        try:
            compile_guard(guard.source)
            proc = OpenGuardProcess(guard, self.limits)
        except GuardSourceError as exc:
            self._rejected[key] = str(exc)
            return str(exc)
        self._live[key] = proc
        return proc

    def check(
        self, guard: Guard, call: ToolCall, view: Mapping[str, Any], history: Sequence[Event]
    ) -> GuardDecision:
        decision: GuardDecision | None = None
        for _ in range(2):
            proc = self._process(guard)
            if isinstance(proc, str):
                return error_decision(guard.id, proc)
            decision = proc.evaluate(GuardItem(guard, call, view, history))
            if decision.kind != "infrastructure_error":
                return decision
        assert decision is not None
        raise GuardInfrastructureError(f"guard {guard.id}: {decision.error}", [decision])

    def check_all(
        self, guards: Iterable[Guard], call: ToolCall, view: Mapping[str, Any], history: Sequence[Event]
    ) -> list[GuardDecision]:
        return [self.check(g, call, view, history) for g in guards]

    def _run_shard(self, items: Sequence[GuardItem], shard: list[int], results: list[Any]) -> None:
        guard = items[shard[0]].guard
        pending, retried = list(shard), False
        while pending:
            try:
                compile_guard(guard.source)
                proc = OpenGuardProcess(guard, self.limits)
            except GuardSourceError as exc:
                for index in pending:
                    results[index] = error_decision(guard.id, str(exc))
                return
            except GuardInfrastructureError as exc:
                for index in pending:
                    results[index] = infrastructure_decision(guard.id, str(exc))
                return
            try:
                while pending:
                    decision = proc.evaluate(items[pending[0]])
                    if decision.kind == "infrastructure_error" and not retried:
                        retried = True  # one more try on a fresh child before it counts
                        break
                    results[pending.pop(0)] = decision
                    retried = False
                    if not proc.alive:
                        break
            finally:
                proc.close()

    def batch(self, items: Sequence[GuardItem]) -> list[GuardDecision]:
        """Items for one guard are split into up to `workers` shards, each on its own child, run
        concurrently. Raises `GuardInfrastructureError` with every decision when any item still failed in
        the runtime after one retry."""
        by_guard: dict[str, list[int]] = {}
        for index, item in enumerate(items):
            by_guard.setdefault(_guard_key(item.guard), []).append(index)
        total = len(items)
        shards: list[list[int]] = []
        for indices in by_guard.values():
            count = max(1, min(self.workers, round(self.workers * len(indices) / max(total, 1))))
            size = -(-len(indices) // count)
            shards.extend(indices[i : i + size] for i in range(0, len(indices), size))
        results: list[GuardDecision | None] = [None] * total
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for future in [pool.submit(self._run_shard, items, shard, results) for shard in shards]:
                future.result()
        done = [r for r in results if r is not None]
        assert len(done) == total
        failed = [d for d in done if d.kind == "infrastructure_error"]
        if failed:
            raise GuardInfrastructureError(
                f"{len(failed)} of {total} guard evaluations failed in the runtime, not in the guard: "
                f"{failed[0].error}",
                done,
            )
        return done
