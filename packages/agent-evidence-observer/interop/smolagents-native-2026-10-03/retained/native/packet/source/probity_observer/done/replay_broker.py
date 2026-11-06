"""Verifier-owned, journaled launches of sealed CI worker templates."""
from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import select
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Mapping


_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)
_STDERR_CAP = 1024 * 1024


class BrokerError(Exception):
    """A protocol error identified by its short code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Template:
    template_id: str
    argv: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    deadline_seconds: float
    max_children: int
    max_read: int = 65536
    max_write: int = 1_048_576


@dataclass(frozen=True)
class ChildResult:
    child_run_id: str
    termination: str
    exit: int
    sensor_status: str
    sensor_reason: str | None
    evidence: tuple[bytes, ...]


@dataclass
class _Child:
    template: Template
    process: subprocess.Popen[bytes]
    evidence_fd: int
    evidence: list[bytes] = field(default_factory=list)
    stderr: bytearray = field(default_factory=bytearray)
    stop_readers: threading.Event = field(default_factory=threading.Event)
    readers: list[threading.Thread] = field(default_factory=list)
    input_lock: threading.Lock = field(default_factory=threading.Lock)
    close_lock: threading.Lock = field(default_factory=threading.Lock)
    started: float = field(default_factory=time.monotonic)
    closing: bool = False
    result: ChildResult | None = None


class Broker:
    def __init__(
        self,
        templates: Mapping[str, Template],
        journal_path: pathlib.Path,
        *,
        supervisor_command: tuple[str, ...] = (
            sys.executable, "-m", "probity_observer.sensors.supervisor"
        ),
    ):
        self._templates = dict(templates)
        for key, template in self._templates.items():
            if (
                not isinstance(key, str)
                or not isinstance(template, Template)
                or key != template.template_id
                or not isinstance(template.argv, tuple)
                or not template.argv
                or any(not isinstance(arg, str) or "\0" in arg
                       for arg in template.argv)
                or not isinstance(template.env, tuple)
                or any(
                    not isinstance(entry, tuple)
                    or len(entry) != 2
                    or not isinstance(entry[0], str)
                    or not entry[0]
                    or "=" in entry[0]
                    or "\0" in entry[0]
                    or not isinstance(entry[1], str)
                    or "\0" in entry[1]
                    for entry in template.env
                )
                or isinstance(template.deadline_seconds, bool)
                or not isinstance(template.deadline_seconds, (int, float))
                or not math.isfinite(template.deadline_seconds)
                or template.deadline_seconds <= 0
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < minimum
                    for value, minimum in (
                        (template.max_children, 0),
                        (template.max_read, 1),
                        (template.max_write, 1),
                    )
                )
            ):
                raise ValueError("invalid sealed template")
        if (
            not isinstance(supervisor_command, tuple)
            or not supervisor_command
            or any(not isinstance(arg, str) or "\0" in arg
                   for arg in supervisor_command)
        ):
            raise ValueError("invalid supervisor command")
        self._supervisor_command = supervisor_command
        self._journal_path = pathlib.Path(journal_path)
        self._lock = threading.RLock()
        self._children: dict[str, _Child] = {}
        self._requests: dict[str, str] = {}
        self._counts = {key: 0 for key in self._templates}
        self._next_child = 0
        # The journal, rather than a parent's inventory, supplies sequence
        # numbers even when this broker appends to an existing file.
        records = self.ledger()
        self._seq = max((record["seq"] for record in records), default=-1) + 1

    def _append(self, event: str, **fields: object) -> None:
        record = {"seq": self._seq, "event": event, **fields}
        encoded = (json.dumps(record, ensure_ascii=False, separators=(",", ":"))
                   + "\n").encode("utf-8")
        with self._journal_path.open("ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self._seq += 1

    def ledger(self) -> list[dict]:
        with self._lock:
            try:
                with self._journal_path.open("rb") as stream:
                    return [json.loads(line) for line in stream]
            except FileNotFoundError:
                return []

    def reconcile(self) -> list[str]:
        problems: list[str] = []
        launched: set[str] = set()
        finished: set[str] = set()
        for expected, record in enumerate(self.ledger()):
            if type(record.get("seq")) is not int or record["seq"] != expected:
                problems.append(f"non-contiguous seq at record {expected}")
            child_id = record.get("child_run_id")
            if record.get("event") == "launch":
                if child_id in launched:
                    problems.append(f"duplicate child id: {child_id}")
                launched.add(child_id)
            elif record.get("event") == "finish":
                if child_id not in launched:
                    problems.append(f"finish with no launch: {child_id}")
                if child_id in finished:
                    problems.append(f"duplicate child id: {child_id}")
                finished.add(child_id)
        problems.extend(
            f"launch with no finish: {child_id}"
            for child_id in sorted(launched - finished)
        )
        return problems

    def start(self, template_id: str, request_id: str) -> str:
        if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
            raise BrokerError("bad_request_id")
        with self._lock:
            if request_id in self._requests:
                return self._requests[request_id]
            if not isinstance(template_id, str) or template_id not in self._templates:
                raise BrokerError("unknown_template")
            template = self._templates[template_id]
            if self._counts[template_id] >= template.max_children:
                self._append(
                    "refused", template_id=template_id, request_id=request_id,
                    reason="quota_exceeded",
                )
                raise BrokerError("quota_exceeded")

            self._next_child += 1
            child_id = f"c{self._next_child:08d}{secrets.token_hex(4)}"
            # Both the reservation and its durable record precede Popen.
            self._append(
                "launch", child_run_id=child_id, template_id=template_id,
                request_id=request_id,
            )
            self._requests[request_id] = child_id
            read_fd, write_fd = os.pipe()
            command = (
                *self._supervisor_command,
                "--deadline", str(template.deadline_seconds),
                "--evidence-fd", str(write_fd),
                *(item for key, value in template.env
                  for item in ("--env", f"{key}={value}")),
                "--", *template.argv,
            )
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(write_fd,),
                    close_fds=True,
                    start_new_session=True,
                    bufsize=0,
                )
            except (OSError, ValueError) as error:
                os.close(read_fd)
                os.close(write_fd)
                raise BrokerError("launch_failed") from error
            os.close(write_fd)
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            child = _Child(template, process, read_fd)
            self._children[child_id] = child
            self._counts[template_id] += 1
            for name, target in (
                ("evidence", lambda: self._drain_evidence(child)),
                ("stderr", lambda: self._drain_stderr(child)),
            ):
                thread = threading.Thread(
                    target=target, name=f"broker-{name}-{child_id}", daemon=True
                )
                child.readers.append(thread)
                thread.start()
            return child_id

    @staticmethod
    def _drain_evidence(child: _Child) -> None:
        pending = bytearray()
        try:
            while True:
                ready, _, _ = select.select(
                    [child.evidence_fd], [], [],
                    0 if child.stop_readers.is_set() else 0.1,
                )
                if not ready:
                    if child.stop_readers.is_set():
                        break
                    continue
                chunk = os.read(child.evidence_fd, 65536)
                if not chunk:
                    break
                pending.extend(chunk)
                while (newline := pending.find(b"\n")) >= 0:
                    child.evidence.append(bytes(pending[:newline + 1]))
                    del pending[:newline + 1]
        finally:
            if pending:
                child.evidence.append(bytes(pending))
            os.close(child.evidence_fd)

    @staticmethod
    def _drain_stderr(child: _Child) -> None:
        assert child.process.stderr is not None
        stream = child.process.stderr
        try:
            while True:
                ready, _, _ = select.select(
                    [stream.fileno()], [], [],
                    0 if child.stop_readers.is_set() else 0.1,
                )
                if not ready:
                    if child.stop_readers.is_set():
                        break
                    continue
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    break
                remaining = _STDERR_CAP - len(child.stderr)
                if remaining > 0:
                    child.stderr.extend(chunk[:remaining])
        finally:
            stream.close()

    def _child(self, child_run_id: str) -> _Child:
        with self._lock:
            if not isinstance(child_run_id, str):
                raise BrokerError("unknown_child")
            try:
                return self._children[child_run_id]
            except KeyError:
                raise BrokerError("unknown_child") from None

    def write(self, child_run_id: str, data: bytes) -> int:
        child = self._child(child_run_id)
        if not isinstance(data, bytes) or len(data) > child.template.max_write:
            raise BrokerError("oversize_write")
        with child.input_lock:
            if child.closing:
                raise BrokerError("closed_child")
            assert child.process.stdin is not None
            fd = child.process.stdin.fileno()
            os.set_blocking(fd, False)
            written = 0
            end = child.started + child.template.deadline_seconds + 10
            try:
                while written < len(data):
                    if child.closing:
                        raise BrokerError("closed_child")
                    remaining = end - time.monotonic()
                    if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                        raise BrokerError("closed_child")
                    try:
                        written += os.write(fd, data[written:])
                    except BlockingIOError:
                        continue
            except (BrokenPipeError, OSError) as error:
                raise BrokerError("closed_child") from error
            return written

    def read(self, child_run_id: str, limit: int) -> bytes:
        child = self._child(child_run_id)
        if (
            type(limit) is not int or limit < 1
            or limit > child.template.max_read
        ):
            raise BrokerError("oversize_read")
        if child.closing:
            raise BrokerError("closed_child")
        assert child.process.stdout is not None
        try:
            return os.read(child.process.stdout.fileno(), limit)
        except OSError as error:
            raise BrokerError("closed_child") from error

    def close(self, child_run_id: str) -> ChildResult:
        child = self._child(child_run_id)
        with child.close_lock:
            if child.result is not None:
                return child.result
            child.closing = True
            with child.input_lock:
                assert child.process.stdin is not None
                child.process.stdin.close()
            watchdog = False
            remaining = max(
                0.0,
                child.started + child.template.deadline_seconds + 10
                - time.monotonic(),
            )
            try:
                child.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                watchdog = True
                try:
                    os.killpg(child.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.process.wait(timeout=2)
            child.stop_readers.set()
            for thread in child.readers:
                thread.join(timeout=2)

            evidence = tuple(child.evidence)
            closing = None
            for line in reversed(evidence):
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(record, dict) and record.get("type") == "closing":
                    closing = record
                    break
            if watchdog:
                termination, exit_code = "watchdog_killed", 137
                status, reason = "incomplete", "watchdog_killed"
            elif (
                closing is not None
                and isinstance(closing.get("termination"), str)
                and type(closing.get("exit")) is int
                and isinstance(closing.get("sensor"), dict)
                and closing["sensor"].get("status") in ("complete", "incomplete")
                and all(not thread.is_alive() for thread in child.readers)
            ):
                termination = closing["termination"]
                exit_code = closing["exit"]
                status = closing["sensor"]["status"]
                reason = closing["sensor"].get("reason")
            else:
                termination = "signaled" if child.process.returncode < 0 else "exited"
                exit_code = child.process.returncode
                status, reason = "incomplete", "missing_closing"
            result = ChildResult(
                child_run_id, termination, exit_code, status, reason, evidence
            )
            with self._lock:
                self._append(
                    "finish", child_run_id=child_run_id,
                    termination=termination, exit=exit_code,
                    sensor_status=status,
                    evidence_sha256=hashlib.sha256(b"".join(evidence)).hexdigest(),
                    evidence_lines=len(evidence),
                )
                child.result = result
            return result
