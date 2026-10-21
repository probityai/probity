"""Parent-compare replay: the sealed test runs in a trusted process, the candidate in a child.

A LiveCodeBench-shaped test asserts on ``candidate(...)``. Running it next to the agent's code
lets that code see the test: its caller frame, its globals, its source file, a counter across
calls. Here the SEALED test script (the contract's copy, never the agent's ``test.py``) runs in
a separate trusted process with ``candidate`` replaced by a proxy. Each call crosses to an
isolated child that holds only the agent's module: its arguments go over as type-tagged
canonical text and its result comes back the same way, so only plain data ever reaches the
assertions, and the candidate's own ``__eq__`` never runs where the test compares.

The parent then holds the purity invariant: every answer on one argument key must be
identical, and each distinct call is run again in a fresh child, in an order seeded from the
grader and recorded, and must give the same answer. On a conflicting task the input the visible
test asserts with two values therefore fails whatever the candidate does.

Three held-out probes run the same way, each as its own acceptance command (the request's
``mode``): ``determinism`` (every case twice in one child and once in a fresh one, each run
with its own time budget), ``type_strict`` (the result's builtin type must be the expected
value's, recursively) and ``import_side_effects`` (importing the module must leave
``builtins`` unchanged). In every mode the comparison and the result file are the parent's.
The ``pytest`` mode (:mod:`.pytest_replay`) runs sealed pytest ids the same way: the sealed
test files under pytest here, the candidate's modules served by a child.

Run as ``python -I -m probity_observer.done.replay <request.json>``; the result is written to
the request's ``out`` path. Exit 0 when every assertion and the invariant hold, 1 otherwise.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import random
import runpy
import select
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

COMMAND = "probity-done-replay"
TERMINATED_EXIT = 143


class Unplain(TypeError):
    """A value that is not plain data cannot cross the proxy."""


def plain(value: Any) -> Any:
    """A type-tagged JSON form of plain data; the tag keeps every builtin type, so ``1``,
    ``1.0`` and ``True`` stay three different values across the proxy."""
    kind = type(value)
    if value is None:
        return ["none"]
    if kind is bool:
        return ["bool", value]
    if kind is int:
        return ["int", str(value)]
    if kind is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise TypeError("non-finite float")
        return ["float", repr(value)]
    if kind is str:
        return ["str", value]
    if kind is bytes:
        return ["bytes", value.hex()]
    if kind is list or kind is tuple:
        return [kind.__name__, [plain(item) for item in value]]
    if kind is set or kind is frozenset:
        return [kind.__name__, sorted((plain(item) for item in value), key=json.dumps)]
    if kind is dict:
        return ["dict", sorted(([plain(key), plain(item)] for key, item in value.items()),
                               key=json.dumps)]
    raise TypeError("not plain data: " + kind.__name__)


def unplain(tagged: Any) -> Any:
    """The value a :func:`plain` form stands for. Only a form :func:`plain` writes is read:
    a payload of another type (``["bool", "false"]``), a number not in its canonical text,
    or a float that is not finite is refused, so the codec's two halves agree."""
    if type(tagged) is not list or not tagged:
        raise TypeError("not a tagged value")
    tag = tagged[0]
    if tag == "none" and len(tagged) == 1:
        return None
    if len(tagged) != 2:
        raise TypeError("not a tagged value")
    body = tagged[1]
    kind = type(body)
    if tag == "bool" and kind is bool:
        return body
    if tag == "int" and kind is str and str(int(body)) == body:
        return int(body)
    if tag == "float" and kind is str:
        number = float(body)
        if number == number and number not in (float("inf"), float("-inf")) and repr(
                number) == body:
            return number
    if tag == "str" and kind is str:
        return body
    if tag == "bytes" and kind is str and bytes.fromhex(body).hex() == body:
        return bytes.fromhex(body)
    if tag in ("list", "tuple", "set", "frozenset") and kind is list:
        items = [unplain(item) for item in body]
        return {"list": list, "tuple": tuple, "set": set, "frozenset": frozenset}[tag](items)
    if tag == "dict" and kind is list and all(type(pair) is list and len(pair) == 2
                                              for pair in body):
        return {unplain(key): unplain(item) for key, item in body}
    raise TypeError("not a plain form: " + str(tag))


def canon(value: Any) -> str:
    return json.dumps(plain(value), separators=(",", ":"), ensure_ascii=True)


CHILD_LOOP = '''
def _serve(codec_source, module, entry, probe_import):
    # Everything the child needs is local to this call: the module under test finds nothing
    # of the protocol in __main__ (no writer, no snapshot helper, no codec) to rebind.
    import builtins, copy, importlib, json, os, sys
    codec = {}
    exec(codec_source, codec)
    plain, unplain = codec["plain"], codec["unplain"]
    proto = os.fdopen(os.dup(1), "w")
    os.dup2(2, 1)
    sys.path.insert(0, os.getcwd())
    names, kinds, idents, ordered, dumps = vars, type, id, sorted, json.dumps
    def snapshot():
        return ordered([name, kinds(value).__name__, idents(value)]
                       for name, value in names(builtins).items())
    def send(message):
        proto.write(dumps(message) + "\\n")
        proto.flush()
    if probe_import:
        send({"builtins": snapshot()})
    failure = None
    try:
        function = getattr(importlib.import_module(module), entry)
    except BaseException as error:
        function, failure = None, type(error).__name__
    if probe_import:
        send({"builtins": snapshot()})
    for line in sys.stdin:
        request = json.loads(line)
        if function is None:
            reply = {"error": "import:" + failure}
        else:
            try:
                args, kwargs = unplain(request["args"]), unplain(request["kwargs"])
                value = function(*copy.deepcopy(args), **copy.deepcopy(kwargs))
            except BaseException as error:
                reply = {"error": type(error).__name__}
            else:
                # A result that is not plain data is the codec's refusal, never the candidate's
                # own exception: the two read differently on the twin rule.
                try:
                    reply = {"ok": plain(value)}
                except BaseException:
                    reply = {"error": "unplain"}
        send(reply)
'''


def child_source(module: str, entry: str, probe_import: bool = False) -> str:
    """The child program: a loop that answers one call per line, with the codec kept out of
    ``__main__``.

    With ``probe_import`` the child first writes the names, types and identities in
    ``builtins`` before and after it imports the module, the first line before any of the
    module's code has run. The helpers that write those lines are local to the child's loop,
    so the module cannot rebind them through ``__main__``; it can still write to the protocol
    descriptor itself, which is why the parent compares only what the child reports and an
    import probe is evidence, never the whole check.
    """
    if not module.isidentifier() or not entry.isidentifier():
        raise ValueError("module and entry must be identifiers")
    codec = ("from __future__ import annotations\nimport json\nfrom typing import Any\n"
             + inspect.getsource(plain) + inspect.getsource(unplain))
    return (CHILD_LOOP + f"_serve({codec!r}, {module!r}, {entry!r}, {probe_import!r})\n")


class CandidateFailed(AssertionError):
    """The candidate raised, timed out or returned something that is not plain data."""


STARTED: list["Child"] = []
# The file the parent appends each child's pid and start time to, for the runner's backstop
# (:func:`kill_recorded`); ``None`` outside a parent the runner started.
CHILDREN: Path | None = None


def start_time(pid: int) -> str | None:
    """The kernel's start time of ``pid`` (``/proc/<pid>/stat`` field 22), or ``None`` when no
    such process exists: with the pid it names one process, never a later one given that pid."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    fields = stat.rsplit(")", 1)[-1].split()
    return fields[19] if len(fields) > 19 else None


def kill_recorded(path: Path) -> None:
    """End every child group a parent recorded in ``path`` that is still running: SIGTERM, then
    SIGKILL after :data:`CLOSE_GRACE`. A child whose start time no longer matches is gone.

    The runner's backstop for a parent it had to kill, or one that left a child behind: each
    child runs in its own session, out of reach of a signal to the parent's group."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return
    alive = []
    for line in lines:
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and start_time(int(parts[0])) == parts[1]:
            alive.append((int(parts[0]), parts[1]))
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, started in alive:
            if start_time(pid) == started:
                try:
                    os.killpg(pid, sig)
                except (ProcessLookupError, PermissionError):
                    pass
        ends = time.monotonic() + CLOSE_GRACE
        while any(start_time(pid) == started for pid, started in alive):
            if time.monotonic() >= ends:
                break
            time.sleep(0.05)

# The longest protocol line a child may write before its newline.
LINE_LIMIT = 1 << 24


class ClientFailure(dict):
    """A failure of the client itself: a time-out, an exited child, a broken pipe or a line
    that is not one reply. JSON never decodes to this type, so no line the child writes can
    pass for one."""

    def __init__(self, error: str) -> None:
        super().__init__(error=error)


# Client failures that mean the candidate gave no answer in time (a closed child answers every
# later call with ``child-pipes``): no answer, as opposed to a wrong one.
STALLS = frozenset({"child-timeout", "child-pipes"})


def stall(reply: Any) -> bool:
    return isinstance(reply, ClientFailure) and reply.get("error") in STALLS


# How long a child that was told to stop (its stdin closed, then SIGTERM) gets before the next
# step. A container runtime cleans up after itself only on an orderly exit.
CLOSE_GRACE = 5.0


class Child:
    """One isolated candidate process, answering calls in order.

    Use it as a context manager (``with Child(...) as child:``); every container spawn goes
    through this one class so that every one is ended the same way.

    The child starts in its own session, so its process group holds the whole tree the command
    starts: for ``apptainer exec`` that includes the ``squashfuse_ll`` daemon that serves the
    image. :meth:`close` ends it in order, closing stdin first (the call loop ends on EOF and
    the runtime unmounts and stops its daemon), then SIGTERM, then SIGKILL, each to the whole
    group, and last kills whatever is left in the group before reaping the leader. Killing
    only the leader, as an earlier version did, left one ``squashfuse_ll`` (about 20 MB
    charged to the job) behind per child, until a batch of probes ran out of memory.
    """

    def __init__(self, argv: list[str], cwd: str | None, timeout: float) -> None:
        self.timeout = timeout
        self.timed_out = False
        self.closed = False
        self.pending = bytearray()
        STARTED.append(self)
        self.process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, start_new_session=True)
        if CHILDREN is not None:
            with CHILDREN.open("a") as record:
                record.write(f"{self.process.pid} {start_time(self.process.pid)}\n")

    def __enter__(self) -> "Child":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def call(self, args_tagged: Any, kwargs_tagged: Any,
             timeout: float | None = None) -> dict[str, Any]:
        return self.ask({"args": args_tagged, "kwargs": kwargs_tagged}, timeout)

    def ask(self, request: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        """Send one request line and read the child's one reply line."""
        if self.closed or self.process.stdin is None or self.process.stdout is None:
            return ClientFailure("child-pipes")
        try:
            self.process.stdin.write(json.dumps(request) + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, ValueError):
            return ClientFailure("child-exited")
        return self.read(timeout)

    def read(self, timeout: float | None = None) -> dict[str, Any]:
        """The child's next protocol line, or an error after ``timeout`` seconds.

        The whole line must arrive inside the limit: the descriptor is read without blocking
        until a newline comes, so a child that writes part of a line and stops is stopped at
        the limit like one that writes nothing."""
        if self.closed or self.process.stdout is None:
            return ClientFailure("child-pipes")
        wait = self.timeout if timeout is None else max(0.0, min(timeout, self.timeout))
        deadline = time.monotonic() + wait
        descriptor = self.process.stdout.fileno()
        while b"\n" not in self.pending:
            if len(self.pending) > LINE_LIMIT:
                self.close()
                return ClientFailure("child-protocol")
            left = deadline - time.monotonic()
            ready = select.select([descriptor], [], [], left)[0] if left > 0 else []
            if not ready:
                # No whole line inside the limit: the candidate gave no answer.
                self.timed_out = True
                self.close()
                return ClientFailure("child-timeout")
            chunk = os.read(descriptor, 1 << 16)
            if not chunk:
                self.close()
                return ClientFailure("child-exited")
            self.pending += chunk
        end = self.pending.index(b"\n")
        line = bytes(self.pending[:end])
        del self.pending[:end + 1]
        try:
            return json.loads(line)
        except (ValueError, RecursionError, MemoryError):
            # A line too deeply nested to decode is no reply either: every way the decoder can
            # refuse a line is a protocol failure, never an exception the sealed code sees.
            return ClientFailure("child-protocol")

    def _exited(self, within: float) -> bool:
        """Whether the leader has exited within ``within`` seconds, WITHOUT reaping it: an
        unreaped leader keeps its pid, so the group id cannot be reused while it is signalled."""
        deadline = time.monotonic() + within
        while True:
            try:
                info = os.waitid(os.P_PID, self.process.pid,
                                 os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                return True
            if info is not None:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)

    def _signal_group(self, sig: int) -> None:
        try:
            os.killpg(self.process.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def close(self) -> None:
        """End the child and everything in its process group, then reap it and close pipes."""
        if self.closed:
            return
        if self.process.returncode is not None:
            # Already reaped: its pid may belong to someone else now, so signal nothing.
            self.closed = True
            return
        try:
            if self.process.stdin is not None:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
            # A child that timed out is busy, not reading: EOF would only cost the grace.
            if self.timed_out or not self._exited(CLOSE_GRACE):
                self._signal_group(signal.SIGTERM)
                if not self._exited(CLOSE_GRACE):
                    self._signal_group(signal.SIGKILL)
            self._exited(CLOSE_GRACE)
            # The leader is gone but not reaped; what is left in its group (a runtime daemon
            # whose parent died before it could stop it) dies here.
            self._signal_group(signal.SIGKILL)
        finally:
            self.process.wait()
            if self.process.stdout is not None:
                self.process.stdout.close()
            self.closed = True


def close_all() -> None:
    """Close every child this process started; the replay parent's last act."""
    for child in STARTED:
        child.close()


class Proxy:
    """``candidate`` in the sealed test: every call goes to the child as plain data."""

    def __init__(self, child: Child, budget: float) -> None:
        self.child = child
        self.deadline = time.monotonic() + budget
        self.timed_out = False
        self.answers: dict[str, list[str]] = {}
        self.requests: dict[str, tuple[Any, Any]] = {}
        # The answers on each request that the candidate gave: every one but a stall.
        self.given: dict[str, set[str]] = {}

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        try:
            args_tagged, kwargs_tagged = plain(tuple(args)), plain(dict(kwargs))
        except TypeError as error:
            raise CandidateFailed(f"argument is not plain data: {error}") from error
        key = json.dumps([args_tagged, kwargs_tagged], separators=(",", ":"))
        left = self.deadline - time.monotonic()
        if left <= 0:
            self.timed_out = True
            raise CandidateFailed("child-timeout")
        reply = self.child.call(args_tagged, kwargs_tagged, left)
        self.timed_out = self.timed_out or self.child.timed_out
        answer = json.dumps(reply, separators=(",", ":"), sort_keys=True)
        self.answers.setdefault(key, []).append(answer)
        if not stall(reply):
            self.given.setdefault(key, set()).add(answer)
        self.requests[key] = (args_tagged, kwargs_tagged)
        if "error" in reply:
            raise CandidateFailed(reply["error"])
        return unplain(reply["ok"])


def _run_test(path: Path, proxy: Proxy) -> str | None:
    """Run the sealed test with ``candidate`` bound to the proxy; the failure, or ``None``."""
    try:
        namespace = runpy.run_path(str(path), init_globals={"candidate": proxy},
                                   run_name="__probity_replay__")
        for name in ("check", "test_func"):
            if callable(namespace.get(name)):
                namespace[name](proxy)
                break
    except CandidateFailed as error:
        return f"candidate: {error}"
    except AssertionError as error:
        return f"assertion: {error}" if str(error) else "assertion"
    except Exception as error:
        return f"test raised {type(error).__name__}"
    return None


MODES = ("assert", "determinism", "type_strict", "import_side_effects")
# How many passes over the cases each mode makes. Every pass has the command's whole
# ``run_timeout`` (a probe that repeats the work is never stricter than one run of the
# command), and the runner's limit on the whole replay is that many timeouts.
# A pytest replay runs under one deadline of its own inside a single run_timeout
# (:func:`.pytest_replay.deadline`), fresh children included.
PASSES = {"assert": 2, "determinism": 3, "type_strict": 1, "import_side_effects": 1,
          "pytest": 1}

# How the candidate ended its own process: the reply errors a SystemExit or an exit gives.
EXIT_ERRORS = ("import:SystemExit", "SystemExit", "child-exited")
# Exceptions whose cause can be the child's isolation rather than the code (a read-only working
# directory, no network, no HOME, only the module's own file copied, a shallower stack): an
# honest candidate can raise one here and not in one process with the test.
ISOLATION_ERRORS = frozenset({
    "OSError", "IOError", "EnvironmentError", "PermissionError", "FileNotFoundError",
    "FileExistsError", "IsADirectoryError", "NotADirectoryError", "BlockingIOError",
    "ConnectionError", "ConnectionRefusedError", "ConnectionResetError",
    "ConnectionAbortedError", "BrokenPipeError", "TimeoutError", "InterruptedError",
    "ChildProcessError", "ProcessLookupError", "ImportError", "ModuleNotFoundError",
    "RecursionError", "MemoryError", "KeyboardInterrupt"})
# Child errors that are the protocol's, not an exception the candidate raised.
PROTOCOL_ERRORS = frozenset({"child-timeout", "child-pipes", "child-protocol", "unplain"})


def failure_kind(result: dict[str, Any]) -> str | None:
    """How a failed replay failed, for the grade: ``assertion`` (the trusted comparison
    failed on the answers, with no impure or fresh-mismatch key; for the import probe, the
    module changed ``builtins``), ``candidate_exit`` (the candidate ended its own process),
    ``candidate_raised`` (the candidate raised, at import or in a call, an exception its code
    raises wherever it runs: not one of :data:`ISOLATION_ERRORS`) or ``candidate`` (anything
    else: an isolation-dependent exception, a timeout, an unplain value, no report).

    probity-verify compares this with the exit of the same test run in one process with the
    candidate (``python test.py``): a trusted ``assertion`` or ``candidate_exit`` failure
    whose in-process twin exits 0 means the candidate changed how its process reports
    failure."""
    if result["passed"]:
        return None
    failure = result.get("failure") or ""
    if result.get("mode") == "import_side_effects":
        return "assertion" if failure == "builtins changed on import" else "candidate"
    if result.get("mode", "assert") != "assert" or result.get("timed_out"):
        return "candidate"
    if failure.startswith("assertion") and not result.get("impure") and not result.get(
            "fresh_mismatch"):
        return "assertion"
    error = failure[len("candidate: "):] if failure.startswith("candidate: ") else None
    if error in EXIT_ERRORS:
        return "candidate_exit"
    if error is not None and error.startswith("import:"):
        error = error[len("import:"):]
    if (error is not None and error.isidentifier() and error not in PROTOCOL_ERRORS
            and error not in ISOLATION_ERRORS and not result.get("impure")
            and not result.get("fresh_mismatch")):
        return "candidate_raised"
    return "candidate"


def sealed_cases(path: Path) -> list[tuple[Any, Any, Any]]:
    """``(args, kwargs, expected)`` for each ``assert candidate(...) == <literal>`` in the
    sealed test's assertion function (the held-out file is written in exactly that shape)."""
    return cases_in(path.read_text())


def cases_in(source: str) -> list[tuple[Any, Any, Any]]:
    """:func:`sealed_cases` over source text; the split checks its own output with it."""
    from .heldout import cases_of, check_body

    found = []
    for case in cases_of(check_body(source)[1]):
        call = ast.parse(f"candidate({case.args})", mode="eval").body
        if not isinstance(call, ast.Call) or any(isinstance(arg, ast.Starred) for arg in call.args):
            raise ValueError(f"case arguments are not literals: {case.args}")
        args = tuple(ast.literal_eval(arg) for arg in call.args)
        kwargs = {keyword.arg: ast.literal_eval(keyword.value) for keyword in call.keywords}
        found.append((args, kwargs, ast.literal_eval(case.expected)))
    return found


def strict_eq(left: Any, right: Any) -> bool:
    """Equal with the same builtin type at every level (``1 != 1.0 != True`` here)."""
    if type(left) is not type(right):
        return False
    if type(left) in (list, tuple):
        return len(left) == len(right) and all(strict_eq(a, b) for a, b in zip(left, right))
    if type(left) is dict:
        return (len(left) == len(right) and all(
            any(strict_eq(key, other) and strict_eq(value, right[other]) for other in right)
            for key, value in left.items()))
    if type(left) in (set, frozenset):
        return len(left) == len(right) and all(
            any(strict_eq(item, other) for other in right) for item in left)
    return bool(left == right)


def _tagged(args: Any, kwargs: Any) -> tuple[Any, Any]:
    return plain(tuple(args)), plain(dict(kwargs))


def _text(reply: Any) -> str:
    return json.dumps(reply, separators=(",", ":"), sort_keys=True)


def _one_run(request: dict[str, Any], calls: list[tuple[Any, Any]], repeat: int,
             budget: float) -> tuple[list[Any], float, bool]:
    """One child, each call ``repeat`` times; each pass over the calls has ``budget`` seconds,
    so the run has ``repeat`` times that. The replies in order, a stall included."""
    started = time.monotonic()
    answers: list[Any] = []
    timed_out = False
    with Child(request["child_argv"], request.get("child_cwd"),
               float(request["call_timeout"])) as child:
        for args_tagged, kwargs_tagged in calls:
            for _ in range(repeat):
                left = budget * repeat - (time.monotonic() - started)
                if left <= 0:
                    timed_out = True
                    break
                reply = child.call(args_tagged, kwargs_tagged, left)
                answers.append(reply)
                if child.timed_out:
                    # The child is closed: no later call can be answered or counted.
                    timed_out = True
                    break
            if timed_out:
                break
    return answers, round(time.monotonic() - started, 3), timed_out


def given_wrong(runs: list[list[Any]], cases: list[tuple[Any, Any, Any]]) -> str | None:
    """What the answers the candidate gave already show wrong, or ``None``: two different
    answers to one case, an error, an answer that is not ``==`` the expected value. ``runs``
    are reply sequences in case order, each possibly cut short; a stall is no answer."""
    given = [[reply for reply in (run[index] for run in runs if index < len(run))
              if not stall(reply)] for index in range(len(cases))]
    if any(len({_text(reply) for reply in replies}) > 1 for replies in given):
        return "answers differ between runs"
    if any("error" in reply for replies in given for reply in replies):
        return "candidate raised"
    if any(unplain(reply["ok"]) != value
           for replies, (_, _, value) in zip(given, cases) for reply in replies):
        return "answer differs from the expected value"
    return None


def determinism(request: dict[str, Any]) -> dict[str, Any]:
    """Every held-out case twice in one child, then once in a fresh child: three identical
    answer sequences, each answer plain and ``==`` the case's expected value (the type is
    :func:`type_strict`'s question).

    Each of the three passes has its own ``run_timeout`` (the first run, two passes, has
    twice that); one slow pass never spends another's.
    """
    cases = sealed_cases(Path(request["test"]))
    calls = [_tagged(args, kwargs) for args, kwargs, _ in cases]
    budget = float(request["run_timeout"])
    first, first_s, first_out = _one_run(request, calls, 2, budget)
    fresh, fresh_s, fresh_out = _one_run(request, calls, 1, budget)
    # A run cut short by a stall still holds the answers it was given, and a wrong one among
    # them is a definitive failure: a later stall never turns it into "no answer".
    failure = given_wrong([first[0::2], first[1::2], fresh], cases)
    definitive = failure is not None
    if not definitive and (first_out or fresh_out or any(child.timed_out for child in STARTED)):
        failure = "timeout"
    return {"passed": failure is None, "failure": failure, "mode": "determinism",
            "definitive": definitive,
            # Count what was asked: a run cut short reached only its first cases.
            "calls_intercepted": len(first) + len(fresh),
            "distinct_calls": max(-(-len(first) // 2), len(fresh)),
            "run_seconds": [first_s, fresh_s], "run_timeout": budget}


def type_strict(request: dict[str, Any]) -> dict[str, Any]:
    """Each held-out case compared with :func:`strict_eq`: the result's builtin type, at every
    level, must be the expected value's. One pass, inside ``run_timeout``."""
    cases = sealed_cases(Path(request["test"]))
    calls = [_tagged(args, kwargs) for args, kwargs, _ in cases]
    answers, _, timed_out = _one_run(request, calls, 1, float(request["run_timeout"]))
    mismatched = 0
    made = 0
    failure = None
    # A run cut short at its budget, or a call that stalled, gave no answer from there on.
    stalled = timed_out
    for reply, (_, _, expected) in zip(answers, cases):
        made += 1
        if "error" in reply:
            stalled = stall(reply)
            failure = "timeout" if stalled else f"candidate: {reply['error']}"
            break
        if not strict_eq(unplain(reply["ok"]), expected):
            mismatched += 1
    if failure is None and stalled:
        failure = "timeout"
    # A mismatch already given stands over a later stall.
    if mismatched and (failure is None or stalled):
        failure = f"{mismatched} result(s) differ in type or value"
    return {"passed": failure is None, "failure": failure, "mode": "type_strict",
            "definitive": failure is not None and (bool(mismatched) or not stalled),
            "calls_intercepted": made, "distinct_calls": made}


def import_side_effects(request: dict[str, Any]) -> dict[str, Any]:
    """Importing the candidate's module must not add, remove or rebind a name in ``builtins``.

    The child reports ``builtins`` before the import (before any module code has run) and
    after it; the report after the import comes from a process the module's code has run in.
    """
    with Child(request["child_argv"], request.get("child_cwd"),
               float(request["call_timeout"])) as child:
        before, after = child.read(), child.read()
    if "builtins" not in before or "builtins" not in after:
        return {"passed": False, "failure": "no builtins report", "mode": "import_side_effects",
                "calls_intercepted": 0, "distinct_calls": 0}
    old = {name: (kind, ident) for name, kind, ident in before["builtins"]}
    new = {name: (kind, ident) for name, kind, ident in after["builtins"]}
    changes = {"added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new)),
               "rebound": sorted(name for name in set(old) & set(new) if old[name] != new[name])}
    changed = any(changes.values())
    return {"passed": not changed, "failure": "builtins changed on import" if changed else None,
            "mode": "import_side_effects", "definitive": changed, "builtins": changes, "calls_intercepted": 0,
            "distinct_calls": 0, "evidence_from_worker": ["builtins_after_import"]}


def replay(request: dict[str, Any]) -> dict[str, Any]:
    """Run one replay request in its mode (the sealed test with the purity check and fresh
    re-runs, or one of the held-out probes)."""
    mode = request.get("mode", "assert")
    if mode == "pytest":
        from .pytest_replay import pytest_replay

        return pytest_replay(request)
    if mode == "determinism":
        return determinism(request)
    if mode == "type_strict":
        return type_strict(request)
    if mode == "import_side_effects":
        return import_side_effects(request)
    timeout = float(request["call_timeout"])
    budget = float(request["run_timeout"])
    # Two passes, each with the whole run_timeout: the sealed test in one child, then every
    # distinct call again in a fresh child of its own.
    with Child(request["child_argv"], request.get("child_cwd"), timeout) as child:
        proxy = Proxy(child, budget)
        failure = _run_test(Path(request["test"]), proxy)
    if proxy.timed_out:
        failure = "timeout"
    impure = sorted(key for key, answers in proxy.answers.items() if len(set(answers)) != 1)
    order = sorted(proxy.answers)
    random.Random(request["order_seed"]).shuffle(order)
    fresh_mismatch = []
    # A failure the candidate's own answers show: a failed assertion or a raise in the run
    # (not its stall, nor the run's budget running out), two answers it gave on one request,
    # or a fresh child's answer.
    definitive = (failure is not None and not proxy.timed_out) or any(
        len(given) > 1 for given in proxy.given.values())
    deadline = time.monotonic() + budget
    for key in order:
        left = deadline - time.monotonic()
        if left <= 0:
            failure = failure or "timeout"
            break
        with Child(request["child_argv"], request.get("child_cwd"), timeout) as fresh:
            reply = fresh.call(*proxy.requests[key], left)
        if fresh.timed_out:
            # No answer from this fresh child; a later key may still show a wrong one.
            failure = failure or "timeout"
        if _text(reply) != proxy.answers[key][0]:
            fresh_mismatch.append(key)
            definitive = definitive or not stall(reply)
    calls = sum(len(answers) for answers in proxy.answers.values())
    passed = failure is None and not impure and not fresh_mismatch
    return {"passed": passed, "failure": failure, "definitive": definitive and not passed,
            "calls_intercepted": calls,
            "distinct_calls": len(order), "impure": impure, "fresh_mismatch": fresh_mismatch,
            "fresh_order": order}


def terminated(signum: int, frame: Any) -> None:
    """The parent's SIGTERM: stop every child, then exit at once.

    Not ``sys.exit``: in a pytest replay the signal lands inside a test, and pytest records
    the ``SystemExit`` as that test's failure and goes on to the next, asking the same child."""
    try:
        close_all()
    finally:
        os._exit(TERMINATED_EXIT)


def main(argv: list[str] | None = None) -> int:
    global CHILDREN
    args = sys.argv[1:] if argv is None else argv
    request = json.loads(Path(args[0]).read_text())
    STARTED.clear()
    CHILDREN = Path(request["children"]) if request.get("children") else None
    # The runner sends SIGTERM when the whole command outruns its limit.
    signal.signal(signal.SIGTERM, terminated)
    try:
        result = replay(request)
    finally:
        close_all()
    # No answer is told from a wrong one only when the run holds no definitive failure: a
    # stall after a wrong answer, or in a fresh child after one, never hides it.
    if not result["passed"] and not result.get("definitive") and (
            result.get("failure") == "timeout" or any(child.timed_out for child in STARTED)):
        result["timed_out"] = True
    kind = failure_kind(result)
    if kind is not None:
        result["failure_kind"] = kind
    Path(request["out"]).write_text(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    # Run as ``-m``, this file is ``__main__``, a second copy of the module: the pytest replay
    # imports ``probity_observer.done.replay``, so its children would be in that copy's
    # ``STARTED`` and out of reach of this one's ``close_all``. ``main`` runs in the one copy.
    from probity_observer.done import replay as harness

    sys.exit(harness.main())
