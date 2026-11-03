"""Open guard runtime child. Runs ONE guard's source; stdlib only; started as `python -I -S -c <source>`.

Resource limits only: CPU seconds, address space, no child processes, no file writes, no core dumps. There
is no network namespace, no syscall filter and no filesystem ruleset, so this child is NOT an isolation
boundary: a guard can read files and open sockets. `ratchet.agent.guard_open` refuses to start it when the
limits require any layer other than `rlimits`.

Startup : setup line in; {"loading": true} once limited (guard code runs from here), then
          {"ready": bool, "isolation": {...}, "error"?: str}.
Request : {"i": n, "call": {...}, "view": {...}, "h_keep": k, "h_add": [event, ...]}
          The child keeps its last history; it keeps the first k events and appends `h_add`.
Replies : {"s": n} when the request is decoded and the guard starts, then
          {"i": n, "block": str | null, "error": str | null, "guard_s": float}.
          The guard's time limit is CPU time (ITIMER_PROF) measured from the start marker only.
"""

import builtins
import json
import os
import resource
import signal
import sys
import time
import types
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

# Modules a guard may import; preloaded so the guard does not pay for their import.
PRELOAD = (
    "re",
    "math",
    "decimal",
    "fractions",
    "datetime",
    "collections",
    "itertools",
    "functools",
    "string",
    "operator",
    "statistics",
)


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any]
    call_id: str


@dataclass(frozen=True)
class Event:
    seq: int
    kind: str
    payload: Any
    ts: float


class GuardTimeout(BaseException):
    pass


def freeze(value: Any) -> Any:
    """Deep read-only copy, so a guard cannot change the history the next evaluation sees."""
    if isinstance(value, dict):
        return types.MappingProxyType({k: freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(freeze(v) for v in value)
    return value


def apply_rlimits(cpu_s: int, memory_mb: int) -> str:  # pragma: no cover - runs only in the child
    limit = memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 1))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return f"cpu={cpu_s}s as={memory_mb}MiB nproc=0 fsize=0 core=0"


def _send(fd: int, obj: Any) -> None:
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
    while data:
        data = data[os.write(fd, data) :]


def _on_alarm(signum: int, frame: Any) -> None:
    raise GuardTimeout()


def evaluate(code: Any, call: ToolCall, view: Any, history: list[Event], timeout_s: float) -> dict[str, Any]:
    """Run the guard under a CPU-time alarm, re-executing its module so no state carries over."""
    started = time.perf_counter()
    signal.setitimer(signal.ITIMER_PROF, timeout_s)
    try:
        namespace: dict[str, Any] = {"__name__": "guard", "__builtins__": builtins}
        exec(code, namespace)
        result = namespace["check"](call, view, history)
    except GuardTimeout:
        return {"block": None, "error": "timeout", "guard_s": time.perf_counter() - started}
    except BaseException as exc:
        return {"block": None, "error": f"{type(exc).__name__}: {exc}"[:500], "guard_s": time.perf_counter() - started}
    finally:
        signal.setitimer(signal.ITIMER_PROF, 0)
    elapsed = time.perf_counter() - started
    if result is None:
        return {"block": None, "error": None, "guard_s": elapsed}
    if isinstance(result, str):
        return {"block": result[:1000], "error": None, "guard_s": elapsed}
    error = f"check returned {type(result).__name__}, expected str or None"
    return {"block": None, "error": error, "guard_s": elapsed}


def load(source: str) -> Any:
    code = compile(source, "<guard>", "exec")
    namespace: dict[str, Any] = {"__name__": "guard", "__builtins__": builtins}
    exec(code, namespace)
    if not callable(namespace.get("check")):
        raise ValueError("guard source does not define a callable check(call, view, history)")
    return code


def serve(
    setup: dict[str, Any],
    isolation: dict[str, str],
    lines: Iterable[bytes],
    send: Callable[[dict[str, Any]], None],
) -> None:
    """Report readiness, load the guard, then answer each request line until stdin closes."""
    missing = [n for n in setup["require"] if n not in isolation]
    if missing:
        send({"ready": False, "isolation": isolation, "error": f"isolation unavailable: {missing}"})
        return
    timeout_s = float(setup["timeout_s"])
    signal.signal(signal.SIGPROF, _on_alarm)
    send({"loading": True})
    signal.setitimer(signal.ITIMER_PROF, timeout_s)
    try:
        code = load(setup["source"])
    except GuardTimeout:
        send({"ready": False, "isolation": isolation, "error": "timeout while loading guard"})
        return
    except BaseException as exc:
        send({"ready": False, "isolation": isolation, "error": f"{type(exc).__name__}: {exc}"[:500]})
        return
    finally:
        signal.setitimer(signal.ITIMER_PROF, 0)
    send({"ready": True, "isolation": isolation})
    history: list[Event] = []
    for line in lines:
        request = json.loads(line)
        del history[int(request["h_keep"]) :]
        history.extend(
            Event(seq=e["seq"], kind=e["kind"], payload=freeze(e["payload"]), ts=e["ts"])
            for e in request["h_add"]
        )
        raw = request["call"]
        call = ToolCall(name=raw["name"], args=raw["args"], call_id=raw["call_id"])
        snapshot = list(history)
        send({"s": request["i"]})
        reply = evaluate(code, call, request["view"], snapshot, timeout_s)
        reply["i"] = request["i"]
        send(reply)


def main() -> None:  # pragma: no cover - runs only in the child
    proto = os.dup(1)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    setup = json.loads(sys.stdin.buffer.readline())
    for name in PRELOAD:
        __import__(name)
    isolation = {"rlimits": apply_rlimits(int(setup["cpu_s"]), int(setup["memory_mb"]))}
    serve(setup, isolation, sys.stdin.buffer, lambda obj: _send(proto, obj))


if __name__ == "__main__":
    main()
