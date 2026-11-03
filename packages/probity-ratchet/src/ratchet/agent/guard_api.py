"""The guard runtime seam: decision types, limits, the `GuardRuntime` protocol and runtime selection.

A guard's `source` defines `check(call, view, history) -> str | None`. Returning a string blocks the call
and the string is the reason shown to the model; `None` allows it. A runtime evaluates guard source in child
processes and fails closed: a guard that does not compile, does not define `check`, raises, returns a
non-string or runs past its time limit yields a BLOCK decision of kind `guard_error`. A failure of the
runtime itself (startup or transport past its bound) is retried once and then raised as
`GuardInfrastructureError`; it is never reported as a guard verdict.

Isolation is a demand the deployment states, not a property this package assumes. `GuardLimits.require`
names the layers a runtime must apply or refuse to start; it comes from RATCHET_GUARD_REQUIRE and is empty
when that variable is unset. It is empty by default because the open runtime this package ships
(`ratchet.agent.guard_open`) applies resource limits only and is not an isolation boundary: a default that
demanded network, syscall or filesystem layers would make every install refuse every guard, and a default
the open runtime ignored would be a silent downgrade. So a deployment that needs isolation names the
layers, and then either an installed runtime provides them or the open runtime refuses to start.

Selection (`guard_runtime`): the runtime registered under the `ratchet.guards` entry-point group with the
name `runtime`, called as `factory(limits, workers=workers)`; with none registered, the open runtime.
Callers that need a specific runtime pass one by argument instead.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from importlib.metadata import entry_points
from types import TracebackType
from typing import Any, Literal, Protocol

from ratchet_cases.types import Event, ToolCall

from ratchet.types import Guard

GUARD_ERROR_REASON = "guard error"
INFRASTRUCTURE_ERROR_REASON = "guard infrastructure error"
DecisionKind = Literal["verdict", "guard_error", "infrastructure_error"]
ALL_LAYERS = ("rlimits", "netns", "seccomp", "landlock")
REQUIRE_ENV = "RATCHET_GUARD_REQUIRE"
ENTRY_POINT_GROUP = "ratchet.guards"
ENTRY_POINT_NAME = "runtime"


def required_layers(value: str | None = None) -> tuple[str, ...]:
    """The isolation layers a runtime must apply: the comma list in RATCHET_GUARD_REQUIRE, or none.

    Only known layer names are accepted, so a typo is an error rather than a demand nobody can meet.
    """
    raw = os.environ.get(REQUIRE_ENV, "") if value is None else value
    layers = tuple(dict.fromkeys(x.strip() for x in raw.split(",") if x.strip()))
    unknown = [x for x in layers if x not in ALL_LAYERS]
    if unknown:
        raise ValueError(f"{REQUIRE_ENV} names unknown layers {unknown}; known: {', '.join(ALL_LAYERS)}")
    return layers


class GuardSourceError(ValueError):
    """Guard source was rejected: it does not compile or does not define a callable `check`."""


class SandboxUnavailableError(RuntimeError):
    """The runtime cannot apply an isolation layer the limits require."""


class GuardInfrastructureError(RuntimeError):
    """The sandbox, not the guard, failed: startup or transport ran past its bound, or the child died
    before the guard started. Carries every decision of the batch so a caller can see what completed."""

    def __init__(self, message: str, decisions: Sequence[GuardDecision] = ()) -> None:
        super().__init__(message)
        self.decisions = list(decisions)


@dataclass(frozen=True)
class GuardLimits:
    call_timeout_s: float = 2.0  # CPU time of one guard evaluation
    guard_wall_grace_s: float = 5.0  # extra wall time from the start marker before the parent kills
    transport_timeout_s: float = 60.0  # encode, pipe and decode one request, under any machine load
    startup_timeout_s: float = 60.0  # interpreter start, preloads and lockdown
    cpu_s: int = 3600  # whole-process CPU backstop; a child serves one shard of a batch
    memory_mb: int = 512
    # Layers that must take effect or the runtime refuses to start (module docstring).
    require: tuple[str, ...] = field(default_factory=required_layers)
    # Use at most this Landlock ABI, to run a sandbox as it runs on an older kernel. None uses the
    # kernel's own ABI. Runtimes without Landlock ignore it.
    landlock_max_abi: int | None = None


@dataclass(frozen=True)
class GuardDecision:
    guard_id: str
    blocked: bool
    reason: str | None
    error: str | None = None
    elapsed_s: float = 0.0
    kind: DecisionKind = "verdict"

    def __post_init__(self) -> None:
        if self.kind != "verdict" and not (isinstance(self.error, str) and self.error.strip()):
            raise ValueError(f"a {self.kind} decision must carry its error message, got {self.error!r}")

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GuardItem:
    """One evaluation for batch mode."""

    guard: Guard
    call: ToolCall
    view: Mapping[str, Any]
    history: Sequence[Event] = field(default_factory=list)


def error_decision(guard_id: str, error: str, elapsed: float = 0.0) -> GuardDecision:
    """The fail-closed decision for a guard's own failure."""
    return GuardDecision(guard_id, True, GUARD_ERROR_REASON, error, elapsed, "guard_error")


def infrastructure_decision(guard_id: str, error: str) -> GuardDecision:
    """The decision for a failure of the runtime, not the guard."""
    return GuardDecision(guard_id, True, INFRASTRUCTURE_ERROR_REASON, error, kind="infrastructure_error")


def compile_guard(source: str) -> None:
    """Parent-side syntax check. Compiling never executes the source."""
    try:
        compile(source, "<guard>", "exec")
    except (SyntaxError, ValueError) as exc:
        raise GuardSourceError(f"guard source does not compile: {exc}") from exc


class GuardRuntime(Protocol):
    """What the worker, replay, the loop and the exporters need from a guard runtime."""

    def __enter__(self) -> GuardRuntime: ...

    def __exit__(
        self, kind: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None: ...

    def close(self) -> None:
        """Stop every child the runtime owns."""
        ...

    def validate(self, guard: Guard) -> dict[str, str]:
        """Load the guard and return the isolation achieved per layer; raise `GuardSourceError`."""
        ...

    def check(
        self, guard: Guard, call: ToolCall, view: Mapping[str, Any], history: Sequence[Event]
    ) -> GuardDecision:
        """One guard on one call; raises `GuardInfrastructureError` after one retry."""
        ...

    def check_all(
        self, guards: Iterable[Guard], call: ToolCall, view: Mapping[str, Any], history: Sequence[Event]
    ) -> list[GuardDecision]:
        """Every guard, in order."""
        ...

    def batch(self, items: Sequence[GuardItem]) -> list[GuardDecision]:
        """Many items, results in input order; raises `GuardInfrastructureError` with every decision."""
        ...


def guard_runtime(limits: GuardLimits | None = None, *, workers: int | None = None) -> GuardRuntime:
    """The selected runtime (module docstring): a registered `ratchet.guards` runtime, else the open one."""
    found = [ep for ep in entry_points(group=ENTRY_POINT_GROUP) if ep.name == ENTRY_POINT_NAME]
    if len(found) > 1:
        names = ", ".join(sorted(ep.value for ep in found))
        raise RuntimeError(f"several {ENTRY_POINT_GROUP} runtimes are installed ({names}); install one")
    if found:
        runtime: GuardRuntime = found[0].load()(limits, workers=workers)
        return runtime
    from ratchet.agent.guard_open import OpenGuardRuntime

    return OpenGuardRuntime(limits, workers=workers)
