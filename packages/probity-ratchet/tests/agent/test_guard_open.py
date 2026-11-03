"""The open guard runtime and the runtime seam: same decisions as an enforcing runtime on well-behaved
guards, a refusal whenever isolation is demanded, and selection through the entry-point group."""

from __future__ import annotations

import json
from typing import Any

import pytest
from ratchet_cases.types import Event, ToolCall

from ratchet.agent import _guard_open_child as child
from ratchet.agent import guard_api, guard_open
from ratchet.agent.guard_api import (
    GUARD_ERROR_REASON,
    GuardInfrastructureError,
    GuardItem,
    GuardLimits,
    GuardSourceError,
    SandboxUnavailableError,
    guard_runtime,
    required_layers,
)
from ratchet.agent.guard_open import OpenGuardRuntime
from ratchet.types import Guard

NO_RM = Guard(
    "no-rm", "", 'def check(call, view, history):\n    return "no" if call.name == "rm" else None\n'
)
COUNT = Guard("count", "", "def check(call, view, history):\n    return str(len(history)) + view['k']\n")
CALL = ToolCall("rm", {}, "c1")


def test_required_layers_default_to_none_and_reject_unknown_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(guard_api.REQUIRE_ENV, raising=False)
    assert required_layers() == () and GuardLimits().require == ()
    assert required_layers("seccomp, netns,seccomp") == ("seccomp", "netns")
    with pytest.raises(ValueError, match="unknown layers"):
        required_layers("rlimits,firewall")


def test_open_runtime_refuses_every_isolation_demand() -> None:
    for layer in ("netns", "seccomp", "landlock"):
        with pytest.raises(SandboxUnavailableError, match="not an isolation boundary"):
            OpenGuardRuntime(GuardLimits(require=("rlimits", layer)))
    with OpenGuardRuntime(GuardLimits(require=("rlimits",))) as rt:
        assert set(rt.validate(NO_RM)) == {"rlimits"}


def test_block_allow_and_history() -> None:
    history = [Event(0, "model", {"x": 1}, 0.0), Event(1, "tool_call", {}, 0.0)]
    with OpenGuardRuntime(workers=1) as rt:
        assert rt.check(NO_RM, CALL, {}, []).reason == "no"
        assert not rt.check(NO_RM, ToolCall("ls", {}, "c2"), {}, []).blocked
        assert [d.reason for d in rt.check_all([NO_RM, COUNT], CALL, {"k": "!"}, history)] == ["no", "2!"]
        assert rt.check(COUNT, CALL, {"k": "?"}, history[:1]).reason == "1?"


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ("raise RuntimeError('boom')", "RuntimeError: boom"),
        ("return 3", "check returned int"),
        ("while True: pass", "timeout"),
        ("import os; os._exit(3)", "exited with status 3"),
    ],
)
def test_guard_errors_fail_closed(body: str, error: str) -> None:
    guard = Guard("bad", "", f"def check(call, view, history):\n    {body}\n")
    with OpenGuardRuntime(GuardLimits(call_timeout_s=0.3, guard_wall_grace_s=1.0), workers=1) as rt:
        decision = rt.check(guard, CALL, {}, [])
    assert decision.blocked and decision.reason == GUARD_ERROR_REASON and decision.kind == "guard_error"
    assert error in str(decision.error)


def test_rejected_source_is_an_error_decision_and_raises_on_validate() -> None:
    broken = Guard("broken", "", "def check(:\n")
    missing = Guard("missing", "", "x = 1\n")
    with OpenGuardRuntime(workers=1) as rt:
        assert rt.check(broken, CALL, {}, []).kind == "guard_error"
        assert rt.check(broken, CALL, {}, []).kind == "guard_error"
        assert "callable check" in str(rt.check(missing, CALL, {}, []).error)
        with pytest.raises(GuardSourceError):
            rt.validate(missing)


def test_batch_keeps_input_order_across_shards_and_guards() -> None:
    items = [GuardItem(NO_RM if i % 2 else COUNT, CALL, {"k": str(i)}, []) for i in range(40)]
    with OpenGuardRuntime(workers=3) as rt:
        decisions = rt.batch(items)
        assert rt.batch([]) == []
    assert [d.reason for d in decisions] == ["no" if i % 2 else f"0{i}" for i in range(40)]
    broken = Guard("broken", "", "def check(:\n")
    with OpenGuardRuntime(workers=1) as rt:
        assert {d.kind for d in rt.batch([GuardItem(broken, CALL, {}, [])] * 3)} == {"guard_error"}


def test_transport_failure_is_retried_then_raised() -> None:
    with OpenGuardRuntime(GuardLimits(startup_timeout_s=0.001), workers=1) as rt:
        with pytest.raises(GuardInfrastructureError, match="failed in the runtime"):
            rt.batch([GuardItem(NO_RM, CALL, {}, [])])
        with pytest.raises(GuardInfrastructureError):
            rt.check(NO_RM, CALL, {}, [])


def test_a_dead_child_is_an_infrastructure_decision_and_check_retries_once() -> None:
    proc = guard_open.OpenGuardProcess(NO_RM, GuardLimits())
    proc.close()
    assert proc.evaluate(GuardItem(NO_RM, CALL, {}, [])).kind == "infrastructure_error"
    rt = OpenGuardRuntime(GuardLimits(transport_timeout_s=0.0), workers=1)
    with rt, pytest.raises(GuardInfrastructureError, match="failed to start"):
        rt.check(NO_RM, CALL, {}, [])


class _EntryPoint:
    name = "runtime"
    value = "elsewhere:factory"

    def load(self) -> Any:
        return lambda limits, workers=None: ("custom", limits, workers)


def test_selection_prefers_one_registered_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guard_api, "entry_points", lambda group: [])
    with guard_runtime(workers=1) as rt:
        assert isinstance(rt, OpenGuardRuntime)
    monkeypatch.setattr(guard_api, "entry_points", lambda group: [_EntryPoint()])
    assert guard_runtime(workers=2) == ("custom", None, 2)
    monkeypatch.setattr(guard_api, "entry_points", lambda group: [_EntryPoint(), _EntryPoint()])
    with pytest.raises(RuntimeError, match="several"):
        guard_runtime()


def test_child_serves_the_protocol_in_process() -> None:
    sent: list[dict[str, Any]] = []
    setup = {"source": COUNT.source, "timeout_s": 1.0, "require": ["rlimits"]}
    event = {"seq": 0, "kind": "model", "payload": {"a": [1]}, "ts": 0.0}
    lines = [
        json.dumps({"i": 0, "call": {"name": "x", "args": {}, "call_id": "c"}, "view": {"k": "!"},
                    "h_keep": 0, "h_add": [event]}).encode(),
        json.dumps({"i": 1, "call": {"name": "x", "args": {}, "call_id": "c"}, "view": {"k": "?"},
                    "h_keep": 0, "h_add": []}).encode(),
    ]  # fmt: skip
    child.serve(setup, {"rlimits": "on"}, lines, sent.append)
    assert sent[0] == {"loading": True} and sent[1]["ready"] is True
    assert [m.get("block") for m in sent[2:]] == [None, "1!", None, "0?"]
    refused: list[dict[str, Any]] = []
    child.serve({**setup, "require": ["seccomp"]}, {"rlimits": "on"}, [], refused.append)
    assert refused[0]["error"] == "isolation unavailable: ['seccomp']"
    bad: list[dict[str, Any]] = []
    child.serve({**setup, "source": "x = 1"}, {"rlimits": "on"}, [], bad.append)
    assert "callable check" in bad[-1]["error"]
    assert child.freeze({"a": [1, {"b": 2}]})["a"][1]["b"] == 2
