"""The AG2 adapter: the eight scenarios on each AG2 path, with a plain tool as the control."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from ag2 import Agent, tool
from ag2.events import ToolCallEvent, ToolErrorEvent
from ag2.stream import MemoryStream
from ag2.testing import TestConfig
from agent_evidence_vectors import uncertaineffect_runtime
from probity_effects import EffectCall, EffectOutcomeUnknown, EffectOwner, Lookup
from probity_effects.ag2 import effect_tool
from probity_effects.testing import (
    AG2_VARIANTS,
    drive_ag2,
    lost_reply_scenarios,
    run_ag2_scenario,
    scenario_owner,
)


def order_tools(owner, journal):
    @effect_tool(owner, journal=journal)
    def create_order(sku: str, quantity: int, effect: EffectCall) -> dict[str, Any]:
        """Create an order at the order service."""
        raise AssertionError("the scenario owner performs the send")

    return [create_order]


def async_order_tools(owner, journal):
    @effect_tool(owner, journal=journal)
    async def create_order(sku: str, quantity: int, effect: EffectCall) -> dict[str, Any]:
        """Create an order at the order service."""
        raise AssertionError("the scenario owner performs the send")

    return [create_order]


@pytest.mark.parametrize("variant", AG2_VARIANTS)
def test_guarded_tool_passes(lost_reply_scenario, variant):
    verdict = run_ag2_scenario(order_tools, lost_reply_scenario, variant=variant)
    assert verdict.passed, verdict.problems
    assert verdict.effects in ((0, 1) if lost_reply_scenario["id"] == "definite-no-effect" else (1,))


@pytest.mark.parametrize("variant", AG2_VARIANTS)
def test_guarded_async_tool_passes(lost_reply_scenario, variant):
    verdict = run_ag2_scenario(async_order_tools, lost_reply_scenario, variant=variant)
    assert verdict.passed, verdict.problems


def plain_tools(run):
    """The control: the same write as an ordinary AG2 tool."""
    key = run.scenario["operation"]["idempotencyKey"]

    @tool
    def create_order(sku: str, quantity: int) -> str:
        """Create an order at the order service."""
        body: dict[str, Any] = {"args": {"quantity": quantity, "sku": sku}, "idempotencyKey": key}
        if run.fencing_token is not None:
            body["fencingToken"] = run.fencing_token
        httpx.post(run.url + "/effects", json=body, timeout=5.0).raise_for_status()
        return "confirmed"

    return [create_order]


def plain_runs(variant: str) -> tuple[dict[str, int], int]:
    """Effects per scenario, and the scenarios passed when a run ending in an error reports nothing happened."""
    counts, passed = {}, 0
    for scenario in lost_reply_scenarios():
        with scenario_owner(scenario) as run:
            error = drive_ag2(lambda owner, journal: plain_tools(run), run, None, variant=variant)
            counts[scenario["id"]] = run.state.effects
            passed += not uncertaineffect_runtime.judge(scenario, run.state, "not_run" if error else "committed")
    return counts, passed


PLAIN_ONE_ASK = {"confirmed": 1, "commit-then-lost-reply": 1, "commit-then-lost-reply-deduplicating": 1,
                 "owner-unreachable-after-lost-reply": 1, "lost-before-commit": 0,
                 "late-commit-after-missed-lookup": 0, "definite-no-effect": 0, "lease-lost-after-lost-reply": 1}
PLAIN_CALLED_AGAIN = {"confirmed": 1, "commit-then-lost-reply": 2, "commit-then-lost-reply-deduplicating": 1,
                      "owner-unreachable-after-lost-reply": 2, "lost-before-commit": 1,
                      "late-commit-after-missed-lookup": 2, "definite-no-effect": 1,
                      "lease-lost-after-lost-reply": 2}


@pytest.mark.parametrize(("variant", "effects", "passed"), [("default", PLAIN_ONE_ASK, 3),
                                                             ("reask", PLAIN_CALLED_AGAIN, 4),
                                                             ("model-retry", PLAIN_CALLED_AGAIN, 4)])
def test_control_plain_tool(variant, effects, passed):
    assert plain_runs(variant) == (effects, passed)


class Orders:
    """A small owner: commits every send, and can lose the reply."""

    def __init__(self, *, lose_replies: bool = False, answers: bool = True) -> None:
        self.ledger: dict[str, dict[str, Any]] = {}
        self.lose_replies = lose_replies
        self.answers = answers

    def lookup(self, key: str) -> Lookup | None:
        return Lookup(present=key in self.ledger) if self.answers else None

    def tool(self, **options: Any) -> Any:
        @effect_tool(EffectOwner("orders", lookup=self.lookup, lookups=1), **options)
        def create_order(sku: str, quantity: int = 1, *, effect: EffectCall) -> dict[str, Any]:
            """Create an order."""
            self.ledger[effect.key] = {"sku": sku, "quantity": quantity}
            if self.lose_replies:
                raise TimeoutError("the reply was lost")
            return {"order": len(self.ledger)}

        return create_order


def ask(guarded: Any, *, stream: MemoryStream | None = None, variables: dict[str, Any] | None = None,
        arguments: str = '{"sku": "A-1", "quantity": 1}') -> tuple[Any, list[Any]]:
    """One ask that calls the tool once; returns the agent's reply and the stream's tool results."""
    config = TestConfig(ToolCallEvent(name=guarded.name, arguments=arguments, id="call-1"), "done",
                        raise_tool_errors=False)
    stream = stream or MemoryStream()

    async def run() -> tuple[Any, list[Any]]:
        reply = await Agent("orders", config=config, tools=[guarded]).ask("order", stream=stream, variables=variables)
        events = await stream.history.get_events()
        return reply, [event for event in events if isinstance(event, ToolErrorEvent)]

    return asyncio.run(run())


def test_the_model_never_sees_the_dispatch_parameter():
    guarded = Orders().tool(name="place_order", description="Place one order.")
    assert guarded.name == "place_order"
    assert guarded.schema.function.description == "Place one order."
    assert set(guarded.schema.function.parameters["properties"]) == {"sku", "quantity"}


def test_two_threads_asking_for_the_same_write_each_get_it():
    orders = Orders()
    guarded = orders.tool()
    ask(guarded, variables={"thread_id": "a"})
    ask(guarded, variables={"thread_id": "b"})
    assert len(orders.ledger) == 2


def test_two_streams_with_no_thread_each_get_the_write():
    orders = Orders()
    guarded = orders.tool()
    ask(guarded)
    ask(guarded)
    assert len(orders.ledger) == 2


def test_one_stream_asked_twice_sends_once():
    orders = Orders()
    guarded = orders.tool()
    stream = MemoryStream()
    ask(guarded, stream=stream)
    ask(guarded, stream=stream)
    assert len(orders.ledger) == 1


def test_a_defaulted_argument_is_part_of_the_operation():
    orders = Orders()
    guarded = orders.tool()
    ask(guarded, variables={"thread_id": "a"})
    ask(guarded, variables={"thread_id": "a"}, arguments='{"sku": "A-1"}')
    assert len(orders.ledger) == 1


def test_key_from_names_the_operation():
    calls = []

    @effect_tool(EffectOwner("orders", lookup=lambda key: None), key_from="request_id")
    def create_order(request_id: str, effect: EffectCall) -> str:
        """Create an order."""
        calls.append(effect.key)
        return "created"

    ask(create_order, arguments='{"request_id": "r-1"}')
    assert calls == ["r-1"]


def test_key_from_must_name_an_argument():
    with pytest.raises(ValueError, match="not an argument"):
        Orders().tool(key_from="order_id")


def test_an_unknown_outcome_with_raise_reaches_the_model_as_a_tool_error():
    orders = Orders(lose_replies=True, answers=False)
    _, errors = ask(orders.tool(on_unknown="raise"), variables={"thread_id": "a"})
    assert [type(event.error) for event in errors] == [EffectOutcomeUnknown]
