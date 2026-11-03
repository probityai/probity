"""The Agents SDK adapter: the eight scenarios on each SDK path, with a plain function tool as the control."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from agent_evidence_vectors import uncertaineffect_runtime
from agents import Agent, Runner, function_tool
from agents.exceptions import UserError
from agents.testing import ScriptedModel, assistant_message, function_call
from probity_effects import (
    EffectCall,
    EffectOutcomeUnknown,
    EffectOwner,
    Lookup,
    UnnamedOperation,
)
from probity_effects.openai_agents import effect_function_tool
from probity_effects.testing import (
    OPENAI_AGENTS_VARIANTS,
    drive_openai_agents,
    lost_reply_scenarios,
    run_openai_agents_scenario,
    scenario_owner,
)


def order_tools(owner, journal):
    @effect_function_tool(owner, journal=journal)
    def create_order(sku: str, quantity: int, effect: EffectCall) -> dict[str, Any]:
        """Create an order at the order service."""
        raise AssertionError("the scenario owner performs the send")

    return [create_order]


def async_order_tools(owner, journal):
    @effect_function_tool(owner, journal=journal)
    async def create_order(sku: str, quantity: int, effect: EffectCall) -> dict[str, Any]:
        """Create an order at the order service."""
        raise AssertionError("the scenario owner performs the send")

    return [create_order]


@pytest.mark.parametrize("variant", OPENAI_AGENTS_VARIANTS)
def test_guarded_function_tool_passes(lost_reply_scenario, variant):
    verdict = run_openai_agents_scenario(order_tools, lost_reply_scenario, variant=variant)
    assert verdict.passed, verdict.problems


@pytest.mark.parametrize("variant", OPENAI_AGENTS_VARIANTS)
def test_guarded_async_function_tool_passes(lost_reply_scenario, variant):
    verdict = run_openai_agents_scenario(async_order_tools, lost_reply_scenario, variant=variant)
    assert verdict.passed, verdict.problems


def plain_tools(run):
    """The control: the same write as an ordinary function tool."""
    key = run.scenario["operation"]["idempotencyKey"]

    @function_tool
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
            error = drive_openai_agents(lambda owner, journal: plain_tools(run), run, None, variant=variant)
            counts[scenario["id"]] = run.state.effects
            passed += not uncertaineffect_runtime.judge(scenario, run.state, "not_run" if error else "committed")
    return counts, passed


PLAIN_ONE_RUN = {"confirmed": 1, "commit-then-lost-reply": 1, "commit-then-lost-reply-deduplicating": 1,
                 "owner-unreachable-after-lost-reply": 1, "lost-before-commit": 0,
                 "late-commit-after-missed-lookup": 0, "definite-no-effect": 0, "lease-lost-after-lost-reply": 1}
PLAIN_CALLED_AGAIN = {"confirmed": 1, "commit-then-lost-reply": 2, "commit-then-lost-reply-deduplicating": 1,
                      "owner-unreachable-after-lost-reply": 2, "lost-before-commit": 1,
                      "late-commit-after-missed-lookup": 2, "definite-no-effect": 1,
                      "lease-lost-after-lost-reply": 2}


@pytest.mark.parametrize(("variant", "effects", "passed"), [("default", PLAIN_ONE_RUN, 3),
                                                             ("session-resume", PLAIN_CALLED_AGAIN, 4),
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
        @effect_function_tool(EffectOwner("orders", lookup=self.lookup, lookups=1), **options)
        def create_order(sku: str, quantity: int = 1, *, effect: EffectCall) -> dict[str, Any]:
            """Create an order."""
            self.ledger[effect.key] = {"sku": sku, "quantity": quantity}
            if self.lose_replies:
                raise TimeoutError("the reply was lost")
            return {"order": len(self.ledger)}

        return create_order


def run_once(tool: Any, context: Any, *, arguments: dict[str, Any] | None = None) -> Any:
    steps = [[function_call(tool.name, arguments or {"sku": "A-1", "quantity": 1}, call_id="call-1")],
             [assistant_message("done")]]
    agent = Agent(name="orders", instructions="Order.", tools=[tool], model=ScriptedModel(steps))
    return asyncio.run(Runner.run(agent, "order", context=context))


def outputs(result: Any) -> list[str]:
    return [str(item.output) for item in result.new_items if item.type == "tool_call_output_item"]


def test_the_model_never_sees_the_dispatch_parameter():
    tool = Orders().tool(name="place_order", description="Place one order.")
    assert tool.name == "place_order"
    assert tool.description == "Place one order."
    assert set(tool.params_json_schema["properties"]) == {"sku", "quantity"}


def test_a_call_with_no_thread_and_no_key_sends_nothing():
    orders = Orders()
    with pytest.raises(UserError) as stopped:
        run_once(orders.tool(), None)
    assert isinstance(stopped.value.__cause__, UnnamedOperation)
    assert orders.ledger == {}


def test_two_threads_asking_for_the_same_write_each_get_it():
    orders = Orders()
    tool = orders.tool()
    first = run_once(tool, {"thread_id": "a"})
    second = run_once(tool, {"thread_id": "b"})
    assert len(orders.ledger) == 2
    assert all(not text.startswith("committed:") for text in outputs(first) + outputs(second))


def test_the_context_may_be_an_object():
    class Run:
        thread_id = "a"
        fencing_token = None

    orders = Orders()
    run_once(orders.tool(), Run())
    assert len(orders.ledger) == 1


def test_a_second_call_on_one_thread_reports_the_first_and_sends_nothing():
    orders = Orders()
    tool = orders.tool()
    run_once(tool, {"thread_id": "a"})
    second = run_once(tool, {"thread_id": "a"})
    assert len(orders.ledger) == 1
    assert outputs(second)[0].startswith("committed: orders holds this effect")


def test_a_defaulted_argument_is_part_of_the_operation():
    orders = Orders()
    tool = orders.tool()
    run_once(tool, {"thread_id": "a"}, arguments={"sku": "A-1", "quantity": 1})
    run_once(tool, {"thread_id": "a"}, arguments={"sku": "A-1"})
    assert len(orders.ledger) == 1


def test_key_from_needs_no_thread():
    calls = []

    @effect_function_tool(EffectOwner("orders", lookup=lambda key: None), key_from="request_id")
    def create_order(request_id: str, effect: EffectCall) -> str:
        """Create an order."""
        calls.append(effect.key)
        return "created"

    run_once(create_order, None, arguments={"request_id": "r-1"})
    assert calls == ["r-1"]


def test_key_from_must_name_an_argument():
    with pytest.raises(ValueError, match="not an argument"):
        Orders().tool(key_from="order_id")


def test_on_unknown_must_be_known():
    with pytest.raises(ValueError, match="on_unknown"):
        effect_function_tool(EffectOwner("orders", lookup=lambda key: None), on_unknown="ignore")


def test_an_unknown_outcome_is_reported_to_the_model_by_default():
    orders = Orders(lose_replies=True, answers=False)
    result = run_once(orders.tool(), {"thread_id": "a"})
    assert outputs(result)[0].startswith("outcome unknown")


def test_on_unknown_raise_stops_the_run():
    orders = Orders(lose_replies=True, answers=False)
    with pytest.raises(UserError) as stopped:
        run_once(orders.tool(on_unknown="raise"), {"thread_id": "a"})
    assert isinstance(stopped.value.__cause__, EffectOutcomeUnknown)


def test_bad_arguments_from_the_model_reach_the_model():
    orders = Orders()
    result = run_once(orders.tool(), {"thread_id": "a"}, arguments={"quantity": "many"})
    assert outputs(result)[0].startswith("An error occurred")
    assert orders.ledger == {}


def test_an_interrupted_async_send_is_reconciled_on_the_next_call():
    ledger: dict[str, int] = {}

    @effect_function_tool(EffectOwner("orders", lookup=lambda key: Lookup(present=key in ledger)), timeout=0.05)
    async def create_order(sku: str, effect: EffectCall) -> str:
        """Create an order."""
        ledger[effect.key] = ledger.get(effect.key, 0) + 1
        await asyncio.sleep(1)
        return "created"

    first = run_once(create_order, {"thread_id": "a"}, arguments={"sku": "A-1"})
    assert "timed out" in outputs(first)[0]
    second = run_once(create_order, {"thread_id": "a"}, arguments={"sku": "A-1"})
    assert list(ledger.values()) == [1]
    assert outputs(second)[0].startswith("committed:")
