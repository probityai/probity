"""The shipped lost-reply scenarios: the guard alone, through LangGraph, and a plain tool as the control."""

from __future__ import annotations

import json
from typing import Any

import pytest
from probity_effects import (
    EffectCall,
    EffectGuard,
    EffectOwner,
    Journal,
    Lookup,
    UnnamedOperation,
)
from probity_effects.langgraph import effect_tool
from probity_effects.testing import (
    LANGGRAPH_VARIANTS,
    drive_langgraph,
    judge,
    lost_reply_scenarios,
    run_langgraph_scenario,
    scenario_owner,
)

#: The scenarios the first corpus shipped; a later corpus may add scenarios, never drop these.
FIRST_EIGHT = {"confirmed", "commit-then-lost-reply", "commit-then-lost-reply-deduplicating",
               "owner-unreachable-after-lost-reply", "lost-before-commit", "late-commit-after-missed-lookup",
               "definite-no-effect", "lease-lost-after-lost-reply"}


def test_every_scenario_the_corpus_pairs_with_a_case_is_driven():
    from agent_evidence_vectors import uncertaineffect

    manifest = json.loads((uncertaineffect.ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    paired = {entry["runtime"]["scenario"]["id"] for entry in manifest["vectors"]}
    driven = [scenario["id"] for scenario in lost_reply_scenarios()]
    assert len(driven) == len(set(driven))
    assert set(driven) == paired
    assert FIRST_EIGHT <= paired


def test_guard_alone_passes(lost_reply_scenario):
    with scenario_owner(lost_reply_scenario) as run:
        journal = Journal()
        EffectGuard(run.owner, journal).perform("create_order", lost_reply_scenario["operation"]["args"],
                                                fencing_token=run.fencing_token)
        verdict = judge(run, journal, variant="guard")
    assert verdict.passed, verdict.problems


def order_tools(owner, journal):
    @effect_tool(owner, journal=journal)
    def create_order(sku: str, quantity: int, effect: EffectCall) -> dict[str, Any]:
        """Create an order at the order service."""
        raise AssertionError("the scenario owner performs the send")

    return [create_order]


@pytest.mark.parametrize("variant", LANGGRAPH_VARIANTS)
def test_guarded_langgraph_tool_passes(lost_reply_scenario, variant):
    verdict = run_langgraph_scenario(order_tools, lost_reply_scenario, variant=variant)
    assert verdict.passed, verdict.problems


def plain_tools(url):
    """The control: the same write as an ordinary tool, the way a plain retry path sends it."""
    import httpx
    from langchain_core.tools import tool

    @tool
    def create_order(sku: str, quantity: int) -> str:
        """Create an order at the order service."""
        reply = httpx.post(url + "/effects", json={"args": {"quantity": quantity, "sku": sku},
                                                    "idempotencyKey": "order-7f3a"}, timeout=5.0)
        reply.raise_for_status()
        return "confirmed"

    return [create_order]


def plain_effects(variant: str) -> dict[str, int]:
    counts = {}
    for scenario in lost_reply_scenarios():
        with scenario_owner(scenario) as run:
            drive_langgraph(lambda owner, journal: plain_tools(run.url), run, None, variant=variant)
            counts[scenario["id"]] = run.state.effects
    return counts


def test_control_plain_tool_duplicates_under_retry_policy():
    counts = plain_effects("retry")
    # The node retry runs every tool call in the step again, so a write whose reply arrived is sent twice too.
    assert counts["confirmed"] == 2
    assert counts["commit-then-lost-reply"] == 2
    assert counts["owner-unreachable-after-lost-reply"] == 2


def test_control_plain_tool_duplicates_when_the_model_calls_again():
    counts = plain_effects("model-retry")
    assert counts["commit-then-lost-reply"] == 2
    assert counts["confirmed"] == 1


def test_a_langgraph_call_with_no_thread_and_no_key_sends_nothing():
    ledger = []
    owner = EffectOwner("orders", lookup=lambda key: Lookup(present=False))

    @effect_tool(owner)
    def create_order(sku: str, effect: EffectCall) -> str:
        """Create an order."""
        ledger.append(effect.key)
        return "created"

    with pytest.raises(UnnamedOperation):
        create_order.invoke({"sku": "A-1"})
    assert ledger == []


def test_two_langgraph_threads_asking_for_the_same_write_each_get_it():
    ledger = []
    owner = EffectOwner("orders", lookup=lambda key: Lookup(present=False))

    @effect_tool(owner)
    def create_order(sku: str, effect: EffectCall) -> str:
        """Create an order."""
        ledger.append(effect.key)
        return "created"

    for thread in ("a", "b"):
        create_order.invoke({"sku": "A-1"}, {"configurable": {"thread_id": thread}})
    assert len(set(ledger)) == 2
