"""Drive a tool through the lost-reply scenarios agent-evidence-vectors ships, and judge each run.

Install ``probity-effects[testing]``. Each scenario starts a counting owner on the loopback interface
that commits, loses replies, answers lookups and moves a lease as the scenario says. A run is judged
three ways: the owner holds an accepted number of effects and the reported outcome is accepted with
it; the record the journal exports is allowed by the reference reader; and the journal recorded
exactly the dispatches and lookups the owner saw.
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from probity_effects.journal import Journal
from probity_effects.owner import EffectCall, EffectOwner, Lookup, NoEffect

#: The framework paths a LangGraph tool is driven through.
LANGGRAPH_VARIANTS = ("default", "retry", "resume", "model-retry")
ToolsFactory = Callable[[EffectOwner, Journal], Sequence[Any]]


def lost_reply_scenarios() -> list[dict[str, Any]]:
    """The runtime scenarios of the uncertain-effect corpus in the installed agent-evidence-vectors."""
    from agent_evidence_vectors import uncertaineffect

    return uncertaineffect.shipped_scenarios()


@dataclass
class ScenarioRun:
    """A counting owner serving one scenario: the port a tool uses, its counts, and its base URL."""

    scenario: dict[str, Any]
    owner: EffectOwner
    state: Any
    url: str

    @property
    def fencing_token(self) -> int | None:
        lease = self.scenario["owner"].get("lease")
        return None if lease is None else int(lease["token"])


@contextmanager
def scenario_owner(scenario: dict[str, Any], *, lookup_interval: float = 0.02) -> Iterator[ScenarioRun]:
    """Serve one scenario's counting owner and the :class:`EffectOwner` that speaks to it."""
    from agent_evidence_vectors import uncertaineffect_runtime

    with uncertaineffect_runtime.effect_owner(scenario) as (url, state):
        yield ScenarioRun(scenario, _http_owner(url, scenario, lookup_interval), state, url)


def _get(url: str) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(url, timeout=5) as reply:
            answer: dict[str, Any] = json.loads(reply.read())
            return answer
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _http_owner(url: str, scenario: dict[str, Any], interval: float) -> EffectOwner:
    def send(call: EffectCall) -> dict[str, Any]:
        body: dict[str, Any] = {"args": dict(call.args), "idempotencyKey": call.key}
        if call.fencing_token is not None:
            body["fencingToken"] = call.fencing_token
        request = urllib.request.Request(url + "/effects", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as reply:
                answer: dict[str, Any] = json.loads(reply.read())
                return answer
        except urllib.error.HTTPError as error:
            if error.code == 409:
                raise NoEffect("the owner answered 409") from error
            raise

    def lookup(key: str) -> Lookup | None:
        answer = _get(url + "/effects/" + urllib.parse.quote(key, safe=""))
        return None if answer is None else Lookup(present=answer["result"] == "present", final=bool(answer["final"]))

    def lease() -> int | None:
        answer = _get(url + "/lease")
        return None if answer is None else int(answer["token"])

    spec = scenario["owner"]
    return EffectOwner(id="scenario-owner", send=send, lookup=lookup,
                       lease=lease if spec.get("lease") else None,
                       deduplicates_by_key=bool(spec["deduplicatesByKey"]), lookup_interval=interval)


@dataclass
class Verdict:
    """One scenario run, judged. ``problems`` is empty when it passed."""

    scenario: str
    variant: str
    effects: int
    calls: int
    outcome: str | None
    problems: list[str] = field(default_factory=list)
    record: dict[str, Any] | None = None
    record_decision: dict[str, str] | None = None

    @property
    def passed(self) -> bool:
        return not self.problems


def judge(run: ScenarioRun, journal: Journal, *, variant: str = "") -> Verdict:
    """Judge one run by the owner's counts, the exported record and the journal's fidelity."""
    from agent_evidence_vectors import uncertaineffect, uncertaineffect_runtime

    state, scenario = run.state, run.scenario
    keys = journal.keys()
    verdict = Verdict(scenario=scenario["id"], variant=variant, effects=state.effects, calls=state.calls,
                      outcome=None)
    if len(keys) != 1:
        verdict.problems.append(f"the journal holds {len(keys)} operations; the scenario performs one")
        verdict.problems.extend(uncertaineffect_runtime.judge(scenario, state, None))
        return verdict
    history = journal.history(keys[0])
    verdict.outcome = history.outcome
    verdict.problems.extend(uncertaineffect_runtime.judge(scenario, state, history.outcome))
    if len(history.attempts) != state.calls:
        verdict.problems.append(f"the journal records {len(history.attempts)} dispatch(es); "
                                f"the owner saw {state.calls} call(s)")
    if history.lookups != state.lookups:
        verdict.problems.append(f"the journal records {history.lookups} lookup(s); "
                                f"the owner answered {state.lookups}")
    verdict.record = journal.record(keys[0], owner_effects=state.effects)
    with tempfile.TemporaryDirectory() as work:
        path = Path(work) / "record.json"
        path.write_text(json.dumps(verdict.record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        verdict.record_decision = uncertaineffect.verify(path)
    if verdict.record_decision["decision"] != "allow":
        verdict.problems.append(f"the reference reader denies the record: {verdict.record_decision['reason']}")
    return verdict


class SimulatedStop(BaseException):
    """The process stops between the owner's answer and the journal's note of it."""


def _stopping(owner: EffectOwner) -> EffectOwner:
    sender = owner.send
    if sender is None:
        raise TypeError("the scenario owner carries a send")

    def send(call: EffectCall) -> Any:
        try:
            sender(call)
        finally:
            raise SimulatedStop()

    return dataclasses.replace(owner, send=send)


def run_langgraph_scenario(make_tools: ToolsFactory, scenario: dict[str, Any], *, variant: str = "default",
                           tool: str | None = None, args: dict[str, Any] | None = None) -> Verdict:
    """Drive the tools ``make_tools(owner, journal)`` builds through one scenario and judge the run.

    ``tool`` names the guarded tool (default: the first), ``args`` one valid set of its arguments
    (default: the scenario's own). The variants are the framework paths a lost reply takes:
    ``default`` (no retry), ``retry`` (a ``RetryPolicy`` on the tool node, and a second tool in the
    same step whose first call fails, so the node runs again), ``resume`` (the process stops right
    after the first send, and a new process resumes the checkpointed thread from the journal file) and
    ``model-retry`` (the model calls the tool again while the result is not committed).
    """
    with scenario_owner(scenario) as run, tempfile.TemporaryDirectory() as work:
        path = Path(work) / "journal.jsonl"
        drive_langgraph(make_tools, run, path, variant=variant, tool=tool, args=args)
        return judge(run, Journal.open(path), variant=variant)


def drive_langgraph(make_tools: ToolsFactory, run: ScenarioRun, journal_path: Path, *, variant: str = "default",
                    tool: str | None = None, args: dict[str, Any] | None = None) -> str:
    """Run one scenario through a LangGraph graph; returns the error the run ended with, if any."""
    if variant not in LANGGRAPH_VARIANTS:
        raise ValueError(f"variant is one of {LANGGRAPH_VARIANTS}")
    from langchain_core.messages import HumanMessage
    from langgraph.checkpoint.memory import InMemorySaver

    arguments = dict(args if args is not None else run.scenario["operation"]["args"])
    config = {"configurable": {"thread_id": "lost-reply-scenario", "fencing_token": run.fencing_token}}
    saver = InMemorySaver() if variant == "resume" else None
    first_owner = _stopping(run.owner) if variant == "resume" else run.owner
    graph = _graph(make_tools(first_owner, Journal.open(journal_path)), tool, arguments, variant, saver)
    try:
        graph.invoke({"messages": [HumanMessage(content="perform the operation")]}, config)
    except SimulatedStop:
        resumed = _graph(make_tools(run.owner, Journal.open(journal_path)), tool, arguments, variant, saver)
        try:
            resumed.invoke(None, config)
        except Exception as error:  # noqa: BLE001 - the error is the run's result
            return f"{type(error).__name__}: {error}"
    except Exception as error:  # noqa: BLE001 - the error is the run's result
        return f"{type(error).__name__}: {error}"
    return ""


def _graph(tools: Sequence[Any], tool: str | None, arguments: dict[str, Any], variant: str, saver: Any) -> Any:
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import tool as as_tool
    from langgraph.graph import START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode, tools_condition
    from langgraph.types import RetryPolicy

    effect = next((item for item in tools if tool is None or item.name == tool), None)
    if effect is None:
        raise ValueError(f"no tool named {tool!r}")
    sibling_calls = {"n": 0}

    @as_tool
    def read_inventory(sku: str) -> str:
        """Read stock for a SKU; its first call loses its connection."""
        sibling_calls["n"] += 1
        if sibling_calls["n"] == 1:
            raise ConnectionResetError("the inventory read lost its connection")
        return "in stock"

    calls = [{"name": effect.name, "args": arguments, "id": "call-1"}]
    node_tools = [*tools]
    if variant == "retry":
        calls.append({"name": "read_inventory", "args": {"sku": "any"}, "id": "call-2"})
        node_tools.append(read_inventory)
    recalls = {"left": 2 if variant == "model-retry" else 0, "n": 1}

    def model(state: MessagesState) -> dict[str, Any]:
        last = state["messages"][-1]
        if not isinstance(last, ToolMessage):
            return {"messages": [AIMessage(content="", tool_calls=calls)]}
        result = next((message for message in reversed(state["messages"])
                       if isinstance(message, ToolMessage) and message.name == effect.name), last)
        text = str(result.content)
        if recalls["left"] and (text.startswith(("outcome unknown", "not run")) or result.status == "error"):
            recalls["left"] -= 1
            recalls["n"] += 1
            return {"messages": [AIMessage(content="", tool_calls=[
                {"name": effect.name, "args": arguments, "id": f"call-1-{recalls['n']}"}])]}
        return {"messages": [AIMessage(content="done")]}

    # The documented RetryPolicy with its default retry_on, which retries a lost connection.
    policy = RetryPolicy(max_attempts=3, initial_interval=0.01, jitter=False) if variant == "retry" else None
    graph = StateGraph(MessagesState)
    graph.add_node("model", model)
    # A model can only call again after an error it was shown, so that path turns tool errors into messages.
    node = ToolNode(node_tools, handle_tool_errors=True) if variant == "model-retry" else ToolNode(node_tools)
    graph.add_node("tools", node, retry_policy=policy)
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", tools_condition)
    graph.add_edge("tools", "model")
    return graph.compile(checkpointer=saver)
