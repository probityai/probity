"""Drive a tool through the lost-reply scenarios agent-evidence-vectors ships, and judge each run.

Install ``probity-effects[testing]``. Each scenario starts a counting owner on the loopback interface
that commits, loses replies, answers lookups and moves a lease as the scenario says. A run is judged
three ways: the owner holds an accepted number of effects and the reported outcome is accepted with
it; the record the journal exports is allowed by the reference reader; and the journal recorded
exactly the dispatches and lookups the owner saw.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import itertools
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
#: The framework paths an OpenAI Agents SDK tool is driven through.
OPENAI_AGENTS_VARIANTS = ("default", "session-resume", "model-retry")
#: The framework paths an AG2 tool is driven through.
AG2_VARIANTS = ("default", "reask", "model-retry")
#: How a tool result says the write is not settled: the SDK's own error text, and the guard's.
UNSETTLED = ("An error occurred", "outcome unknown", "not run")
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


def _stopping(owner: EffectOwner, signal: Callable[[], Any] | None = None) -> EffectOwner:
    sender = owner.send
    if sender is None:
        raise TypeError("the scenario owner carries a send")

    def send(call: EffectCall) -> Any:
        try:
            sender(call)
        finally:
            if signal is not None:
                signal()
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


def run_openai_agents_scenario(make_tools: ToolsFactory, scenario: dict[str, Any], *, variant: str = "default",
                               tool: str | None = None, args: dict[str, Any] | None = None) -> Verdict:
    """Drive the tools ``make_tools(owner, journal)`` builds through one scenario and judge the run.

    ``tool`` and ``args`` work as in :func:`run_langgraph_scenario`. The variants are the paths a lost
    reply takes in the SDK, which has no tool retry setting: ``default`` (one run, and the model finishes
    after the first tool result), ``session-resume`` (the process stops right after the first send, and a
    supervisor runs the same ``SQLiteSession`` again from the journal file while the write is not settled)
    and ``model-retry`` (the model calls the tool again while the write is not settled).
    """
    with scenario_owner(scenario) as run, tempfile.TemporaryDirectory() as work:
        path = Path(work) / "journal.jsonl"
        drive_openai_agents(make_tools, run, path, variant=variant, tool=tool, args=args)
        return judge(run, Journal.open(path), variant=variant)


def drive_openai_agents(make_tools: ToolsFactory, run: ScenarioRun, journal_path: Path | None, *,
                        variant: str = "default", tool: str | None = None,
                        args: dict[str, Any] | None = None) -> str:
    """Run one scenario through ``Runner.run``; returns the error the run ended with, if any."""
    if variant not in OPENAI_AGENTS_VARIANTS:
        raise ValueError(f"variant is one of {OPENAI_AGENTS_VARIANTS}")
    from agents import set_tracing_disabled

    set_tracing_disabled(True)
    arguments = dict(args if args is not None else run.scenario["operation"]["args"])
    with tempfile.TemporaryDirectory() as work:
        return asyncio.run(_agents_turns(make_tools, run, journal_path, Path(work) / "session.db",
                                         variant, tool, arguments))


async def _agents_turns(make_tools: ToolsFactory, run: ScenarioRun, journal_path: Path | None, session_path: Path,
                        variant: str, tool: str | None, arguments: dict[str, Any]) -> str:
    from agents import Runner, SQLiteSession

    resuming = variant == "session-resume"
    session = SQLiteSession("lost-reply-scenario", session_path) if resuming else None
    context = {"thread_id": "lost-reply-scenario", "fencing_token": run.fencing_token}
    tools = make_tools(_stopping(run.owner) if resuming else run.owner, Journal.open(journal_path))
    call_ids = itertools.count(1)
    prompt, ended = "perform the operation", ""
    for _ in range(3 if resuming else 1):
        agent = _agent(tools, tool, arguments, variant, call_ids)
        try:
            result = await Runner.run(agent, prompt, context=context, session=session)
        except SimulatedStop:
            tools = make_tools(run.owner, Journal.open(journal_path))
            prompt = "the run stopped, try again"
            continue
        except Exception as error:  # noqa: BLE001 - the error is the run's result
            return f"{type(error).__name__}: {error}"
        text = _last_tool_output(result)
        if not text.startswith(UNSETTLED):
            return ""
        ended, prompt = text, "that did not go through, try again"
    return ended


def _last_tool_output(result: Any) -> str:
    outputs = [str(item.output) for item in result.new_items if item.type == "tool_call_output_item"]
    return outputs[-1] if outputs else ""


def _agent(tools: Sequence[Any], tool: str | None, arguments: dict[str, Any], variant: str,
           call_ids: Iterator[int]) -> Any:
    from agents import Agent
    from agents.testing import ScriptedModel, assistant_message, function_call

    effect = next((item for item in tools if tool is None or item.name == tool), None)
    if effect is None:
        raise ValueError(f"no tool named {tool!r}")
    recalls = {"left": 2 if variant == "model-retry" else 0}

    def respond(call: Any) -> list[Any]:
        items = call.input if isinstance(call.input, list) else []
        last = items[-1] if items else {}
        answered = last.get("type") == "function_call_output" if isinstance(last, dict) else False
        if answered:
            if not (recalls["left"] and str(last.get("output", "")).startswith(UNSETTLED)):
                return [assistant_message("done")]
            recalls["left"] -= 1
        return [function_call(effect.name, arguments, call_id=f"call-{next(call_ids)}")]

    return Agent(name="scenario", instructions="Perform the operation.", tools=[*tools],
                 model=ScriptedModel([{"responder": respond}] * 8))


def run_ag2_scenario(make_tools: ToolsFactory, scenario: dict[str, Any], *, variant: str = "default",
                     tool: str | None = None, args: dict[str, Any] | None = None) -> Verdict:
    """Drive the tools ``make_tools(owner, journal)`` builds through one scenario and judge the run.

    ``tool`` and ``args`` work as in :func:`run_langgraph_scenario`. The variants are the paths a lost
    reply takes in AG2, whose ``RetryMiddleware`` retries model calls only: ``default`` (one ask, and the
    model finishes after the first tool result), ``reask`` (the process stops right after the first send,
    and a supervisor asks again on the same stream from the journal file while the write is not settled)
    and ``model-retry`` (the model calls the tool again while the write is not settled).
    """
    with scenario_owner(scenario) as run, tempfile.TemporaryDirectory() as work:
        path = Path(work) / "journal.jsonl"
        drive_ag2(make_tools, run, path, variant=variant, tool=tool, args=args)
        return judge(run, Journal.open(path), variant=variant)


def drive_ag2(make_tools: ToolsFactory, run: ScenarioRun, journal_path: Path | None, *, variant: str = "default",
              tool: str | None = None, args: dict[str, Any] | None = None) -> str:
    """Run one scenario through ``Agent.ask``; returns the error the run ended with, if any."""
    if variant not in AG2_VARIANTS:
        raise ValueError(f"variant is one of {AG2_VARIANTS}")
    arguments = dict(args if args is not None else run.scenario["operation"]["args"])
    return asyncio.run(_ag2_asks(make_tools, run, journal_path, variant, tool, arguments))


class _AG2Model:
    """A scripted model client: it calls the tool, then finishes or, if told to, calls again."""

    def __init__(self, tool: str, arguments: dict[str, Any], recalls: int) -> None:
        self.tool, self.arguments, self.recalls = tool, json.dumps(arguments), recalls
        self.calls = itertools.count(1)
        self.unsettled = "the tool was not called"

    async def __call__(self, messages: Sequence[Any], context: Any, **kwargs: Any) -> Any:
        from ag2.events import ModelMessage, ModelResponse, ToolCallEvent, ToolCallsEvent, ToolResultsEvent

        if isinstance(messages[-1], ToolResultsEvent):
            self.unsettled = _ag2_unsettled(messages[-1])
            if not (self.recalls and self.unsettled):
                message = ModelMessage("done")
                await context.send(message)
                return ModelResponse(message)
            self.recalls -= 1
        call = ToolCallEvent(name=self.tool, arguments=self.arguments, id=f"call-{next(self.calls)}")
        return ModelResponse(tool_calls=ToolCallsEvent([call]))


def _ag2_unsettled(results: Any) -> str:
    from ag2.events import TextInput, ToolErrorEvent

    last = results.results[-1]
    text = "".join(part.content for part in last.result.parts if isinstance(part, TextInput))
    return text if isinstance(last, ToolErrorEvent) or text.startswith(UNSETTLED) else ""


async def _until_stopped(ask: Any, stopped: asyncio.Event) -> None:
    """Await an ask, and abandon it when the process stops: AG2 does not unwind a stop as an error."""
    asking, stopping = asyncio.ensure_future(ask), asyncio.ensure_future(stopped.wait())
    await asyncio.wait({asking, stopping}, return_when=asyncio.FIRST_COMPLETED)
    stopping.cancel()
    if not stopped.is_set():
        await asking
        return
    asking.cancel()
    with contextlib.suppress(asyncio.CancelledError, SimulatedStop):
        await asking
    stopped.clear()
    raise SimulatedStop()


async def _ag2_asks(make_tools: ToolsFactory, run: ScenarioRun, journal_path: Path | None, variant: str,
                    tool: str | None, arguments: dict[str, Any]) -> str:
    from ag2 import Agent
    from ag2.stream import MemoryStream
    from ag2.testing import TestConfig

    class Config(TestConfig):
        def copy(self) -> Any:
            return self

        def create(self) -> Any:
            return model

    asking = variant == "reask"
    loop, stopped = asyncio.get_running_loop(), asyncio.Event()
    first_owner = _stopping(run.owner, lambda: loop.call_soon_threadsafe(stopped.set)) if asking else run.owner
    tools = make_tools(first_owner, Journal.open(journal_path))
    effect = next((item for item in tools if tool is None or item.name == tool), None)
    if effect is None:
        raise ValueError(f"no tool named {tool!r}")
    model = _AG2Model(effect.name, arguments, 2 if variant == "model-retry" else 0)
    variables = {"thread_id": "lost-reply-scenario", "fencing_token": run.fencing_token}
    stream, prompt = MemoryStream(), "perform the operation"
    for _ in range(3 if asking else 1):
        try:
            agent = Agent("scenario", config=Config(), tools=[*tools])
            await _until_stopped(agent.ask(prompt, stream=stream, variables=variables), stopped)
        except SimulatedStop:
            # A new process holds the journal file and the thread id; an in-memory stream did not survive.
            tools = make_tools(run.owner, Journal.open(journal_path))
            stream, prompt = MemoryStream(), "the run stopped, try again"
            continue
        except Exception as error:  # noqa: BLE001 - the error is the run's result
            return f"{type(error).__name__}: {error}"
        if not model.unsettled:
            return ""
        prompt = "that did not go through, try again"
    return model.unsettled
