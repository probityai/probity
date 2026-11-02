"""A LangChain tool, for LangGraph's ToolNode or any agent built on it, guarded against lost replies.

The tool never lets a lost reply escape as an exception, so neither a node retry policy nor a
resumed thread nor a model that calls again can send the write blind: each call goes through the
guard, which reads the journal first.
"""

import inspect
import typing
from collections.abc import Callable
from typing import Any

from probity_effects.guard import EffectGuard, EffectOutcomeUnknown, Outcome
from probity_effects.journal import Journal
from probity_effects.owner import EffectCall, EffectOwner

ON_UNKNOWN = ("report", "raise")


def effect_tool(owner: EffectOwner, *, journal: Journal | None = None, name: str | None = None,
                description: str | None = None, key_from: str | None = None,
                on_unknown: str = "report") -> Callable[[Callable[..., Any]], Any]:
    """Decorate a function that performs one write into a guarded ``StructuredTool``.

    The function's parameters, except one annotated ``EffectCall``, become the tool's arguments. That
    parameter receives the dispatch: put ``effect.key`` in the request the owner deduplicates by. The key
    is derived from the graph's ``thread_id``, the tool name and the arguments, unless ``key_from`` names an
    argument that carries one. A worker holding a lease passes its token as ``fencing_token`` in the
    graph's ``configurable``. An unknown outcome is reported to the model as a tool result, or raised
    as :class:`EffectOutcomeUnknown` with ``on_unknown="raise"``.
    """
    if on_unknown not in ON_UNKNOWN:
        raise ValueError(f"on_unknown is one of {ON_UNKNOWN}")
    guard = EffectGuard(owner, journal)

    def decorate(func: Callable[..., Any]) -> Any:
        from langchain_core.runnables import RunnableConfig
        from langchain_core.tools import StructuredTool
        from langchain_core.tools.base import create_schema_from_function

        tool_name = name or func.__name__
        effect_param = _effect_parameter(func)
        schema = create_schema_from_function(tool_name, func,
                                             filter_args=[effect_param] if effect_param else [])
        if key_from is not None and key_from not in schema.model_fields:
            raise ValueError(f"key_from names {key_from!r}, which is not an argument of {tool_name}")

        def body_args(call: EffectCall, args: dict[str, Any]) -> dict[str, Any]:
            return {**args, effect_param: call} if effect_param else dict(args)

        def settle(outcome: Outcome) -> Any:
            return _render(tool_name, owner, outcome, on_unknown)

        if inspect.iscoroutinefunction(func):
            async def arun(config: RunnableConfig, **args: Any) -> Any:
                outcome = await guard.aperform(tool_name, args, send=lambda call: func(**body_args(call, args)),
                                               key=_key(args, key_from), scope=_scope(config),
                                               fencing_token=_token(config))
                return settle(outcome)

            return StructuredTool.from_function(coroutine=arun, name=tool_name, args_schema=schema,
                                                description=description or inspect.getdoc(func) or tool_name)

        def run(config: RunnableConfig, **args: Any) -> Any:
            outcome = guard.perform(tool_name, args, send=lambda call: func(**body_args(call, args)),
                                    key=_key(args, key_from), scope=_scope(config), fencing_token=_token(config))
            return settle(outcome)

        return StructuredTool.from_function(func=run, name=tool_name, args_schema=schema,
                                            description=description or inspect.getdoc(func) or tool_name)

    return decorate


def _effect_parameter(func: Callable[..., Any]) -> str | None:
    try:
        hints = typing.get_type_hints(func)
    except (NameError, TypeError):
        hints = {}
    for parameter in inspect.signature(func).parameters.values():
        annotation = hints.get(parameter.name, parameter.annotation)
        if annotation is EffectCall or annotation == "EffectCall":
            return parameter.name
    return None


def _configurable(config: Any) -> dict[str, Any]:
    return dict((config or {}).get("configurable") or {})


def _scope(config: Any) -> str:
    thread = _configurable(config).get("thread_id")
    return "" if thread is None else str(thread)


def _token(config: Any) -> int | None:
    token = _configurable(config).get("fencing_token")
    return None if token is None else int(token)


def _key(args: dict[str, Any], key_from: str | None) -> str | None:
    return None if key_from is None else str(args[key_from])


def _render(tool_name: str, owner: EffectOwner, outcome: Outcome, on_unknown: str) -> Any:
    if outcome.outcome == "committed":
        if outcome.sent and outcome.value is not None:
            return outcome.value
        return f"committed: {owner.id} holds this effect (idempotency key {outcome.key}); {outcome.reason}."
    if outcome.outcome == "not_run":
        return f"not run: {outcome.reason}."
    if on_unknown == "raise":
        raise EffectOutcomeUnknown(outcome)
    return (f"outcome unknown: {outcome.reason}. The effect may have happened. Do not call {tool_name} again "
            f"for this request; ask {owner.id} or the user what it holds (idempotency key {outcome.key}).")
