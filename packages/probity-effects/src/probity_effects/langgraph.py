"""A LangChain tool, for LangGraph's ToolNode or any agent built on it, guarded against lost replies.

The tool never lets a lost reply escape as an exception, so neither a node retry policy nor a
resumed thread nor a model that calls again can send the write blind: each call goes through the
guard, which reads the journal first.
"""

import inspect
from collections.abc import Callable
from typing import Any

from probity_effects._tool import GuardedBody, check_on_unknown, thread_and_token
from probity_effects.journal import Journal
from probity_effects.owner import EffectOwner


def effect_tool(owner: EffectOwner, *, journal: Journal | None = None, name: str | None = None,
                description: str | None = None, key_from: str | None = None,
                on_unknown: str = "report") -> Callable[[Callable[..., Any]], Any]:
    """Decorate a function that performs one write into a guarded ``StructuredTool``.

    The function's parameters, except one annotated ``EffectCall``, become the tool's arguments. That
    parameter receives the dispatch: put ``effect.key`` in the request the owner deduplicates by. The key
    is derived from the graph's ``thread_id``, the tool name and the arguments, unless ``key_from`` names an
    argument that carries one; a call with neither is refused with
    :class:`~probity_effects.UnnamedOperation`, because a key that names no thread is the same for
    everyone. A worker holding a lease passes its token as ``fencing_token`` in the graph's
    ``configurable``. An unknown outcome is reported to the model as a tool result, or raised as
    :class:`EffectOutcomeUnknown` with ``on_unknown="raise"``.
    """
    check_on_unknown(on_unknown)

    def decorate(func: Callable[..., Any]) -> Any:
        from langchain_core.runnables import RunnableConfig
        from langchain_core.tools import StructuredTool
        from langchain_core.tools.base import create_schema_from_function

        body = GuardedBody(func, owner, journal=journal, name=name, key_from=key_from, on_unknown=on_unknown)
        schema = create_schema_from_function(body.name, func,
                                             filter_args=[body.effect_param] if body.effect_param else [])
        summary = description or inspect.getdoc(func) or body.name

        if body.asynchronous:
            async def arun(config: RunnableConfig, **args: Any) -> Any:
                scope, token = _thread(config)
                return await body.arun(args, scope=scope, fencing_token=token)

            return StructuredTool.from_function(coroutine=arun, name=body.name, args_schema=schema,
                                                description=summary)

        def run(config: RunnableConfig, **args: Any) -> Any:
            scope, token = _thread(config)
            return body.run(args, scope=scope, fencing_token=token)

        return StructuredTool.from_function(func=run, name=body.name, args_schema=schema, description=summary)

    return decorate


def _thread(config: Any) -> tuple[str, int | None]:
    return thread_and_token((config or {}).get("configurable") or {})
