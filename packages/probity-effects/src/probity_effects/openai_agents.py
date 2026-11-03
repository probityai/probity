"""A function tool for the OpenAI Agents SDK, guarded against lost replies.

The SDK hands a tool exception to the model as an error string, and the model or a supervisor
running the session again then sends the write blind. This tool never raises a lost reply: each
call goes through the guard, which reads the journal first.
"""

from collections.abc import Callable
from typing import Any

from probity_effects._tool import (
    GuardedBody,
    UnnamedOperation,
    check_on_unknown,
    thread_and_token,
)
from probity_effects.guard import EffectOutcomeUnknown
from probity_effects.journal import Journal
from probity_effects.owner import EffectOwner


def effect_function_tool(owner: EffectOwner, *, journal: Journal | None = None, name: str | None = None,
                         description: str | None = None, key_from: str | None = None,
                         on_unknown: str = "report", **options: Any) -> Callable[[Callable[..., Any]], Any]:
    """Decorate a function that performs one write into a guarded ``FunctionTool``.

    The function's parameters, except one annotated ``EffectCall``, become the tool's arguments. That
    parameter receives the dispatch: put ``effect.key`` in the request the owner deduplicates by. The key
    is derived from the run's thread, the tool name and the arguments, unless ``key_from`` names an
    argument that carries one; a call with neither is refused with
    :class:`~probity_effects.UnnamedOperation`, because a key that names no thread is the same for
    everyone. The thread and any fencing token come from the context given to ``Runner.run``, a mapping or
    an object with ``thread_id`` and ``fencing_token``: use the same ``thread_id`` for every run of one
    conversation. An unknown outcome is reported to the model as a tool result, or stops the run with
    ``on_unknown="raise"``. The SDK wraps what a tool raises, so a stopped run raises its ``UserError``,
    whose ``__cause__`` is the :class:`EffectOutcomeUnknown` or the refusal. Other keywords go to
    ``function_tool``.
    """
    check_on_unknown(on_unknown)

    def decorate(func: Callable[..., Any]) -> Any:
        from agents import function_tool
        from agents.tool_context import ToolContext

        body = GuardedBody(func, owner, journal=journal, name=name, key_from=key_from, on_unknown=on_unknown)
        options.setdefault("failure_error_function", _surface_refusals)
        return function_tool(body.contextual(ToolContext, _thread), name_override=body.name,
                             description_override=description, **options)

    return decorate


def _thread(context: Any) -> tuple[str, int | None]:
    return thread_and_token(context.context)


def _surface_refusals(context: Any, error: Exception) -> str:
    """Stop the run on what the guard itself refuses; the rest goes to the model as the SDK's default does."""
    from agents.tool import default_tool_error_function

    if isinstance(error, (EffectOutcomeUnknown, UnnamedOperation)):
        raise error
    return default_tool_error_function(context, error)
