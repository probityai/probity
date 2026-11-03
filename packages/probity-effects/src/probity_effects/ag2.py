"""An AG2 tool, for ``Agent.ask``, guarded against lost replies.

AG2 hands a tool exception to the model as a ``ToolErrorEvent``, and the model or a supervisor asking
again then sends the write blind. This tool never raises a lost reply: each call goes through the
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
                on_unknown: str = "report", **options: Any) -> Callable[[Callable[..., Any]], Any]:
    """Decorate a function that performs one write into a guarded AG2 tool.

    The function's parameters, except one annotated ``EffectCall``, become the tool's arguments. That
    parameter receives the dispatch: put ``effect.key`` in the request the owner deduplicates by. The key
    is derived from the conversation, the tool name and the arguments, unless ``key_from`` names an
    argument that carries one. The conversation is ``thread_id`` in the ``variables`` given to
    ``Agent.ask``, or else the stream's id: pass the same stream, or the same ``thread_id``, for every ask
    of one conversation, and a ``thread_id`` to resume in a new process. A worker holding a lease passes
    its token as ``fencing_token`` in the same ``variables``. An unknown outcome is reported to the model
    as a tool result. With ``on_unknown="raise"`` it is raised, and AG2 turns any tool exception into a
    ``ToolErrorEvent`` for the model, so the run goes on. Other keywords go to ``ag2.tool``.
    """
    check_on_unknown(on_unknown)

    def decorate(func: Callable[..., Any]) -> Any:
        from ag2 import Context, tool

        body = GuardedBody(func, owner, journal=journal, name=name, key_from=key_from, on_unknown=on_unknown)
        return tool(body.contextual(Context, _thread), name=body.name,
                    description=description or inspect.getdoc(func) or body.name, **options)

    return decorate


def _thread(context: Any) -> tuple[str, int | None]:
    thread, token = thread_and_token(context.variables)
    return thread or str(context.stream.id), token
