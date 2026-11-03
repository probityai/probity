"""What every framework adapter shares: one function that performs a write, behind the guard.

A framework hands a tool its arguments and some context; everything else is the same whichever
framework it is, so the adapters only translate those two.
"""

from __future__ import annotations

import inspect
import typing
from collections.abc import Callable, Mapping
from typing import Any

from probity_effects.guard import EffectGuard, EffectOutcomeUnknown, Outcome
from probity_effects.journal import Journal
from probity_effects.owner import EffectCall, EffectOwner

ON_UNKNOWN = ("report", "raise")
#: The name of the parameter a framework passes its context in, on the function it is handed.
CONTEXT_PARAMETER = "tool_context"
ContextReader = Callable[[Any], tuple[str, int | None]]


class UnnamedOperation(ValueError):
    """A call that carries neither a thread nor an idempotency key, so nothing was sent.

    A key derived from the tool and its arguments alone is the same for everyone, so the second
    person to ask for the same write would be told it was committed when it was never sent.
    """


def check_on_unknown(on_unknown: str) -> None:
    if on_unknown not in ON_UNKNOWN:
        raise ValueError(f"on_unknown is one of {ON_UNKNOWN}")


class GuardedBody:
    """A function that performs one write, as a tool layer calls it."""

    def __init__(self, func: Callable[..., Any], owner: EffectOwner, *, journal: Journal | None = None,
                 name: str | None = None, key_from: str | None = None, on_unknown: str = "report") -> None:
        check_on_unknown(on_unknown)
        self.func = func
        self.owner = owner
        self.name = name or func.__name__
        self.key_from = key_from
        self.on_unknown = on_unknown
        self.guard = EffectGuard(owner, journal)
        self.effect_param = effect_parameter(func)
        self.parameters = _tool_parameters(func, self.effect_param)
        if key_from is not None and key_from not in {item.name for item in self.parameters}:
            raise ValueError(f"key_from names {key_from!r}, which is not an argument of {self.name}")

    @property
    def asynchronous(self) -> bool:
        return inspect.iscoroutinefunction(self.func)

    def run(self, args: dict[str, Any], *, scope: str, fencing_token: int | None = None) -> Any:
        key = self._key(args, scope)
        outcome = self.guard.perform(self.name, args, send=self._send(args), key=key, scope=scope,
                                     fencing_token=fencing_token)
        return self._render(outcome)

    async def arun(self, args: dict[str, Any], *, scope: str, fencing_token: int | None = None) -> Any:
        key = self._key(args, scope)
        outcome = await self.guard.aperform(self.name, args, send=self._send(args), key=key, scope=scope,
                                            fencing_token=fencing_token)
        return self._render(outcome)

    def contextual(self, annotation: Any, read: ContextReader) -> Callable[..., Any]:
        """A function that takes the framework's context first, then the tool's own parameters.

        Its signature is what a framework builds the tool's schema from, so the ``EffectCall``
        parameter never reaches the model.
        """
        visible = inspect.Signature(list(self.parameters))

        def arguments(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
            bound = visible.bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)

        if self.asynchronous:
            async def tool(tool_context: Any, *args: Any, **kwargs: Any) -> Any:
                scope, token = read(tool_context)
                return await self.arun(arguments(args, kwargs), scope=scope, fencing_token=token)
        else:
            def tool(tool_context: Any, *args: Any, **kwargs: Any) -> Any:
                scope, token = read(tool_context)
                return self.run(arguments(args, kwargs), scope=scope, fencing_token=token)

        first = inspect.Parameter(CONTEXT_PARAMETER, inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=annotation)
        tool.__name__ = self.name
        tool.__qualname__ = self.name
        tool.__doc__ = self.func.__doc__
        tool.__signature__ = inspect.Signature([first, *self.parameters])  # type: ignore[attr-defined]
        tool.__annotations__ = {CONTEXT_PARAMETER: annotation,
                                **{item.name: item.annotation for item in self.parameters
                                   if item.annotation is not inspect.Parameter.empty}}
        return tool

    def _key(self, args: dict[str, Any], scope: str) -> str | None:
        if self.key_from is not None:
            return str(args[self.key_from])
        if not scope:
            raise UnnamedOperation(f"{self.name} was called with no thread, so nothing was sent: pass a thread_id, "
                                   "or name the argument that carries a business key with key_from")
        return None

    def _send(self, args: dict[str, Any]) -> Callable[[EffectCall], Any]:
        def send(call: EffectCall) -> Any:
            return self.func(**(args | {self.effect_param: call} if self.effect_param else args))

        return send

    def _render(self, outcome: Outcome) -> Any:
        owner, name = self.owner, self.name
        if outcome.outcome == "committed":
            if outcome.sent and outcome.value is not None:
                return outcome.value
            return f"committed: {owner.id} holds this effect (idempotency key {outcome.key}); {outcome.reason}."
        if outcome.outcome == "not_run":
            return f"not run: {outcome.reason}."
        if self.on_unknown == "raise":
            raise EffectOutcomeUnknown(outcome)
        return (f"outcome unknown: {outcome.reason}. The effect may have happened. Do not call {name} again "
                f"for this request; ask {owner.id} or the user what it holds (idempotency key {outcome.key}).")


def effect_parameter(func: Callable[..., Any]) -> str | None:
    """The parameter that receives the dispatch: the one annotated ``EffectCall``."""
    hints = _hints(func)
    for parameter in inspect.signature(func).parameters.values():
        annotation = hints.get(parameter.name, parameter.annotation)
        if annotation is EffectCall or annotation == "EffectCall":
            return parameter.name
    return None


def thread_and_token(values: Any) -> tuple[str, int | None]:
    """The thread and fencing token a mapping or an object carries, under those names."""
    read = values.get if isinstance(values, Mapping) else lambda name: getattr(values, name, None)
    thread, token = read("thread_id"), read("fencing_token")
    return ("" if thread is None else str(thread)), (None if token is None else int(token))


def _hints(func: Callable[..., Any]) -> dict[str, Any]:
    try:
        return typing.get_type_hints(func, include_extras=True)
    except (NameError, TypeError):
        return {}


def _tool_parameters(func: Callable[..., Any], effect_param: str | None) -> tuple[inspect.Parameter, ...]:
    hints = _hints(func)
    return tuple(parameter.replace(annotation=hints.get(parameter.name, parameter.annotation))
                 for parameter in inspect.signature(func).parameters.values() if parameter.name != effect_param)
