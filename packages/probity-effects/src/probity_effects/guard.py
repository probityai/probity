"""Reconcile before resend: one policy, driven synchronously or asynchronously."""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from probity_effects.journal import Attempt, Journal
from probity_effects.owner import EffectCall, EffectOwner, Lookup, Reply
from probity_effects.record import args_digest, derive_key, jsonable, parse


@dataclass(frozen=True)
class Outcome:
    """What one call of the guard reports.

    ``outcome`` is ``committed``, ``not_run`` or ``unknown``. ``value`` is what the send returned when
    this call's attempt was confirmed. ``sent`` counts the dispatches this call made.
    """

    outcome: str
    key: str
    reason: str
    value: Any = None
    sent: int = 0
    error: str | None = None

    @property
    def committed(self) -> bool:
        return self.outcome == "committed"


class EffectOutcomeUnknown(RuntimeError):
    """Raised by a tool configured to stop, rather than report, when the outcome is unknown."""

    def __init__(self, outcome: Outcome) -> None:
        super().__init__(f"outcome unknown for idempotency key {outcome.key}: {outcome.reason}")
        self.outcome = outcome


# What the policy asks its driver to do.
Request = tuple[str, Any]
Plan = Generator[Request, Any, Outcome]


class EffectGuard:
    """Perform an operation at most once in effect, whatever retries, re-asks and resumes do."""

    def __init__(self, owner: EffectOwner, journal: Journal | None = None) -> None:
        self.owner = owner
        self.journal = journal if journal is not None else Journal()
        self._locks: dict[str, threading.Lock] = {}
        self._async_locks: dict[str, asyncio.Lock] = {}
        self._registry = threading.Lock()

    def key_for(self, action: str, args: Mapping[str, Any], scope: str = "") -> str:
        return derive_key(action, jsonable(dict(args)), scope)

    def perform(self, action: str, args: Mapping[str, Any], *, send: Callable[[EffectCall], Any] | None = None,
                key: str | None = None, scope: str = "", fencing_token: int | None = None) -> Outcome:
        plain, digest, key = self._identify(action, args, key, scope)
        sender = self._sender(send)
        with self._lock(key):
            plan = self._plan(action, key, plain, digest, fencing_token)
            try:
                request = next(plan)
                while True:
                    request = plan.send(self._serve(request, sender))
            except StopIteration as done:
                return done.value

    async def aperform(self, action: str, args: Mapping[str, Any], *, send: Callable[[EffectCall], Any] | None = None,
                       key: str | None = None, scope: str = "", fencing_token: int | None = None) -> Outcome:
        plain, digest, key = self._identify(action, args, key, scope)
        sender = self._sender(send)
        async with self._async_lock(key):
            plan = self._plan(action, key, plain, digest, fencing_token)
            try:
                request = next(plan)
                while True:
                    request = plan.send(await self._aserve(request, sender))
            except StopIteration as done:
                return done.value

    # The drivers: the only code that touches the owner.

    def _identify(self, action: str, args: Mapping[str, Any], key: str | None,
                  scope: str) -> tuple[dict[str, Any], str, str]:
        plain = jsonable(dict(args))
        return plain, args_digest(plain), key or derive_key(action, plain, scope)

    def _sender(self, send: Callable[[EffectCall], Any] | None) -> Callable[[EffectCall], Any]:
        sender = self.owner.send or send
        if sender is None:
            raise TypeError("nothing performs the effect: pass send=, or give the owner a send")
        return sender

    def _lock(self, key: str) -> threading.Lock:
        with self._registry:
            return self._locks.setdefault(key, threading.Lock())

    def _async_lock(self, key: str) -> asyncio.Lock:
        with self._registry:
            return self._async_locks.setdefault(key, asyncio.Lock())

    def _serve(self, request: Request, sender: Callable[[EffectCall], Any]) -> Any:
        kind, payload = request
        if kind == "sleep":
            time.sleep(payload)
            return None
        if kind == "send":
            try:
                return Reply.CONFIRMED, sender(payload), None
            except Exception as error:  # noqa: BLE001 - every failure is read, none is lost
                return self.owner.read_failure(error), None, f"{type(error).__name__}: {error}"
        return self._ask(kind, payload, lambda result: result)

    async def _aserve(self, request: Request, sender: Callable[[EffectCall], Any]) -> Any:
        kind, payload = request
        if kind == "sleep":
            await asyncio.sleep(payload)
            return None
        if kind == "send":
            try:
                value = sender(payload)
                return Reply.CONFIRMED, (await value if inspect.isawaitable(value) else value), None
            except Exception as error:  # noqa: BLE001 - every failure is read, none is lost
                return self.owner.read_failure(error), None, f"{type(error).__name__}: {error}"
        try:
            result = self._call_owner(kind, payload)
            return await result if inspect.isawaitable(result) else result
        except Exception:  # noqa: BLE001 - an owner that cannot answer is no answer
            return None

    def _ask(self, kind: str, payload: Any, finish: Callable[[Any], Any]) -> Any:
        try:
            result = self._call_owner(kind, payload)
        except Exception:  # noqa: BLE001 - an owner that cannot answer is no answer
            return None
        if inspect.isawaitable(result):
            raise TypeError(f"the owner's {kind} is asynchronous; call aperform")
        return finish(result)

    def _call_owner(self, kind: str, payload: Any) -> Any:
        if kind == "lookup":
            return self.owner.lookup(payload)
        if kind == "lease":
            return self.owner.lease() if self.owner.lease is not None else None
        raise ValueError(f"unknown request {kind!r}")

    # The policy: no I/O of its own, only requests to a driver and writes to the journal.

    def _plan(self, action: str, key: str, args: dict[str, Any], digest: str, token: int | None) -> Plan:
        journal, owner = self.journal, self.owner
        history = journal.history(key)
        if history.operation is not None and history.operation["argsDigest"] != digest:
            journal.append({"event": "refused", "key": key, "argsDigest": digest,
                            "reason": "key used with other arguments"})
            return Outcome("not_run", key, f"idempotency key {key} already names an operation with other "
                                           "arguments, so nothing was sent")
        if history.operation is None:
            journal.append({"event": "operation", "key": key, "action": action, "argsDigest": digest,
                            "owner": owner.describe()})
        if history.committed:
            return self._report(key, "committed", "the owner already holds this effect, so it was not sent again")
        pending = history.unresolved()
        if pending is not None and not self._deduplicated(pending):
            answer = yield from self._settle(key)
            if answer is not False:
                return self._settled(key, answer, "an earlier reply was lost")
        sent = 0
        while True:
            history = journal.history(key)
            if len(history.attempts) >= owner.max_sends:
                settled = history.settled()
                return self._report(key, settled, f"the send limit of {owner.max_sends} is reached", sent=sent)
            if token is not None:
                current = yield ("lease", None)
                held = current is not None and current == token
                journal.append({"event": "lease", "key": key, "token": current, "held": held})
                if not held:
                    return (yield from self._lease_lost(key, history, sent))
            attempt = len(history.attempts) + 1
            call = EffectCall(key=key, action=action, args=args, attempt=attempt, fencing_token=token)
            journal.append({"event": "dispatch", "key": key, "attempt": attempt, "argsDigest": digest,
                            **({"fencingToken": token} if token is not None else {})})
            reply, value, error = yield ("send", call)
            sent += 1
            journal.append({"event": "reply", "key": key, "attempt": attempt, "reply": reply.value,
                            **({"detail": error} if error else {})})
            if reply is Reply.CONFIRMED:
                return self._report(key, "committed", "the owner confirmed the effect", value=value, sent=sent)
            if reply is Reply.NO_EFFECT:
                return self._report(key, "not_run", f"the owner answered that the effect did not happen ({error})",
                                    sent=sent, error=error)
            if self._deduplicated(journal.history(key).unresolved()):
                continue
            answer = yield from self._settle(key)
            if answer is not False:
                return self._settled(key, answer, "the reply was lost", sent=sent, error=error)

    def _lease_lost(self, key: str, history: Any, sent: int) -> Plan:
        if history.unresolved() is None:
            return self._report(key, history.settled(), "this worker no longer holds the lease, so nothing was sent",
                                sent=sent)
        answer = yield from self._settle(key)
        if answer is False:
            return self._report(key, "not_run", "the lease moved and the owner holds no effect", sent=sent)
        return self._settled(key, answer, "the lease moved after a lost reply", sent=sent)

    def _settle(self, key: str) -> Generator[Request, Any, bool | None]:
        """Ask the owner until it answers finally: True present, False absent, None no final answer."""
        for number in range(self.owner.lookups):
            if number:
                yield ("sleep", self.owner.lookup_interval)
            answer: Lookup | None = yield ("lookup", key)
            if answer is None:
                self.journal.append({"event": "lookup", "key": key, "answered": False})
                continue
            final = bool(answer.present or answer.final)
            self.journal.append({"event": "lookup", "key": key, "answered": True,
                                 "result": "present" if answer.present else "absent", "final": final})
            if answer.present:
                return True
            if final:
                return False
        return None

    def _deduplicated(self, pending: Attempt | None) -> bool:
        """Whether the owner's deduplication covers sending the same key again now."""
        owner = self.owner
        if pending is None or not owner.deduplicates_by_key:
            return False
        if owner.key_retention_seconds is None:
            return True
        age = (datetime.now(UTC) - parse(pending.dispatched_at)).total_seconds()
        return age <= owner.key_retention_seconds

    def _settled(self, key: str, answer: bool | None, why: str, *, sent: int = 0, error: str | None = None) -> Outcome:
        if answer is True:
            return self._report(key, "committed", f"{why}, and the owner holds the effect", sent=sent, error=error)
        return self._report(key, "unknown", f"{why}, and the owner could not confirm what it holds",
                            sent=sent, error=error)

    def _report(self, key: str, outcome: str, reason: str, *, value: Any = None, sent: int = 0,
                error: str | None = None) -> Outcome:
        self.journal.append({"event": "outcome", "key": key, "outcome": outcome, "reason": reason})
        return Outcome(outcome=outcome, key=key, reason=reason, value=value, sent=sent, error=error)
