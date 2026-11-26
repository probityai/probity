"""One clock for every time read: a protocol, the system clock and a fixed clock.

A producer reads the time to stamp a record, to set an expiry and to decide whether one has passed. A verifier
reads it to judge a record "as of" a moment. Both take a ``Clock`` at construction and never read the system clock
themselves, so a test, a simulation or a verifier can choose the time.

Every value is an integer count of nanoseconds. ``now()`` is wall time since the Unix epoch, in UTC; it can step
in either direction when the host's clock is corrected. ``monotonic()`` has an arbitrary origin and never
decreases; deadlines, sleeps and timers are expressed in it, so a step of the wall clock never fires or delays
one. ``HighWater`` gives a component a wall time that never decreases, for code where a step back would reopen
an expiry or reverse a chain.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

__all__ = [
    "Clock",
    "FixedClock",
    "HighWater",
    "SystemClock",
    "Timer",
    "from_datetime",
    "sleep_until_async",
    "to_datetime",
]

NS_PER_S = 1_000_000_000
_NS_PER_US = 1_000


@runtime_checkable
class Timer(Protocol):
    """A callback scheduled on a clock. ``cancel`` returns True when it stopped the callback before it ran."""

    def cancel(self) -> bool: ...


@runtime_checkable
class Clock(Protocol):
    """The four time operations a component may use; nothing else reads the time."""

    def now(self) -> int:
        """Wall time, in integer nanoseconds since the Unix epoch (UTC)."""
        ...

    def monotonic(self) -> int:
        """Monotonic time, in integer nanoseconds from an arbitrary origin; never decreases."""
        ...

    def sleep_until(self, t: int) -> None:
        """Return once ``monotonic()`` has reached ``t``."""
        ...

    def timer(self, t: int, callback: Callable[[], None]) -> Timer:
        """Run ``callback`` once, when ``monotonic()`` reaches ``t``, on a thread the clock chooses."""
        ...


def to_datetime(ns: int) -> datetime:
    """An aware UTC datetime for a wall time in nanoseconds (truncated to microseconds)."""
    seconds, rest = divmod(ns, NS_PER_S)
    return datetime.fromtimestamp(seconds, UTC).replace(microsecond=rest // _NS_PER_US)


def from_datetime(moment: datetime) -> int:
    """Nanoseconds since the Unix epoch for an aware datetime; a naive one is refused."""
    if moment.tzinfo is None:
        raise ValueError("a naive datetime names no instant; give it a timezone")
    delta = moment - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * NS_PER_S + delta.microseconds * _NS_PER_US


class _ThreadTimer:
    def __init__(self, inner: threading.Timer) -> None:
        self._inner = inner

    def cancel(self) -> bool:
        fired = self._inner.finished.is_set()
        self._inner.cancel()
        return not fired


class SystemClock:
    """The host's clocks. Construct one per process, at its entry point, and pass it down."""

    def now(self) -> int:
        return time.time_ns()

    def monotonic(self) -> int:
        return time.monotonic_ns()

    def sleep_until(self, t: int) -> None:
        while (remaining := t - time.monotonic_ns()) > 0:
            time.sleep(remaining / NS_PER_S)

    def timer(self, t: int, callback: Callable[[], None]) -> Timer:
        inner = threading.Timer(max(0, t - time.monotonic_ns()) / NS_PER_S, callback)
        inner.daemon = True
        inner.start()
        return _ThreadTimer(inner)


class _FixedTimer:
    def __init__(self, clock: FixedClock, key: int) -> None:
        self._clock, self._key = clock, key

    def cancel(self) -> bool:
        return self._clock._cancel(self._key)


class FixedClock:
    """A clock that moves only when told to: a verifier's "as of" time, and the clock of every test.

    ``advance`` moves wall and monotonic time forward together and runs each timer that comes due, in deadline
    order, with the clock standing at that timer's deadline. ``step_wall`` moves only the wall clock, in either
    direction, as a host clock correction would; monotonic time and timers are untouched. ``sleep_until`` advances
    the clock to its deadline, because no other thread is assumed to move it. A timer whose deadline has already
    passed runs at once, on the thread that scheduled it.
    """

    def __init__(self, now: int, monotonic: int = 0) -> None:
        if monotonic < 0:
            raise ValueError("monotonic time starts at zero or later")
        self._wall, self._mono = now, monotonic
        self._lock = threading.RLock()
        self._timers: list[tuple[int, int, Callable[[], None]]] = []
        self._live: set[int] = set()
        self._ids = itertools.count()

    @classmethod
    def at(cls, moment: datetime) -> FixedClock:
        """A fixed clock whose wall time is ``moment``."""
        return cls(from_datetime(moment))

    def now(self) -> int:
        with self._lock:
            return self._wall

    def monotonic(self) -> int:
        with self._lock:
            return self._mono

    def advance(self, ns: int) -> None:
        """Move both clocks forward by ``ns`` and run every timer that comes due on the way."""
        if ns < 0:
            raise ValueError("a fixed clock advances forward; use step_wall for a wall clock step back")
        with self._lock:
            target = self._mono + ns
        while True:
            with self._lock:
                if not self._timers or self._timers[0][0] > target:
                    step = max(0, target - self._mono)  # a callback may already have advanced past target
                    self._wall += step
                    self._mono += step
                    return
                deadline, key, callback = heapq.heappop(self._timers)
                if key not in self._live:
                    continue
                self._live.discard(key)
                self._wall += deadline - self._mono
                self._mono = max(self._mono, deadline)
            callback()

    def advance_seconds(self, seconds: float) -> None:
        self.advance(round(seconds * NS_PER_S))

    def step_wall(self, ns: int) -> None:
        """Step only the wall clock by ``ns`` (negative steps it back)."""
        with self._lock:
            self._wall += ns

    def sleep_until(self, t: int) -> None:
        with self._lock:
            behind = t - self._mono
        if behind > 0:
            self.advance(behind)

    def timer(self, t: int, callback: Callable[[], None]) -> Timer:
        with self._lock:
            key = next(self._ids)
            due = t <= self._mono
            if not due:
                self._live.add(key)
                heapq.heappush(self._timers, (t, key, callback))
        if due:
            callback()
        return _FixedTimer(self, key)

    def _cancel(self, key: int) -> bool:
        with self._lock:
            if key in self._live:
                self._live.discard(key)
                return True
            return False


class HighWater:
    """A component's wall time that never decreases: the highest ``clock.now()`` it has read.

    An expiry judged against it stays expired after the host clock steps back, and timestamps taken from it
    keep a chain in order.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._mark: int | None = None
        self._lock = threading.Lock()

    def now(self) -> int:
        read = self._clock.now()
        with self._lock:
            self._mark = read if self._mark is None or read > self._mark else self._mark
            return self._mark


async def sleep_until_async(clock: Clock, t: int) -> None:
    """Await until ``clock.monotonic()`` reaches ``t``, through the clock's timer."""
    loop = asyncio.get_running_loop()
    done = loop.create_future()

    def fire() -> None:
        loop.call_soon_threadsafe(lambda: None if done.done() else done.set_result(None))

    handle = clock.timer(t, fire)
    try:
        await done
    finally:
        handle.cancel()
