"""The clock protocol and its two public implementations."""

from __future__ import annotations

import asyncio
import random
import threading
from datetime import UTC, datetime, timedelta, timezone

import pytest
from probity_records.clock import (
    NS_PER_S,
    Clock,
    FixedClock,
    HighWater,
    SystemClock,
    Timer,
    from_datetime,
    sleep_until_async,
    to_datetime,
)

T0 = from_datetime(datetime(2026, 11, 21, 12, 0, tzinfo=UTC))


def test_both_implementations_are_clocks() -> None:
    assert isinstance(SystemClock(), Clock)
    assert isinstance(FixedClock(T0), Clock)
    assert isinstance(FixedClock(T0).timer(1, lambda: None), Timer)


def test_datetime_round_trip_is_exact_to_the_microsecond() -> None:
    moment = datetime(2026, 11, 21, 12, 0, 0, 123456, tzinfo=UTC)
    assert to_datetime(from_datetime(moment)) == moment
    assert to_datetime(T0 + 999) == to_datetime(T0)  # sub-microsecond nanoseconds are truncated, never rounded up


def test_from_datetime_takes_any_zone_and_refuses_a_naive_one() -> None:
    eastern = datetime(2026, 11, 21, 7, 0, tzinfo=timezone(timedelta(hours=-5)))
    assert from_datetime(eastern) == T0
    with pytest.raises(ValueError, match="naive"):
        from_datetime(datetime(2026, 11, 21, 12, 0))


def test_fixed_clock_moves_only_when_told() -> None:
    clock = FixedClock(T0, monotonic=5)
    assert (clock.now(), clock.monotonic()) == (T0, 5)
    clock.advance(NS_PER_S)
    assert (clock.now(), clock.monotonic()) == (T0 + NS_PER_S, 5 + NS_PER_S)
    with pytest.raises(ValueError, match="forward"):
        clock.advance(-1)


def test_a_wall_step_leaves_monotonic_time_and_timers_alone() -> None:
    clock = FixedClock(T0)
    fired: list[int] = []
    clock.timer(10, lambda: fired.append(clock.monotonic()))
    clock.step_wall(-3600 * NS_PER_S)
    assert clock.now() == T0 - 3600 * NS_PER_S
    assert clock.monotonic() == 0 and fired == []
    clock.advance(10)
    assert fired == [10]


def test_timers_fire_in_deadline_order_with_the_clock_at_each_deadline() -> None:
    clock = FixedClock(T0)
    seen: list[tuple[str, int, int]] = []
    clock.timer(30, lambda: seen.append(("c", clock.monotonic(), clock.now() - T0)))
    clock.timer(10, lambda: seen.append(("a", clock.monotonic(), clock.now() - T0)))
    clock.timer(20, lambda: seen.append(("b", clock.monotonic(), clock.now() - T0)))
    clock.advance(25)
    assert seen == [("a", 10, 10), ("b", 20, 20)]
    assert clock.monotonic() == 25
    clock.advance(5)
    assert seen[-1] == ("c", 30, 30)


def test_a_timer_scheduled_by_a_timer_fires_in_the_same_advance() -> None:
    clock = FixedClock(T0)
    seen: list[int] = []
    clock.timer(10, lambda: clock.timer(15, lambda: seen.append(clock.monotonic())))
    clock.advance(20)
    assert seen == [15] and clock.monotonic() == 20


def test_cancel_stops_a_pending_timer_and_reports_whether_it_did() -> None:
    clock = FixedClock(T0)
    fired: list[int] = []
    handle = clock.timer(10, lambda: fired.append(1))
    assert handle.cancel() is True
    assert handle.cancel() is False
    clock.advance(20)
    assert fired == []
    late = clock.timer(30, lambda: fired.append(2))
    clock.advance(20)
    assert fired == [2] and late.cancel() is False


def test_a_past_due_timer_runs_at_once_on_the_calling_thread() -> None:
    clock = FixedClock(T0, monotonic=100)
    where: list[int | None] = []
    clock.timer(50, lambda: where.append(threading.get_ident()))
    assert where == [threading.get_ident()]


def test_sleep_until_advances_a_fixed_clock_and_fires_timers_on_the_way() -> None:
    clock = FixedClock(T0)
    fired: list[int] = []
    clock.timer(5, lambda: fired.append(clock.monotonic()))
    clock.sleep_until(8)
    assert clock.monotonic() == 8 and clock.now() == T0 + 8 and fired == [5]
    clock.sleep_until(3)  # already past: no change
    assert clock.monotonic() == 8


def test_a_callback_that_advances_the_clock_never_moves_it_back() -> None:
    clock = FixedClock(T0)
    clock.timer(5, lambda: clock.advance(100))
    clock.advance(10)
    assert clock.monotonic() == 105 and clock.now() == T0 + 105


def test_high_water_never_decreases_when_the_wall_steps_back() -> None:
    clock = FixedClock(T0)
    wall = HighWater(clock)
    assert wall.now() == T0
    clock.step_wall(-NS_PER_S)
    assert wall.now() == T0
    clock.advance(2 * NS_PER_S)
    assert wall.now() == T0 + NS_PER_S


@pytest.mark.parametrize("seed", range(500))
def test_under_any_steps_monotonic_and_high_water_never_decrease(seed: int) -> None:
    rng = random.Random(seed)
    clock = FixedClock(T0)
    wall = HighWater(clock)
    last_mono, last_wall = clock.monotonic(), wall.now()
    for _ in range(rng.randrange(1, 50)):
        if rng.random() < 0.5:
            clock.advance(rng.randrange(0, 10**12))
        else:
            clock.step_wall(rng.randrange(-10**12, 10**12))
        assert clock.monotonic() >= last_mono and wall.now() >= last_wall
        last_mono, last_wall = clock.monotonic(), wall.now()


def test_sleep_until_async_wakes_when_the_fixed_clock_is_advanced() -> None:
    clock = FixedClock(T0)

    async def run() -> int:
        waiter = asyncio.ensure_future(sleep_until_async(clock, 50))
        await asyncio.sleep(0)
        assert not waiter.done()
        clock.advance(49)
        await asyncio.sleep(0)
        assert not waiter.done()
        clock.advance(1)
        await waiter
        return clock.monotonic()

    assert asyncio.run(run()) == 50


def test_sleep_until_async_cancels_its_timer_when_cancelled() -> None:
    clock = FixedClock(T0)

    async def run() -> None:
        waiter = asyncio.ensure_future(sleep_until_async(clock, 50))
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter

    asyncio.run(run())
    assert clock._timers == [] or all(key not in clock._live for _, key, _ in clock._timers)


def test_system_clock_reads_the_host_and_its_timer_fires() -> None:
    clock = SystemClock()
    start = clock.monotonic()
    assert abs(clock.now() - from_datetime(datetime.now(UTC))) < 5 * NS_PER_S
    clock.sleep_until(start + 2_000_000)
    assert clock.monotonic() >= start + 2_000_000
    fired = threading.Event()
    clock.timer(clock.monotonic() + 1_000_000, fired.set)
    assert fired.wait(5)
    pending = clock.timer(clock.monotonic() + 60 * NS_PER_S, fired.clear)
    assert pending.cancel() is True
