"""The runtime tripwire: real clock reads are caught however the name was bound, and exemptions are exact."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from probity_records.clock import FixedClock
from probity_records.clock_tripwire import (
    Exemption,
    Read,
    Tripwire,
    WallClockUse,
    load_exemptions,
)

# The subprocess cases run in a fresh interpreter, so the tripwire under test is the only one installed.


def _run(code: str, tmp_path: Path, *, exempt: str | None = None) -> subprocess.CompletedProcess[str]:
    module = tmp_path / "pipeline_under_test.py"
    module.write_text(textwrap.dedent(code))
    driver = tmp_path / "driver.py"
    driver.write_text(textwrap.dedent(f"""
        import sys
        from probity_records.clock_tripwire import Tripwire, WallClockUse, load_exemptions
        wire = Tripwire(load_exemptions({str(exempt)!r}) if {exempt is not None!r} else ())
        wire.install()
        sys.path.insert(0, {str(tmp_path)!r})
        raised = None
        try:
            import pipeline_under_test
            pipeline_under_test.run()
        except WallClockUse as exc:
            raised = exc.read
        wire.uninstall()
        for read in wire.take():
            print("READ", read.function, read.reader, read.origin)
        print("RAISED", raised.function if raised else None)
    """))
    return subprocess.run([sys.executable, str(driver)], capture_output=True, text=True, timeout=60, check=False)


def _reads(out: str) -> list[tuple[str, ...]]:
    return [tuple(line.split()[1:]) for line in out.splitlines() if line.startswith("READ ")]


def test_an_attribute_read_raises_at_the_call_site(tmp_path: Path) -> None:
    proc = _run("""
        import time
        def run():
            return time.time()
    """, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "RAISED time.time" in proc.stdout
    assert ("time.time", "pipeline_under_test", "pipeline_under_test") in _reads(proc.stdout)


def test_a_reference_saved_before_install_is_still_seen(tmp_path: Path) -> None:
    saved = tmp_path / "saved_early.py"
    saved.write_text("from time import monotonic_ns as EARLY\n")
    driver = tmp_path / "early_driver.py"
    driver.write_text(textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(tmp_path)!r})
        import saved_early  # binds the real builtin before the tripwire exists
        from probity_records.clock_tripwire import Tripwire
        wire = Tripwire()
        wire.install()
        def reader():
            return saved_early.EARLY()
        reader()
        wire.uninstall()
        print([(r.function, r.reader) for r in wire.take()])
    """))
    proc = subprocess.run([sys.executable, str(driver)], capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "('time.monotonic_ns', '__main__')" in proc.stdout


def test_datetime_now_is_caught_though_it_cannot_be_patched(tmp_path: Path) -> None:
    proc = _run("""
        from datetime import UTC, date, datetime
        def run():
            datetime.now(UTC)
            date.today()
    """, tmp_path)
    assert proc.returncode == 0, proc.stderr
    functions = {r[0] for r in _reads(proc.stdout)}
    assert {"datetime.datetime.now", "datetime.date.today"} <= functions


def test_asyncio_sleep_raises(tmp_path: Path) -> None:
    exempt = tmp_path / "loop.toml"
    exempt.write_text('[[exempt]]\nreader = "asyncio.*"\nreason = "the event loop reads its own time"\nrow = "R"\n')
    proc = _run("""
        import asyncio
        def run():
            async def main():
                await asyncio.sleep(0)
            asyncio.run(main())
    """, tmp_path, exempt=str(exempt))
    assert proc.returncode == 0, proc.stderr
    assert "RAISED asyncio.sleep" in proc.stdout


def test_a_fixed_clock_reads_nothing(tmp_path: Path) -> None:
    proc = _run("""
        from probity_records.clock import FixedClock, HighWater
        def run():
            clock = FixedClock(10**18)
            clock.advance(5)
            clock.timer(clock.monotonic() + 3, lambda: None)
            clock.sleep_until(clock.monotonic() + 10)
            return HighWater(clock).now()
    """, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert _reads(proc.stdout) == [] and "RAISED None" in proc.stdout


def test_the_system_clock_is_not_exempt(tmp_path: Path) -> None:
    proc = _run("""
        from probity_records.clock import SystemClock
        def run():
            return SystemClock().now()
    """, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert ("time.time_ns", "probity_records.clock", "pipeline_under_test") in _reads(proc.stdout)


def test_a_stdlib_read_is_attributed_to_the_code_that_called_the_stdlib(tmp_path: Path) -> None:
    proc = _run("""
        import logging
        def run():
            logging.getLogger("x").warning("hi")
    """, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert ("time.time_ns", "logging", "pipeline_under_test") in _reads(proc.stdout)


def test_an_exemption_by_reader_lets_only_that_read_through(tmp_path: Path) -> None:
    exempt = tmp_path / "CLOCK-EXEMPT.toml"
    exempt.write_text(textwrap.dedent("""
        [[exempt]]
        reader = "logging"
        functions = ["time.time_ns"]
        reason = "log record timestamps; the pipeline never reads them back"
        tier = "none"
        row = "ID-TEST-ROW"
    """))
    proc = _run("""
        import logging, time
        def run():
            logging.getLogger("x").warning("hi")
            time.time()
    """, tmp_path, exempt=str(exempt))
    assert proc.returncode == 0, proc.stderr
    assert _reads(proc.stdout) == [("time.time", "pipeline_under_test", "pipeline_under_test")]


def test_exemption_file_refuses_unknown_fields_and_missing_rows(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text('[[exempt]]\nreader = "x"\nreason = "r"\nrow = "R"\nwhatever = 1\n')
    with pytest.raises(ValueError, match="unknown fields"):
        load_exemptions(bad)
    bad.write_text('[[exempt]]\nreader = "x"\nreason = "r"\n')
    with pytest.raises(ValueError, match="board row"):
        load_exemptions(bad)
    bad.write_text('[[exempt]]\nreason = "r"\nrow = "R"\n')
    with pytest.raises(ValueError, match="reader, an origin"):
        load_exemptions(bad)
    bad.write_text('extra = 1\n')
    with pytest.raises(ValueError, match="unknown keys"):
        load_exemptions(bad)
    empty = tmp_path / "empty.toml"
    empty.write_text("")
    assert load_exemptions(empty) == ()


def test_exemption_matching_is_by_reader_origin_and_function() -> None:
    read = Read("time.monotonic", "threading", "pkg.mod", "f.py:1")
    assert Exemption("r", reader="threading").matches(read)
    assert Exemption("r", origin="pkg.*").matches(read)
    assert not Exemption("r", reader="threading", origin="other").matches(read)
    assert not Exemption("r", reader="threading", functions=("time.time",)).matches(read)


def test_installing_twice_is_refused_and_uninstall_restores_the_module() -> None:
    import time

    real = time.time
    wire = Tripwire()
    wire.install()
    try:
        assert time.time is not real
        with pytest.raises(RuntimeError, match="already installed"):
            wire.install()
    finally:
        wire.uninstall()
    assert time.time is real


def test_the_pytest_plugin_fails_a_test_that_reads_the_clock(tmp_path: Path) -> None:
    (tmp_path / "test_reads.py").write_text(textwrap.dedent("""
        import time
        from probity_records.clock import FixedClock

        def test_clean():
            clock = FixedClock(0)
            clock.advance(1)

        def test_reads():
            time.monotonic()
    """))
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "probity_records.clock_tripwire",
                           "-p", "no:cacheprovider", str(tmp_path / "test_reads.py")],
                          capture_output=True, text=True, timeout=120, cwd=tmp_path, check=False)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "1 failed, 1 passed" in proc.stdout
    assert "WallClockUse" in proc.stdout and "time.monotonic" in proc.stdout


def test_wall_clock_use_names_the_caller() -> None:
    read = Read("time.time", "pkg.mod", "pkg.mod", "/x/pkg/mod.py:3")
    assert "pkg.mod" in str(WallClockUse(read)) and WallClockUse(read).read is read
    assert FixedClock(0).now() == 0
