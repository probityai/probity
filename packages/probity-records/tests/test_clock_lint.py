"""The source lint: every way of reading the clock is refused, and the scan reads every source file."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from probity_records.clock_lint import (
    FORBIDDEN,
    FORBIDDEN_METHODS,
    main,
    scan_paths,
    scan_source,
)

SRC = Path(__file__).resolve().parents[1] / "src" / "probity_records"
CLOCK = SRC / "clock.py"

PLANTED = [
    ("import time\nx = time.time()\n", "time.time"),
    ("import time\nx = time.time_ns()\n", "time.time_ns"),
    ("import time\nx = time.monotonic()\n", "time.monotonic"),
    ("import time\nx = time.monotonic_ns()\n", "time.monotonic_ns"),
    ("import time\nx = time.perf_counter()\n", "time.perf_counter"),
    ("import time\nx = time.perf_counter_ns()\n", "time.perf_counter_ns"),
    ("import time\ntime.sleep(1)\n", "time.sleep"),
    ("import time\nx = time.gmtime()\n", "time.gmtime with no time argument"),
    ("import time\nx = time.localtime()\n", "time.localtime with no time argument"),
    ("import time\nx = time.ctime()\n", "time.ctime with no time argument"),
    ("import time\nx = time.asctime()\n", "time.asctime with no time argument"),
    ("import time\nx = time.strftime('%Y')\n", "time.strftime with no time argument"),
    ("from datetime import datetime\nx = datetime.now()\n", "datetime.datetime.now"),
    ("from datetime import datetime, UTC\nx = datetime.now(UTC)\n", "datetime.datetime.now"),
    ("from datetime import datetime\nx = datetime.utcnow()\n", "datetime.datetime.utcnow"),
    ("from datetime import datetime\nx = datetime.today()\n", "datetime.datetime.today"),
    ("from datetime import date\nx = date.today()\n", "datetime.date.today"),
    ("import datetime\nx = datetime.datetime.now()\n", "datetime.datetime.now"),
    ("import datetime as d\nx = d.date.today()\n", "datetime.date.today"),
    ("import asyncio\nasync def f():\n    await asyncio.sleep(1)\n", "asyncio.sleep"),
    ("import asyncio\nx = asyncio.get_running_loop().time()\n", "event loop time()"),
    ("def f(loop):\n    return loop.time()\n", "event loop time()"),
    ("class A:\n    def f(self):\n        return self._loop.time()\n", "event loop time()"),
    ("import threading\nt = threading.Timer(1, print)\n", "threading.Timer"),
    ("import uuid\nx = uuid.uuid1()\n", "uuid.uuid1"),
    ("import time as t\nx = t.time()\n", "time.time"),
    ("from time import monotonic\nx = monotonic()\n", "time.monotonic"),
    ("from time import monotonic as m\nx = m()\n", "time.monotonic"),
    ("from datetime import datetime as dt\nx = dt.now()\n", "datetime.datetime.now"),
    ("import time\nfrom dataclasses import field\nclock = field(default=time.time)\n", "time.time"),
    ("import time\ndef f(clock=time.monotonic_ns):\n    return clock()\n", "time.monotonic_ns"),
]


@pytest.mark.parametrize(("source", "name"), PLANTED, ids=[n for _, n in PLANTED])
def test_each_planted_read_is_refused(source: str, name: str) -> None:
    findings = scan_source(source, "planted.py")
    assert name in {f.name for f in findings}, findings


def test_every_forbidden_name_has_a_planted_case() -> None:
    planted = {n.split(" with ")[0] for _, n in PLANTED}
    listed = {f"{m}.{n}" for m, names in FORBIDDEN.items() for n in names}
    listed |= {f"{m}.{c}.{n}" for (m, c), names in FORBIDDEN_METHODS.items() for n in names}
    assert listed - planted <= {"uuid.uuid6", "uuid.uuid7"}, listed - planted


CLEAN = [
    "import time\nx = time.gmtime(0)\n",
    "import time\nx = time.strftime('%Y', time.gmtime(0))\n",
    "from datetime import datetime, UTC\nx = datetime.fromtimestamp(0, UTC)\n",
    "from datetime import datetime\ndef f(d: datetime):\n    return d.time()\n",
    "def f(clock):\n    return clock.now()\n",
    "import time\nx = time.struct_time\n",
]


@pytest.mark.parametrize("source", CLEAN)
def test_reads_that_supply_the_time_pass(source: str) -> None:
    assert scan_source(source) == []


def test_the_package_source_reads_the_clock_only_in_the_clock_module() -> None:
    result = scan_paths([SRC], allow=[CLOCK])
    assert result.findings == (), "\n".join(map(str, result.findings))


def test_the_scan_reads_every_tracked_source_file() -> None:
    tracked = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"], cwd=SRC, capture_output=True, text=True, check=True)
    expected = {str((SRC / line).resolve()) for line in tracked.stdout.split()} - {str(CLOCK.resolve())}
    assert len(expected) > 20  # the read path works: a broken listing reports absence identically to a clean tree
    scanned = {str(Path(f).resolve()) for f in scan_paths([SRC], allow=[CLOCK]).files}
    assert scanned == expected


def test_cli_exit_codes(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("import time\ntime.time()\n")
    (tmp_path / "good.py").write_text("x = 1\n")
    assert main([str(tmp_path / "good.py")]) == 0
    assert main([str(tmp_path)]) == 1
    assert main([str(tmp_path / "missing")]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main([str(empty)]) == 2
    (tmp_path / "broken.py").write_text("def (:\n")
    assert main([str(tmp_path / "broken.py")]) == 2


def test_cli_runs_as_a_module(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("from datetime import date\ndate.today()\n")
    proc = subprocess.run([sys.executable, "-m", "probity_records.clock_lint", str(tmp_path)],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "datetime.date.today" in proc.stdout and "1 files scanned" in proc.stdout
