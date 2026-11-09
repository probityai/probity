"""Where the time of one gated decision goes, on this host.

Runs the 2,000-call speed test's workload three ways (as shipped, with fsync stubbed out, under
cProfile), measures a bare append-and-fsync on the same filesystem, and records CPU steal over each
phase, so a p95 over budget can be attributed to the code, the disk or the host.

    uv run python scripts/profile_authorize.py [--dir DIR] [--out FILE]
"""

from __future__ import annotations

import argparse
import cProfile
import io
import json
import os
import platform
import pstats
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from probity_records import Signer, canonical  # noqa: E402
from test_authority import _approval, _req  # noqa: E402

from probity_temporal.authority import LocalAuthority  # noqa: E402

CALLS = 2000


def _steal() -> tuple[int, int]:
    fields = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    values = list(map(int, fields))
    return values[7] if len(values) > 7 else 0, sum(values)


def _workload(directory: Path) -> tuple[list[float], float]:
    approver = Signer.generate()
    authority = LocalAuthority(directory, {"human:a": approver.public_pem()})
    calls = [_req([_approval(approver, "human:a", f"{n:064x}")], str(n)) for n in range(CALLS)]
    steal0, total0 = _steal()
    times = []
    for req in calls:
        t0 = time.perf_counter()
        assert authority.authorize(req).ok
        times.append(time.perf_counter() - t0)
    steal1, total1 = _steal()
    return times, (steal1 - steal0) / max(1, total1 - total0)


def _summary(times: list[float], steal: float) -> dict[str, float]:
    q = statistics.quantiles(times, n=100)
    return {"p50_ms": statistics.median(times) * 1e3, "p95_ms": q[94] * 1e3, "p99_ms": q[98] * 1e3,
            "max_ms": max(times) * 1e3, "steal_fraction": steal}


def _bare_fsync(directory: Path, n: int = 2000) -> dict[str, float]:
    path = directory / "bare.log"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    times = []
    line = b"x" * 1500 + b"\n"
    try:
        for _ in range(n):
            t0 = time.perf_counter()
            os.write(fd, line)
            os.fsync(fd)
            times.append(time.perf_counter() - t0)
    finally:
        os.close(fd)
    return _summary(times, 0.0)


def _in_memory_judge() -> Callable[[], None]:
    """The published reader's checks on the record and bytes in memory, no scratch directory."""
    from agent_evidence_vectors import approvalbinding

    import probity_temporal.authority as auth

    def judge(record, payload):  # noqa: ANN001, ANN202
        failure = approvalbinding._first_failure(json.loads(canonical(dict(record))), payload, frozenset())  # noqa: SLF001
        return {"decision": "deny", "reason": failure} if failure else {"decision": "allow", "reason": "bound"}

    real = auth.judge_approval_binding
    auth.judge_approval_binding = judge
    return lambda: setattr(auth, "judge_approval_binding", real)


def _lock_no_truncate() -> Callable[[], None]:
    """Open the journal lock file without O_TRUNC, so taking the lock dirties no inode."""
    import probity_records.journal as journal

    real_open = Path.open

    def opener(self, mode="r", *a, **k):  # noqa: ANN001, ANN002, ANN003, ANN202
        if mode == "w" and self.name.endswith(".lock"):
            mode = "a"
        return real_open(self, mode, *a, **k)

    Path.open = opener  # type: ignore[method-assign]
    del journal
    return lambda: setattr(Path, "open", real_open)


def _both() -> Callable[[], None]:
    undo = [_in_memory_judge(), _lock_no_truncate()]
    return lambda: [u() for u in reversed(undo)] and None


def _variants() -> dict[str, Callable[[], Callable[[], None]]]:
    return {"in_memory_judge": _in_memory_judge, "lock_no_truncate": _lock_no_truncate, "both": _both}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    base = args.dir or Path(tempfile.mkdtemp(prefix="probity-perf-"))
    base.mkdir(parents=True, exist_ok=True)
    fs = subprocess.run(["stat", "-f", "-c", "%T", str(base)], capture_output=True, text=True).stdout.strip()
    report: dict[str, object] = {"host": platform.node(), "cpus": os.cpu_count(), "fs": fs,
                                 "cpu": next((ln.split(":", 1)[1].strip() for ln in
                                              Path("/proc/cpuinfo").read_text().splitlines()
                                              if ln.startswith("model name")), "")}
    report["shipped"] = _summary(*_workload(base / "shipped"))
    real_fsync = os.fsync
    os.fsync = lambda fd: None
    try:
        report["no_fsync"] = _summary(*_workload(base / "nofsync"))
    finally:
        os.fsync = real_fsync
    report["bare_fsync"] = _bare_fsync(base)
    for name, patch in _variants().items():
        undo = patch()
        try:
            report[name] = _summary(*_workload(base / name))
        finally:
            undo()
    prof = cProfile.Profile()
    prof.enable()
    _workload(base / "profiled")
    prof.disable()
    out = io.StringIO()
    pstats.Stats(prof, stream=out).sort_stats("tottime").print_stats(25)
    report["profile_tottime"] = out.getvalue()
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        args.out.write_text(text)


if __name__ == "__main__":
    main()
