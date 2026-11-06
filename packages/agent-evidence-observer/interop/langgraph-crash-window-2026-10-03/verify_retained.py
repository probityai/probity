"""Verify the retained crash-window packet with public code only.

Runs the offline reader over ``retained/fresh-run`` with the retained pins and the
withheld-source record, then requires the report to equal the retained run report.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "joint-recovery-2026-10-02"))

from joint_common import withheld_sources  # noqa: E402
from crash_common import load  # noqa: E402
from crash_reader import verify_saved  # noqa: E402

RETAINED = HERE / "retained"


def main() -> int:
    """Exit zero only when the reader's report equals the retained run report."""
    packet = RETAINED / "fresh-run"
    report = verify_saved(packet, load(packet, "consumer-pins.json"), withheld_sources(RETAINED / "WITHHELD-SOURCES.json"))
    if report != json.loads((RETAINED / "fresh-report.json").read_bytes()):
        print("retained crash-window report differs from the retained run report", file=sys.stderr)
        return 1
    print("retained crash-window packet verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
