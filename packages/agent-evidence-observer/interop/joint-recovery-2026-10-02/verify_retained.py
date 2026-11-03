"""Verify the retained joint recovery packet with public code only.

Runs the offline reader over ``retained/fresh-run`` with the retained pins and
the withheld-source record, then requires the canonical report to equal the
retained reader stdout byte for byte and the retained run report as JSON.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from joint_common import load, withheld_sources  # noqa: E402
from joint_reader import verify_saved  # noqa: E402
from probity_observer.crypto import canonical  # noqa: E402

RETAINED = HERE / "retained"


def verify() -> bytes:
    """Return the reader's canonical report for the retained packet."""
    packet = RETAINED / "fresh-run"
    report = verify_saved(packet, load(packet, "consumer-pins.json"), withheld_sources(RETAINED / "WITHHELD-SOURCES.json"))
    return canonical(report)


def main() -> int:
    """Exit zero only when the report equals the retained report bytes."""
    produced = verify()
    if produced != (RETAINED / "host-receipts/reader.stdout").read_bytes():
        print("retained joint recovery report differs from the retained reader output", file=sys.stderr)
        return 1
    if json.loads(produced) != json.loads((RETAINED / "fresh-report.json").read_bytes()):
        print("retained joint recovery report differs from the retained run report", file=sys.stderr)
        return 1
    print("retained joint recovery packet verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
