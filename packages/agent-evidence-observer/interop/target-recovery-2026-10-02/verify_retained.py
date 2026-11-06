"""Verify the retained target recovery packet with public code only.

Runs the offline reader over ``retained/fresh-run`` with the retained pins and
withheld-source record, then requires its output to equal the retained reader
output byte for byte.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from target_common import load, withheld_sources  # noqa: E402
from target_reader import verify_saved  # noqa: E402

RETAINED = HERE / "retained"


def verify() -> bytes:
    """Return the reader's report bytes for the retained packet."""
    packet = RETAINED / "fresh-run"
    report = verify_saved(packet, load(packet, "consumer-pins.json"), withheld_sources(RETAINED / "WITHHELD-SOURCES.json"))
    return (json.dumps(report, indent=2) + "\n").encode()


def main() -> int:
    """Exit zero only when the report equals the retained reader output."""
    if verify() != (RETAINED / "host-receipts/reader.stdout").read_bytes():
        print("retained target recovery report differs from the retained reader output", file=sys.stderr)
        return 1
    print("retained target recovery packet verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
