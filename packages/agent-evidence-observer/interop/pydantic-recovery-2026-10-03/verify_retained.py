"""Verify the retained pydantic recovery packet with public code only.

Runs the framework-free reader over ``retained/fresh-run`` with the retained pins
and withheld-source record, then requires its output to equal the retained
reader output byte for byte.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from probity_observer.crypto import canonical  # noqa: E402
from probity_pydantic_recovery.common import load, withheld_sources  # noqa: E402
from probity_pydantic_recovery.reader import verify_saved  # noqa: E402

RETAINED = HERE / "retained"


def verify() -> bytes:
    """Return the reader's output bytes for the retained packet."""
    packet = RETAINED / "fresh-run"
    report = verify_saved(packet, load(packet / "consumer-pins.json"), withheld_sources(RETAINED / "WITHHELD-SOURCES.json"))
    return canonical(report) + b"\n"


def main() -> int:
    """Exit zero only when the report equals the retained reader output."""
    if verify() != (RETAINED / "host-receipts/reader.stdout").read_bytes():
        print("retained pydantic recovery report differs from the retained reader output", file=sys.stderr)
        return 1
    print("retained pydantic recovery packet verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
