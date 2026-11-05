"""Verify the retained authority reference run with public code only.

Runs the offline reader over ``retained/native`` with the retained consumer
pins, then requires its report to equal the retained reader report byte for
byte.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from reader import read_run  # noqa: E402

RETAINED = HERE / "retained"


def verify() -> bytes:
    """Return the reader's report bytes for the retained run."""
    pins = json.loads((RETAINED / "native" / "consumer-pins.json").read_text(encoding="ascii"))
    return (json.dumps(read_run(RETAINED / "native", pins), indent=2) + "\n").encode("ascii")


def main() -> int:
    """Exit zero only when the report equals the retained reader report."""
    if verify() != (RETAINED / "reader-report.json").read_bytes():
        print("retained authority report differs from the retained reader report", file=sys.stderr)
        return 1
    print("retained authority reference run verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
