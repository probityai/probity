"""Verify the retained authority reference run with public code only.

Runs the offline reader over ``retained/native`` with the retained consumer
pins, then requires its report to equal the retained reader report byte for
byte. Then reads the vendored implementation records against that reader
report and the retained source-discriminator report, and requires the result
to equal the retained implementation-records report byte for byte.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from implementation_records import read_all
from reader import read_run

RETAINED = HERE / "retained"


def verify() -> bytes:
    """Return the reader's report bytes for the retained run."""
    pins = json.loads((RETAINED / "native" / "consumer-pins.json").read_text(encoding="ascii"))
    return (json.dumps(read_run(RETAINED / "native", pins), indent=2) + "\n").encode("ascii")


def verify_records() -> bytes:
    """Return the implementation-records report bytes over the retained reports."""
    report = read_all(HERE / "implementation-records", RETAINED / "reader-report.json",
                      RETAINED / "source-discriminator-report.json")
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    """Exit zero only when both reports equal their retained copies."""
    if verify() != (RETAINED / "reader-report.json").read_bytes():
        print("retained authority report differs from the retained reader report", file=sys.stderr)
        return 1
    if verify_records() != (RETAINED / "implementation-records-report.json").read_bytes():
        print("implementation-records report differs from the retained report", file=sys.stderr)
        return 1
    print("retained authority reference run verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
