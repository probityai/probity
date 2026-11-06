"""Verify the retained native packet with public code only.

Runs the framework-free reader over ``retained/`` with the retained pins and exits
0 only if its report equals the retained report bytes.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "src"))

from probity_pydantic.contract import decode, encode, withheld_for  # noqa: E402
from probity_pydantic.reader import verify_saved  # noqa: E402


def main() -> int:
    retained = HERE / "retained"
    run = retained / "fresh-run"
    packet = run / "packet"
    report = verify_saved(
        packet,
        decode((packet / "consumer-pins.json").read_bytes()),
        withheld_for(retained / "WITHHELD-SOURCES.json", packet),
    )
    expected = (packet / "report.json").read_bytes()
    same = encode(report) == expected and all(
        (run / name).read_bytes().rstrip(b"\n") == expected
        for name in ("producer-stdout.json", "fresh-consumer-report.json")
    )
    print("retained report " + ("matches" if same else "DIFFERS"))
    return 0 if same else 1


if __name__ == "__main__":
    raise SystemExit(main())
