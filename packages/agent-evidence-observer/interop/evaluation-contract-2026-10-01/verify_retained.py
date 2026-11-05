"""Verify the retained joined packet with public code only.

Runs the offline reader over ``retained/native-ticket-run`` with its retained
pins and exits 0 only if the result equals the retained report bytes.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from evaluation_contract import decode, encode, withheld_for  # noqa: E402
from inspect_ticket_reader import verify_saved  # noqa: E402


def main() -> int:
    retained = HERE / "retained"
    packet = retained / "native-ticket-run"
    pins = decode((packet / "consumer-pins.json").read_bytes())
    report = verify_saved(packet, pins, withheld_for(retained / "WITHHELD-SOURCES.json", packet))
    ok = encode(report) == (packet / "report.json").read_bytes()
    print("retained report " + ("matches" if ok else "DIFFERS"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
