"""Verify the retained native packets with public code only.

Runs the framework-free readers over ``retained/`` with the retained pins and exits
0 only if every report equals the retained report bytes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lg_common import decode, read, withheld_for  # noqa: E402
from durable_reader import verify_saved as verify_durable  # noqa: E402
from lg_reader import verify_saved as verify_fresh  # noqa: E402


def check(retained: Path, run: str, verify, expected: Path) -> bool:
    packet = retained / run
    report = verify(packet, decode(read(packet, "consumer-pins.json")), withheld_for(retained / "WITHHELD-SOURCES.json", packet))
    return (json.dumps(report, indent=2) + "\n").encode() == expected.read_bytes()


def main() -> int:
    retained = HERE / "retained"
    ok = check(retained, "fresh-run", verify_fresh, retained / "fresh-reader.json")
    ok = check(retained, "durable-run", verify_durable, retained / "durable-reader.json") and ok
    print("retained reports " + ("match" if ok else "DIFFER"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
