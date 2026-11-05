"""Check the retained three routing cases with the public reader and public observer code only."""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from probity_adk_responses.contract import encode  # noqa: E402
from probity_adk_responses.reader import read  # noqa: E402

RUN = HERE / "retained"


def materialize(destination: Path) -> Path:
    """Copy the retained run and restore the empty workspaces that Git cannot store."""
    shutil.copytree(RUN, destination)
    for history in sorted((destination / "packet" / "cases").rglob("history.jsonl")):
        (history.parent / "workspace").mkdir(exist_ok=True)
    return destination


def check(run: Path) -> int:
    """Read the packet with the retained pins and compare both retained decisions."""
    policy = (run / "host-policy.json").read_bytes()
    decision = encode(read(run / "packet", policy, hashlib.sha256(policy).hexdigest()))
    for name in ("decision-1.json", "decision-2.json"):
        if decision != (run / name).read_bytes():
            print(f"retained decision differs from {name}", file=sys.stderr)
            return 1
    print(decision.decode())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materialize", type=Path, help="write a readable copy of the retained run here and stop")
    args = parser.parse_args()
    if args.materialize:
        materialize(args.materialize)
        return 0
    with tempfile.TemporaryDirectory() as scratch:
        return check(materialize(Path(scratch) / "run"))


if __name__ == "__main__":
    raise SystemExit(main())
