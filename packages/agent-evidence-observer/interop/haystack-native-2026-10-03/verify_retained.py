"""Check the retained Haystack packet with the public reader and observer code only."""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from probity_haystack.contract import encode, load, sha  # noqa: E402
from probity_haystack.reader import publish_saved, verify_saved  # noqa: E402

RETAINED = HERE / "retained"


def withheld_sources() -> dict[str, str]:
    """Return the withheld source digests, keyed by manifest path."""
    prefix = "packet/source/"
    held = load(RETAINED / "WITHHELD-SOURCES.json")
    return {name.removeprefix(prefix): digest for name, digest in held.items() if name.startswith(prefix)}


def materialize(destination: Path) -> Path:
    """Copy the retained packet and restore the empty target directories that Git cannot store."""
    shutil.copytree(RETAINED / "packet", destination)
    for history in sorted(destination.rglob("history.jsonl")):
        (history.parent / "work").mkdir(exist_ok=True)
    return destination


def check(packet: Path, scratch: Path) -> list[str]:
    """Return the differences between the reader's output and the retained reports."""
    policy_path = packet / "host-policy.json"
    policy = load(policy_path)
    held = withheld_sources()
    problems = []
    if encode(verify_saved(packet, policy, held)) + b"\n" != (RETAINED / "reader-report.json").read_bytes():
        problems.append("reader output differs from reader-report.json")
    published = publish_saved(packet, policy, scratch / "publication", held)
    if encode(published) + b"\n" != (RETAINED / "publication-report.json").read_bytes():
        problems.append("publication output differs from the retained report")
    if (scratch / "publication" / "published.json").read_bytes() != (RETAINED / "publication" / "published.json").read_bytes():
        problems.append("published record differs from the retained record")
    if sha(policy_path.read_bytes()) != sha(encode(policy)):
        problems.append("host policy is not in canonical form")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materialize", type=Path, help="write a readable copy of the retained packet here and stop")
    args = parser.parse_args()
    if args.materialize:
        materialize(args.materialize)
        return 0
    with tempfile.TemporaryDirectory() as scratch:
        problems = check(materialize(Path(scratch) / "packet"), Path(scratch))
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print("retained Haystack packet verified")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
