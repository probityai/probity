"""The evaluator-replay command line."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evaluator_replay_kit.replay import Pin, PinError, make_pin, replay_bytes

EXIT_FOR = {"intact": 0, "tampered": 1, "gap": 1, "broken": 1, "invalid": 2}


def _record_path(target: Path) -> Path:
    return target / "record.jsonl" if target.is_dir() else target


def _load_pin(args: argparse.Namespace, target: Path) -> Pin:
    path = args.pin or (target / "pin.json" if target.is_dir() and (target / "pin.json").is_file() else None)
    node = json.loads(path.read_text(encoding="utf-8")) if path else {"schema": "evaluator-replay-pin/v1"}
    pin = Pin.from_json(node)
    return Pin(args.count if args.count is not None else pin.count,
               args.head or pin.head, pin.records)


def _verify(args: argparse.Namespace) -> int:
    pin = _load_pin(args, args.bundle)
    report = replay_bytes(_record_path(args.bundle).read_bytes(), pin, args.require_end)
    if args.json:
        print(json.dumps(report.to_json(), indent=2, sort_keys=True))
    else:
        print(f"{report.verdict}: {report.steps} steps, end {report.end}")
        for item in report.findings:
            where = "" if item.index is None else f" line {item.index}"
            print(f"  {item.code} [{item.cls}]{where} {item.id or ''}: {item.detail}")
    return EXIT_FOR[report.verdict]


def _pin(args: argparse.Namespace) -> int:
    print(json.dumps(make_pin(_record_path(args.bundle).read_bytes()), indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the command; exit 0 intact, 1 tampered, gap or broken, 2 unreadable."""
    parser = argparse.ArgumentParser(prog="evaluator-replay")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="replay a record and flag tamper or a gap")
    verify.add_argument("bundle", type=Path, help="record.jsonl, or a directory holding it")
    verify.add_argument("--pin", type=Path, help="pin.json (default: pin.json beside the record)")
    verify.add_argument("--head", help="pinned digest of the last step")
    verify.add_argument("--count", type=int, help="pinned number of steps")
    verify.add_argument("--require-end", action="store_true", help="fail when no head proves the end")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(run=_verify)
    pin = commands.add_parser("pin", help="print a pin describing a record")
    pin.add_argument("bundle", type=Path)
    pin.set_defaults(run=_pin)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (OSError, ValueError, PinError) as exc:
        print(f"evaluator-replay: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
