"""CLI for portable, offline claim adjudication."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import CaseError, adjudicate, canonical_json, render_packet


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CaseError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise CaseError(f"non-JSON number: {value}")


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=_invalid_constant)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probity-verify")
    parser.add_argument("case", type=Path)
    parser.add_argument("--policy", type=Path, required=True,
                        help="consumer-held witness pins and claim requirements")
    parser.add_argument("--artifact-root", type=Path,
                        help="directory containing the case's relative artifact paths (default: case directory)")
    parser.add_argument("--packet", type=Path, help="write a readable text decision packet")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a short text decision")
    args = parser.parse_args(argv)
    try:
        case = _load(args.case)
        policy = _load(args.policy)
        result = adjudicate(case, policy, args.artifact_root or args.case.parent)
        if args.packet:
            args.packet.write_text(render_packet(result), encoding="utf-8")
    except (OSError, json.JSONDecodeError, CaseError) as exc:
        print(f"probity-verify: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(canonical_json(result))
    else:
        print(render_packet(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
