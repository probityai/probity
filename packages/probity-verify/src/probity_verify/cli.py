"""CLI for portable, offline claim adjudication."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import CaseError, adjudicate, canonical_json, render_packet
from .common import MAX_ARTIFACT_BYTES, _read_input
from .json_input import parse_json


def _load(path: Path) -> object:
    raw = _read_input(path, MAX_ARTIFACT_BYTES, "control JSON")
    return parse_json(raw, max_bytes=MAX_ARTIFACT_BYTES, max_depth=32, max_nodes=32768)


SUMMARY = "decide whether a claim holds against pinned evidence bytes, offline"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Declare the verifier's arguments on ``parser``."""
    parser.add_argument("case", type=Path)
    parser.add_argument("--policy", type=Path, required=True,
                        help="consumer-held witness pins and claim requirements")
    parser.add_argument("--artifact-root", type=Path,
                        help="directory containing the case's relative artifact paths (default: case directory)")
    parser.add_argument("--packet", type=Path, help="write a readable text decision packet")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a short text decision")
    parser.add_argument("--require-witness-scope", choices=("PEER", "EXTERNAL"), default="PEER",
                        help="hold supported verdicts that do not rest on this witness scope as not_established; contradicted verdicts stand")


def run(args: argparse.Namespace, prog: str) -> int:
    """Adjudicate the parsed arguments; exit 0 with a decision, 2 for invalid input."""
    try:
        case = _load(args.case)
        policy = _load(args.policy)
        result = adjudicate(case, policy, args.artifact_root or args.case.parent,
                            require_witness_scope=args.require_witness_scope)
        if args.packet:
            args.packet.write_text(render_packet(result), encoding="utf-8")
    except (OSError, json.JSONDecodeError, CaseError) as exc:
        print(f"{prog}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(canonical_json(result))
    else:
        print(render_packet(result), end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point of the ``probity-verify`` console script."""
    parser = argparse.ArgumentParser(prog="probity-verify", description=SUMMARY)
    add_arguments(parser)
    return run(parser.parse_args(argv), "probity-verify")


def register(subparsers) -> None:
    """Add ``verify`` to the ``probity`` command line (entry point ``probityai.cli_subcommands``)."""
    from probityai.cli import register_leaf  # only the probity launcher calls this, so it is installed

    parser = subparsers.add_parser("verify", help=SUMMARY, description=SUMMARY)
    add_arguments(parser)
    prog = parser.prog
    register_leaf(parser, handler=lambda args: run(args, prog))

if __name__ == "__main__":
    raise SystemExit(main())
