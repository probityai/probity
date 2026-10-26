"""CLI for portable, offline claim adjudication."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .common import MAX_ARTIFACT_BYTES, _read_input
from .core import CaseError, adjudicate, canonical_json, render_packet
from .dsse import IN_TOTO_PAYLOAD_TYPE, adjudicate_envelope, is_envelope, load_key
from .json_input import parse_json


def _load(path: Path) -> object:
    raw = _read_input(path, MAX_ARTIFACT_BYTES, "control JSON")
    return parse_json(raw, max_bytes=MAX_ARTIFACT_BYTES, max_depth=32, max_nodes=32768)


SUMMARY = "decide whether a claim holds against pinned evidence bytes, offline"
INPUT_HELP = ("a probity case, or a DSSE envelope whose payload is one of the case's "
              "artifacts (the type is detected from the JSON members)")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Declare the verifier's arguments on ``parser``."""
    parser.add_argument("input", type=Path, metavar="INPUT", help=INPUT_HELP)
    parser.add_argument("--policy", type=Path, required=True,
                        help="consumer-held witness pins and claim requirements")
    parser.add_argument("--artifact-root", type=Path,
                        help="directory containing the case's relative artifact paths (default: case directory)")
    parser.add_argument("--packet", type=Path, help="write a readable text decision packet")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a short text decision")
    parser.add_argument("--require-witness-scope", choices=("PEER", "EXTERNAL"), default="PEER",
                        help="hold supported verdicts that do not rest on this witness scope as not_established; contradicted verdicts stand")
    envelope = parser.add_argument_group("DSSE envelope input")
    envelope.add_argument("--case", type=Path, dest="envelope_case",
                          help="the case the envelope's payload belongs to (required for an envelope)")
    envelope.add_argument("--key", type=Path, action="append", default=[],
                          help="a trusted Ed25519 public key, raw 32 bytes or PEM; repeat for a keyring")
    envelope.add_argument("--payload-type", default=IN_TOTO_PAYLOAD_TYPE,
                          help=f"the payloadType the envelope must carry (default: {IN_TOTO_PAYLOAD_TYPE})")


def _decide(args: argparse.Namespace) -> dict:
    value = _load(args.input)
    policy = _load(args.policy)
    if not is_envelope(value):
        if args.envelope_case or args.key:
            raise CaseError("--case and --key apply only to a DSSE envelope input")
        return adjudicate(value, policy, args.artifact_root or args.input.parent,
                          require_witness_scope=args.require_witness_scope)
    if args.envelope_case is None:
        raise CaseError("a DSSE envelope input needs --case")
    keys = [load_key(_read_input(path, 64 * 1024, "key"), f"key {path.name}")
            for path in args.key]
    return adjudicate_envelope(value, _load(args.envelope_case), policy,
                               args.artifact_root or args.envelope_case.parent, keys,
                               payload_type=args.payload_type,
                               require_witness_scope=args.require_witness_scope)


def run(args: argparse.Namespace, prog: str) -> int:
    """Adjudicate the parsed arguments; exit 0 with a decision, 2 for invalid input."""
    try:
        result = _decide(args)
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
    """Add ``verify`` to the ``probityai`` command line (entry point ``probityai.cli_subcommands``)."""
    from probityai.cli import (
        register_leaf,  # only the probity launcher calls this, so it is installed
    )

    parser = subparsers.add_parser("verify", help=SUMMARY, description=SUMMARY)
    add_arguments(parser)
    prog = parser.prog
    register_leaf(parser, handler=lambda args: run(args, prog))

if __name__ == "__main__":
    raise SystemExit(main())
