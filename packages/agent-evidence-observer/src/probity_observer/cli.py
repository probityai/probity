"""Check retained broker packets, boundary runs and workload runs offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from .crypto import strict_loads
from .isolation import verify_boundary_bundle
from .verify import verify_packet
from .workload import verify_workload_bundle


def add_verify_commands(subcommands: Any) -> None:
    """Register the offline verification subcommands on a parser."""
    checked_workload = subcommands.add_parser("verify-workload", help="check a retained workload run with pinned keys")
    checked_workload.add_argument("directory", type=Path)
    checked_workload.add_argument("--observer-key", required=True)
    checked_workload.add_argument("--witness-key", required=True)
    checked = subcommands.add_parser("verify-boundary", help="check a retained boundary run with pinned keys")
    checked.add_argument("directory", type=Path)
    checked.add_argument("--observer-key", required=True)
    checked.add_argument("--witness-key", required=True)
    verify = subcommands.add_parser("verify", help="check a retained sample offline")
    verify.add_argument("directory", type=Path)


def run_verify_command(arguments: argparse.Namespace) -> dict[str, str]:
    """Check one retained record named by a verification subcommand."""
    if arguments.command == "verify-workload":
        report = verify_workload_bundle(arguments.directory, arguments.observer_key, arguments.witness_key)
        return {"status": "verified", "workloadStatus": report["status"], "witnessScope": report["witnessScope"]}
    if arguments.command == "verify-boundary":
        report = verify_boundary_bundle(arguments.directory, arguments.observer_key, arguments.witness_key)
        return {"status": "verified", "boundaryStatus": report["status"], "witnessScope": report["witnessScope"]}
    directory = arguments.directory
    packet = strict_loads((directory / "packet.json").read_bytes())
    keys = strict_loads((directory / "trusted-keys.json").read_bytes())
    claim = verify_packet(packet, directory / "history.jsonl", keys["observer"], keys["witness"], directory / "workspace")
    return {"status": "verified", "witnessScope": claim["witnessScope"], "noDetectedGap": str(claim["coverage"]["noDetectedGap"]).lower()}


def main(argv: Sequence[str] | None = None) -> int:
    """Verify a retained packet, boundary run or workload run with pinned keys."""
    parser = argparse.ArgumentParser(description=__doc__)
    add_verify_commands(parser.add_subparsers(dest="command", required=True))
    print(json.dumps(run_verify_command(parser.parse_args(argv)), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
