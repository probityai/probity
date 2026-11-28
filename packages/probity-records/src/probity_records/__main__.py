"""Command line: seal a governance export, verify a seal, compare two seals.

    python -m probity_records seal-export EXPORT --key KEY.pem --source NAME --kind entities --out SEAL.json
    python -m probity_records verify-export EXPORT SEAL.json --pub PUB.pem
    python -m probity_records compare-seals OLD.json NEW.json
    python -m probity_records identity-vectors [--check FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .clock import SystemClock
from .core import Signer, admitted_loads
from .exports import EXPORT_KINDS, compare_seals, seal_export, verify_export_seal
from .journal import timestamp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m probity_records")
    sub = parser.add_subparsers(dest="cmd", required=True)
    seal = sub.add_parser("seal-export")
    seal.add_argument("export", type=Path)
    seal.add_argument("--key", type=Path, required=True)
    seal.add_argument("--source", required=True)
    seal.add_argument("--kind", choices=EXPORT_KINDS, required=True)
    seal.add_argument("--captured-at")
    seal.add_argument("--out", type=Path, required=True)
    ver = sub.add_parser("verify-export")
    ver.add_argument("export", type=Path)
    ver.add_argument("seal", type=Path)
    ver.add_argument("--pub", type=Path, action="append", required=True)
    cmp_ = sub.add_parser("compare-seals")
    cmp_.add_argument("older", type=Path)
    cmp_.add_argument("newer", type=Path)
    idv = sub.add_parser("identity-vectors")
    idv.add_argument("--check", type=Path)
    args = parser.parse_args(argv)
    if args.cmd == "identity-vectors":
        from .identity_vectors import check, vectors

        if args.check is None:
            print(json.dumps(vectors(), indent=2, sort_keys=True))
            return 0
        bad = check(admitted_loads(args.check.read_bytes()))
        print(json.dumps({"differ": bad}))
        return 1 if bad else 0
    if args.cmd == "seal-export":
        sealed_at = timestamp(SystemClock().now())  # the command line is the process entry point: its one clock
        envelope = seal_export(Signer.from_pem(args.key.read_bytes()), args.export.read_bytes(), source=args.source,
                               kind=args.kind, captured_at=args.captured_at or sealed_at, sealed_at=sealed_at)
        args.out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
        return 0
    if args.cmd == "verify-export":
        try:
            seal_doc = admitted_loads(args.seal.read_bytes())
        except ValueError as exc:  # a seal the strict reader refuses is a failed check, not a traceback
            print(json.dumps({"verdict": "FAIL", "failures": [f"seal:{exc}"]}, sort_keys=True))
            return 1
        report = verify_export_seal(seal_doc, args.export.read_bytes(), [p.read_bytes() for p in args.pub])
        print(json.dumps({k: report[k] for k in ("verdict", "failures")}, sort_keys=True))
        census = report["census"] or {}
        print(f"records {census.get('records')} missing ids {census.get('missingIds')}")
        return 0 if report["verdict"] == "PASS" else 1
    try:
        moved = compare_seals(admitted_loads(args.older.read_bytes()), admitted_loads(args.newer.read_bytes()))
    except (ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": f"seals_unreadable:{exc}"}, sort_keys=True))
        return 1
    print(json.dumps(moved, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
