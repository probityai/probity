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

from .core import Signer
from .exports import EXPORT_KINDS, compare_seals, seal_export, verify_export_seal
from .journal import now


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
        from .identity_vectors import check, vectors  # noqa: PLC0415

        if args.check is None:
            print(json.dumps(vectors(), indent=2, sort_keys=True))
            return 0
        bad = check(json.loads(args.check.read_text()))
        print(json.dumps({"differ": bad}))
        return 1 if bad else 0
    if args.cmd == "seal-export":
        envelope = seal_export(Signer.from_pem(args.key.read_bytes()), args.export.read_bytes(), source=args.source,
                               kind=args.kind, captured_at=args.captured_at or now())
        args.out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
        return 0
    if args.cmd == "verify-export":
        report = verify_export_seal(json.loads(args.seal.read_text()), args.export.read_bytes(),
                                    [p.read_bytes() for p in args.pub])
        print(json.dumps({k: report[k] for k in ("verdict", "failures")}, sort_keys=True))
        census = report["census"] or {}
        print(f"records {census.get('records')} missing ids {census.get('missingIds')}")
        return 0 if report["verdict"] == "PASS" else 1
    print(json.dumps(compare_seals(json.loads(args.older.read_text()), json.loads(args.newer.read_text())),
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
