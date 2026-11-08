"""``probity-temporal verify DIR --key authority.pub --checkpoint checkpoint.json``: offline check of a
run's records. Imports neither Temporal nor the network; exit 0 only on PASS."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="probity-temporal")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify a journal offline")
    v.add_argument("journal", type=Path, help="journal.jsonl or the directory holding it")
    v.add_argument("--key", type=Path, action="append", required=True, help="trusted authority public key (PEM)")
    v.add_argument("--checkpoint", type=Path, help="the signed checkpoint you pinned")
    v.add_argument("--policy", type=Path, action="append", default=[],
                   help="an approval quorum policy you pinned (JSON: policyId, threshold, approvers)")
    v.add_argument("--json", action="store_true")
    sub.add_parser("demo", help="the refund demo: run | worker (see probity_temporal.demo)", add_help=False)
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["demo"]:
        from .demo import main as demo_main  # noqa: PLC0415 - imported as a package module, never __main__

        return demo_main(args[1:])
    a = ap.parse_args(args)
    from probity_records import Trust, verify_journal  # noqa: PLC0415

    checkpoint = json.loads(a.checkpoint.read_text()) if a.checkpoint else None
    policies = [json.loads(path.read_text()) for path in a.policy]
    trust = Trust(quorum_policies={pol["policyId"]: pol for pol in policies}) if policies else None
    report = verify_journal(a.journal, [k.read_bytes() for k in a.key], checkpoint, trust=trust)
    if a.json:
        print(json.dumps({k: v for k, v in report.items() if k != "statements"}, indent=2))
    else:
        print(f"{report['verdict']}: {report['verified']} of {report['records']} records verified, "
              f"checkpoint {report['checkpoint']}, outcomes {report['outcomes']}")
        for failure in report["failures"]:
            print("  " + failure)
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
