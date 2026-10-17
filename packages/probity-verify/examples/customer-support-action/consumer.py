"""Run the local support adapter or replay its portable decision bundle."""

from __future__ import annotations

import argparse
import sys
import tempfile
import zipfile
from pathlib import Path

from adapter import CLAIM_TYPE
from adapter import adjudicate as check_action
from probity_verify import adjudicate
from probity_verify.bundle import create_bundle, replay_bundle
from probity_verify.common import CaseError, _read_input
from probity_verify.core import canonical_json, render_packet
from probity_verify.json_input import parse_json

ADAPTERS = {CLAIM_TYPE: check_action}


def _load(path: Path) -> object:
    return parse_json(_read_input(path, 1024 * 1024, "support control JSON"),
                      max_bytes=1024 * 1024, max_depth=16, max_nodes=4096)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path, nargs="?")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--bundle", type=Path, help="Create a new portable ZIP")
    parser.add_argument("--replay", type=Path, help="Replay a carried ZIP offline")
    parser.add_argument("--json", action="store_true", help="Project decision, reason and action for the independent corpus")
    args = parser.parse_args(argv)
    if args.replay:
        if args.case or args.policy or args.artifact_root or args.bundle:
            parser.error("--replay cannot be combined with case inputs")
    elif args.case is None or args.policy is None:
        parser.error("case and --policy are required")
    try:
        if args.replay:
            result = replay_bundle(args.replay, adapters=ADAPTERS)
        else:
            case, policy = _load(args.case), _load(args.policy)
            artifact_root = args.artifact_root or args.case.parent
            if args.bundle:
                # The bundle API rereads these already bounded control snapshots.
                with tempfile.TemporaryDirectory() as directory:
                    controls = Path(directory)
                    (controls / "case.json").write_bytes(canonical_json(case))
                    (controls / "policy.json").write_bytes(canonical_json(policy))
                    result = create_bundle(controls / "case.json", controls / "policy.json",
                                           args.bundle, artifact_root, adapters=ADAPTERS)
            else:
                result = adjudicate(case, policy, artifact_root, adapters=ADAPTERS)
    except (OSError, CaseError, zipfile.BadZipFile) as exc:
        print(f"customer-support-action: {exc}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.buffer.write(canonical_json({key: result[key] for key in ("decision", "reason", "action")}))
    else:
        print(render_packet(result), end="")
        print(f"Action permission: {result['action']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
