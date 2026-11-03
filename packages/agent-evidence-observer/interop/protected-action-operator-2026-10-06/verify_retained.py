"""Replay the retained protected-action packet and the retained witness packet with public code.

Exit 0 only when both replays reproduce the retained report bytes. The readers and the
public observer modules are the only code involved; no producer runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / "witness-operator-2026-10-03")]

from probity_observer.crypto import canonical  # noqa: E402
from probity_protected_operator import reader as protected  # noqa: E402
from probity_witness_operator import reader as witness  # noqa: E402
from probity_witness_operator.protocol import sha  # noqa: E402
from probity_witness_operator.sources import load_withheld  # noqa: E402

RETAINED = HERE / "retained"
# Host-selected pin for retained/existing-native/host-policy.json (original CI run packet).
WITNESS_POLICY_SHA256 = "c3b2f9c35a04b3a005b95d1ccfcb8bf69c5e2bca51541075c9e847e89599812d"


def _witness() -> bool:
    """Replay the retained witness packet twice and compare the retained reports."""
    policy_path = RETAINED / "existing-native" / "host-policy.json"
    if sha(policy_path.read_bytes()) != WITNESS_POLICY_SHA256:
        return False
    packet = RETAINED / "existing-native" / "packet"
    withheld = load_withheld(RETAINED / "WITHHELD-SOURCES.json", packet / "source")
    produced = canonical(witness.read(packet, witness.load(policy_path), withheld)) + b"\n"
    expected = (RETAINED / "existing-reader-report.json").read_bytes()
    return produced == expected == (RETAINED / "existing-reader-repeat-report.json").read_bytes()


def _protected() -> bool:
    """Replay the retained protected-action packet and compare the retained replay report."""
    produced = protected.encode(protected.read(RETAINED / "native"))
    return produced == (RETAINED / "protected-reader-report.json").read_bytes()


def main() -> int:
    """Return 0 when both retained packets replay to their retained report bytes."""
    for name, check in (("witness packet", _witness), ("protected-action packet", _protected)):
        if not check():
            print(name + ": replayed report differs from the retained report", file=sys.stderr)
            return 1
    print("protected action operator retained packets verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
