"""Replay the retained native witness packet with public code and compare the retained report.

Exit 0 only when the reader reproduces the retained report bytes. The reader and the
public observer modules are the only code involved; no producer runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from probity_observer.crypto import canonical  # noqa: E402
from probity_witness_operator import reader  # noqa: E402
from probity_witness_operator.protocol import sha  # noqa: E402
from probity_witness_operator.sources import load_withheld  # noqa: E402

RETAINED = HERE / "retained"
# Host-selected pin for retained/native/host-policy.json (original CI run packet).
POLICY_SHA256 = "7d209ab59ce4a0e4668b4cf144c84546b6e365f668109b64328232c739264e1d"


def main() -> int:
    """Return 0 when the retained packet replays to the retained report bytes."""
    policy_path = RETAINED / "native" / "host-policy.json"
    if sha(policy_path.read_bytes()) != POLICY_SHA256:
        print("retained host policy differs from the selected pin", file=sys.stderr)
        return 1
    packet = RETAINED / "native" / "packet"
    withheld = load_withheld(RETAINED / "WITHHELD-SOURCES.json", packet / "source")
    produced = canonical(reader.read(packet, reader.load(policy_path), withheld)) + b"\n"
    if produced != (RETAINED / "reader-report.json").read_bytes():
        print("replayed report differs from the retained report", file=sys.stderr)
        return 1
    print("witness operator retained packet verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
