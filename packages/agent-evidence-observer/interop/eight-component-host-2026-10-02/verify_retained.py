"""Verify the retained eight-component host run with public observer code only.

Two checks run over ``retained/fresh-completed``. Every retained gate stream
must match the digest its process record carries. The native ticket effect is
then re-verified with the public ticket-state reader from the retained signed
receipt, separate HTTP readback and host grant, and its result must equal the
retained gate output byte for byte.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from probity_observer.grant_records import ActionRequest, GrantPolicy
from probity_observer.ticket_state import verify_ticket_result

RETAINED = Path(__file__).resolve().parent / "retained" / "fresh-completed"


def read(name: str) -> Any:
    """Parse one retained JSON member."""
    return json.loads((RETAINED / name).read_bytes())


def stream_failures() -> list[str]:
    """Return gate streams whose bytes differ from their process record."""
    failures = []
    for record in sorted(RETAINED.glob("*.process.json")):
        stem = record.name.removesuffix(".process.json")
        process = json.loads(record.read_bytes())
        for stream, suffix in (("stdout", ".stdout"), ("stderr", ".stderr")):
            raw = (RETAINED / (stem + suffix)).read_bytes()
            if len(raw) != process[stream + "Bytes"] or hashlib.sha256(raw).hexdigest() != process[stream + "Sha256"]:
                failures.append(stem + suffix)
    return failures


def effect_report() -> bytes:
    """Return the public reader's gate output for the retained native effect."""
    config, selected = read("verify-effect.config.json"), read("host-grant.json")
    now = datetime.fromisoformat(config["currentTime"].replace("Z", "+00:00"))
    result = verify_ticket_result(config["receipt"], config["readback"], ActionRequest(**selected["request"]),
                                  GrantPolicy(**selected["grantPolicy"]), config["policy"]["publicKeys"]["service"],
                                  selected["grant"], now=now)
    report = {"gate": "native-effect-readback", "admitted": True, "result": result,
              "doesNotAssert": config["policy"]["doesNotAssert"]}
    return (json.dumps(report, sort_keys=True) + "\n").encode("ascii")


def main() -> int:
    """Exit zero only when every retained stream and the native effect verify."""
    failures = stream_failures()
    if effect_report() != (RETAINED / "verify-effect.stdout").read_bytes():
        failures.append("native-effect-readback")
    for failure in failures:
        print("retained eight-component record differs: " + failure, file=sys.stderr)
    if failures:
        return 1
    print("retained eight-component host run verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
