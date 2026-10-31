"""Check a retained Linux boundary gate result with pinned public keys."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .crypto import VerificationError, digest, strict_loads, verify_signature
from .history import read_history
from .verify import verify_incomplete, verify_packet


def sha256(path: Path) -> str:
    """Hash the exact file bytes used for this run."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_boundary_bundle(output: Path, observer_key: str, witness_key: str) -> dict[str, Any]:
    """Check a retained gate result with public keys pinned outside the bundle."""
    report = strict_loads((output / "boundary-report.json").read_bytes())
    authority = strict_loads((output / "authority.json").read_bytes())
    launch = strict_loads((output / "launch-policy.json").read_bytes())
    attestation = strict_loads((output / "boundary-attestation.json").read_bytes())
    if report["witnessScope"] != "PEER" or report["evidence_vantage"] != "artifact":
        raise VerificationError("boundary report claims an unsupported vantage")
    if report["probeSha256"] != authority["probeSha256"] or sha256(output / "agent-probe.py") != authority["probeSha256"]:
        raise VerificationError("probe bytes differ from the committed authority")
    if digest("probity-launch-policy-v0", launch) != authority["launchPolicySha256"]:
        raise VerificationError("launch policy differs from the committed authority")
    for name in ("stdout", "stderr"):
        if sha256(output / f"probe-{name}.bin") != report[f"{name}Sha256"]:
            raise VerificationError("raw probe output differs from the report")
    entries = read_history(output / "history.jsonl")
    payload = {
        "reportDigest": digest("probity-boundary-report-v0", report),
        "authorityDigest": digest("probity-authority-v0", authority),
        "historyHead": entries[-1]["hash"],
    }
    if attestation["keyid"] != observer_key or attestation["payload"] != payload:
        raise VerificationError("boundary attestation differs from the pinned result")
    verify_signature(observer_key, "probity-boundary-result-v0", payload, attestation["signature"])
    history = output / "history.jsonl"
    if report["status"] == "probe-passed":
        packet = strict_loads((output / "packet.json").read_bytes())
        if packet["authority"] != authority:
            raise VerificationError("packet authority differs from the launch authority")
        verify_packet(packet, history, observer_key, witness_key, output / "workspace")
    elif report["status"] == "incomplete":
        incomplete = strict_loads((output / "incomplete.json").read_bytes())
        terminal = verify_incomplete(history, incomplete["startCheckpoint"], incomplete["checkpoint"], observer_key, witness_key)
        if terminal["reason"] != report["reason"] or (output / "packet.json").exists():
            raise VerificationError("incomplete result differs from the history")
    else:
        raise VerificationError("boundary report has an unknown status")
    committed = entries[0]["event"]["commitment"]["preimage"]["authorityDigest"]
    if committed != payload["authorityDigest"]:
        raise VerificationError("history commitment differs from the launch authority")
    return report
