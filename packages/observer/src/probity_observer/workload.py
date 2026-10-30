"""Check a retained bounded-broker workload run with pinned public keys."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .crypto import VerificationError, digest, strict_loads, verify_signature
from .history import read_history
from .isolation import sha256
from .verify import verify_incomplete, verify_packet


def _counts(history: Path) -> dict[str, int]:
    kinds = [entry["event"]["kind"] for entry in read_history(history)]
    return {
        "accepted": kinds.count("write"),
        "replayed": kinds.count("retry"),
        "denied": kinds.count("denied"),
        "knownGaps": kinds.count("gap"),
    }


def verify_workload_bundle(output: Path, observer_key: str, witness_key: str) -> dict[str, Any]:
    """Check retained bytes against separately pinned observer and witness keys."""
    report = strict_loads((output / "workload-report.json").read_bytes())
    authority = strict_loads((output / "authority.json").read_bytes())
    launch = strict_loads((output / "launch-policy.json").read_bytes())
    attestation = strict_loads((output / "workload-attestation.json").read_bytes())
    if report["witnessScope"] != "PEER" or report["evidence_vantage"] != "artifact":
        raise VerificationError("workload report claims an unsupported vantage")
    if sha256(output / "workload.py") != authority["workloadSha256"]:
        raise VerificationError("workload bytes differ from authority")
    if digest("probity-launch-policy-v0", launch) != authority["launchPolicySha256"]:
        raise VerificationError("launch policy differs from authority")
    for name in ("stdout", "stderr"):
        if sha256(output / f"workload-{name}.bin") != report[f"{name}Sha256"]:
            raise VerificationError("raw workload output differs from report")
    history = output / "history.jsonl"
    entries = read_history(history)
    if report["channelCounts"] != _counts(history):
        raise VerificationError("channel counts differ from broker history")
    payload = {
        "reportDigest": digest("probity-workload-report-v0", report),
        "authorityDigest": digest("probity-authority-v0", authority),
        "historyHead": entries[-1]["hash"],
    }
    if attestation["keyid"] != observer_key or attestation["payload"] != payload:
        raise VerificationError("workload attestation differs from pinned result")
    verify_signature(observer_key, "probity-workload-result-v0", payload, attestation["signature"])
    if entries[0]["event"]["commitment"]["preimage"]["authorityDigest"] != payload["authorityDigest"]:
        raise VerificationError("history commitment differs from authority")
    if report["status"] == "completed":
        packet = strict_loads((output / "packet.json").read_bytes())
        if packet["authority"] != authority:
            raise VerificationError("packet authority differs from workload authority")
        claim = verify_packet(packet, history, observer_key, witness_key, output / "workspace")
        if report["exitCode"] != 0 or report["channelCounts"]["accepted"] < 1 or not claim["coverage"]["noDetectedGap"]:
            raise VerificationError("completed workload has no covered broker effect")
    elif report["status"] == "incomplete":
        incomplete = strict_loads((output / "incomplete.json").read_bytes())
        terminal = verify_incomplete(history, incomplete["startCheckpoint"], incomplete["checkpoint"], observer_key, witness_key)
        if terminal["reason"] != report["reason"] or (output / "packet.json").exists():
            raise VerificationError("incomplete workload differs from history")
    else:
        raise VerificationError("workload report has an unknown status")
    return report
