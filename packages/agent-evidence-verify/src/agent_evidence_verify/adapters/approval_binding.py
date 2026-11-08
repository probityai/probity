"""Approval binding: is this approval bound to the exact use it is presented for.

The reader judges an ``approval-binding/v1`` record and names the first check
that fails, in a fixed order. A record that passes all of them is ``allow`` with
reason ``bound``. Every denied record carries an approval that a verifier
checking only its own signature, payload digest and expiry would accept.
A failed policy lookup is a deny: "not checked" is never read as "matched".
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..json_input import parse_json

SUITE = "approval-binding/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1"
ALLOW, DENY = "allow", "deny"
ACCEPTED = "bound"
MAX_RECORD_BYTES = 1 << 20
CHECKS = (
    "contract_id_missing", "contract_id_unknown", "approval_not_cited",
    "approval_id_ambiguous", "approval_replayed", "approval_superseded",
    "renewal_transition_missing", "renewal_binding_invalid", "key_not_bound",
    "principal_mismatch", "event_phase_mismatch", "payload_mismatch",
    "approval_outside_validity", "effect_already_closed", "comparison_unavailable",
    "release_not_served_at_decision",
)
BOUND_FIELDS = ("event", "payloadSha256", "phase", "principal", "target", "tool")
REPLACEMENT = "exclusive-replacement"
CLOSED_EFFECT_STATES = ("CONSUMED", "UNCERTAIN_CLOSE")


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _accepted_into(record: dict[str, Any]) -> list[dict[str, Any]]:
    approval, used = record["approval"], _when(record["use"]["usedAt"])
    return [t for t in record.get("transitions", [])
            if t["status"] == "accepted" and t["successorApprovalId"] == approval["approvalId"]
            and _when(t["acceptedAt"]) <= used]


def _binds(record: dict[str, Any], approval: dict[str, Any], transition: dict[str, Any]) -> bool:
    candidates: list[dict[str, Any]] = []
    for presented in record.get("presentedApprovals", []):
        if presented["approvalId"] == transition["predecessorApprovalId"] and (
                presented not in candidates):
            candidates.append(presented)
    if len(candidates) != 1 or transition["mode"] != REPLACEMENT:
        return False
    predecessor, decision = candidates[0], approval.get("decisionId")
    return bool(
        decision is not None and transition["successorDecisionId"] == decision
        and transition["predecessorDecisionId"] == predecessor.get("decisionId")
        and decision != predecessor.get("decisionId")
        and all(predecessor.get(f) == approval.get(f) for f in BOUND_FIELDS))


def _superseded(record: dict[str, Any]) -> bool:
    approval, used = record["approval"], _when(record["use"]["usedAt"])
    return any(t["status"] == "accepted" and t["predecessorApprovalId"] == approval["approvalId"]
               and _when(t["acceptedAt"]) <= used for t in record.get("transitions", []))


def _renewal_invalid(record: dict[str, Any]) -> bool:
    if record["use"].get("authorityForm") != "renewed":
        return False
    accepted = _accepted_into(record)
    return bool(accepted) and not any(_binds(record, record["approval"], t) for t in accepted)


def _served(record: dict[str, Any]) -> bool:
    release, decided = record["policyRelease"], _when(record["decisionTime"])
    grace = timedelta(seconds=release["graceSeconds"])
    return _when(release["firstServedAt"]) <= decided <= _when(release["lastServedAt"]) + grace


def _payload_matches(record: dict[str, Any], used: bytes) -> bool:
    approval, use = record["approval"], record["use"]
    return bool(use["tool"] == approval["tool"] and use["target"] == approval["target"]
                and hashlib.sha256(used).hexdigest() == approval["payloadSha256"])


def first_failure(record: dict[str, Any], used: bytes) -> str | None:
    """The first check in ``CHECKS`` the record fails, or None."""
    approval, use = record["approval"], record["use"]
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "approval_not_cited": lambda: use.get("approvalId") != approval["approvalId"],
        "approval_id_ambiguous": lambda: any(
            o["approvalId"] == approval["approvalId"] and o != approval
            for o in record.get("presentedApprovals", [])),
        "approval_replayed": lambda: approval["approvalId"] in record.get(
            "consumedApprovalIds", []),
        "approval_superseded": lambda: _superseded(record),
        "renewal_transition_missing": lambda: use.get("authorityForm") == "renewed"
        and not _accepted_into(record),
        "renewal_binding_invalid": lambda: _renewal_invalid(record),
        "key_not_bound": lambda: record["trustedKeys"].get(approval["approver"]) != approval[
            "keyId"],
        "principal_mismatch": lambda: use["principal"] != approval["principal"],
        "event_phase_mismatch": lambda: (use["event"], use["phase"]) != (
            approval["event"], approval["phase"]),
        "payload_mismatch": lambda: not _payload_matches(record, used),
        "approval_outside_validity": lambda: not (
            _when(approval["issuedAt"]) <= _when(use["usedAt"]) < _when(approval["expiresAt"])),
        "effect_already_closed": lambda: use.get("effectKey") is not None
        and record.get("effectRegistry", {}).get(use["effectKey"]) in CLOSED_EFFECT_STATES,
        "comparison_unavailable": lambda: record["policyRelease"]["lookup"] != "ok",
        "release_not_served_at_decision": lambda: not _served(record),
    }
    return next((name for name in CHECKS if failures[name]()), None)


def judge(record_path: Path) -> tuple[str, str]:
    """(decision, reason) for the ``record.json`` at ``record_path``."""
    record = parse_json(record_path.read_bytes(), max_bytes=MAX_RECORD_BYTES,
                        max_depth=32, max_nodes=32768)
    if not isinstance(record, dict):
        raise ValueError("record: expected a JSON object")
    used = (record_path.parent / record["use"]["payloadFile"]).read_bytes()
    failure = first_failure(record, used)
    return (ALLOW, ACCEPTED) if failure is None else (DENY, failure)
