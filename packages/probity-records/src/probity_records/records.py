"""Builders for the two record contracts every tool-call record carries, and the published readers.

* ``approval-binding/v1`` (agent-evidence-vectors): one approval presented for one use, with the
  payload bytes of that use. Judged by ``agent_evidence_vectors.approvalbinding``.
* ``uncertain_effect/v1`` (agent-evidence-vectors, ported into agent-evidence-verify): the trail of
  one intended effect, including a lost reply. Judged by agent-evidence-verify's built-in adapter.

Neither judgement is ours: both readers are the published ones, so a record is checked by the same
code an outsider installs.
"""

from __future__ import annotations

import base64
import json
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .core import canonical, sha256_hex

APPROVAL_BINDING_CONTRACT = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1"
UNCERTAIN_EFFECT_CONTRACT = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"
TOOL_CALL_RECORD = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/tool-call-record"
PAYLOAD_FILE = "payload.bin"
OUTCOMES = ("committed", "not_run", "unknown")
REPLIES = ("confirmed", "no_effect", "timeout", "connection_lost")


def build_approval_binding(approval: Mapping[str, Any], use: Mapping[str, Any], payload: bytes,
                           consumed: list[str], trusted_keys: Mapping[str, str], decision_time: str,
                           policy_release: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    """An approval-binding/v1 record for one use, and the payload bytes it binds."""
    record = {
        "approval": dict(approval),
        "consumedApprovalIds": sorted(set(consumed)),
        "contractId": APPROVAL_BINDING_CONTRACT,
        "decisionTime": decision_time,
        "policyRelease": dict(policy_release),
        "presentedApprovals": [dict(approval)],
        "trustedKeys": dict(trusted_keys),
        "use": {**dict(use), "payloadFile": PAYLOAD_FILE},
    }
    return record, payload


def judge_approval_binding(record: Mapping[str, Any], payload: bytes) -> dict[str, str]:
    """``{"decision": "allow"|"deny", "reason": ...}`` from the published approval-binding reader."""
    from agent_evidence_vectors import approvalbinding  # noqa: PLC0415 - optional at import time

    with tempfile.TemporaryDirectory(prefix="probity-ab-") as tmp:
        path = Path(tmp) / "record.json"
        path.write_bytes(canonical(dict(record)))
        name = str(record.get("use", {}).get("payloadFile", PAYLOAD_FILE))
        if "/" in name or name in ("", ".", ".."):
            return {"decision": "deny", "reason": "payload_file_unsafe"}
        (Path(tmp) / name).write_bytes(payload)
        verdict = approvalbinding.verify(path)
    return {"decision": verdict["decision"], "reason": verdict["reason"]}


def build_uncertain_effect(*, record_id: str, action: str, operation_id: str, idempotency_key: str,
                           args_sha256_hex: str, attempts: list[Mapping[str, Any]], owner_id: str,
                           owner_effects: int, outcome: str, as_of: str,
                           reconciliations: list[Mapping[str, Any]] | None = None,
                           deduplicates_by_key: bool = False,
                           key_retention_seconds: float | None = None) -> dict[str, Any]:
    """An uncertain_effect/v1 record. ``attempts`` items carry ``dispatchedAt`` and ``reply``.

    ``owner_effects`` is the count the effect owner itself reports, never the caller's own tally.
    """
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {OUTCOMES}")
    digest = "sha256:" + args_sha256_hex
    trail = []
    for number, item in enumerate(attempts, 1):
        if item["reply"] not in REPLIES:
            raise ValueError(f"reply must be one of {REPLIES}")
        trail.append({"argsDigest": digest, "attempt": number, "idempotencyKey": idempotency_key,
                      **{k: v for k, v in item.items() if k not in ("argsDigest", "idempotencyKey")}})
    return {
        "asOf": as_of,
        "attempts": trail,
        "contractId": UNCERTAIN_EFFECT_CONTRACT,
        "effectOwner": {"deduplicatesByKey": deduplicates_by_key, "id": owner_id,
                        "keyRetentionSeconds": key_retention_seconds},
        "operation": {"action": action, "argsDigest": digest, "id": operation_id,
                      "idempotencyKey": idempotency_key},
        "ownerEffects": owner_effects,
        "reconciliations": [{"idempotencyKey": idempotency_key, **dict(r)} for r in reconciliations or []],
        "recordId": record_id,
        "reported": {"outcome": outcome},
    }


def judge_uncertain_effect(record: Mapping[str, Any]) -> dict[str, Any]:
    """The decision of agent-evidence-verify's built-in ``uncertain_effect/v1`` adapter."""
    from agent_evidence_verify.core import adjudicate  # noqa: PLC0415 - optional at import time

    data = canonical(dict(record))
    with tempfile.TemporaryDirectory(prefix="probity-ue-") as tmp:
        (Path(tmp) / "record.json").write_bytes(data)
        case = {"schema_version": "probity-case/v1", "case_id": "record",
                "artifacts": {"record": {"path": "record.json", "sha256": sha256_hex(data),
                                         "length": len(data)}}}
        policy = {"schema_version": "probity-policy/v1",
                  "assessments": {"record": {"claim_type": "uncertain_effect/v1", "record": "record"}}}
        result = adjudicate(case, policy, Path(tmp))
    check = next((c for c in result.get("checks", []) if c.get("id") == "uncertain_effect_checks"), {})
    return {"decision": result["decision"], "reason": result["reason"],
            "settled_outcome": check.get("settled_outcome"), "reported_outcome": check.get("reported_outcome")}


def verifier_case(record: Mapping[str, Any]) -> tuple[bytes, dict[str, Any], dict[str, Any]]:
    """The record bytes plus a case and policy, so ``agent-evidence-verify verify case.json --policy
    policy.json`` judges an exported record with nothing but the published CLI."""
    data = canonical(dict(record))
    case = {"schema_version": "probity-case/v1", "case_id": "record",
            "artifacts": {"record": {"path": "record.json", "sha256": sha256_hex(data), "length": len(data)}}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {"record": {"claim_type": "uncertain_effect/v1", "record": "record"}}}
    return data, case, policy


def embed_approval_binding(record: Mapping[str, Any], payload: bytes) -> dict[str, Any]:
    """The form a tool-call predicate carries: the record plus its payload bytes in base64."""
    return {"payloadB64": base64.b64encode(payload).decode("ascii"), "record": dict(record)}


def tool_call_predicate(*, phase: str, run_id: str, tool_call_id: str, tool: str, args_sha256_hex: str,
                        permit_id: str | None, decision: str | None = None, reason: str | None = None,
                        approval_binding: Mapping[str, Any] | None = None, outcome: str | None = None,
                        result_sha256: str | None = None, uncertain_effect: Mapping[str, Any] | None = None,
                        context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The predicate of one tool-call record (the journal adds ``seq``, ``prev`` and ``at``).

    ``phase`` is ``authorize`` (a permit decision), ``intent`` (the call is about to leave the
    worker) or ``effect`` (what came back, as an uncertain_effect/v1 record).
    """
    if phase not in ("authorize", "intent", "effect"):
        raise ValueError("phase must be authorize, intent or effect")
    return {"approvalBinding": dict(approval_binding) if approval_binding else None,
            "argsSha256": args_sha256_hex, "context": dict(context or {}), "decision": decision,
            "outcome": outcome, "permitId": permit_id, "phase": phase, "reason": reason,
            "resultSha256": result_sha256, "runId": run_id, "tool": tool, "toolCallId": tool_call_id,
            "uncertainEffect": dict(uncertain_effect) if uncertain_effect else None}


def dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)
