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
from .identifiers import identifier

APPROVAL_BINDING_CONTRACT = identifier("agent-evidence-vectors/contract/approval-binding/v1")
UNCERTAIN_EFFECT_CONTRACT = identifier("agent-evidence-vectors/predicate/v1/uncertain-effect")
TOOL_CALL_RECORD = identifier("agent-evidence-vectors/predicate/v1/tool-call-record")
PAYLOAD_FILE = "payload.bin"
OUTCOMES = ("committed", "not_run", "unknown")
REPLIES = ("confirmed", "no_effect", "timeout", "connection_lost")
#: The modes a gate records an approval under. Only ``enforce`` gated the call; the reader denies an approval
#: gathered in ``observe`` or ``monitor`` mode (``approval_not_enforced``).
ENFORCEMENT_MODES = ("enforce", "observe", "monitor")
#: The reason a binding whose record the reader cannot read at all is denied with, instead of an exception that
#: would end the whole journal verification on one malformed line.
BINDING_MALFORMED = "approval_binding_malformed"


def build_approval_binding(approval: Mapping[str, Any], use: Mapping[str, Any], payload: bytes,
                           consumed: list[str], trusted_keys: Mapping[str, str], decision_time: str,
                           policy_release: Mapping[str, Any], *, issued: list[str],
                           enforcement: str) -> tuple[dict[str, Any], bytes]:
    """An approval-binding/v1 record for one use, and the payload bytes it binds.

    Every member comes from the party that holds it, never from a default the reader would accept:

    * ``approval`` is the approver's own signed body. Its ``outcome`` (``approved``,
      ``approved-with-corrections`` or a refusal) and its ``requestId`` are the approver's words; an
      approval that carries no ``requestId`` is refused here, because no reader can tell whether its
      request was answered twice.
    * ``issued`` is the server's issuance register: every approval identifier it issued. The approval
      the client presents is not added to it here; one the server never issued is denied
      (``approval_not_issued``).
    * ``consumed`` is the server's register of approvals already used (``approval_replayed``).
    * ``enforcement`` is the mode the gate ran in when it took the approval, one of
      ``ENFORCEMENT_MODES``; only ``enforce`` gated the call (``approval_not_enforced``).
    """
    if not isinstance(approval.get("requestId"), str) or not approval["requestId"]:
        raise ValueError("approval_request_id_missing")
    if enforcement not in ENFORCEMENT_MODES:
        raise ValueError(f"enforcement must be one of {ENFORCEMENT_MODES}")
    record = {
        "approval": dict(approval),
        "consumedApprovalIds": sorted(set(consumed)),
        "contractId": APPROVAL_BINDING_CONTRACT,
        "decisionTime": decision_time,
        "enforcement": enforcement,
        "issuedApprovalIds": sorted(set(issued)),
        "policyRelease": dict(policy_release),
        "presentedApprovals": [dict(approval)],
        "trustedKeys": dict(trusted_keys),
        "use": {**dict(use), "payloadFile": PAYLOAD_FILE},
    }
    return record, payload


def judge_approval_binding(record: Mapping[str, Any], payload: bytes) -> dict[str, str]:
    """``{"decision": "allow"|"deny", "reason": ...}`` from the published approval-binding reader,
    through its public entry point on the record and payload exactly as an outsider would hold them.

    A record the reader cannot read (a member it needs is missing or of the wrong type) is a deny with
    ``approval_binding_malformed``: the record comes from the journal under verification, so its shape
    is the writer's claim, and a verifier never ends on it."""
    from agent_evidence_vectors import approvalbinding

    use = record.get("use") if isinstance(record, Mapping) else None
    name = str(use.get("payloadFile", PAYLOAD_FILE)) if isinstance(use, Mapping) else PAYLOAD_FILE
    if "/" in name or name in ("", ".", ".."):
        return {"decision": "deny", "reason": "payload_file_unsafe"}
    with tempfile.TemporaryDirectory(prefix="probity-ab-") as tmp:
        path = Path(tmp) / "record.json"
        try:
            path.write_bytes(canonical(dict(record)))
            (Path(tmp) / name).write_bytes(payload)
            verdict = approvalbinding.verify(path)
        except (AttributeError, KeyError, TypeError, ValueError):
            return {"decision": "deny", "reason": BINDING_MALFORMED}
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
    from agent_evidence_verify.core import adjudicate

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


def embed_approval_binding(record: Mapping[str, Any], payload: bytes, approval_sig: str) -> dict[str, Any]:
    """The form a tool-call predicate carries: the record, its payload bytes in base64, and the
    approver's own signature over the approval body (``sign_approval``'s ``sig``), so an auditor
    re-verifies the human's signature under a key it pinned, not the authority's word for it."""
    return {"approvalSig": approval_sig, "payloadB64": base64.b64encode(payload).decode("ascii"),
            "record": dict(record)}


def tool_call_predicate(*, phase: str, run_id: str, tool_call_id: str, tool: str, args_sha256_hex: str,
                        permit_id: str | None, decision: str | None = None, reason: str | None = None,
                        approval_bindings: list[Mapping[str, Any]] | None = None, threshold: int | None = None,
                        approval_policy: str | None = None,
                        outcome: str | None = None,
                        result_sha256: str | None = None, uncertain_effect: Mapping[str, Any] | None = None,
                        context: Mapping[str, Any] | None = None,
                        authority: Mapping[str, Any] | None = None,
                        grant_digest: str | None = None,
                        exception_digest: str | None = None,
                        principals: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The predicate of one tool-call record (the journal adds ``seq``, ``prev`` and ``at``).

    ``phase`` is ``authorize`` (a permit decision), ``intent`` (the call is about to leave the
    worker) or ``effect`` (what came back, as an uncertain_effect/v1 record). An allow carries one
    approval-binding record per approver, the ``threshold`` (M of N) the authority applied and the id
    of the quorum policy (``approval_policy``) the auditor pins to re-count them, or an
    ``authority`` object when it rests on a grant chain, a quorum or an exception; ``grant_digest`` is
    the grant the permit names.
    """
    if phase not in ("authorize", "intent", "effect"):
        raise ValueError("phase must be authorize, intent or effect")
    return {"approvalBindings": [dict(b) for b in approval_bindings or []], "approvalPolicyId": approval_policy,
            "authority": dict(authority) if authority else None, "exceptionDigest": exception_digest, "grantDigest": grant_digest,
            "argsSha256": args_sha256_hex, "context": dict(context or {}), "decision": decision,
            "principals": dict(principals) if principals else None,
            "outcome": outcome, "permitId": permit_id, "phase": phase, "reason": reason,
            "resultSha256": result_sha256, "runId": run_id, "threshold": threshold, "tool": tool,
            "toolCallId": tool_call_id,
            "uncertainEffect": dict(uncertain_effect) if uncertain_effect else None}


def dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)
