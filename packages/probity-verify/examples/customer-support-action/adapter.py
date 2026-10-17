"""A consumer-selected check for one structured customer discount offer.

This example checks retained records, exact draft rendering and a selected
approval snapshot. It does not authenticate records or send an email.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from probity_verify.common import CaseError, _artifact, _digest, _instant, _object, _string
from probity_verify.json_input import parse_json

CLAIM_TYPE = "customer_support_action/v1"
REQUIRED_CHECKS = (
    "action_binding", "recipient", "plan", "discount", "tenure",
    "draft_rendering", "report", "manager_authorization",
)
BASE_ROLES = ("action", "draft", "customer", "company_policy", "report")
MANAGER_ROLES = ("manager_approval", "approval_uses")
ROLES = frozenset(BASE_ROLES + MANAGER_ROLES)
FIELDS = {
    "action": {"schema_version", "action_id", "request_id", "recipient", "plan", "discount_bps"},
    "customer": {"customer_id", "recipient", "plan", "tenure_months"},
    "company_policy": {"policy_id", "plan", "routine_discount_bps", "maximum_discount_bps", "minimum_tenure_months"},
    "report": {"schema_version", "status", "score"},
    "manager_approval": {"approval_id", "action_id", "request_id", "recipient", "plan", "discount_bps", "action_sha256", "draft_sha256", "approver_id", "not_before", "expires_at"},
    "approval_uses": {"consumed_approval_ids"},
}


def _integer(value: Any, label: str, *, discount: bool = False) -> int:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise CaseError(f"{label}: expected nonnegative integer")
    if discount and (value > 10000 or value % 100):
        raise CaseError(f"{label}: expected whole percent in basis points")
    return value


def _text(value: Any, label: str) -> str:
    text = _string(value, label)
    if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        raise CaseError(f"{label}: expected Unicode scalar values")
    return text


def _strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise CaseError(f"{label}: expected list")
    items = [_text(item, label) for item in value]
    if len(items) != len(set(items)):
        raise CaseError(f"{label}: duplicate member")
    return items


def _clock(value: Any, label: str):
    if not isinstance(value, str) or not value.isascii():
        raise CaseError(f"{label}: expected ASCII UTC timestamp")
    return _instant(value, label)


def _raw(data: bytes, role: str) -> Any:
    if role == "draft":
        try:
            return data.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise CaseError("draft: expected UTF-8") from exc
    value = _object(parse_json(data, max_bytes=1024 * 1024, max_depth=16,
                               max_nodes=4096), role, FIELDS[role])
    for name, item in value.items():
        label = f"{role}.{name}"
        if name.endswith("_bps"):
            _integer(item, label, discount=True)
        elif name.endswith("_months"):
            _integer(item, label)
        elif name.endswith("_sha256"):
            _digest(item, label)
        elif name in {"not_before", "expires_at"}:
            _clock(item, label)
        elif name == "consumed_approval_ids":
            _strings(item, label)
        elif name == "score":
            if type(item) not in {int, float} or not 0 <= item <= 100 or not math.isfinite(item):
                raise CaseError(f"{label}: expected finite score from 0 to 100")
        else:
            _text(item, label)
    if role == "action" and value["schema_version"] != "support-discount-action/v1":
        raise CaseError("unsupported action schema_version")
    if role == "report" and (value["schema_version"] != "synthetic-quality-report/v1" or
                              value["status"] not in {"GREEN", "AMBER", "RED"}):
        raise CaseError("unsupported advisory report")
    if role == "company_policy" and value["routine_discount_bps"] > value["maximum_discount_bps"]:
        raise CaseError("routine discount exceeds company maximum")
    if role == "manager_approval" and _clock(value["not_before"], "not_before") >= _clock(value["expires_at"], "expires_at"):
        raise CaseError("approval interval must be nonempty")
    return value


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Derive every check from bound bytes and separately selected policy."""
    case = _object(case, "case", {"schema_version", "case_id", "artifacts"})
    policy = _object(policy, "policy", {"schema_version", "assessments"})
    if (case["schema_version"] != "customer-support-action-case/v1" or
            policy["schema_version"] != "customer-support-action-policy/v1"):
        raise CaseError("unsupported customer support schema_version")
    case_id = _text(case["case_id"], "case_id")
    if not isinstance(case["artifacts"], dict) or set(case["artifacts"]) - ROLES:
        raise CaseError("artifacts: expected known artifact roles")
    if not isinstance(policy["assessments"], dict) or case_id not in policy["assessments"]:
        raise CaseError("case_id has no consumer assessment")
    assessment = _object(policy["assessments"][case_id], "assessment", {
        "claim_type", "bindings", "required_checks", "clock", "manager_ids", "manager_approval_id",
    })
    if assessment["claim_type"] != CLAIM_TYPE:
        raise CaseError("unsupported claim_type")
    bindings = assessment["bindings"]
    if not isinstance(bindings, dict) or set(bindings) - ROLES:
        raise CaseError("bindings: expected known artifact roles")
    for role, digest in bindings.items():
        _digest(digest, f"bindings.{role}")
    required = _strings(assessment["required_checks"], "required_checks")
    if set(required) - set(REQUIRED_CHECKS):
        raise CaseError("required_checks: unsupported check")
    clock = _clock(assessment["clock"], "clock")
    manager_ids = _strings(assessment["manager_ids"], "manager_ids")
    approval_id = _text(assessment["manager_approval_id"], "manager_approval_id")

    raw, artifacts = {}, {}
    for role, metadata in case["artifacts"].items():
        if isinstance(metadata, dict) and "path" in metadata:
            _text(metadata["path"], f"artifacts.{role}.path")
        data, check = _artifact(artifact_root, metadata, f"artifacts.{role}")
        artifacts[role] = check
        if data is not None:
            raw[role] = _raw(data, role)

    scope = {
        "artifacts": artifacts,
        "consumer_bindings": bindings,
        "clock": assessment["clock"],
        "manager_ids": manager_ids,
        "manager_approval_id": approval_id,
        "required_checks": required,
        "evidence_decision": "not_established",
        "authorization": "not_established",
        "observed_effect": "not_established",
        "limit": "Retained records and a selected approval-use snapshot only. No source authentication, atomic grant consumption, or email effect is established.",
    }
    checks = []
    result = {"schema_version": "probity-decision/v1", "case_id": case_id,
              "claim_type": CLAIM_TYPE, "scope": scope, "checks": checks}

    def finish(decision: str, reason: str) -> dict:
        return {**result, "decision": decision, "reason": reason,
                "action": {"supported": "APPROVE", "contradicted": "BLOCK",
                           "not_established": "HOLD_FOR_REVIEW"}[decision]}

    def selected(roles: tuple[str, ...]) -> str | None:
        if any(role not in raw for role in roles):
            return "artifact_unavailable_or_unbound"
        if any(artifacts[role]["sha256"] != bindings.get(role) for role in roles):
            return "consumer_binding_mismatch"
        return None

    problem = selected(BASE_ROLES)
    if problem:
        return finish("not_established", problem)
    if set(required) != set(REQUIRED_CHECKS):
        return finish("not_established", "incomplete_check_coverage")
    action, customer, company = raw["action"], raw["customer"], raw["company_policy"]
    scope["action"] = action
    scope["advisory_report"] = raw["report"]
    checks.append({"id": "action_binding", "status": "met"})
    facts = (
        ("recipient", action["recipient"] == customer["recipient"], "recipient_mismatch"),
        ("plan", action["plan"] == customer["plan"] == company["plan"], "plan_mismatch"),
        ("discount", action["discount_bps"] <= company["maximum_discount_bps"], "discount_exceeds_maximum"),
        ("tenure", customer["tenure_months"] >= company["minimum_tenure_months"], "tenure_below_minimum"),
        ("draft_rendering", raw["draft"] == f"Your {action['discount_bps'] // 100}% loyalty discount applies to the {action['plan']} plan.\n", "draft_rendering_mismatch"),
    )
    for name, met, _ in facts:
        checks.append({"id": name, "status": "met" if met else "failed"})
    checks.append({"id": "report", "status": "met", "advisory": True})
    failed = next((reason for _, met, reason in facts if not met), None)
    if failed:
        scope["evidence_decision"] = "contradicted"
        scope["authorization"] = "contradicted"
        checks.append({"id": "manager_authorization", "status": "not_needed"})
        return finish("contradicted", failed)
    scope["evidence_decision"] = "supported"
    if action["discount_bps"] <= company["routine_discount_bps"]:
        scope["authorization"] = "supported"
        checks.append({"id": "manager_authorization", "status": "not_needed"})
        return finish("supported", "routine_action_supported")

    problem = selected(MANAGER_ROLES)
    if problem:
        checks.append({"id": "manager_authorization", "status": "unavailable"})
        return finish("not_established", problem)
    grant = raw["manager_approval"]
    if grant["approval_id"] != approval_id or grant["approver_id"] not in manager_ids:
        checks.append({"id": "manager_authorization", "status": "unavailable"})
        return finish("not_established", "approval_not_selected")
    bound = all(grant[name] == action[name] for name in (
        "action_id", "request_id", "recipient", "plan", "discount_bps",
    )) and grant["action_sha256"] == artifacts["action"]["sha256"] and grant["draft_sha256"] == artifacts["draft"]["sha256"]
    if not bound:
        reason = "manager_approval_binding_mismatch"
    elif not _clock(grant["not_before"], "not_before") <= clock < _clock(grant["expires_at"], "expires_at"):
        reason = "manager_approval_outside_window"
    elif approval_id in raw["approval_uses"]["consumed_approval_ids"]:
        reason = "manager_approval_already_consumed"
    else:
        scope["authorization"] = "supported"
        checks.append({"id": "manager_authorization", "status": "met"})
        return finish("supported", "manager_action_supported")
    scope["authorization"] = "contradicted"
    checks.append({"id": "manager_authorization", "status": "failed"})
    return finish("contradicted", reason)
