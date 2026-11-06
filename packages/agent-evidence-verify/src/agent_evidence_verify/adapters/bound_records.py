"""Read the bound artifacts a record-contract claim names, for the corpus-route claim types.

Each of these claim types checks that one record, or a few, satisfies a published contract. The
assessment names the artifacts by role; this module binds each one (path, length, SHA-256) and
returns its bytes, or ``None`` when it is absent, so the adapter can return ``not_established``
instead of guessing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..common import CaseError, _artifact, _object, _string


def decision(case_id: str, claim_type: str, scope: dict, decision_value: str, reason: str,
             checks: list[dict] | None = None) -> dict:
    """The common decision envelope."""
    return {"schema_version": "probity-decision/v1", "case_id": case_id,
            "claim_type": claim_type, "decision": decision_value, "reason": reason,
            "scope": scope, "checks": checks or []}


def assessment_for(case: Any, policy: Any, claim_type: str, required: set[str],
                   optional: set[str] = frozenset()) -> tuple[str, dict, dict]:
    """The case id, the case's artifact map and the claim's assessment, each checked for shape."""
    case = _object(case, "case", {"schema_version", "case_id", "artifacts"})
    policy = _object(policy, "policy", {"schema_version", "assessments"}, {"witnesses"})
    if case["schema_version"] != "probity-case/v1" or policy["schema_version"] != "probity-policy/v1":
        raise CaseError("unsupported schema_version")
    case_id = _string(case["case_id"], "case_id")
    if not isinstance(case["artifacts"], dict) or not isinstance(policy["assessments"], dict):
        raise CaseError("artifacts and assessments: expected objects")
    assessment = _object(policy["assessments"].get(case_id), "assessment",
                         required | {"claim_type"}, optional)
    if assessment["claim_type"] != claim_type:
        raise CaseError("unsupported claim_type")
    return case_id, case["artifacts"], assessment


def bound(artifacts: dict, artifact_root: Path, name: Any, label: str) -> tuple[bytes | None, dict]:
    """The bytes of the artifact ``name`` and its binding record."""
    name = _string(name, label)
    if name not in artifacts:
        raise CaseError(f"{label}: names no case artifact")
    return _artifact(artifact_root, artifacts[name], "artifacts." + name)
