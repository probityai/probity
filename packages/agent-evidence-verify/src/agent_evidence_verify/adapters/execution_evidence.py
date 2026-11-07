"""Judge one Adversarial Execution Evidence statement against the consumer's key pins."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import execution_evidence as aee
from ..common import CaseError, _artifact, _object, _string

CLAIM_TYPE = "adversarial_execution_evidence/v1"
LIMIT = ("The verdict, result and tiers are recomputed from the statement's own bytes. A tier is "
         "attested only under a key the consumer pinned here; this program does not establish who "
         "holds that key, and a valid statement's result is the producer's run as recorded, not a "
         "fresh execution.")


def _keys(value: Any) -> list[bytes]:
    if not isinstance(value, list) or len(value) > 64:
        raise CaseError("substrate_observation_keys: expected a list of at most 64 keys")
    keys = []
    for index, item in enumerate(value):
        text = _string(item, f"substrate_observation_keys[{index}]")
        if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
            raise CaseError(f"substrate_observation_keys[{index}]: expected 64 lowercase hex digits")
        keys.append(bytes.fromhex(text))
    return keys


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Decide whether the named statement is a valid AEE v0.7 statement, and report its result.

    ``supported`` means the statement passes every gate and its carried result equals the
    recomputed one; ``contradicted`` means a gate refused it, and the check names the codes.
    A missing statement is ``not_established``.
    """
    case = _object(case, "case", {"schema_version", "case_id", "artifacts"})
    policy = _object(policy, "policy", {"schema_version", "assessments"}, {"witnesses"})
    if case["schema_version"] != "probity-case/v1" or policy["schema_version"] != "probity-policy/v1":
        raise CaseError("unsupported schema_version")
    case_id = _string(case["case_id"], "case_id")
    artifacts, assessments = case["artifacts"], policy["assessments"]
    if not isinstance(artifacts, dict) or not isinstance(assessments, dict):
        raise CaseError("artifacts and assessments: expected objects")
    assessment = _object(assessments.get(case_id), "assessment",
                         {"claim_type", "statement"}, {"substrate_observation_keys"})
    if assessment["claim_type"] != CLAIM_TYPE:
        raise CaseError("unsupported claim_type")
    statement_id = _string(assessment["statement"], "statement")
    if statement_id not in artifacts:
        raise CaseError("statement names no case artifact")
    raw_keys = _keys(assessment.get("substrate_observation_keys", []))
    try:
        keys = [aee.load_public_key(raw) for raw in raw_keys]
    except ValueError as exc:
        raise CaseError("substrate_observation_keys: not an Ed25519 public key") from exc
    data, binding = _artifact(artifact_root, artifacts[statement_id], f"artifacts.{statement_id}")
    scope = {"claim_type": CLAIM_TYPE, "predicate_type": aee.PREDICATE_TYPE,
             "statement": {"id": statement_id, "artifact": binding},
             "substrate_observation_keys": [key.hex() for key in raw_keys], "limit": LIMIT}
    result = {"schema_version": "probity-decision/v1", "case_id": case_id,
              "claim_type": CLAIM_TYPE, "scope": scope, "checks": []}
    if data is None:
        return {**result, "decision": "not_established", "reason": "statement_unavailable"}
    report = aee.verify(data, keys)
    valid = report.verdict == aee.VALID
    result["checks"] = [{"id": "execution_evidence", "status": "met" if valid else "failed",
                         **report.as_dict()}]
    if valid:
        return {**result, "decision": "supported", "reason": "statement_valid"}
    return {**result, "decision": "contradicted", "reason": "statement_invalid"}
