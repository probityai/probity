"""Consumer-side adjudication kernel and stable decision envelope.

Consumers can select additional versioned adapters for one call. The kernel
pins the exact consumer policy in every decision and refuses unknown claim
types. Adapter selection does not authenticate the adapter or its evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from .adapters import (
    authority_anchor,
    brokered_file_write,
    event_absence,
    operand_lineage,
    protected_paths,
    source_coverage,
    spend_reservation,
)
from .common import CaseError

ADAPTERS: dict[str, Callable[[Any, Any, Path], dict]] = {
    "brokered_file_write/v1": brokered_file_write.adjudicate,
    "source_text_coverage/v1": source_coverage.adjudicate,
    "operand_lineage/v1": operand_lineage.adjudicate,
    "authority_anchor/v1": authority_anchor.adjudicate,
    "event_absence/v1": event_absence.adjudicate,
    "event_absence/v2": event_absence.adjudicate_v2,
    "spend_reservation/v1": spend_reservation.adjudicate,
    "protected_paths/v1": protected_paths.adjudicate,
}
_BUILTIN_CLAIM_TYPES = frozenset(ADAPTERS)
_ADAPTER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*/v[1-9][0-9]*")
DECISIONS = {"supported", "contradicted", "not_established"}


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _adapter_registry(
    adapters: Mapping[str, Callable[[Any, Any, Path], dict]] | None,
) -> dict[str, Callable[[Any, Any, Path], dict]]:
    """Snapshot the legacy registry and add explicit consumer selections."""
    registry = dict(ADAPTERS)
    if adapters is None:
        return registry
    if not isinstance(adapters, Mapping):
        raise CaseError("adapters must be a mapping")
    additions = dict(adapters)
    for claim_type, adapter in additions.items():
        if not isinstance(claim_type, str) or not _ADAPTER_NAME.fullmatch(claim_type):
            raise CaseError("adapter names must be versioned claim identifiers")
        if claim_type in registry or claim_type in _BUILTIN_CLAIM_TYPES:
            raise CaseError("adapter collides with a registered claim_type")
        if not callable(adapter):
            raise CaseError("adapter must be callable")
    registry.update(additions)
    return registry


def _control_bytes(case: dict, policy: dict) -> tuple[bytes, bytes]:
    """Bind JSON control values without converting a malformed input to a verdict."""
    try:
        return canonical_json(case), canonical_json(policy)
    except (TypeError, ValueError, RecursionError) as error:
        raise CaseError("case and policy must contain JSON-compatible values") from error


def adjudicate(
    case: Any,
    policy: Any,
    artifact_root: Path,
    *,
    adapters: Mapping[str, Callable[[Any, Any, Path], dict]] | None = None,
) -> dict:
    """Check one claim using built-in and explicitly selected adapters.

    ``adapters`` supplies additional exact claim versions for this call only.
    It cannot replace a registered or built-in claim type. The kernel copies
    both registries before it reads the claim selection. Each selected adapter
    must accept ``(case, policy, artifact_root)`` and return the common decision
    envelope. The callback receives private copies of the case and policy.
    Changes to those copies refuse the call. The decision binds the policy
    bytes captured before the callback. Malformed selections or envelopes
    raise :class:`CaseError`.

    Existing callers can continue to use the three positional arguments and
    the legacy ``ADAPTERS`` registry. Adapter callbacks are trusted Python code;
    the registry provides selection and isolation, not a code sandbox.
    """
    if not isinstance(case, dict) or not isinstance(policy, dict):
        raise CaseError("case and policy must be JSON objects")
    registry = _adapter_registry(adapters)
    case, policy = deepcopy(case), deepcopy(policy)
    control_bytes = _control_bytes(case, policy)
    policy_sha256 = hashlib.sha256(control_bytes[1]).hexdigest()
    case_id = case.get("case_id")
    assessments = policy.get("assessments")
    if not isinstance(case_id, str) or not isinstance(assessments, dict):
        raise CaseError("case_id and consumer assessments are required")
    assessment = assessments.get(case_id)
    if not isinstance(assessment, dict):
        raise CaseError("case_id has no consumer assessment")
    claim_type = assessment.get("claim_type")
    if not isinstance(claim_type, str) or claim_type not in registry:
        raise CaseError("unsupported claim_type")
    result = registry[claim_type](case, policy, artifact_root)
    try:
        unchanged = _control_bytes(case, policy) == control_bytes
    except CaseError:
        unchanged = False
    if not unchanged:
        raise CaseError("adapter changed the case or consumer policy")
    if (not isinstance(result, dict) or
            result.get("schema_version") != "probity-decision/v1" or
            not isinstance(result.get("decision"), str) or
            result.get("decision") not in DECISIONS or
            not isinstance(result.get("reason"), str) or
            result.get("case_id") != case_id or
            result.get("claim_type") != claim_type or
            not isinstance(result.get("scope"), dict) or
            not isinstance(result.get("checks"), list)):
        raise CaseError("adapter returned an invalid decision envelope")
    result["policy_sha256"] = policy_sha256
    return result


def render_packet(result: dict) -> str:
    """Readable packet whose sections work for every registered claim type."""
    lines = [
        "Probity decision packet v1",
        f"Case: {json.dumps(result['case_id'], ensure_ascii=True)}",
        f"Claim: {result['claim_type']}",
        f"Decision: {result['decision']}",
        f"Reason: {result['reason']}",
        f"Policy SHA-256: {result['policy_sha256']}",
        "Scope and evidence:",
        json.dumps(result["scope"], indent=2, sort_keys=True, ensure_ascii=True),
        "Checks:",
        json.dumps(result["checks"], indent=2, sort_keys=True, ensure_ascii=True),
    ]
    return "\n".join(lines) + "\n"
