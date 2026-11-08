"""Stable error codes. Each refusal carries one of these as ``ApplicationError.type``.

The set is closed: a code is never renamed, and a new refusal gets a new code. ``RETRYABLE`` names the
codes a retry can cure (the state they depend on changes on its own); every other code is final and
raised non-retryable, so Temporal never re-runs a refused call on its own.
"""

from __future__ import annotations

from typing import Any

from temporalio.exceptions import ApplicationError

PREFIX = "PROBITY_"

# Worker-side checks, in the order they run (see ``CHECK_ORDER``).
LOCAL_ACTIVITY_BLOCKED = "PROBITY_LOCAL_ACTIVITY_BLOCKED"
ARGS_NOT_ADMISSIBLE = "PROBITY_ARGS_NOT_ADMISSIBLE"
ARGS_CHANGED_AFTER_SCHEDULE = "PROBITY_ARGS_CHANGED_AFTER_SCHEDULE"
# Authority checks.
APPROVAL_MISSING = "PROBITY_APPROVAL_MISSING"
APPROVAL_PENDING = "PROBITY_APPROVAL_PENDING"
REVOCATION_STATE_STALE = "PROBITY_REVOCATION_STATE_STALE"
APPROVAL_SIGNATURE_INVALID = "PROBITY_APPROVAL_SIGNATURE_INVALID"
APPROVER_REVOKED = "PROBITY_APPROVER_REVOKED"
PERMIT_REVOKED = "PROBITY_PERMIT_REVOKED"
CONTENT_BLOCKED = "PROBITY_CONTENT_BLOCKED"
APPROVAL_THRESHOLD_NOT_MET = "PROBITY_APPROVAL_THRESHOLD_NOT_MET"
AUTHORITY_UNAVAILABLE = "PROBITY_AUTHORITY_UNAVAILABLE"
# Outcomes of an already-used permit.
OUTCOME_UNKNOWN = "PROBITY_OUTCOME_UNKNOWN"
# Workflow-side refusals.
UPDATE_NOT_AUTHORIZED = "PROBITY_UPDATE_NOT_AUTHORIZED"
APPROVAL_NOT_FOR_THIS_CALL = "PROBITY_APPROVAL_NOT_FOR_THIS_CALL"

#: The published approval-binding/v1 reader's own check names; each maps to ``PROBITY_<NAME>``.
READER_CHECKS = (
    "contract_id_missing", "contract_id_unknown", "approval_not_cited", "approval_id_ambiguous",
    "approval_replayed", "approval_superseded", "renewal_transition_missing", "renewal_binding_invalid",
    "key_not_bound", "principal_mismatch", "event_phase_mismatch", "payload_mismatch",
    "approval_outside_validity", "effect_already_closed", "comparison_unavailable",
    "release_not_served_at_decision", "payload_file_unsafe",
)

CHECK_ORDER = (
    LOCAL_ACTIVITY_BLOCKED, ARGS_NOT_ADMISSIBLE, ARGS_CHANGED_AFTER_SCHEDULE, APPROVAL_MISSING,
    APPROVAL_PENDING, REVOCATION_STATE_STALE, APPROVAL_SIGNATURE_INVALID, APPROVER_REVOKED, PERMIT_REVOKED,
    CONTENT_BLOCKED, *(PREFIX + c.upper() for c in READER_CHECKS), APPROVAL_THRESHOLD_NOT_MET,
)

RETRYABLE = frozenset({APPROVAL_PENDING, REVOCATION_STATE_STALE, AUTHORITY_UNAVAILABLE})

ALL = frozenset({*CHECK_ORDER, AUTHORITY_UNAVAILABLE, OUTCOME_UNKNOWN, UPDATE_NOT_AUTHORIZED,
                 APPROVAL_NOT_FOR_THIS_CALL})


def code_for(reason: str) -> str:
    """The stable code for a recorded reason (``payload_mismatch`` -> ``PROBITY_PAYLOAD_MISMATCH``)."""
    code = reason if reason.startswith(PREFIX) else PREFIX + reason.upper()
    if code not in ALL:
        raise ValueError(f"no stable code for reason {reason!r}")
    return code


def reason_for(code: str) -> str:
    return code[len(PREFIX):].lower()


def refusal(code: str, message: str, **details: Any) -> ApplicationError:
    """The one constructor every refusal goes through: stable type, retry rule from ``RETRYABLE``."""
    if code not in ALL:
        raise ValueError(f"unknown code {code!r}")
    return ApplicationError(f"probity: {message}", {"code": code, "reason": reason_for(code), **details},
                            type=code, non_retryable=code not in RETRYABLE)


class ProbityWorkflowError(ApplicationError):
    """Raised in workflow code for a refusal there; registered as a workflow failure type so the
    workflow fails with the code instead of retrying its task forever."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"probity: {message}", {"code": code, "reason": reason_for(code)}, type=code,
                         non_retryable=True)
