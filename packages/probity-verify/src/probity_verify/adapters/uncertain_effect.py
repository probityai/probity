"""``uncertain_effect/v1``: one operation whose effect may have happened after its reply was lost.

The record is one runtime's trail for one intended effect: the operation and its idempotency key,
each dispatch attempt with its reply, the workers' leases, the effect owner's reconciliation
answers, the owner's own effect count, the reservation, the reported outcome and, optionally, a
stop. The claim: the trail is consistent with at most one effect, and the reported outcome is one
the owner's answers support. Thirteen checks run in a fixed order and the first that fails is the
reason. The rules are a port of probityai/agent-evidence-vectors at commit
317df600f9a1503f32bcc2742b9f111036bdee32, ``packaging/agent_evidence_vectors/uncertaineffect.py``.

A record that passes every check is ``supported`` with reason ``effect_held``; a failing check is
``contradicted`` with the check's name. A record that is not strict JSON, or that is not an object
carrying the fields the checks read within the contract's domains, raises :class:`CaseError`: the
port adds that refusal, because a repeated member or a word outside a closed list would otherwise
read as a pass.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from ..common import CaseError
from ..json_input import parse_json
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "uncertain_effect/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"
ACCEPTED = "effect_held"
UNKNOWN_REPLIES = ("timeout", "connection_lost")
REPLIES = ("confirmed", "no_effect", *UNKNOWN_REPLIES)
ANSWERS = ("present", "absent")
OUTCOMES = ("committed", "not_run", "unknown")
STOP_REPORTS = ("quiescent", "effect_after_stop", "not_established")
AUTHORITY_ANSWERS = ("accepted", "refused")
MAX_RECORD_BYTES = 16 * 1024 * 1024
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "operation_identity_missing",
    "idempotency_key_args_changed",
    "dispatch_beyond_lease",
    "retry_after_unknown",
    "duplicate_effect",
    "unknown_released",
    "outcome_settled_without_authority",
    "outcome_disagrees_with_authority",
    "authority_used_after_revocation",
    "effect_after_stop_reported_quiescent",
    "stop_straddle_reported_settled",
)
LIMIT = ("Checks the trail as recorded. A pass does not establish that the producer recorded its "
         "attempts, replies or the owner's answers truthfully, that the owner's count is right, "
         "or that the parties' clocks agree.")

Record = dict[str, Any]


def _at(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp)


def _final_absent_between(record: Record, start: datetime, end: datetime | None) -> bool:
    """Whether a final reconciliation found the effect absent at or after ``start``."""
    return any(item["result"] == "absent" and item["final"] and _at(item["at"]) >= start
               and (end is None or _at(item["at"]) <= end)
               for item in record["reconciliations"])


def settled_outcome(record: Record) -> str:
    """The outcome the effect owner's own answers settle."""
    attempts = record["attempts"]
    if (any(item["reply"] == "confirmed" for item in attempts)
            or any(item["result"] == "present" for item in record["reconciliations"])):
        return "committed"
    unknown = [_at(item["dispatchedAt"]) for item in attempts if item["reply"] in UNKNOWN_REPLIES]
    if not unknown or _final_absent_between(record, max(unknown), None):
        return "not_run"
    return "unknown"


def _identity_missing(record: Record) -> bool:
    items = [record["operation"], *record["attempts"]]
    return any(not item.get(key) for item in items for key in ("idempotencyKey", "argsDigest"))


def _key_args_changed(record: Record) -> bool:
    operation = record["operation"]
    return any(item.get("idempotencyKey") == operation.get("idempotencyKey")
               and item.get("argsDigest") != operation.get("argsDigest")
               for item in record["attempts"])


def _outside_lease(attempt: dict[str, Any], leases: list[dict[str, Any]]) -> bool:
    held = [lease for lease in leases if lease["worker"] == attempt.get("worker")
            and lease["fencingToken"] == attempt.get("fencingToken")]
    if not held:
        return True
    sent, lease = _at(attempt["dispatchedAt"]), held[0]
    if not _at(lease["acquiredAt"]) <= sent < _at(lease["expiresAt"]):
        return True
    return any(other["fencingToken"] > lease["fencingToken"] and _at(other["acquiredAt"]) <= sent
               for other in leases)


def _beyond_lease(record: Record) -> bool:
    leases = record.get("leases") or []
    return bool(leases) and any(_outside_lease(item, leases) for item in record["attempts"])


def _protected_retry(record: Record, earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    """Whether ``later`` may follow ``earlier``, whose outcome the caller did not learn."""
    owner = record["effectOwner"]
    sent, resent = _at(earlier["dispatchedAt"]), _at(later["dispatchedAt"])
    retention = owner.get("keyRetentionSeconds")
    deduplicated = (owner["deduplicatesByKey"]
                    and later.get("idempotencyKey") == earlier.get("idempotencyKey")
                    and (retention is None or (resent - sent).total_seconds() <= retention))
    return bool(deduplicated) or _final_absent_between(record, sent, resent)


def _unprotected_retry(record: Record) -> bool:
    attempts = sorted(record["attempts"], key=lambda item: _at(item["dispatchedAt"]))
    return any(not _protected_retry(record, earlier, later)
               for index, earlier in enumerate(attempts) if earlier["reply"] in UNKNOWN_REPLIES
               for later in attempts[index + 1:])


def _unknown_released(record: Record) -> bool:
    reservation = record.get("reservation")
    return (reservation is not None and settled_outcome(record) == "unknown"
            and not reservation["charged"])


def _settled_without_authority(record: Record) -> bool:
    return (settled_outcome(record) == "unknown"
            and record["reported"]["outcome"] in ("committed", "not_run"))


def _disagrees(record: Record) -> bool:
    settled = settled_outcome(record)
    return settled != "unknown" and record["reported"]["outcome"] != settled


def _stop(record: Record) -> dict[str, Any] | None:
    stop = record.get("stop")
    return stop if isinstance(stop, dict) and stop else None


def _authority_after_revocation(record: Record) -> bool:
    stop = _stop(record)
    if stop is None:
        return False
    revoked = _at(stop["revokedAt"])
    return any(item["result"] == "accepted" and _at(item["at"]) >= revoked
               for item in stop.get("authorityChecks", []))


def _commit_after_ack(stop: dict[str, Any]) -> bool | None:
    """True when the owner's commit lies wholly after the acknowledgement, False when wholly at
    or before it, and None when its interval contains the acknowledgement."""
    commit = stop.get("ownerCommit")
    if not commit:
        return False
    ack = _at(stop["acknowledgedAt"])
    if _at(commit["notBefore"]) > ack:
        return True
    if _at(commit["notAfter"]) <= ack:
        return False
    return None


def _orphan_reported_quiescent(record: Record) -> bool:
    stop = _stop(record)
    return stop is not None and _commit_after_ack(stop) is True and stop["reported"] == "quiescent"


def _straddle_settled(record: Record) -> bool:
    stop = _stop(record)
    return (stop is not None and _commit_after_ack(stop) is None
            and stop["reported"] != "not_established")


def first_failure(record: Record) -> str | None:
    """The first check in ``CHECKS`` the record fails, or None when it passes every one."""
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "operation_identity_missing": lambda: _identity_missing(record),
        "idempotency_key_args_changed": lambda: _key_args_changed(record),
        "dispatch_beyond_lease": lambda: _beyond_lease(record),
        "retry_after_unknown": lambda: _unprotected_retry(record),
        "duplicate_effect": lambda: record["ownerEffects"] > 1,
        "unknown_released": lambda: _unknown_released(record),
        "outcome_settled_without_authority": lambda: _settled_without_authority(record),
        "outcome_disagrees_with_authority": lambda: _disagrees(record),
        "authority_used_after_revocation": lambda: _authority_after_revocation(record),
        "effect_after_stop_reported_quiescent": lambda: _orphan_reported_quiescent(record),
        "stop_straddle_reported_settled": lambda: _straddle_settled(record),
    }
    for name in CHECKS:
        if failures[name]():
            return name
    return None


def _require(condition: bool, field: str) -> None:
    if not condition:
        raise ValueError(field + " is outside the contract")


def _word(item: dict[str, Any], name: str, allowed: tuple[str, ...]) -> None:
    _require(name not in item or item[name] in allowed, name)


def _flag(item: dict[str, Any], name: str) -> None:
    _require(isinstance(item.get(name, False), bool), name)


def _objects(record: Record, name: str) -> list[dict[str, Any]]:
    items = record.get(name)
    _require(items is None or (isinstance(items, list)
                               and all(isinstance(item, dict) for item in items)), name)
    return items or []


def _object(record: Record, name: str) -> dict[str, Any]:
    item = record.get(name)
    _require(item is None or isinstance(item, dict), name)
    return item or {}


def _retention_seconds(owner: dict[str, Any]) -> None:
    value = owner.get("keyRetentionSeconds")
    _require(value is None or (type(value) in (int, float) and value >= 0), "keyRetentionSeconds")


def check_domains(record: Record) -> None:
    """Refuse a value the contract does not allow, before any check reads it.

    The checks branch on truthiness and on closed word lists, so ``"final": "no"`` would read as
    final, an unlisted reply as a known outcome and ``true`` as a count of at most one effect. Each
    turns a refusal into a pass. Only carried fields are judged: a record refused early need not
    carry the rest, and a missing field stays the checks' concern.
    """
    count = record.get("ownerEffects", 0)
    _require(type(count) is int and count >= 0, "ownerEffects")
    for item in _objects(record, "attempts"):
        _word(item, "reply", REPLIES)
    for item in _objects(record, "reconciliations"):
        _word(item, "result", ANSWERS)
        _flag(item, "final")
    _objects(record, "leases")
    owner = _object(record, "effectOwner")
    _flag(owner, "deduplicatesByKey")
    _retention_seconds(owner)
    _word(_object(record, "reported"), "outcome", OUTCOMES)
    _flag(_object(record, "reservation"), "charged")
    stop = _object(record, "stop")
    _word(stop, "reported", STOP_REPORTS)
    for item in _objects(stop, "authorityChecks"):
        _word(item, "result", AUTHORITY_ANSWERS)


def _record(data: bytes) -> Record:
    record = parse_json(data, max_bytes=MAX_RECORD_BYTES, max_depth=32, max_nodes=32768)
    if not isinstance(record, dict):
        raise CaseError("record: expected a JSON object")
    return record


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge one bound uncertain-effect record."""
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, {"record"})
    data, binding = bound(artifacts, artifact_root, assessment["record"], "assessment.record")
    scope = {"record": binding, "contract_id": CONTRACT_ID, "limit": LIMIT}
    if data is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "record_unavailable")
    record = _record(data)
    errors = (KeyError, TypeError, ValueError, AttributeError)
    try:
        check_domains(record)
        failure = first_failure(record)
    except errors as exc:
        raise CaseError(f"record: lacks a field the checks read ({exc!r})") from exc
    try:
        settled: str | None = settled_outcome(record)
        reported = record["reported"]["outcome"]
    except errors:  # a record refused before these fields matter need not carry them
        settled, reported = None, None
    check = {"id": "uncertain_effect_checks", "status": "fail" if failure else "pass",
             "first_failure": failure, "settled_outcome": settled,
             "reported_outcome": reported}
    if failure is None:
        return decision(case_id, CLAIM_TYPE, scope, "supported", ACCEPTED, [check])
    return decision(case_id, CLAIM_TYPE, scope, "contradicted", failure, [check])
