"""Record schema and pure state-transition checks for the HTTP ticket profile.

A reader replays retained ticket state from signed records alone: the signed
envelope, the exact state schema, the closed event vocabulary and its order,
the retained prefix, and the native row relation. Nothing here accepts a grant
for dispatch, writes a ticket store or serves a request.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from .crypto import (
    VerificationError,
    canonical,
    digest,
    strict_loads,
    verify_signature,
)
from .grant_records import (
    ActionRequest,
    GrantPolicy,
    validate_utc_time,
    verify_grant,
)

DOMAIN = "probity-http-ticket-v0"

MAX_BODY = 65536

STATE_FIELDS = frozenset({"format", "configuration", "phase", "revision", "contentDigest", "effectId", "grantDigest", "revoked", "eventCount", "eventHead", "intentTime", "effectTime"})

RECEIPT_FIELDS = STATE_FIELDS | {"request", "authorityKey", "witnessScope", "coverage"}

READBACK_FIELDS = frozenset({"tenantId", "ticketId", "contentHex", "revision", "effectId", "receipt"})

def _timestamp(value: datetime, time_precision: Literal["seconds", "milliseconds"] = "seconds") -> str:
    """Serialize the selected UTC observation precision without input rounding."""
    reference = validate_utc_time(value, "ticket reference time", precision=time_precision)
    return reference.isoformat(timespec=time_precision).replace("+00:00", "Z")

def parse_time(value: Any, time_precision: Literal["seconds", "milliseconds"] = "seconds") -> datetime:
    """Refuse noncanonical timestamps before checking historical authorization."""
    if not isinstance(value, str):
        raise VerificationError("ticket reference time is malformed")
    try:
        format_string = "%Y-%m-%dT%H:%M:%SZ" if time_precision == "seconds" else "%Y-%m-%dT%H:%M:%S.%fZ"
        result = datetime.strptime(value, format_string).replace(tzinfo=UTC)
    except ValueError as error:
        raise VerificationError("ticket reference time is malformed") from error
    if _timestamp(result, time_precision) != value:
        raise VerificationError("ticket reference time is noncanonical")
    return result

def _hex(value: Any) -> bool:
    """Require a literal lowercase SHA-256 digest, without integer coercion."""
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

def state_schema(state: Any, *, receipt: bool = False, time_precision: Literal["seconds", "milliseconds"] = "seconds") -> None:
    """Apply exact schemas and phase-dependent native relations to signed state."""
    fields = RECEIPT_FIELDS if receipt else STATE_FIELDS
    if not isinstance(state, dict) or set(state) != fields:
        raise VerificationError("ticket signed state fields differ")
    if state["format"] != DOMAIN or not _hex(state["configuration"]) or not _hex(state["eventHead"]):
        raise VerificationError("ticket signed state domain or digest differs")
    if type(state["revision"]) is not int or state["revision"] not in {0, 1} or type(state["eventCount"]) is not int or not 1 <= state["eventCount"] <= 5 or type(state["revoked"]) is not bool:
        raise VerificationError("ticket signed state counters or revocation differ")
    phase = state["phase"]
    if not isinstance(phase, str) or phase not in {"ready", "pending", "completed", "incomplete"}:
        raise VerificationError("ticket signed state phase differs")
    if phase == "ready":
        if state["revision"] != 0 or any(state[name] is not None for name in ("contentDigest", "effectId", "grantDigest", "intentTime", "effectTime")):
            raise VerificationError("ticket ready state carries an effect")
        return
    if not _hex(state["effectId"]) or not _hex(state["grantDigest"]):
        raise VerificationError("ticket intent identity differs")
    intent_time = parse_time(state["intentTime"], time_precision)
    if phase == "completed":
        if state["revision"] != 1 or not _hex(state["contentDigest"]) or parse_time(state["effectTime"], time_precision) < intent_time:
            raise VerificationError("ticket completed native relation differs")
    elif state["revision"] != 0 or state["contentDigest"] is not None or state["effectTime"] is not None:
        raise VerificationError("ticket incomplete state claims a completed effect")

def checked_record(record: Any, public_key: str) -> dict[str, Any]:
    """Authenticate a fixed envelope without accepting its own key as policy."""
    if not isinstance(record, dict) or set(record) != {"payload", "keyid", "signature"}:
        raise VerificationError("ticket envelope fields differ")
    if not _hex(public_key) or record["keyid"] != public_key or not isinstance(record["payload"], dict) or not isinstance(record["signature"], str):
        raise VerificationError("ticket key differs from consumer pin")
    verify_signature(public_key, DOMAIN, record["payload"], record["signature"])
    return record["payload"]

def ticket_configuration(request: ActionRequest, policy: GrantPolicy, service_key: str,
                          decision_digest: str | None,
                          time_precision: Literal["seconds", "milliseconds"] = "seconds") -> dict[str, Any]:
    """Validate one supported host selection before committing its configuration."""
    if not isinstance(time_precision, str) or time_precision not in {"seconds", "milliseconds"}:
        raise VerificationError("ticket selected time precision is unsupported")
    if request.tool_id != "ticket-update" or not isinstance(request.target_path, str) or not request.target_path.startswith("/work/tickets/"):
        raise VerificationError("ticket action or target is unsupported")
    ticket_id = request.target_path.removeprefix("/work/tickets/")
    safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    if not isinstance(request.tenant_id, str) or not ticket_id or any(c not in safe for c in ticket_id + request.tenant_id):
        raise VerificationError("ticket and tenant must use literal URL-safe identifiers")
    if not _hex(service_key) or not _hex(policy.issuer_key):
        raise VerificationError("ticket selected role keys differ")
    if service_key == policy.issuer_key:
        raise VerificationError("service and issuer keys must differ")
    configuration = {"request": asdict(request), "policy": asdict(policy), "serviceKey": service_key}
    if time_precision == "milliseconds":
        configuration["timePrecision"] = time_precision
    if decision_digest is not None:
        if not _hex(decision_digest):
            raise VerificationError("ticket decision commitment differs")
        configuration["decisionDigest"] = decision_digest
    return configuration

@dataclass(frozen=True)
class VerifiedTicketCapture:
    """Authenticated native state and measured populations under selected public policy.

    This result establishes the supplied signed history and local row relation.
    It does not establish current grant validity, custody or provider execution.
    """
    state: dict[str, Any]
    content: bytes | None
    logical_admissions: int
    local_effects: int

@dataclass(frozen=True)
class _TicketHistoryProgress:
    """Native phase and authority after one verified history prefix."""
    phase: str = "ready"
    revoked: bool = False
    admissions: int = 0

def _ticket_history_transition(number: int, carried: Any, state: dict[str, Any],
                               request: ActionRequest, policy: GrantPolicy,
                               progress: _TicketHistoryProgress) -> _TicketHistoryProgress:
    """Apply the closed native event vocabulary to one authenticated prefix."""
    if not isinstance(carried, dict) or not isinstance(carried.get("kind"), str):
        raise VerificationError("ticket event body differs")
    kind = carried["kind"]
    if kind == "initialize":
        if number != 1 or carried != {"kind": "initialize", "configuration": state["configuration"]}:
            raise VerificationError("ticket initialization history differs")
        return progress
    if number == 1:
        raise VerificationError("ticket history lacks initial configuration")
    if kind == "intent":
        expected = {"kind": "intent", "request": asdict(request), "grantDigest": state["grantDigest"],
                    "effectId": state["effectId"], "beforeRevision": 0, "intentTime": state["intentTime"]}
        if progress.phase != "ready" or progress.revoked or carried != expected or type(carried.get("beforeRevision")) is not int:
            raise VerificationError("ticket intent history differs")
        return _TicketHistoryProgress("pending", progress.revoked, progress.admissions + 1)
    if kind == "effect":
        expected = {"kind": "effect", "effectId": state["effectId"], "revision": 1,
                    "contentDigest": request.content_sha256, "effectTime": state["effectTime"], "grantDigest": state["grantDigest"]}
        if progress.phase != "pending" or progress.revoked or progress.admissions != 1 or carried != expected or type(carried.get("revision")) is not int:
            raise VerificationError("ticket native effect history differs")
        return _TicketHistoryProgress("completed", progress.revoked, progress.admissions)
    if kind == "revoke":
        if progress.revoked or carried != {"kind": "revoke", "authorityKey": policy.issuer_key}:
            raise VerificationError("ticket revocation history differs")
        return _TicketHistoryProgress(progress.phase, True, progress.admissions)
    if kind == "incomplete":
        expected = {"kind": "incomplete", "effectId": state["effectId"], "requestId": request.request_id,
                    "outcome": "not-established-after-interruption"}
        if progress.phase != "pending" or carried != expected:
            raise VerificationError("ticket interruption history differs")
        return _TicketHistoryProgress("incomplete", progress.revoked, progress.admissions)
    raise VerificationError("ticket history has unsupported event")

def _verify_ticket_history(events: Sequence[tuple[int, bytes]], state: dict[str, Any],
                           request: ActionRequest, policy: GrantPolicy, service_key: str,
                           retained: dict[str, Any] | None) -> _TicketHistoryProgress:
    """Verify signed ordering, native transitions and the externally retained prefix."""
    head, progress = "0" * 64, _TicketHistoryProgress()
    for number, (sequence, raw) in enumerate(events, 1):
        event = checked_record(strict_loads(raw), service_key)
        if set(event) != {"sequence", "previous", "event", "hash"} or type(event["sequence"]) is not int or type(sequence) is not int:
            raise VerificationError("ticket event schema differs")
        body = {name: event[name] for name in ("sequence", "previous", "event")}
        if sequence != number or event["sequence"] != number or event["previous"] != head or event["hash"] != digest(DOMAIN + "-event", body):
            raise VerificationError("ticket history differs")
        progress = _ticket_history_transition(number, event["event"], state, request, policy, progress)
        head = event["hash"]
        if retained is not None and number == retained["eventCount"]:
            if head != retained["eventHead"]:
                raise VerificationError("ticket history changed retained prefix")
            prefix = {**state, "phase": progress.phase, "revoked": progress.revoked,
                "eventCount": number, "eventHead": head, "revision": int(progress.phase == "completed"),
                "contentDigest": request.content_sha256 if progress.phase == "completed" else None,
                "effectTime": state["effectTime"] if progress.phase == "completed" else None}
            if progress.phase == "ready":
                prefix.update(effectId=None, grantDigest=None, intentTime=None)
            if canonical({name: retained[name] for name in STATE_FIELDS}) != canonical(prefix):
                raise VerificationError("ticket retained state differs from native history")
    if len(events) != state["eventCount"] or head != state["eventHead"]:
        raise VerificationError("ticket history is incomplete")
    if progress.phase != state["phase"] or progress.revoked != state["revoked"]:
        raise VerificationError("ticket terminal state differs from native history")
    if retained is not None and retained["eventCount"] > len(events):
        raise VerificationError("ticket history predates retained head")
    return progress

def _verify_ticket_rows(tickets: Sequence[tuple[str, str, bytes, int, str]],
                        state: dict[str, Any], request: ActionRequest) -> bytes | None:
    """Join the actual native row population, storage types and exact content bytes."""
    if state["revision"] == 0:
        if tickets:
            raise VerificationError("unrecorded ticket bypass detected")
        return None
    if len(tickets) != 1:
        raise VerificationError("native ticket population differs")
    tenant, ticket, content, revision, effect = tickets[0]
    if not isinstance(content, bytes) or type(revision) is not int:
        raise VerificationError("native ticket row types differ")
    if (tenant, ticket, revision, effect) != (request.tenant_id, request.target_path.removeprefix("/work/tickets/"), state["revision"], state["effectId"]):
        raise VerificationError("native ticket relation differs")
    if state["contentDigest"] != request.content_sha256 or hashlib.sha256(content).hexdigest() != request.content_sha256:
        raise VerificationError("native ticket bytes differ")
    return content

def verify_ticket_capture(
    state_record: bytes, events: Sequence[tuple[int, bytes]],
    tickets: Sequence[tuple[str, str, bytes, int, str]], request: ActionRequest,
    policy: GrantPolicy, service_key: str, *, decision_digest: str | None = None,
    retained_head: dict[str, Any] | None = None,
    time_precision: Literal["seconds", "milliseconds"] = "seconds",
) -> VerifiedTicketCapture:
    """Verify selected native populations with public keys and no storage mutation.

    The caller selects the request, issuer policy, service key, optional decision
    digest and captured bytes. This authenticates native state, complete phase
    history, retained prefix and actual row relation. Current grant authorization
    and external native decision replay remain separate consumer checks.
    """
    configuration = ticket_configuration(request, policy, service_key, decision_digest, time_precision)
    configuration_digest = digest(DOMAIN + "-configuration", configuration)
    state = checked_record(strict_loads(state_record), service_key)
    state_schema(state, time_precision=time_precision)
    if state["configuration"] != configuration_digest:
        raise VerificationError("ticket configuration differs on restart")
    if state["phase"] != "ready" and state["effectId"] != digest(DOMAIN + "-effect", {
            "configuration": configuration_digest, "requestId": request.request_id, "grantDigest": state["grantDigest"]}):
        raise VerificationError("ticket deterministic effect identity differs")
    retained = None
    if retained_head is not None:
        retained = checked_record(retained_head, service_key)
        state_schema(retained, receipt=True, time_precision=time_precision)
        if retained["configuration"] != configuration_digest:
            raise VerificationError("retained ticket head configuration differs")
        if canonical(retained["request"]) != canonical(asdict(request)) or retained["authorityKey"] != policy.issuer_key or retained["witnessScope"] != "PEER" or retained["coverage"] != "one-native-ticket-row-and-service-events":
            raise VerificationError("retained ticket head profile differs")
    history = _verify_ticket_history(events, state, request, policy, service_key, retained)
    content = _verify_ticket_rows(tickets, state, request)
    return VerifiedTicketCapture(state, content, history.admissions, len(tickets))

def verify_ticket_result(
    receipt: Mapping[str, Any], readback: Mapping[str, Any],
    request: ActionRequest, policy: GrantPolicy, service_key: str,
    grant: Mapping[str, Any], *, now: datetime,
    decision_digest: str | None = None,
    time_precision: Literal["seconds", "milliseconds"] = "seconds",
) -> dict[str, Any]:
    """Join signed completion with separately retrieved native bytes and policy.

    This reader requires current grant validity and an unrevoked read-back,
    authenticates both service receipts, and recomputes content from native
    response bytes. It does not assign custody, authenticate the bearer caller,
    or infer general containment from a local HTTP gate. A selected optional
    decision digest is a configuration binding; native decision recomputation
    belongs to the profile reader. Omitting it refuses records that carry it.
    """
    authorized = verify_grant(grant, request, policy, now=now, reference_precision=time_precision)
    if not isinstance(readback, Mapping) or set(readback) != READBACK_FIELDS or type(readback["revision"]) is not int:
        raise VerificationError("ticket native read-back fields or counter differ")
    carried = checked_record(dict(receipt), service_key)
    current = checked_record(readback["receipt"], service_key)
    configuration_fields = ticket_configuration(request, policy, service_key, decision_digest, time_precision)
    configuration = digest(DOMAIN + "-configuration", configuration_fields)
    for record in (carried, current):
        state_schema(record, receipt=True, time_precision=time_precision)
        if record["request"] != asdict(request) or record["configuration"] != configuration or record["authorityKey"] != policy.issuer_key or record["grantDigest"] != authorized.grant_digest:
            raise VerificationError("ticket consumer binding differs")
        if record["phase"] != "completed" or record["revoked"] or record["revision"] != 1 or record["witnessScope"] != "PEER" or record["coverage"] != "one-native-ticket-row-and-service-events":
            raise VerificationError("ticket consumer requires unrevoked bounded completion")
        for field in ("intentTime", "effectTime"):
            verify_grant(grant, request, policy, now=parse_time(record[field], time_precision), reference_precision=time_precision)
        if now < parse_time(record["effectTime"], time_precision):
            raise VerificationError("ticket consumer clock predates completed effect")
    if carried != current:
        raise VerificationError("ticket current state differs from retained completion")
    expected_effect = digest(DOMAIN + "-effect", {"configuration": configuration, "requestId": request.request_id, "grantDigest": authorized.grant_digest})
    if carried["effectId"] != expected_effect:
        raise VerificationError("ticket effect identity differs")
    if readback["tenantId"] != request.tenant_id or readback["ticketId"] != request.target_path.removeprefix("/work/tickets/") or readback["revision"] != 1 or readback["effectId"] != expected_effect:
        raise VerificationError("ticket native read-back identity differs")
    encoded = readback["contentHex"]
    if not isinstance(encoded, str) or len(encoded) > MAX_BODY or len(encoded) % 2 or any(c not in "0123456789abcdef" for c in encoded):
        raise VerificationError("ticket native read-back encoding differs")
    try:
        content = bytes.fromhex(encoded)
    except (TypeError, ValueError) as error:
        raise VerificationError("ticket native read-back bytes are malformed") from error
    if hashlib.sha256(content).hexdigest() != request.content_sha256 or carried["contentDigest"] != request.content_sha256:
        raise VerificationError("ticket native read-back content differs")
    return {"status": "verified", "requestId": request.request_id, "attemptId": request.attempt_id, "effectId": expected_effect, "nativeRevision": 1, "witnessScope": "PEER"}


def load_ticket_capture(
    db: sqlite3.Connection, request: ActionRequest, policy: GrantPolicy, service_key: str, *,
    decision_digest: str | None = None, retained_head: dict[str, Any] | None = None,
    time_precision: Literal["seconds", "milliseconds"] = "seconds",
) -> VerifiedTicketCapture:
    """Replay one retained ticket store snapshot through :func:`verify_ticket_capture`.

    The caller opens ``db`` read-only and selects every key and policy outside
    the snapshot. Only the three native populations are queried; nothing is written.
    """
    row = db.execute("SELECT record FROM state WHERE singleton=1").fetchone()
    if row is None:
        raise VerificationError("ticket state is missing")
    return verify_ticket_capture(
        row[0],
        db.execute("SELECT sequence,record FROM events ORDER BY sequence").fetchall(),
        db.execute("SELECT tenant,ticket,content,revision,effect FROM tickets").fetchall(),
        request, policy, service_key, decision_digest=decision_digest,
        retained_head=retained_head, time_precision=time_precision)
