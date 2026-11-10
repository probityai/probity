"""``idp_log_witness/v1``: does the identity provider's own log back every principal the records name?

An agent audit record names the principal a decision point established from a token it validated:
the issuer, the subject, the client and when the token was issued. That is the record producer's
account. The identity provider keeps a second account of the same issuance in its tenant log, which
it writes on its own side and exports through a log stream or its log API. This claim reconciles
the two. For every signed record the consumer pins, the provider's export must hold a successful
token issuance to the same client, for the same subject, within the skew tolerance of the record's
``principal.issuedAt``. A mismatch is a finding with its own code. The first contradicting finding in record order is
the decision's reason; when nothing contradicts, the first finding that leaves the claim open is.

Two exports are read, each in its published shape:

* ``auth0``: tenant log events, as a JSON array, as newline-delimited JSON, or as log-stream
  webhook batches (each element ``{"log_id": ..., "data": {...}}``). An issuance is an event whose
  ``type`` is a token-exchange success code; a refusal is the matching failure code. The subject
  of an event is any of ``user_id``, ``agent_id``, ``external_agent_id`` and every ``sub`` in the
  on-behalf-of ``details.actor`` chain.
* ``okta``: System Log ``LogEvent`` objects, as a JSON array. An issuance is the event type
  ``app.oauth2.as.token.grant.access_token`` (or ``.id_token``) with ``outcome.result`` ``SUCCESS``;
  any other result is a refusal. The client and subject of an event are read from the ids and
  alternate ids of its ``actor`` and ``target`` entries.

Findings, in the order they are tested for each record:

``principal-issuer-unpinned``
    the record's issuer is not the issuer the consumer pinned for this export;
``issuance-outside-window``
    the record's issuance time is outside the window the consumer says the export covers, so the
    export cannot speak to it (``not_established``, never a contradiction);
``issuance-refused``
    the provider logged only refusals for that client and subject near that time;
``issuance-principal-mismatch``
    the provider logged a successful issuance to that client near that time, for another subject;
``issuance-unlogged``
    the provider logged nothing for that client near that time.

Issuances to an agent principal inside the window that no record accounts for are reported in the
``unobserved_issuances`` check. They do not contradict the claim, which is about the records, but a
consumer who holds a complete set of records reads them as tokens used outside the sandbox.

Each record is first judged by ``audit_principal/v1``. A record whose principal does not conform
contradicts the claim with that rule's code; a record without a principal leaves it
``not_established``. The export is bound by length and SHA-256 like every other artifact, and a
malformed export refuses with no verdict.
"""

from __future__ import annotations

import base64
import datetime
import json
from pathlib import Path
from typing import Any

from ..common import CaseError, _digest, _string
from . import audit_principal
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "idp_log_witness/v1"
LIMIT = ("Reconciles each record's principal with the issuance events in the pinned export. It "
         "does not establish that the export is complete or unaltered: the consumer pins its "
         "bytes and declares the window it covers, and the provider's log is the provider's word.")

PROVIDERS = frozenset({"auth0", "okta"})
SKEW = datetime.timedelta(seconds=300)

#: Auth0 tenant log codes for a successful token issuance, from the "Token Exchange - Success"
#: event filter and the per-type reference pages.
AUTH0_ISSUED = frozenset({
    "seacft", "seccft", "sede", "seoobft", "seotpft", "sepft", "sercft", "sertft", "secte",
    "success_on_behalf_of_token_exchange", "ciba_exchange_succeeded", "idjag_exchange_succeeded",
})
#: The matching failure codes.
AUTH0_REFUSED = frozenset({
    "feacft", "feccft", "fede", "feoobft", "feotpft", "fepft", "fercft", "fertft", "fecte",
    "failed_on_behalf_of_token_exchange", "ciba_exchange_failed", "idjag_exchange_failed",
})
OKTA_GRANTS = frozenset({
    "app.oauth2.as.token.grant.access_token", "app.oauth2.as.token.grant.id_token",
})
#: Auth0 ``sub_profile`` and Okta actor types that mark an agent principal.
AGENT_MARKERS = frozenset({"ai_agent", "AIAgent", "WorkloadPrincipal"})


class _Event:
    """One normalized issuance or refusal from the provider's export."""

    __slots__ = ("event_id", "at", "clients", "subjects", "issued", "agent")

    def __init__(self, event_id: str, at: datetime.datetime, clients: set[str],
                 subjects: set[str], issued: bool, agent: bool) -> None:
        self.event_id = event_id
        self.at = at
        self.clients = clients
        self.subjects = subjects
        self.issued = issued
        self.agent = agent


def _instant(value: Any, label: str) -> datetime.datetime:
    text = _string(value, label)
    try:
        moment = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise CaseError(f"{label}: expected an RFC 3339 timestamp") from error
    if moment.tzinfo is None:
        raise CaseError(f"{label}: expected a timestamp with an offset")
    return moment


def _ids(*values: Any) -> set[str]:
    return {v for v in values if isinstance(v, str) and v}


def _actor_subjects(actor: Any) -> set[str]:
    found: set[str] = set()
    depth = 0
    while isinstance(actor, dict):
        depth += 1
        if depth > 32:
            raise CaseError("idp export: actor chain deeper than 32")
        found |= _ids(actor.get("sub"))
        actor = actor.get("act")
    return found


def _auth0_events(raw: bytes) -> list[_Event]:
    text = raw.decode("utf-8")
    stripped = text.strip()
    try:
        if stripped.startswith("["):
            items = json.loads(stripped)
        else:
            items = [json.loads(line) for line in stripped.splitlines() if line.strip()]
    except json.JSONDecodeError as error:
        raise CaseError("idp export: not JSON or newline-delimited JSON") from error
    events: list[_Event] = []
    for index, item in enumerate(items):
        label = f"idp export[{index}]"
        if not isinstance(item, dict):
            raise CaseError(f"{label}: expected an object")
        data = item.get("data") if "data" in item and isinstance(item.get("data"), dict) else item
        kind = data.get("type")
        if not isinstance(kind, str):
            raise CaseError(f"{label}.type: expected a string")
        if kind not in AUTH0_ISSUED and kind not in AUTH0_REFUSED:
            continue
        event_id = _string(data.get("log_id", item.get("log_id")), f"{label}.log_id")
        details = data.get("details") if isinstance(data.get("details"), dict) else {}
        subjects = _ids(data.get("user_id"), data.get("agent_id"), data.get("external_agent_id"))
        subjects |= _actor_subjects(details.get("actor"))
        agent = bool(_ids(data.get("agent_id"), data.get("external_agent_id")))
        events.append(_Event(event_id, _instant(data.get("date"), f"{label}.date"),
                             _ids(data.get("client_id")), subjects, kind in AUTH0_ISSUED, agent))
    return events


def _okta_events(raw: bytes) -> list[_Event]:
    try:
        items = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise CaseError("idp export: not JSON") from error
    if not isinstance(items, list):
        raise CaseError("idp export: expected a JSON array of System Log events")
    events: list[_Event] = []
    for index, item in enumerate(items):
        label = f"idp export[{index}]"
        if not isinstance(item, dict):
            raise CaseError(f"{label}: expected an object")
        if item.get("eventType") not in OKTA_GRANTS:
            continue
        actor = item.get("actor")
        targets = item.get("target") or []
        if not isinstance(actor, dict) or not isinstance(targets, list):
            raise CaseError(f"{label}: expected an actor object and a target array")
        entities = [actor, *targets]
        if not all(isinstance(e, dict) for e in entities):
            raise CaseError(f"{label}.target: expected objects")
        ids: set[str] = set()
        for entity in entities:
            ids |= _ids(entity.get("id"), entity.get("alternateId"))
        outcome = item.get("outcome")
        result = outcome.get("result") if isinstance(outcome, dict) else None
        agent = any(e.get("type") in AGENT_MARKERS for e in entities)
        events.append(_Event(_string(item.get("uuid"), f"{label}.uuid"),
                             _instant(item.get("published"), f"{label}.published"),
                             ids, ids, result == "SUCCESS", agent))
    return events


READERS = {"auth0": _auth0_events, "okta": _okta_events}


def _principal(raw: bytes) -> dict[str, Any]:
    """The principal member of an envelope ``audit_principal`` has already judged valid."""
    envelope = json.loads(raw)
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    return statement["predicate"]["principal"]


def _finding(principal: dict[str, Any], events: list[_Event]) -> tuple[str | None, set[str]]:
    """The first finding for one principal, or ``None``, and the event ids that back it."""
    issued_at = datetime.datetime.fromisoformat(principal["issuedAt"].replace("Z", "+00:00"))
    client, subject = principal["clientId"], principal["subject"]
    near = [e for e in events if abs(e.at - issued_at) <= SKEW and client in e.clients]
    backing = {e.event_id for e in near if e.issued and subject in e.subjects}
    if backing:
        return None, backing
    if any(not e.issued and subject in e.subjects for e in near):
        return "issuance-refused", set()
    if any(e.issued for e in near):
        return "issuance-principal-mismatch", set()
    return "issuance-unlogged", set()


def _window(value: Any) -> tuple[datetime.datetime, datetime.datetime]:
    if not isinstance(value, dict) or set(value) != {"start", "end"}:
        raise CaseError("assessment.export_window: expected {start, end}")
    start = _instant(value["start"], "assessment.export_window.start")
    end = _instant(value["end"], "assessment.export_window.end")
    if end <= start:
        raise CaseError("assessment.export_window: end must follow start")
    return start, end


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Reconcile every pinned record's principal with the provider's pinned log export."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE,
        {"envelopes", "observer_public_key", "idp_export", "provider", "issuer", "export_window"})
    provider = assessment["provider"]
    if provider not in PROVIDERS:
        raise CaseError(f"assessment.provider: expected one of {sorted(PROVIDERS)}")
    issuer = _string(assessment["issuer"], "assessment.issuer")
    key = _digest(assessment["observer_public_key"], "assessment.observer_public_key")
    start, end = _window(assessment["export_window"])
    names = assessment["envelopes"]
    if not isinstance(names, list) or not names:
        raise CaseError("assessment.envelopes: expected a nonempty list of artifact names")
    export_raw, export_binding = bound(artifacts, artifact_root, assessment["idp_export"],
                                       "assessment.idp_export")
    scope: dict[str, Any] = {"provider": provider, "issuer": issuer, "observer_public_key": key,
                             "export": export_binding,
                             "export_window": {"start": assessment["export_window"]["start"],
                                               "end": assessment["export_window"]["end"]},
                             "envelopes": [], "limit": LIMIT}
    records = []
    for index, name in enumerate(names):
        raw, binding = bound(artifacts, artifact_root, name, f"assessment.envelopes[{index}]")
        scope["envelopes"].append(binding)
        records.append((name, raw))
    if export_raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "export_unavailable")
    try:
        events = READERS[provider](export_raw)
    except UnicodeDecodeError as error:
        raise CaseError("idp export: not UTF-8") from error

    checks: list[dict[str, Any]] = []
    found_by: dict[str, str] = {}
    accounted: set[str] = set()
    for name, raw in records:
        if raw is None:
            found_by.setdefault("not_established", "envelope_unavailable")
            checks.append({"id": f"record:{name}", "status": "unknown", "finding": "envelope-unavailable"})
            continue
        report = audit_principal.verify(raw, key)
        if report.verdict == "absent":
            found_by.setdefault("not_established", "principal_absent")
            checks.append({"id": f"record:{name}", "status": "unknown", "finding": "principal-absent"})
            continue
        if report.verdict != "valid":
            found_by.setdefault("contradicted", report.codes[0])
            checks.append({"id": f"record:{name}", "status": "fail", "finding": report.codes[0]})
            continue
        principal = _principal(raw)
        issued_at = datetime.datetime.fromisoformat(principal["issuedAt"].replace("Z", "+00:00"))
        if principal["issuer"] != issuer:
            code, status, verdict = "principal-issuer-unpinned", "fail", "contradicted"
            backing: set[str] = set()
        elif not start <= issued_at <= end:
            code, status, verdict, backing = "issuance-outside-window", "unknown", "not_established", set()
        else:
            found, backing = _finding(principal, events)
            code, status, verdict = (found, "fail", "contradicted") if found else (None, "pass", None)
        accounted |= backing
        check: dict[str, Any] = {"id": f"record:{name}", "status": status,
                                 "client": principal["clientId"], "subject": principal["subject"],
                                 "issued_at": principal["issuedAt"],
                                 "backing_events": sorted(backing)}
        if code:
            check["finding"] = code
            found_by.setdefault(verdict, code)
        checks.append(check)
    unobserved = sorted(e.event_id for e in events
                        if e.issued and e.agent and start <= e.at <= end and e.event_id not in accounted)
    checks.append({"id": "unobserved_issuances", "status": "pass" if not unobserved else "unknown",
                   "events": unobserved})
    for verdict in ("contradicted", "not_established"):
        if verdict in found_by:
            return decision(case_id, CLAIM_TYPE, scope, verdict, found_by[verdict], checks)
    return decision(case_id, CLAIM_TYPE, scope, "supported", "issuances_reconciled", checks)

