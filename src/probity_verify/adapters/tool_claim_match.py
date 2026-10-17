"""Match each tool run an agent claims to an exec the observer recorded.

A claimed run matches an ``exec`` event with the same argv whose step follows
the last edit. For each claim, an edit is a mutation event made outside the
process trees of runs of that same argv, so a test run's own cache writes do
not make it stale while any other command's writes do. Any
unmatched claim contradicts only under complete coverage with exec and every
mutation type visible, because an unseen run could otherwise exist.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..common import _string
from . import done_records as records
from .event_absence import _capabilities, _scope

CLAIM_TYPE = "tool_claim_match/v1"
FIELDS = {"claim_type", "invocation_id", "scope", "observed_party", "claims_witness",
          "capability_witness", "observation_witness"}
REQUIRED_TYPES = records.MUTATION_TYPES | {records.EXEC_TYPE}
LIMIT = ("Producer, vantage and witness scope are consumer pins, not authenticated "
         "identities. Claims are matched by exact argv; the claim parser and the "
         "observer must record argv the same way.")
CONTRADICTIONS = {"unmatched": "tool_claim_unmatched",
                  "precedes_last_edit": "tool_claim_precedes_last_edit",
                  "exit_mismatch": "tool_claim_exit_mismatch"}


def _status(claim: dict, events: list[dict]) -> dict:
    execs = [event for event in events if event["type"] == records.EXEC_TYPE]
    candidates = [event for event in execs if event["argv"] == claim["argv"]]
    own = {event.get("origin", event["id"]) for event in candidates}
    last_edit = max((event["step"] for event in events
                     if event["type"] in records.MUTATION_TYPES
                     and event.get("origin") not in own), default=-1)
    fresh = [event for event in candidates if event["step"] > last_edit]
    outcome = {"id": claim["id"], "last_edit_step": last_edit,
               "exec_ids": [event["id"] for event in fresh or candidates]}
    if not candidates:
        return {**outcome, "status": "unmatched"}
    if not fresh:
        return {**outcome, "status": "precedes_last_edit"}
    if "exit" not in claim:
        return {**outcome, "status": "matched"}
    agreeing = [event["id"] for event in fresh if event.get("exit") == claim["exit"]]
    if agreeing:
        return {**outcome, "status": "matched", "exec_ids": agreeing}
    if any("exit" not in event for event in fresh):
        return {**outcome, "status": "exit_unobserved"}
    return {**outcome, "status": "exit_mismatch"}


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    case_id, assessment = records.start(case, policy, CLAIM_TYPE, FIELDS)
    invocation = _string(assessment["invocation_id"], "invocation_id")
    scope = _scope(assessment["scope"], "assessment.scope")
    observed_party = _string(assessment["observed_party"], "observed_party")
    bound = records.witnesses(case, policy, assessment, artifact_root, {
        "claims": False, "capability": False, "observation": True})
    result = {
        "schema_version": "probity-decision/v1", "case_id": case_id, "claim_type": CLAIM_TYPE,
        "scope": {"invocation_id": invocation, "interval": scope,
                  "observed_party": observed_party,
                  "witnesses": {role: pin for role, (_, pin) in bound.items()},
                  "limit": LIMIT},
        "checks": [], "vantage": "unestablished",
    }
    checks = result["checks"]

    def decide(decision: str, reason: str) -> dict:
        return {**result, "decision": decision, "reason": reason}

    claims_bytes, _ = bound["claims"]
    observed, observation_pin = bound["observation"]
    capability, _ = bound["capability"]
    claimed = records.claims(claims_bytes) if claims_bytes is not None else None
    record = records.observation(observed) if observed is not None else None
    manifest = _capabilities(capability) if capability is not None else None
    if claimed is None:
        return decide("not_established", "claims_unavailable_or_unbound")
    if claimed["claim_id"] != case_id or claimed["invocation_id"] != invocation:
        return decide("not_established", "claims_context_mismatch")
    if record is None:
        return decide("not_established", "observation_unavailable_or_unbound")
    if (record["claim_id"] != case_id or record["invocation_id"] != invocation
            or record["scope"] != scope):
        return decide("not_established", "observation_context_mismatch")
    independent = records.independent(record, observation_pin, observed_party)
    checks.append({"id": "observation_vantage", "status": "met" if independent
                   else "unavailable"})
    if not independent:
        return decide("not_established", "observation_vantage_unestablished")
    events = record.get("events", [])
    outcomes = [_status(claim, events) for claim in claimed["claims"]]
    unsettled = [item for item in outcomes if item["status"] != "matched"]
    checks.append({"id": "tool_claims", "status": "failed" if unsettled else "met",
                   "claims": outcomes})
    if manifest is None:
        return decide("not_established", "capability_unavailable_or_unbound")
    if (manifest["claim_id"] != case_id or manifest["invocation_id"] != invocation
            or manifest["producer"] != record["producer"]):
        return decide("not_established", "capability_context_mismatch")
    visible = REQUIRED_TYPES <= set(manifest["visible_event_types"])
    complete = record["coverage"] == "complete"
    checks.extend([
        {"id": "field_visibility", "status": "met" if visible else "unavailable"},
        {"id": "observation_coverage", "status": "met" if complete else "unavailable"},
    ])
    if not visible:
        return decide("not_established", "field_visibility_unestablished")
    if not complete:
        return decide("not_established", "observation_coverage_unestablished")
    contradicted = [item for item in unsettled if item["status"] in CONTRADICTIONS]
    if contradicted or not unsettled:
        result.update(vantage="independent",
                      witness_scope=records.scope_of((record, observation_pin)))
    if contradicted:
        return decide("contradicted", CONTRADICTIONS[contradicted[0]["status"]])
    if unsettled:
        return decide("not_established", "tool_exit_unobserved")
    return decide("supported", "tool_claims_matched")
