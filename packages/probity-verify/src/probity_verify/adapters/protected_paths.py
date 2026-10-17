"""Check that an agent left the done contract's protected paths alone.

This is the bounded event-absence rule (``event_absence.settle_absence``)
profiled for file mutation: every mutation type must be visible and the
observation complete before an empty record supports the claim. A recorded
mutation of a protected path contradicts it. A separate final tree record then
catches a protected change whose events were lost.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..common import _string
from . import done_records as records
from .event_absence import _scope, settle_absence

CLAIM_TYPE = "protected_paths/v1"
FIELDS = {"claim_type", "invocation_id", "scope", "observed_party", "contract_witness",
          "capability_witness", "observation_witness", "tree_witness"}
LIMIT = ("Producer, vantage and witness scope are consumer pins, not authenticated "
         "identities. Paths are compared as recorded; the observer must resolve links "
         "and case folding before it writes them.")


def _protected(entries: list[dict]):
    def hit(name: str) -> bool:
        return any(records.protects(entry, name) for entry in entries)

    def matches(event: dict) -> bool:
        return event["type"] in records.MUTATION_TYPES and (
            hit(event["path"]) or ("target" in event and hit(event["target"])))
    return matches


def _changed(entries: list[dict], files: dict[str, str]) -> list[str]:
    changed = []
    for entry in entries:
        if entry["kind"] == "file":
            now = files.get(entry["path"])
        else:
            selected = {name: digest for name, digest in files.items()
                        if name != entry["path"] and records.protects(entry, name)}
            now = records.tree_digest(selected)
        if now != entry["sha256"]:
            changed.append(entry["path"])
    return changed


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    case_id, assessment = records.start(case, policy, CLAIM_TYPE, FIELDS)
    invocation = _string(assessment["invocation_id"], "invocation_id")
    scope = _scope(assessment["scope"], "assessment.scope")
    observed_party = _string(assessment["observed_party"], "observed_party")
    bound = records.witnesses(case, policy, assessment, artifact_root, {
        "contract": False, "capability": False, "observation": True, "tree": True})
    result = {
        "schema_version": "probity-decision/v1", "case_id": case_id, "claim_type": CLAIM_TYPE,
        "scope": {"invocation_id": invocation, "interval": scope,
                  "observed_party": observed_party,
                  "witnesses": {role: pin for role, (_, pin) in bound.items()},
                  "limit": LIMIT},
        "checks": [], "vantage": "unestablished",
    }

    def decide(decision: str, reason: str, *pairs: tuple[dict, dict]) -> dict:
        if decision != "not_established":
            result.update(vantage="independent", witness_scope=records.scope_of(*pairs))
        return {**result, "decision": decision, "reason": reason}

    contract_bytes, _ = bound["contract"]
    if contract_bytes is None:
        return decide("not_established", "contract_unavailable_or_unbound")
    entries = records.contract(contract_bytes)["protected_paths"]
    result["scope"]["protected_paths"] = [entry["path"] for entry in entries]
    tree_bytes, tree_pin = bound["tree"]
    tree = records.tree(tree_bytes) if tree_bytes is not None else None

    parsed: dict[str, dict] = {}

    def parse(data: bytes) -> dict:
        parsed["record"] = records.observation(data)
        return parsed["record"]

    observed, observation_pin = bound["observation"]
    capability, _ = bound["capability"]
    settled = settle_absence(
        result, observed, capability, case_id=case_id, invocation=invocation, scope=scope,
        observation_pin=observation_pin, observed_party=observed_party,
        required_types=records.MUTATION_TYPES, matches=_protected(entries), parse=parse)
    observation_pair = (parsed.get("record"), observation_pin)
    if settled["decision"] == "contradicted":
        return decide("contradicted", "protected_path_mutated", observation_pair)

    tree_check = {"id": "final_tree", "status": "unavailable"}
    result["checks"].append(tree_check)
    if (tree is not None and tree["claim_id"] == case_id
            and tree["invocation_id"] == invocation
            and records.independent(tree, tree_pin, observed_party)):
        changed = _changed(entries, tree["files"])
        tree_check.update(status="failed" if changed else "met", changed_paths=changed)
        if changed:
            return decide("contradicted", "protected_path_digest_changed", (tree, tree_pin))
    if settled["decision"] == "not_established":
        return decide("not_established", settled["reason"])
    if tree_check["status"] != "met":
        return decide("not_established", "final_tree_unestablished")
    return decide("supported", "protected_paths_untouched", observation_pair,
                  (tree, tree_pin))
