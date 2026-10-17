"""Check a done contract's acceptance commands as graded outside the agent.

The grade must come from a separate verifier run on the agent's final tree:
its record names the contract digest and the tree digest it ran on, and the
tree record from the observer must report the same final tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..common import _string
from . import done_records as records

CLAIM_TYPE = "acceptance_observed/v1"
FIELDS = {"claim_type", "invocation_id", "observed_party", "contract_witness",
          "tree_witness", "grade_witness"}
LIMIT = ("Producer, vantage and witness scope are consumer pins, not authenticated "
         "identities. The grade reports exit statuses; it does not show that the "
         "acceptance commands test the task.")


def _compare(acceptance: list[dict], results: list[dict]) -> tuple[str | None, list]:
    by_id = {item["id"]: item for item in results}
    outcomes = []
    for command in acceptance:
        found = by_id.pop(command["id"], None)
        if found is None:
            return "acceptance_result_missing", outcomes
        if found["argv"] != command["argv"]:
            return "acceptance_argv_mismatch", outcomes
        outcomes.append({"id": command["id"], "exit": found["exit"]})
    if by_id:
        return "acceptance_result_unexpected", outcomes
    return None, outcomes


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    case_id, assessment = records.start(case, policy, CLAIM_TYPE, FIELDS)
    invocation = _string(assessment["invocation_id"], "invocation_id")
    observed_party = _string(assessment["observed_party"], "observed_party")
    bound = records.witnesses(case, policy, assessment, artifact_root, {
        "contract": False, "tree": True, "grade": True})
    result = {
        "schema_version": "probity-decision/v1", "case_id": case_id, "claim_type": CLAIM_TYPE,
        "scope": {"invocation_id": invocation, "observed_party": observed_party,
                  "witnesses": {role: pin for role, (_, pin) in bound.items()},
                  "limit": LIMIT},
        "checks": [], "vantage": "unestablished",
    }
    checks = result["checks"]

    def decide(decision: str, reason: str, *pairs: tuple[dict, dict]) -> dict:
        if decision != "not_established":
            result.update(vantage="independent", witness_scope=records.scope_of(*pairs))
        return {**result, "decision": decision, "reason": reason}

    contract_bytes, contract_pin = bound["contract"]
    tree_bytes, tree_pin = bound["tree"]
    grade_bytes, grade_pin = bound["grade"]
    contract = records.contract(contract_bytes) if contract_bytes is not None else None
    tree = records.tree(tree_bytes) if tree_bytes is not None else None
    grade = records.grade(grade_bytes) if grade_bytes is not None else None
    if contract is None:
        return decide("not_established", "contract_unavailable_or_unbound")
    tree_ok = (tree is not None and tree["claim_id"] == case_id
               and tree["invocation_id"] == invocation
               and records.independent(tree, tree_pin, observed_party))
    checks.append({"id": "final_tree", "status": "met" if tree_ok else "unavailable"})
    if not tree_ok:
        return decide("not_established", "final_tree_unestablished")
    if grade is None:
        return decide("not_established", "grade_unavailable_or_unbound")
    if grade["claim_id"] != case_id or grade["invocation_id"] != invocation:
        return decide("not_established", "grade_context_mismatch")
    grade_ok = records.independent(grade, grade_pin, observed_party)
    checks.append({"id": "grade_vantage", "status": "met" if grade_ok else "unavailable"})
    if not grade_ok:
        return decide("not_established", "grade_vantage_unestablished")
    bindings = {"contract": grade["contract_sha256"] == contract_pin["consumer_pinned_sha256"],
                "tree": grade["tree_sha256"] == tree["tree_sha256"]}
    checks.append({"id": "grade_binding", "status": "met" if all(bindings.values())
                   else "unavailable", "contract": bindings["contract"],
                   "tree": bindings["tree"]})
    if not bindings["contract"]:
        return decide("not_established", "grade_contract_mismatch")
    if not bindings["tree"]:
        return decide("not_established", "grade_tree_unbound")
    problem, outcomes = _compare(contract["acceptance"], grade["results"])
    if problem is not None:
        return decide("not_established", problem)
    failed = [item["id"] for item in outcomes if item["exit"] != 0]
    checks.append({"id": "acceptance", "status": "failed" if failed else "met",
                   "results": outcomes})
    if failed:
        return decide("contradicted", "acceptance_failed_in_verifier", (tree, tree_pin),
                      (grade, grade_pin))
    adequacy = contract["adequacy"]
    adequate = adequacy["killed"] > 0
    checks.append({"id": "contract_adequacy", "status": "met" if adequate else "unavailable",
                   **adequacy})
    if not adequate:
        return decide("not_established", "contract_adequacy_zero")
    return decide("supported", "acceptance_passed_in_verifier", (tree, tree_pin),
                  (grade, grade_pin))
