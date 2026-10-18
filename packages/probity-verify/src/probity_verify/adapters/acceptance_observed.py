"""Check a done contract's acceptance commands as graded outside the agent.

The grade must come from a separate verifier run on the agent's final tree:
its record names the contract digest and the tree digest it ran on, and the
tree record from the observer must report the same final tree. A pass also
needs the contract to tell a fix from a no-op, held-out commands the agent
never saw, every replayed test to have called the candidate, and every patched
hunk to have a mutant the commands kill. A failure only of held-out probes the
verifier stopped at their limit (``timed_out`` in the grade) gave no answer to
judge and leaves the check unestablished (``probe_timed_out``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..common import CaseError, _string
from . import done_records as records

CLAIM_TYPE = "acceptance_observed/v1"
FIELDS = {"claim_type", "invocation_id", "observed_party", "contract_witness",
          "tree_witness", "grade_witness"}
OPTIONAL = {"allow_no_heldout"}
HELDOUT_PREFIX = "heldout"
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
        outcome = {"id": command["id"], "exit": found["exit"]}
        for key in ("collected", "replay", "timed_out"):
            if key in found:
                outcome[key] = found[key]
        if "ids" in command:
            outcome["ids_sealed"] = len(command["ids"])
        outcomes.append(outcome)
    if by_id:
        return "acceptance_result_unexpected", outcomes
    return None, outcomes


def _heldout(contract: dict) -> bool:
    """A sealed held-out split with at least one held-out command to grade it."""
    return "heldout_split_sha256" in contract and any(
        command["id"].startswith(HELDOUT_PREFIX) for command in contract["acceptance"])


def _passed_checks(contract: dict, grade: dict, outcomes: list[dict],
                   allow_no_heldout: bool) -> tuple[list[dict], str | None]:
    """The checks a run whose commands all exited zero must still meet, in order."""
    adequacy = contract["adequacy"]
    silent = [item["id"] for item in outcomes if item.get("replay", {}).get(
        "calls_intercepted") == 0]
    idle = [{"path": hunk["path"], "lines": hunk["lines"]} for hunk in grade.get("hunks", [])
            if hunk["mutants"] and not hunk["killed"]]
    heldout = _heldout(contract)
    found = [
        ({"id": "contract_adequacy", "status": "met" if adequacy["killed"] > 0
          else "unavailable", **adequacy}, "contract_adequacy_zero"),
        ({"id": "calls_intercepted", "status": "unavailable" if silent else "met",
          "silent_ids": silent}, "no_calls_intercepted"),
        ({"id": "patch_exercised", "status": "unavailable" if idle else "met",
          "hunks": len(grade.get("hunks", [])), "unexercised": idle}, "patch_not_exercised"),
        ({"id": "heldout", "status": "met" if heldout or allow_no_heldout else "unavailable",
          "sealed": heldout}, "heldout_unavailable"),
    ]
    checks = []
    for check, reason in found:
        checks.append(check)
        if check["status"] != "met":
            return checks, reason
    return checks, None


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    case_id, assessment = records.start(case, policy, CLAIM_TYPE, FIELDS, OPTIONAL)
    invocation = _string(assessment["invocation_id"], "invocation_id")
    allow_no_heldout = assessment.get("allow_no_heldout", False)
    if type(allow_no_heldout) is not bool:
        raise CaseError("allow_no_heldout: expected a boolean")
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
            result.update(vantage="independent", **records.scope_fields(*pairs))
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
    failed = [item for item in outcomes if item["exit"] != 0]
    # A held-out probe the verifier stopped at its limit gave no answer: that is no wrong
    # answer, and only an answered failure contradicts. A visible command the agent could
    # run itself and that outran its limit failed.
    answered = [item["id"] for item in failed
                if not (item["id"].startswith(HELDOUT_PREFIX) and item.get("timed_out"))]
    checks.append({"id": "acceptance", "status": "failed" if answered else (
        "unavailable" if failed else "met"), "results": outcomes})
    if failed and not answered:
        return decide("not_established", "probe_timed_out")
    if answered:
        reason = ("heldout_failed" if all(item.startswith(HELDOUT_PREFIX) for item in answered)
                  else "acceptance_failed_in_verifier")
        return decide("contradicted", reason, (tree, tree_pin), (grade, grade_pin))
    short = [item["id"] for item in outcomes
             if "ids_sealed" in item and item.get("collected") != item["ids_sealed"]]
    checks.append({"id": "collection", "status": "unavailable" if short else "met",
                   "short_ids": short})
    if short:
        return decide("not_established", "acceptance_collection_mismatch")
    passed, reason = _passed_checks(contract, grade, outcomes, allow_no_heldout)
    checks.extend(passed)
    if reason is not None:
        return decide("not_established", reason)
    return decide("supported", "acceptance_passed_in_verifier", (tree, tree_pin),
                  (grade, grade_pin))
