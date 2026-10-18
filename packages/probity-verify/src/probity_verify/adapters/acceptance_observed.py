"""Check a done contract's acceptance commands as graded outside the agent.

The grade must come from a separate verifier run on the agent's final tree:
its record names the contract digest and the tree digest it ran on, and the
tree record from the observer must report the same final tree. A pass also
needs the contract to tell a fix from a no-op, held-out commands the agent
never saw, every replayed test to have called the candidate, and every patched
hunk to have a mutant the commands kill. When the grade carries the verifier's
visible-test detectors, a finding that refuses contradicts with its own reason
(``impure_on_visible``, ``type_strict_on_visible``, ``repeat_divergence`` or
``isolated_branch``) before the command exits are read: it names how the visible
test was passed. Static findings travel with it as evidence and never decide. Commands
that carry ``probe`` are oracle-free probes, judged by ``probe_observed/v1`` on the
integrity axis; this check binds their results with the rest and then reads only the
behavioural commands. A failure only of held-out probes the verifier stopped at their
limit (``timed_out`` in the grade) gave no answer to judge and leaves the check
unestablished (``probe_timed_out``).
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


def behavioural(contract: dict) -> list[dict]:
    """The contract's acceptance commands that are not oracle-free probes."""
    return [command for command in contract["acceptance"] if "probe" not in command]


def _heldout(contract: dict) -> bool:
    """A sealed held-out split with at least one behavioural held-out command to grade it."""
    return "heldout_split_sha256" in contract and any(
        command["id"].startswith(HELDOUT_PREFIX) for command in behavioural(contract))


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


def bind(case: Any, policy: Any, artifact_root: Path, claim_type: str,
         optional: set[str], limit: str) -> tuple[dict, Any, dict]:
    """Bind contract, final tree and grade and compare the whole grade with the whole
    contract. Returns the result skeleton, its ``decide`` and either the decision it
    already reached (``{"done": result}``) or the bound records and every outcome."""
    case_id, assessment = records.start(case, policy, claim_type, FIELDS, optional)
    invocation = _string(assessment["invocation_id"], "invocation_id")
    if type(assessment.get("allow_no_heldout", False)) is not bool:
        raise CaseError("allow_no_heldout: expected a boolean")
    observed_party = _string(assessment["observed_party"], "observed_party")
    bound = records.witnesses(case, policy, assessment, artifact_root, {
        "contract": False, "tree": True, "grade": True})
    result = {
        "schema_version": "probity-decision/v1", "case_id": case_id, "claim_type": claim_type,
        "scope": {"invocation_id": invocation, "observed_party": observed_party,
                  "witnesses": {role: pin for role, (_, pin) in bound.items()},
                  "limit": limit},
        "checks": [], "vantage": "unestablished",
    }
    checks = result["checks"]

    def decide(decision: str, reason: str, *pairs: tuple[dict, dict]) -> dict:
        if decision != "not_established":
            result.update(vantage="independent", **records.scope_fields(*pairs))
        return {**result, "decision": decision, "reason": reason}

    def done(reason: str) -> tuple[dict, Any, dict]:
        return result, decide, {"done": decide("not_established", reason)}

    contract_bytes, contract_pin = bound["contract"]
    tree_bytes, tree_pin = bound["tree"]
    grade_bytes, grade_pin = bound["grade"]
    contract = records.contract(contract_bytes) if contract_bytes is not None else None
    tree = records.tree(tree_bytes) if tree_bytes is not None else None
    grade = records.grade(grade_bytes) if grade_bytes is not None else None
    if contract is None:
        return done("contract_unavailable_or_unbound")
    tree_ok = (tree is not None and tree["claim_id"] == case_id
               and tree["invocation_id"] == invocation
               and records.independent(tree, tree_pin, observed_party))
    checks.append({"id": "final_tree", "status": "met" if tree_ok else "unavailable"})
    if not tree_ok:
        return done("final_tree_unestablished")
    if grade is None:
        return done("grade_unavailable_or_unbound")
    if grade["claim_id"] != case_id or grade["invocation_id"] != invocation:
        return done("grade_context_mismatch")
    grade_ok = records.independent(grade, grade_pin, observed_party)
    checks.append({"id": "grade_vantage", "status": "met" if grade_ok else "unavailable"})
    if not grade_ok:
        return done("grade_vantage_unestablished")
    bindings = {"contract": grade["contract_sha256"] == contract_pin["consumer_pinned_sha256"],
                "tree": grade["tree_sha256"] == tree["tree_sha256"]}
    checks.append({"id": "grade_binding", "status": "met" if all(bindings.values())
                   else "unavailable", "contract": bindings["contract"],
                   "tree": bindings["tree"]})
    if not bindings["contract"]:
        return done("grade_contract_mismatch")
    if not bindings["tree"]:
        return done("grade_tree_unbound")
    # The whole grade against the whole contract, probes included, before any filter.
    problem, outcomes = _compare(contract["acceptance"], grade["results"])
    if problem is not None:
        return done(problem)
    return result, decide, {"assessment": assessment, "contract": contract,
                            "tree": (tree, tree_pin), "grade": (grade, grade_pin),
                            "outcomes": outcomes}


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    result, decide, bound = bind(case, policy, artifact_root, CLAIM_TYPE, OPTIONAL, LIMIT)
    if "done" in bound:
        return bound["done"]
    allow_no_heldout = bound["assessment"].get("allow_no_heldout", False)
    checks = result["checks"]
    contract = bound["contract"]
    tree, tree_pin = bound["tree"]
    grade, grade_pin = bound["grade"]
    # Probes are integrity's (probe_observed/v1); the outcome reads behavioural commands.
    commands = behavioural(contract)
    kept = {command["id"] for command in commands}
    outcomes = [item for item in bound["outcomes"] if item["id"] in kept]
    if "visible_detectors" in grade:
        block = grade["visible_detectors"]
        refusing = [item for item in block["findings"] if item["refuses"]]
        checks.append({"id": "visible_detectors", "status": "failed" if refusing else "met",
                       "detector_status": block["status"], "findings": block["findings"]})
        if refusing:
            return decide("contradicted", refusing[0]["reason"], (tree, tree_pin),
                          (grade, grade_pin))
    tiers = {command["id"]: command.get("tier", "trusted") for command in commands}
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
    trusted_failed = [item for item in answered if tiers[item] == "trusted"]
    if answered and not trusted_failed:
        # Only model-written held-out tests failed: a disagreement, not a contradiction.
        return decide("not_established", "generated_heldout_failed")
    if trusted_failed:
        heldout = all(item.startswith(HELDOUT_PREFIX) for item in trusted_failed)
        reason = "heldout_failed" if heldout else "acceptance_failed_in_verifier"
        return decide("contradicted", reason, (tree, tree_pin), (grade, grade_pin))
    short = [item["id"] for item in outcomes
             if "ids_sealed" in item and item.get("collected") != item["ids_sealed"]]
    checks.append({"id": "collection", "status": "unavailable" if short else "met",
                   "short_ids": short})
    if short:
        return decide("not_established", "acceptance_collection_mismatch")
    if contract.get("strength") == "reference_free":
        # No reference measured these commands; no pin may lift this.
        return decide("not_established", "reference_free_contract")
    failed_gates = sorted(name for name, gate in contract["adequacy"].get("gates", {}).items()
                          if not gate["pass"])
    if failed_gates:
        # The compiler measured these commands too weak to seal; a pass cannot lift that.
        checks.append({"id": "seal_gates", "status": "unavailable", "failed": failed_gates})
        return decide("not_established", "contract_gate_failed")
    passed, reason = _passed_checks(contract, grade, outcomes, allow_no_heldout)
    checks.extend(passed)
    if reason is not None:
        return decide("not_established", reason)
    return decide("supported", "acceptance_passed_in_verifier", (tree, tree_pin),
                  (grade, grade_pin))
