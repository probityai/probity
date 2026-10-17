"""Check a done receipt by deriving its verdict again from the records it names.

The receipt is an in-toto Statement v1 whose ``predicateType`` is
``https://w3id.org/agent-evidence/predicate/v1/done-receipt``. Its predicate
names the verifier that wrote it (``verifier.id``, a URI, required), the digest
of every record the verdict rests on, and the verdict. This check binds those
digests to the consumer's own pins, runs ``protected_paths/v1``,
``acceptance_observed/v1`` and ``tool_claim_match/v1`` on the pinned records,
combines them, and compares the result with the receipt:

1. The first ``contradicted`` check, in that order, gives ``contradicted`` with
   its reason.
2. Three ``supported`` checks give ``supported`` (``done_checks_supported``).
3. Otherwise ``not_established`` with the first such check's reason.

A receipt whose verdict differs from the derived one is contradicted
(``receipt_verdict_mismatch``): the verifier that wrote it reported a verdict
its own records do not give.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..common import CaseError, _digest, _object, _string
from . import acceptance_observed, protected_paths, tool_claim_match
from . import done_records as records
from .event_absence import _record, _scope
from ..vocabulary import EXTERNAL, PEER

CLAIM_TYPE = "done_receipt/v1"
RECORD_ROLES = ("contract", "capability", "observation", "tree", "grade", "claims")
FIELDS = {"claim_type", "invocation_id", "scope", "observed_party", "receipt_witness"} | {
    f"{role}_witness" for role in RECORD_ROLES}
OPTIONAL = {"allow_no_heldout", "verifier_ids"}
OBSERVED = {"observation": True, "tree": True, "grade": True}
CHECKS = (
    (protected_paths, ("contract", "capability", "observation", "tree"), True),
    (acceptance_observed, ("contract", "tree", "grade"), False),
    (tool_claim_match, ("claims", "capability", "observation", "contract"), True),
)
URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+")
LIMIT = ("The receipt's signature is not checked here; verify its DSSE envelope first. "
         "The verdict is derived again from the pinned records, so it rests on the same "
         "pins and limits as the three checks.")


def statement(data: bytes) -> dict:
    """The receipt Statement; refuses another predicate type or a missing verifier id."""
    value = _record(data, "receipt", {"_type", "subject", "predicateType", "predicate"})
    if value["_type"] != records.STATEMENT_TYPE:
        raise CaseError("receipt._type: expected an in-toto Statement v1")
    if value["predicateType"] != records.DONE_RECEIPT_PREDICATE:
        raise CaseError("receipt.predicateType: expected "
                        f"{records.DONE_RECEIPT_PREDICATE}")
    subjects = value["subject"]
    if not isinstance(subjects, list) or not subjects:
        raise CaseError("receipt.subject: expected a nonempty list")
    for index, item in enumerate(subjects):
        subject = _object(item, f"receipt.subject[{index}]", {"name", "digest"})
        _string(subject["name"], f"receipt.subject[{index}].name")
        digest = _object(subject["digest"], f"receipt.subject[{index}].digest", {"sha256"})
        _digest(digest["sha256"], f"receipt.subject[{index}].digest.sha256")
    raw = value["predicate"]
    if not isinstance(raw, dict) or not isinstance(raw.get("verifier"), dict) or (
            "id" not in raw["verifier"]):
        raise CaseError("receipt.predicate.verifier.id: required")
    predicate = _object(raw, "receipt.predicate",
                        {"schema_version", "claim_id", "invocation_id", "records", "checks",
                         "verdict", "verifier"},
                        {"external_effects", "policy", "stop_decision", "verifier_isolation"})
    if predicate["schema_version"] != "probity-done-receipt/v1":
        raise CaseError("unsupported receipt schema_version")
    _string(predicate["claim_id"], "receipt.predicate.claim_id")
    _string(predicate["invocation_id"], "receipt.predicate.invocation_id")
    verifier = _object(predicate["verifier"], "receipt.predicate.verifier", {"id"}, {"version"})
    if not isinstance(verifier["id"], str) or not URI.fullmatch(verifier["id"]):
        raise CaseError("receipt.predicate.verifier.id: expected a URI")
    named = _object(predicate["records"], "receipt.predicate.records", set(RECORD_ROLES),
                    {"launch", "launch_receipt"})
    for role, entry in named.items():
        _digest(_object(entry, f"receipt.predicate.records.{role}", {"sha256"})["sha256"],
                f"receipt.predicate.records.{role}.sha256")
    verdict = _object(predicate["verdict"], "receipt.predicate.verdict",
                      {"decision", "reason", "vantage"}, {"witness_scope"})
    if verdict["decision"] not in ("supported", "contradicted", "not_established"):
        raise CaseError("receipt.predicate.verdict.decision: unsupported value")
    _string(verdict["reason"], "receipt.predicate.verdict.reason")
    if not isinstance(predicate["checks"], list):
        raise CaseError("receipt.predicate.checks: expected list")
    return value


def _sub_policy(policy: dict, case_id: str, assessment: dict, adapter, roles,
                observed: bool) -> dict:
    sub = {"claim_type": adapter.CLAIM_TYPE, "invocation_id": assessment["invocation_id"],
           "observed_party": assessment["observed_party"]}
    if observed:
        sub["scope"] = assessment["scope"]
    sub.update({f"{role}_witness": assessment[f"{role}_witness"] for role in roles})
    if adapter is acceptance_observed and "allow_no_heldout" in assessment:
        sub["allow_no_heldout"] = assessment["allow_no_heldout"]
    return {"schema_version": "probity-policy/v1", "witnesses": policy["witnesses"],
            "assessments": {case_id: sub}}


def combine(found: list[dict]) -> dict:
    """The done verdict from the three check results, in check order."""
    for entry in found:
        if entry["decision"] == "contradicted":
            return {"decision": "contradicted", "reason": entry["reason"],
                    "witness_scope": entry.get("witness_scope", PEER)}
    if all(entry["decision"] == "supported" for entry in found):
        external = all(entry.get("witness_scope") == EXTERNAL for entry in found)
        return {"decision": "supported", "reason": "done_checks_supported",
                "witness_scope": EXTERNAL if external else PEER}
    first = next(entry for entry in found if entry["decision"] == "not_established")
    return {"decision": "not_established", "reason": first["reason"]}


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    case_id, assessment = records.start(case, policy, CLAIM_TYPE, FIELDS, OPTIONAL)
    invocation = _string(assessment["invocation_id"], "invocation_id")
    scope = _scope(assessment["scope"], "assessment.scope")
    observed_party = _string(assessment["observed_party"], "observed_party")
    accepted = assessment.get("verifier_ids")
    if accepted is not None and (not isinstance(accepted, list) or not accepted or any(
            not isinstance(item, str) or not URI.fullmatch(item) for item in accepted)):
        raise CaseError("verifier_ids: expected a nonempty list of URIs")
    roles = {"receipt": False, **{role: OBSERVED.get(role, False) for role in RECORD_ROLES}}
    bound = records.witnesses(case, policy, assessment, artifact_root, roles)
    result = {
        "schema_version": "probity-decision/v1", "case_id": case_id, "claim_type": CLAIM_TYPE,
        "scope": {"invocation_id": invocation, "interval": scope,
                  "observed_party": observed_party,
                  "witnesses": {role: pin for role, (_, pin) in bound.items()},
                  "limit": LIMIT},
        "checks": [], "vantage": "unestablished",
    }
    checks = result["checks"]

    def decide(decision: str, reason: str, witness_scope: str | None = None) -> dict:
        if decision != "not_established":
            result.update(vantage="independent", witness_scope=witness_scope or PEER)
        return {**result, "decision": decision, "reason": reason}

    receipt_bytes, _ = bound["receipt"]
    if receipt_bytes is None:
        return decide("not_established", "receipt_unavailable_or_unbound")
    receipt = statement(receipt_bytes)
    predicate = receipt["predicate"]
    result["verifier_id"] = predicate["verifier"]["id"]
    if predicate["claim_id"] != case_id or predicate["invocation_id"] != invocation:
        return decide("not_established", "receipt_context_mismatch")
    pinned = accepted is None or result["verifier_id"] in accepted
    checks.append({"id": "verifier", "status": "met" if pinned else "unavailable",
                   "verifier_id": result["verifier_id"]})
    if not pinned:
        return decide("not_established", "verifier_unpinned")
    unbound = sorted(role for role in RECORD_ROLES
                     if predicate["records"][role]["sha256"]
                     != bound[role][1]["consumer_pinned_sha256"])
    checks.append({"id": "receipt_records", "status": "unavailable" if unbound else "met",
                   "unbound_roles": unbound})
    if unbound:
        return decide("not_established", "receipt_records_mismatch")
    tree_bytes, _ = bound["tree"]
    if tree_bytes is not None:
        tree = records.tree(tree_bytes)
        named = any(item["digest"]["sha256"] == tree["tree_sha256"]
                    for item in receipt["subject"])
        checks.append({"id": "receipt_subject", "status": "met" if named else "unavailable"})
        if not named:
            return decide("not_established", "receipt_subject_mismatch")
    found = []
    for adapter, check_roles, observed in CHECKS:
        sub = _sub_policy(policy, case_id, assessment, adapter, check_roles, observed)
        decision = adapter.adjudicate(case, sub, artifact_root)
        found.append({key: decision[key] for key in ("claim_type", "decision", "reason")
                      if key in decision} | ({"witness_scope": decision["witness_scope"]}
                                             if "witness_scope" in decision else {}))
    derived = combine(found)
    reported = predicate["verdict"]
    agrees = (reported["decision"], reported["reason"]) == (derived["decision"],
                                                             derived["reason"])
    checks.append({"id": "derived_verdict", "status": "met" if agrees else "failed",
                   "checks": found, "derived": derived,
                   "reported": {"decision": reported["decision"],
                                "reason": reported["reason"]}})
    if not agrees:
        return decide("contradicted", "receipt_verdict_mismatch")
    return decide(derived["decision"], derived["reason"], derived.get("witness_scope"))


def encode_statement(predicate: dict, tree_sha256: str) -> bytes:
    """Statement bytes for tests and examples; producers sign their own encoding."""
    value = {"_type": records.STATEMENT_TYPE,
             "subject": [{"name": "workspace-tree", "digest": {"sha256": tree_sha256}}],
             "predicateType": records.DONE_RECEIPT_PREDICATE, "predicate": predicate}
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
