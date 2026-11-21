"""``evidence_sufficiency/v1``: what one signed Observed Effect record lets a verifier conclude.

``observed_effect/v1`` decides whether a record conforms. This adapter decides the next question, the
one section 7.4 of the CoSAI WS4 containment paper asks: given a conforming record, what may a
verifier say about the claim? The record is admitted through ``observed_effect.verify`` under the
consumer's pinned observer key, and the rules below read only the admitted predicate and the
consumer's own context.

Three properties, each with its own result axis:

- ``no_write_in_scope``: no write occurred under these paths during the one observed interval.
  ``supported`` is a pass, ``contradicted`` is a fail (an observed write inside the scope), and
  ``not_established`` names the unmet obligation.
- ``action_outcome``: the same evidence read as the invoked action's outcome. An observed write is
  ``present`` (``contradicted``), an established absence is ``absent`` (``supported``), and anything
  the evidence leaves open is ``pending`` (``not_established``), including after the window ends.
- ``observer_independence``: the three-condition independence test. The evidence for each condition
  is a premise the consumer supplies; this adapter checks that every condition names evidence the
  producer neither controls nor established, and never opens the evidence reference.

A record the admission step refuses as malformed, an unsupported property and a structurally invalid
assessment are processing failures: they raise ``CaseError`` and never become ``not_established``.
A record the admission step finds coherent but whose own rules refuse its claim (``invalid``) is not
a processing failure: the verification ran, and the property is ``not_established`` under the
obligation that refusal code names.

``supported`` here is a verdict given the consumer's stipulated context (the expected commitment,
the producer's write visibility, the independence evidence). The check echoes that context back so a
reader sees what the verdict rests on.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from ..common import CaseError, _digest, _string
from . import observed_effect
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "evidence_sufficiency/v1"
LIMIT = ("Decides what the admitted record lets a verifier conclude under the consumer's stipulated "
         "context. It does not establish who holds the observer key, that the expected commitment "
         "was witnessed before the invocation, that the producer's write visibility is true, or that "
         "an independence evidence reference says what its fields claim.")

NO_WRITE_IN_SCOPE = "no_write_in_scope"
ACTION_OUTCOME = "action_outcome"
OBSERVER_INDEPENDENCE = "observer_independence"
SUPPORTED_PROPERTIES = frozenset({NO_WRITE_IN_SCOPE, ACTION_OUTCOME, OBSERVER_INDEPENDENCE})

OBSERVATION_COVERAGE = "observation_coverage"
OBSERVATION_VANTAGE = "observation_vantage"
OBSERVATION_SCOPE = "observation_scope"
ADMISSIBLE_OBSERVATION = "admissible_observation"
INVOCATION_BINDING = "invocation_binding"
PRODUCER_CAPABILITY_COVERAGE = "producer_capability_coverage"

#: The independence test's three conditions, in the order the paper lists them; the first unmet one
#: is named.
INDEPENDENCE_CONDITIONS = (
    ("trust_domain", "observer_trust_domain"),
    ("identity_basis", "observer_identity_basis"),
    ("key_control", "observer_key_control"),
)
_EVIDENCE_FIELDS = ("controlled_by", "established_by", "evidence_ref")

#: The obligation a refused-but-coherent record leaves unmet, by the observed-effect refusal code.
INVALID_CODE_OBLIGATION = {
    "authoritative-vantage-not-independent": OBSERVATION_VANTAGE,
    "commitment-keyid-not-disjoint": OBSERVATION_VANTAGE,
    "commitment-not-prior": OBSERVATION_VANTAGE,
    "commitment-signature-invalid": OBSERVATION_VANTAGE,
    "authoritative-coverage-incomplete": OBSERVATION_COVERAGE,
    "authoritative-empty-path-scope": OBSERVATION_SCOPE,
    "authoritative-without-observed-rows": OBSERVATION_SCOPE,
}
_SETTLED_OUTCOME = {"fail": "present", "pass": "absent"}


def _not_established(obligation: str, reason: str) -> dict[str, Any]:
    return {"verdict": "not_established", "unmet_obligation": obligation, "reason": reason}


def _under(path: str, prefix: str) -> bool:
    return observed_effect._under(path, prefix)


def _overlaps(a: str, b: str) -> bool:
    return _under(a, b) or _under(b, a)


def _literal_path(value: Any) -> bool:
    return (observed_effect._path_normalized(value, allow_trailing_slash=True)
            and not observed_effect.GLOB_METACHARACTERS & set(value))


def _gap_outside(gap: Any, scope: list[str]) -> bool:
    """True only for a normalized literal path that overlaps no scope entry."""
    return _literal_path(gap) and not any(_overlaps(gap, s) for s in scope)


def _paths(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(p, str) and p.startswith("/") for p in value):
        raise CaseError(f"{label}: expected a list of absolute path prefixes")
    return value


def _property(value: Any) -> tuple[str, list[str]]:
    if not isinstance(value, dict) or set(value) - {"name", "scope", "statement"}:
        raise CaseError("assessment.property: expected an object with name, scope and optional statement")
    name = _string(value.get("name"), "assessment.property.name")
    scope = _paths(value.get("scope"), "assessment.property.scope")
    if not scope:
        raise CaseError("assessment.property.scope: expected at least one path prefix")
    return name, scope


def _capability(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"claim_ref", "visible_write_paths"}:
        raise CaseError("assessment.producer_capability: expected claim_ref and visible_write_paths")
    _string(value["claim_ref"], "assessment.producer_capability.claim_ref")
    _paths(value["visible_write_paths"], "assessment.producer_capability.visible_write_paths")
    return value


def _independence(assessment: dict) -> tuple[str, dict[str, dict[str, str]]]:
    producer = assessment.get("producer")
    if not isinstance(producer, str) or not producer:
        raise CaseError("observer_independence requires assessment.producer: independence holds "
                        "between one observer and one named producer")
    evidence = assessment.get("independence_evidence")
    if not isinstance(evidence, dict):
        raise CaseError("observer_independence requires assessment.independence_evidence as an "
                        "object; an absent condition is an empty entry, not an absent object")
    unknown = sorted(set(evidence) - {name for name, _ in INDEPENDENCE_CONDITIONS})
    if unknown:
        raise CaseError(f"unknown independence condition(s) {unknown}")
    for name, entry in evidence.items():
        if not isinstance(entry, dict):
            raise CaseError(f"independence_evidence.{name} must be an object")
        for key, item in entry.items():
            if key not in (*_EVIDENCE_FIELDS, "basis") or not isinstance(item, str):
                raise CaseError(f"independence_evidence.{name}.{key} is not a known string field")
    return producer, evidence


def _admit(raw: bytes, key: str) -> dict[str, Any]:
    """The predicate of an admitted record, or a ``refused`` not_established result."""
    report = observed_effect.verify(raw, observed_effect.Policy(observed_effect.PREDICATE_TYPE, key))
    if report.verdict == "malformed":
        raise CaseError("malformed_record: " + ",".join(report.codes))
    if report.verdict == "invalid":
        code = report.codes[0] if report.codes else ""
        return {"refused": _not_established(
            INVALID_CODE_OBLIGATION.get(code, ADMISSIBLE_OBSERVATION),
            f"the reference verifier refused the record ({code}); a refused record supports "
            "neither pass nor fail")}
    if report.verdict != "valid":
        raise CaseError(f"unexpected admission verdict {report.verdict!r}")
    return {"predicate": json.loads(base64.b64decode(json.loads(raw)["payload"]))["predicate"]}


def _independence_verdict(raw: bytes, key: str, claim_ref: str, producer: str,
                          evidence: dict[str, dict[str, str]]) -> dict[str, Any]:
    admitted = _admit(raw, key)
    if "refused" in admitted:
        return admitted["refused"]
    pred = admitted["predicate"]
    if pred["intervalId"] != claim_ref:
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the record covers interval {pred['intervalId']!r}, not the evaluated claim "
            f"{claim_ref!r}; independence is recorded per claim")
    vantage = pred["observation"]["vantage"]
    if vantage != "below-observed":
        return _not_established(
            OBSERVATION_VANTAGE,
            f"observation vantage is {vantage!r}; the record places the observer inside the "
            "producer's reach, which fails the first condition")
    for name, obligation in INDEPENDENCE_CONDITIONS:
        entry = evidence.get(name, {})
        missing = [f for f in _EVIDENCE_FIELDS if not entry.get(f, "").strip()]
        if missing:
            return _not_established(
                obligation, f"{name}: no evidence establishes this condition (missing {missing}); "
                "a declaration does not establish independence")
        held = [f for f in ("controlled_by", "established_by") if entry[f] == producer]
        if held:
            return _not_established(
                obligation, f"{name}: {held} is the producer {producer!r}; the producer cannot "
                "establish its own observer's independence")
    return {"verdict": "pass", "unmet_obligation": None,
            "reason": "each independence condition names evidence that the producer neither "
            "controls nor established; the verdict holds given that evidence, which this "
            "adapter takes as a stipulated premise and does not appraise"}


def _binding_gate(pred: dict, claim_ref: str, scope: list[str], expected_commitment: Any) -> dict | None:
    observation = pred["observation"]
    if pred["intervalId"] != claim_ref:
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the record covers interval {pred['intervalId']!r}, not the evaluated claim {claim_ref!r}")
    if not all(_literal_path(p) for p in scope):
        raise CaseError("candidate_input: property.scope must be normalized literal paths")
    witnessed = any(_under(w["path"], s) for w in pred["writes"] for s in scope)
    uncovered = ([] if witnessed
                 else [p for p in scope if not any(_under(p, s) for s in pred["pathScope"])])
    if uncovered:
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the property scope {uncovered} lies outside the observed pathScope {pred['pathScope']}")
    if observation["vantage"] != "below-observed":
        return _not_established(
            OBSERVATION_VANTAGE,
            f"observation vantage is {observation['vantage']!r}; only a vantage the observed party "
            "cannot address is independent evidence")
    prior = observation.get("priorCommitment")
    actual = prior.get("commitmentDigest") if isinstance(prior, dict) else None
    if not expected_commitment or actual != expected_commitment:
        return _not_established(
            INVOCATION_BINDING,
            "the record's prior commitment is not independently bound to the evaluated invocation")
    return None


def _coverage_gate(observation: dict, scope: list[str]) -> dict | None:
    coverage = observation["coverage"]
    if coverage.get("notEstablished"):
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the record states that coverage could not be determined: {coverage['notEstablished']}")
    if not isinstance(coverage["scopeComplete"], bool):
        raise CaseError("malformed_record: coverage-scope-complete-not-boolean")
    if coverage.get("unobservedIntervals"):
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the record names unobserved sub-interval(s): {coverage['unobservedIntervals']}")
    blind = [g for g in coverage["gaps"] if not _gap_outside(g, scope)]
    if blind:
        return _not_established(
            OBSERVATION_COVERAGE,
            f"the record names unobserved path(s) inside the property scope: {blind}")
    return None


def _capability_gate(capability: dict | None, claim_ref: str, scope: list[str]) -> dict | None:
    if capability is None:
        return _not_established(PRODUCER_CAPABILITY_COVERAGE,
                                "no write visibility was established for the evaluated invocation")
    if capability["claim_ref"] != claim_ref:
        return _not_established(PRODUCER_CAPABILITY_COVERAGE,
                                "write visibility was established for a different invocation")
    if any(not any(_under(p, v) for v in capability["visible_write_paths"]) for p in scope):
        return _not_established(PRODUCER_CAPABILITY_COVERAGE,
                                "write visibility does not cover the evaluated path scope")
    return None


def _absence_verdict(raw: bytes, key: str, claim_ref: str, scope: list[str],
                     expected_commitment: Any, capability: dict | None) -> dict[str, Any]:
    admitted = _admit(raw, key)
    if "refused" in admitted:
        return admitted["refused"]
    pred = admitted["predicate"]
    gate = _binding_gate(pred, claim_ref, scope, expected_commitment)
    if gate is not None:
        return gate
    witnesses = [w["path"] for w in pred["writes"] if any(_under(w["path"], s) for s in scope)]
    if witnesses:
        return {"verdict": "fail", "unmet_obligation": None,
                "reason": f"write(s) observed inside the property scope: {witnesses}"}
    gate = _coverage_gate(pred["observation"], scope) or _capability_gate(capability, claim_ref, scope)
    if gate is not None:
        return gate
    return {"verdict": "pass", "unmet_obligation": None,
            "reason": "no write observed inside the property scope, with write visibility and "
            "complete coverage for the interval from an independent vantage"}


def _action_outcome(verdict: dict[str, Any]) -> dict[str, Any]:
    if verdict["verdict"] == "not_established":
        return {"outcome": "pending", "unmet_obligation": verdict["unmet_obligation"],
                "reason": f"not verified by the end of the window: {verdict['reason']}"}
    return {"outcome": _SETTLED_OUTCOME[verdict["verdict"]], "unmet_obligation": None,
            "reason": verdict["reason"]}


def _evaluate(raw: bytes, assessment: dict, key: str) -> dict[str, Any]:
    name, scope = _property(assessment["property"])
    claim_ref = _string(assessment["claim_ref"], "assessment.claim_ref")
    expected = assessment.get("anchored_commitment_digest")
    if expected is not None:
        _digest(expected, "assessment.anchored_commitment_digest")
    capability = _capability(assessment.get("producer_capability"))
    if name not in SUPPORTED_PROPERTIES:
        raise CaseError(f"unsupported_property: {name!r} is not implemented by this adapter; "
                        "no verification of the property was performed")
    if name == OBSERVER_INDEPENDENCE:
        producer, evidence = _independence(assessment)
        return _independence_verdict(raw, key, claim_ref, producer, evidence)
    verdict = _absence_verdict(raw, key, claim_ref, scope, expected, capability)
    return verdict if name == NO_WRITE_IN_SCOPE else _action_outcome(verdict)


#: (verdict or outcome) -> the common decision
_DECISION = {"pass": "supported", "absent": "supported", "fail": "contradicted",
             "present": "contradicted", "not_established": "not_established",
             "pending": "not_established"}


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge one bound Observed Effect envelope against one property, under the consumer's context."""
    optional = {"anchored_commitment_digest", "producer_capability", "producer", "independence_evidence"}
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"envelope", "observer_public_key", "property", "claim_ref"}, optional)
    key = _digest(assessment["observer_public_key"], "assessment.observer_public_key")
    raw, binding = bound(artifacts, artifact_root, assessment["envelope"], "assessment.envelope")
    name, scope = _property(assessment["property"])
    scope_out = {"envelope": binding, "observer_public_key": key,
                 "property": {"name": name, "scope": list(scope)},
                 "claim_ref": assessment["claim_ref"],
                 "anchored_commitment_digest": assessment.get("anchored_commitment_digest"),
                 "producer_capability": assessment.get("producer_capability"),
                 "producer": assessment.get("producer"),
                 "independence_evidence": assessment.get("independence_evidence"),
                 "limit": LIMIT}
    if raw is None:
        return decision(case_id, CLAIM_TYPE, scope_out, "not_established", "envelope_unavailable")
    result = _evaluate(raw, assessment, key)
    axis = "outcome" if "outcome" in result else "verdict"
    value = result[axis]
    check = {"id": "evidence_sufficiency", "status": "pass" if _DECISION[value] == "supported" else "fail",
             axis: value, "unmet_obligation": result["unmet_obligation"], "reason": result["reason"]}
    reason = result["unmet_obligation"] or ("write_observed_in_scope" if _DECISION[value] == "contradicted"
                                            else "evidence_sufficient")
    return decision(case_id, CLAIM_TYPE, scope_out, _DECISION[value], reason, [check])
