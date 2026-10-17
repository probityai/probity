import copy
import hashlib
import json

import pytest

from probity_verify import CaseError, adjudicate


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.fixture
def claim(tmp_path):
    scope = {"id": "session-4", "start": "2026-09-01T00:00:00Z",
             "end": "2026-09-01T00:01:00Z"}
    manifest = {"schema_version": "probity-capabilities/v1", "claim_id": "case-1",
                "invocation_id": "call-7", "producer": "sink-1",
                "visible_event_types": ["write"]}
    observation = {"schema_version": "probity-observation/v1", "claim_id": "case-1",
                   "invocation_id": "call-7", "producer": "sink-1", "scope": scope,
                   "coverage": "complete", "events": []}
    case = {"schema_version": "probity-case/v1", "case_id": "case-1", "artifacts": {}}
    policy = {"schema_version": "probity-policy/v1", "witnesses": {},
              "assessments": {"case-1": {
                  "claim_type": "event_absence/v1", "event_type": "write",
                  "invocation_id": "call-7", "scope": scope,
                  "capability_witness": "capability", "observation_witness": "observation"}}}

    def put(role, value):
        data = encoded(value)
        (tmp_path / f"{role}.json").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        case["artifacts"][role] = {"path": f"{role}.json", "sha256": digest,
                                   "length": len(data)}
        policy["witnesses"][role] = {"artifact": role, "sha256": digest,
                                     "authority": f"consumer-pinned {role}"}

    put("capability", manifest)
    put("observation", observation)
    return tmp_path, case, policy, manifest, observation, put


def evaluate(claim):
    root, case, policy, *_ = claim
    return adjudicate(case, policy, root)


def incomplete(claim):
    claim[4]["coverage"] = "incomplete"
    claim[4]["gaps"] = [{"start": "2026-09-01T00:00:20Z",
                         "end": "2026-09-01T00:00:40Z"}]
    claim[5]("observation", claim[4])


def test_absence_requires_visibility_and_complete_coverage(claim):
    result = evaluate(claim)
    assert (result["decision"], result["reason"]) == (
        "supported", "absence_within_covered_scope")
    claim[3]["visible_event_types"] = []
    claim[5]("capability", claim[3])
    result = evaluate(claim)
    assert (result["decision"], result["reason"]) == (
        "not_established", "field_visibility_unestablished")
    assert result["checks"][0]["status"] == "unavailable"
    claim[3]["visible_event_types"] = ["write"]
    claim[5]("capability", claim[3])
    incomplete(claim)
    result = evaluate(claim)
    assert (result["decision"], result["reason"]) == (
        "not_established", "observation_coverage_unestablished")


def test_missing_and_empty_event_field_need_the_same_coverage(claim):
    claim[4].pop("events")
    claim[5]("observation", claim[4])
    result = evaluate(claim)
    assert result["decision"] == "supported"
    assert result["checks"][0]["field_present"] is False
    incomplete(claim)
    assert evaluate(claim)["reason"] == "observation_coverage_unestablished"


def test_observed_write_refutes_claim_despite_incomplete_coverage(claim):
    incomplete(claim)
    claim[4]["events"] = [{"id": "event-1", "type": "write",
                           "time": "2026-09-01T00:00:30Z"}]
    claim[5]("observation", claim[4])
    claim[0].joinpath("capability.json").unlink()
    result = evaluate(claim)
    assert (result["decision"], result["reason"]) == ("contradicted", "event_observed")
    assert result["checks"][0]["observed_ids"] == ["event-1"]


def test_write_from_other_invocation_does_not_refute_claim(claim):
    claim[4]["invocation_id"] = "other-call"
    claim[4]["events"] = [{"id": "event-1", "type": "write",
                           "time": "2026-09-01T00:00:30Z"}]
    claim[5]("observation", claim[4])
    assert evaluate(claim)["reason"] == "observation_context_mismatch"


def test_bad_capability_record_cannot_hide_behind_observed_event(claim):
    claim[3]["visible_event_types"] = ["write", "write"]
    claim[5]("capability", claim[3])
    claim[4]["events"] = [{"id": "event-1", "type": "write",
                           "time": "2026-09-01T00:00:30Z"}]
    claim[5]("observation", claim[4])
    with pytest.raises(CaseError, match="duplicate type"):
        evaluate(claim)


@pytest.mark.parametrize("role,field,value,reason", [
    ("observation", "invocation_id", "other-call", "observation_context_mismatch"),
    ("observation", "scope", {"id": "other-session", "start": "2026-09-01T00:00:00Z",
                              "end": "2026-09-01T00:01:00Z"}, "observation_context_mismatch"),
    ("capability", "claim_id", "other-case", "capability_context_mismatch"),
    ("capability", "producer", "other-sink", "capability_context_mismatch"),
])
def test_records_cannot_cross_claim_or_scope(claim, role, field, value, reason):
    record = claim[3] if role == "capability" else claim[4]
    record[field] = value
    claim[5](role, record)
    assert (evaluate(claim)["decision"], evaluate(claim)["reason"]) == (
        "not_established", reason)


def test_pinned_capability_cannot_be_replaced_by_case_bytes(claim):
    claim[3]["visible_event_types"] = []
    data = encoded(claim[3])
    claim[0].joinpath("capability.json").write_bytes(data)
    claim[1]["artifacts"]["capability"].update(
        length=len(data), sha256=hashlib.sha256(data).hexdigest())
    assert evaluate(claim)["reason"] == "capability_unavailable_or_unbound"


@pytest.mark.parametrize("change", [
    lambda record: record.update(coverage=[]),
    lambda record: record.update(events=[{"id": "e", "type": "write",
                                          "time": "2026-09-01T00:02:00Z"}]),
    lambda record: record.update(events=[{"id": "e", "type": "read",
                                          "time": "2026-09-01T00:00:30Z"}] * 2),
])
def test_malformed_record_has_no_verdict(claim, change):
    change(claim[4])
    claim[5]("observation", claim[4])
    with pytest.raises(CaseError):
        evaluate(claim)


def test_unsupported_claim_type_is_not_a_property_verdict(claim):
    policy = copy.deepcopy(claim[2])
    policy["assessments"]["case-1"]["claim_type"] = "event_absence/v3"
    with pytest.raises(CaseError, match="unsupported claim_type"):
        adjudicate(claim[1], policy, claim[0])


def test_unknown_coverage_is_unestablished(claim):
    claim[4]["coverage"] = "unknown"
    claim[5]("observation", claim[4])
    assert evaluate(claim)["reason"] == "observation_coverage_unestablished"


@pytest.mark.parametrize("change", [
    lambda record: record.update(coverage="incomplete"),
    lambda record: record.update(coverage="incomplete", gaps=[]),
    lambda record: record.update(coverage="incomplete", gaps=[
        {"start": "2026-09-01T00:01:00Z", "end": "2026-09-01T00:02:00Z"}]),
    lambda record: record.update(coverage="complete", gaps=[
        {"start": "2026-09-01T00:00:20Z", "end": "2026-09-01T00:00:40Z"}]),
])
def test_malformed_coverage_has_no_verdict(claim, change):
    change(claim[4])
    claim[5]("observation", claim[4])
    with pytest.raises(CaseError):
        evaluate(claim)
