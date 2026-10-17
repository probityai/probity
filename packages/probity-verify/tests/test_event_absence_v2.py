import hashlib
import json
from pathlib import Path

import pytest

from probity_verify import CaseError, adjudicate


@pytest.fixture
def claim(tmp_path):
    scope = {"id": "run-1", "start": "2026-09-01T00:00:00Z",
             "end": "2026-09-01T00:01:00Z"}
    capability = {"schema_version": "probity-capabilities/v1", "claim_id": "case-1",
                  "invocation_id": "call-1", "producer": "host-broker",
                  "visible_event_types": ["write"]}
    observation = {"schema_version": "probity-observation/v1", "claim_id": "case-1",
                   "invocation_id": "call-1", "producer": "host-broker",
                   "vantage": "independent", "scope": scope, "coverage": "complete",
                   "events": []}
    case = {"schema_version": "probity-case/v1", "case_id": "case-1", "artifacts": {}}
    policy = {"schema_version": "probity-policy/v1", "witnesses": {},
              "assessments": {"case-1": {
                  "claim_type": "event_absence/v2", "event_type": "write",
                  "invocation_id": "call-1", "scope": scope,
                  "observed_party": "agent-1", "capability_witness": "capability",
                  "observation_witness": "observation"}}}

    def put(role, record):
        data = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (tmp_path / f"{role}.json").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        case["artifacts"][role] = {"path": f"{role}.json", "length": len(data),
                                   "sha256": digest}
        policy["witnesses"][role] = {"artifact": role, "sha256": digest,
                                     "authority": "consumer-pinned fixture"}
        if role == "observation":
            policy["witnesses"][role].update(
                producer=record["producer"], vantage=record["vantage"])

    put("capability", capability)
    put("observation", observation)
    return tmp_path, case, policy, capability, observation, put


def decide(claim):
    root, case, policy, *_ = claim
    return adjudicate(case, policy, root)


class TestPassingCases:
    @pytest.mark.parametrize("name,decision", [
        ("covered", "supported"),
        ("observed-write", "contradicted"),
        ("self-reported-write", "not_established"),
    ])
    def test_replayable_examples(self, name, decision):
        root = Path(__file__).resolve().parents[1] / "examples/event-absence-v2" / name
        case = json.loads((root / "case.json").read_text())
        policy = json.loads((root / "policy.json").read_text())
        assert adjudicate(case, policy, root)["decision"] == decision

    def test_empty_independent_record_with_complete_coverage(self, claim):
        result = decide(claim)
        assert (result["decision"], result["reason"]) == (
            "supported", "absence_within_covered_scope")
        assert result["checks"][0] == {"id": "observation_vantage", "status": "met"}
        assert next(c for c in result["checks"] if c["id"] == "event")["status"] == "met"

    def test_independent_write_refutes_even_with_a_gap(self, claim):
        observation = claim[4]
        observation["coverage"] = "incomplete"
        observation["gaps"] = [{"start": "2026-09-01T00:00:20Z",
                                "end": "2026-09-01T00:00:40Z"}]
        observation["events"] = [{"id": "write-1", "type": "write",
                                  "time": "2026-09-01T00:00:50Z"}]
        claim[5]("observation", observation)
        result = decide(claim)
        assert (result["decision"], result["reason"]) == (
            "contradicted", "event_observed")


class TestFailingCases:
    @pytest.mark.parametrize("has_write", [False, True])
    def test_self_report_cannot_settle_claim(self, claim, has_write):
        observation = claim[4]
        observation["producer"] = "agent-1"
        observation["vantage"] = "self_reported"
        if has_write:
            observation["events"] = [{"id": "write-1", "type": "write",
                                      "time": "2026-09-01T00:00:30Z"}]
        claim[3]["producer"] = "agent-1"
        claim[5]("capability", claim[3])
        claim[5]("observation", observation)
        result = decide(claim)
        assert (result["decision"], result["reason"]) == (
            "not_established", "observation_vantage_unestablished")

    def test_record_cannot_upgrade_consumer_pin(self, claim):
        claim[2]["witnesses"]["observation"]["vantage"] = "self_reported"
        assert decide(claim)["reason"] == "observation_vantage_unestablished"

    def test_observed_party_cannot_claim_independence(self, claim):
        claim[2]["assessments"]["case-1"]["observed_party"] = "host-broker"
        assert decide(claim)["reason"] == "observation_vantage_unestablished"

    def test_changed_producer_cannot_reuse_consumer_pin(self, claim):
        claim[2]["witnesses"]["observation"]["producer"] = "other-broker"
        assert decide(claim)["reason"] == "observation_vantage_unestablished"

    def test_missing_vantage_is_malformed(self, claim):
        claim[4].pop("vantage")
        data = (json.dumps(claim[4], sort_keys=True, separators=(",", ":")) + "\n").encode()
        claim[0].joinpath("observation.json").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        claim[1]["artifacts"]["observation"].update(length=len(data), sha256=digest)
        claim[2]["witnesses"]["observation"]["sha256"] = digest
        with pytest.raises(CaseError, match="observation: expected fields"):
            decide(claim)

    def test_missing_visibility_does_not_support_absence(self, claim):
        claim[3]["visible_event_types"] = []
        claim[5]("capability", claim[3])
        assert decide(claim)["reason"] == "field_visibility_unestablished"

    def test_malformed_capability_cannot_hide_behind_self_report(self, claim):
        claim[4]["vantage"] = "self_reported"
        claim[5]("observation", claim[4])
        claim[3]["visible_event_types"] = ["write", "write"]
        claim[5]("capability", claim[3])
        with pytest.raises(CaseError, match="duplicate type"):
            decide(claim)
