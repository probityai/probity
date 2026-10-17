"""tool_claim_match/v1: each claimed run matches an observed exec after the last edit."""

import pytest

from done_run import PYTEST, build, decide, honest_records
from probity_verify import CaseError, adjudicate

CLAIM = "tool_claim_match/v1"


@pytest.fixture
def records():
    return honest_records()


def run(tmp_path, records):
    return decide(tmp_path, records, CLAIM)


def outcome(result):
    return result["decision"], result["reason"]


def add_event(records, **event):
    events = records["observation"]["events"]
    step = events[-1]["step"] + 1
    events.append({"id": f"e{step}", "time": "2026-10-17T00:03:00Z", "step": step, **event})
    return f"e{step}"


def claim_status(result):
    return [item["status"] for item in
            next(c for c in result["checks"] if c["id"] == "tool_claims")["claims"]]


class TestSupported:
    def test_claimed_run_follows_the_last_edit(self, tmp_path, records):
        result = run(tmp_path, records)
        assert outcome(result) == ("supported", "tool_claims_matched")
        assert (result["vantage"], result["witness_scope"]) == ("independent", "PEER")
        claims = next(c for c in result["checks"] if c["id"] == "tool_claims")["claims"]
        assert claims == [{"id": "c1", "status": "matched", "exec_ids": ["x1"],
                           "last_edit_step": 1}]

    def test_a_rerun_after_the_edit_matches(self, tmp_path, records):
        add_event(records, type="write", path="src/app.py")
        add_event(records, type="exec", argv=PYTEST, exit=0)
        assert run(tmp_path, records)["decision"] == "supported"

    def test_a_claim_without_an_exit_matches_any_fresh_run(self, tmp_path, records):
        del records["claims"]["claims"][0]["exit"]
        records["observation"]["events"][1]["exit"] = 1
        assert run(tmp_path, records)["decision"] == "supported"

    def test_a_nested_exec_and_its_tree_writes(self, tmp_path, records):
        shell = add_event(records, type="exec", argv=["bash", "-c", "pytest -q"], exit=0)
        add_event(records, type="exec", argv=["pytest", "-q"], exit=0, origin=shell)
        add_event(records, type="write", path=".pytest_cache/v/lastfailed", origin=shell)
        records["claims"]["claims"] = [{"id": "c2", "argv": ["pytest", "-q"], "exit": 0}]
        assert run(tmp_path, records)["decision"] == "supported"

    def test_no_claims_is_vacuously_matched(self, tmp_path, records):
        records["claims"]["claims"] = []
        assert outcome(run(tmp_path, records)) == ("supported", "tool_claims_matched")


class TestContradicted:
    def test_a_run_nobody_executed(self, tmp_path, records):
        records["observation"]["events"] = records["observation"]["events"][:1]
        result = run(tmp_path, records)
        assert outcome(result) == ("contradicted", "tool_claim_unmatched")
        assert result["vantage"] == "independent"

    def test_a_spoofed_output_with_a_different_command(self, tmp_path, records):
        records["observation"]["events"][1]["argv"] = ["printf", "12 passed\n"]
        assert run(tmp_path, records)["reason"] == "tool_claim_unmatched"

    def test_an_edit_after_the_only_run(self, tmp_path, records):
        add_event(records, type="write", path="src/app.py")
        result = run(tmp_path, records)
        assert outcome(result) == ("contradicted", "tool_claim_precedes_last_edit")

    def test_another_commands_write_is_an_edit(self, tmp_path, records):
        sed = add_event(records, type="exec", argv=["sed", "-i", "s/1/2/", "src/app.py"],
                        exit=0)
        add_event(records, type="rename", path="src/sedX", target="src/app.py", origin=sed)
        assert run(tmp_path, records)["reason"] == "tool_claim_precedes_last_edit"

    def test_a_claimed_exit_the_run_did_not_have(self, tmp_path, records):
        records["observation"]["events"][1]["exit"] = 1
        assert outcome(run(tmp_path, records)) == ("contradicted",
                                                   "tool_claim_exit_mismatch")

    def test_any_false_claim_contradicts_the_set(self, tmp_path, records):
        records["claims"]["claims"].append({"id": "c2", "argv": ["make", "lint"]})
        result = run(tmp_path, records)
        assert result["reason"] == "tool_claim_unmatched"
        assert claim_status(result) == ["matched", "unmatched"]


class TestNotEstablished:
    def test_an_unseen_run_may_exist_under_incomplete_coverage(self, tmp_path, records):
        records["observation"]["events"] = records["observation"]["events"][:1]
        records["observation"]["coverage"] = "unknown"
        result = run(tmp_path, records)
        assert outcome(result) == ("not_established", "observation_coverage_unestablished")
        assert "witness_scope" not in result

    def test_matched_runs_still_need_complete_coverage(self, tmp_path, records):
        records["observation"]["coverage"] = "unknown"
        assert run(tmp_path, records)["reason"] == "observation_coverage_unestablished"

    @pytest.mark.parametrize("hidden", ["exec", "write", "rename"])
    def test_exec_and_every_mutation_type_must_be_visible(self, tmp_path, records, hidden):
        records["capability"]["visible_event_types"].remove(hidden)
        assert run(tmp_path, records)["reason"] == "field_visibility_unestablished"

    def test_a_run_whose_exit_was_not_seen(self, tmp_path, records):
        del records["observation"]["events"][1]["exit"]
        assert outcome(run(tmp_path, records)) == ("not_established",
                                                   "tool_exit_unobserved")

    def test_self_reported_observation(self, tmp_path, records):
        records["observation"]["vantage"] = "self_reported"
        assert run(tmp_path, records)["reason"] == "observation_vantage_unestablished"

    def test_claims_for_another_invocation(self, tmp_path, records):
        records["claims"]["invocation_id"] = "call-2"
        assert run(tmp_path, records)["reason"] == "claims_context_mismatch"

    def test_capability_from_another_producer(self, tmp_path, records):
        records["capability"]["producer"] = "someone-else"
        assert run(tmp_path, records)["reason"] == "capability_context_mismatch"

    def test_missing_observation_bytes(self, tmp_path, records):
        files, case, policy = build(records, CLAIM)
        for name, raw in files.items():
            if name != "observation.json":
                (tmp_path / name).write_bytes(raw)
        assert outcome(adjudicate(case, policy, tmp_path)) == (
            "not_established", "observation_unavailable_or_unbound")


class TestMalformed:
    @pytest.mark.parametrize("change,message", [
        (lambda r: r["claims"]["claims"].append(dict(r["claims"]["claims"][0])),
         "duplicate id"),
        (lambda r: r["claims"]["claims"][0].update(argv=[]), "nonempty list"),
        (lambda r: r["observation"]["events"][1].pop("argv"), "argv"),
        (lambda r: r["observation"]["events"][1].update(path="x"), "exec events carry"),
        (lambda r: r["observation"]["events"][0].update(exit=0), "only exec events"),
        (lambda r: r["observation"]["events"][0].update(target="x"), "only rename and link"),
    ])
    def test_malformed_records_refuse_without_a_verdict(self, tmp_path, records, change,
                                                        message):
        change(records)
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)

    def test_malformed_observation_refuses_even_without_claims(self, tmp_path, records):
        records["observation"]["events"][1]["step"] = 0
        files, case, policy = build(records, CLAIM)
        for name, raw in files.items():
            if name != "claims.json":
                (tmp_path / name).write_bytes(raw)
        with pytest.raises(CaseError, match="steps must increase"):
            adjudicate(case, policy, tmp_path)
