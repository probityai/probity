"""acceptance_observed/v1: the verifier's grade, bound to the contract and the final tree."""

import hashlib

import pytest

from done_run import PYTEST, build, decide, honest_records, sha
from probity_verify import CaseError, adjudicate
from probity_verify.adapters.done_records import tree_digest

CLAIM = "acceptance_observed/v1"


@pytest.fixture
def records():
    return honest_records()


def run(tmp_path, records):
    return decide(tmp_path, records, CLAIM)


def outcome(result):
    return result["decision"], result["reason"]


class TestSupported:
    def test_passing_grade_on_the_final_tree(self, tmp_path, records):
        result = run(tmp_path, records)
        assert outcome(result) == ("supported", "acceptance_passed_in_verifier")
        assert (result["vantage"], result["witness_scope"]) == ("independent", "PEER")
        assert next(c for c in result["checks"] if c["id"] == "acceptance")["results"] == [
            {"id": "unit", "exit": 0}]

    def test_external_scope_needs_tree_and_grade(self, tmp_path, records):
        records["grade"]["witness_scope"] = "EXTERNAL"
        assert run(tmp_path, records)["witness_scope"] == "PEER"
        records["tree"]["witness_scope"] = "EXTERNAL"
        assert run(tmp_path, records)["witness_scope"] == "EXTERNAL"


class TestContradicted:
    def test_failing_acceptance_in_the_verifier(self, tmp_path, records):
        records["grade"]["results"][0]["exit"] = 1
        result = run(tmp_path, records)
        assert outcome(result) == ("contradicted", "acceptance_failed_in_verifier")
        assert result["vantage"] == "independent"

    def test_failure_contradicts_even_with_zero_adequacy(self, tmp_path, records):
        records["contract"]["adequacy"]["killed"] = 0
        records["grade"]["results"][0]["exit"] = 2
        assert run(tmp_path, records)["decision"] == "contradicted"

    def test_one_failing_command_among_several(self, tmp_path, records):
        lint = ["ruff", "check", "src"]
        records["contract"]["acceptance"].append({"id": "lint", "argv": lint})
        records["grade"]["results"].append({"id": "lint", "argv": lint, "exit": 1})
        assert run(tmp_path, records)["reason"] == "acceptance_failed_in_verifier"


class TestNotEstablished:
    def test_contract_that_kills_no_mutant_cannot_support(self, tmp_path, records):
        records["contract"]["adequacy"]["killed"] = 0
        result = run(tmp_path, records)
        assert outcome(result) == ("not_established", "contract_adequacy_zero")
        assert result["vantage"] == "unestablished" and "witness_scope" not in result

    def test_grade_on_another_tree(self, tmp_path, records):
        records["grade"]["tree_sha256"] = sha("another tree")
        assert run(tmp_path, records)["reason"] == "grade_tree_unbound"

    def test_grade_for_another_contract(self, tmp_path, records):
        records["grade"]["contract_sha256"] = sha("another contract")
        assert run(tmp_path, records)["reason"] == "grade_contract_mismatch"

    def test_grade_by_the_agent_cannot_settle(self, tmp_path, records):
        records["grade"]["producer"] = "agent-1"
        assert run(tmp_path, records)["reason"] == "grade_vantage_unestablished"

    def test_self_reported_grade_cannot_settle(self, tmp_path, records):
        records["grade"]["vantage"] = "self_reported"
        records["grade"]["results"][0]["exit"] = 1
        assert run(tmp_path, records)["reason"] == "grade_vantage_unestablished"

    def test_self_reported_tree_cannot_bind_the_grade(self, tmp_path, records):
        records["tree"]["vantage"] = "self_reported"
        assert run(tmp_path, records)["reason"] == "final_tree_unestablished"

    def test_grade_for_another_invocation(self, tmp_path, records):
        records["grade"]["invocation_id"] = "call-2"
        assert run(tmp_path, records)["reason"] == "grade_context_mismatch"

    @pytest.mark.parametrize("change,reason", [
        (lambda g: g["results"].clear(), "acceptance_result_missing"),
        (lambda g: g["results"][0].update(argv=["pytest"]), "acceptance_argv_mismatch"),
        (lambda g: g["results"].append({"id": "extra", "argv": PYTEST, "exit": 0}),
         "acceptance_result_unexpected"),
    ])
    def test_results_must_answer_the_contract_exactly(self, tmp_path, records, change,
                                                       reason):
        change(records["grade"])
        assert run(tmp_path, records)["reason"] == reason

    def test_missing_grade_bytes(self, tmp_path, records):
        files, case, policy = build(records, CLAIM)
        for name, raw in files.items():
            if name != "grade.json":
                (tmp_path / name).write_bytes(raw)
        assert outcome(adjudicate(case, policy, tmp_path)) == (
            "not_established", "grade_unavailable_or_unbound")


class TestMalformed:
    @pytest.mark.parametrize("change,message", [
        (lambda r: r["grade"]["results"].append(dict(r["grade"]["results"][0])),
         "duplicate id"),
        (lambda r: r["grade"]["results"][0].update(exit=True), "exit status"),
        (lambda r: r["grade"].update(tree_sha256="ABC"), "lowercase SHA-256"),
        (lambda r: r["contract"]["adequacy"].update(killed=9), "more mutants killed"),
        (lambda r: r["contract"]["acceptance"].clear(), "nonempty list"),
        (lambda r: r["grade"].update(vantage="external"), "vantage"),
        (lambda r: r["tree"].update(tree_sha256=sha("unlisted")), "does not match"),
    ])
    def test_malformed_records_refuse_without_a_verdict(self, tmp_path, records, change,
                                                        message):
        change(records)
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)

    def test_malformed_grade_refuses_even_without_a_tree(self, tmp_path, records):
        records["grade"]["results"][0]["exit"] = "0"
        files, case, policy = build(records, CLAIM)
        for name, raw in files.items():
            if name != "tree.json":
                (tmp_path / name).write_bytes(raw)
        with pytest.raises(CaseError, match="exit status"):
            adjudicate(case, policy, tmp_path)


def test_tree_digest_is_the_sha256sum_listing():
    files = {"b": sha("b"), "a/c": sha("c")}
    listing = f"{files['a/c']}  a/c\n{files['b']}  b\n"
    assert tree_digest(files) == hashlib.sha256(listing.encode()).hexdigest()
