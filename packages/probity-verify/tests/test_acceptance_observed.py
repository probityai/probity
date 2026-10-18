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
            {"id": "unit", "exit": 0}, {"id": "heldout-unit", "exit": 0}]


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


def run_with(tmp_path, records, **assessment):
    files, case, policy = build(records, CLAIM)
    policy["assessments"]["case-1"].update(assessment)
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    return adjudicate(case, policy, tmp_path)


class TestHeldOut:
    def test_a_failure_only_on_held_out_commands(self, tmp_path, records):
        records["grade"]["results"][1]["exit"] = 1
        assert outcome(run(tmp_path, records)) == ("contradicted", "heldout_failed")

    def test_a_visible_failure_is_not_a_held_out_one(self, tmp_path, records):
        for result in records["grade"]["results"]:
            result["exit"] = 1
        assert run(tmp_path, records)["reason"] == "acceptance_failed_in_verifier"

    def test_no_sealed_split_cannot_support(self, tmp_path, records):
        del records["contract"]["heldout_split_sha256"]
        result = run(tmp_path, records)
        assert outcome(result) == ("not_established", "heldout_unavailable")
        assert run_with(tmp_path, records, allow_no_heldout=True)["decision"] == "supported"

    def test_a_split_digest_without_a_held_out_command(self, tmp_path, records):
        records["contract"]["acceptance"].pop()
        records["grade"]["results"].pop()
        assert run(tmp_path, records)["reason"] == "heldout_unavailable"

    def test_the_allowance_must_be_a_boolean(self, tmp_path, records):
        with pytest.raises(CaseError, match="allow_no_heldout"):
            run_with(tmp_path, records, allow_no_heldout="yes")


class TestGradeCounts:
    def test_a_replay_that_never_called_the_candidate(self, tmp_path, records):
        records["grade"]["results"][0]["replay"] = {"calls_intercepted": 0,
                                                    "distinct_calls": 0}
        result = run(tmp_path, records)
        assert outcome(result) == ("not_established", "no_calls_intercepted")
        assert next(c for c in result["checks"]
                    if c["id"] == "calls_intercepted")["silent_ids"] == ["unit"]

    def test_a_replay_with_calls_supports(self, tmp_path, records):
        records["grade"]["results"][0]["replay"] = {"calls_intercepted": 6,
                                                    "distinct_calls": 3}
        assert run(tmp_path, records)["decision"] == "supported"

    def test_a_patched_hunk_no_mutant_of_which_dies(self, tmp_path, records):
        records["grade"]["hunks"] = [
            {"path": "src/app.py", "lines": [1, 1], "mutants": 3, "killed": 2},
            {"path": "src/app.py", "lines": [4, 9], "mutants": 2, "killed": 0},
            {"path": "src/util.py", "lines": [2, 2], "mutants": 0, "killed": 0}]
        result = run(tmp_path, records)
        assert outcome(result) == ("not_established", "patch_not_exercised")
        assert next(c for c in result["checks"]
                    if c["id"] == "patch_exercised")["unexercised"] == [
            {"path": "src/app.py", "lines": [4, 9]}]

    def test_sealed_ids_must_all_be_collected(self, tmp_path, records):
        records["contract"]["acceptance"][0]["ids"] = ["tests/test_app.py::test_app",
                                                       "tests/test_app.py::test_b"]
        records["grade"]["results"][0]["collected"] = 1
        assert run(tmp_path, records)["reason"] == "acceptance_collection_mismatch"
        records["grade"]["results"][0]["collected"] = 2
        assert run(tmp_path, records)["decision"] == "supported"

    def test_sealed_ids_with_no_count_cannot_support(self, tmp_path, records):
        records["contract"]["acceptance"][0]["ids"] = ["tests/test_app.py::test_app"]
        assert run(tmp_path, records)["reason"] == "acceptance_collection_mismatch"


class TestContractV1Members:
    def test_class_counts_and_kill_vector_digest_are_read(self, tmp_path, records):
        records["contract"]["adequacy"].update(
            by_class={"operator": {"mutants": 3, "killed": 3},
                      "any-eq": {"mutants": 1, "killed": 0}},
            kill_vector_sha256=sha("[true,true,true,false]"))
        records["contract"]["acceptance"][0]["run_writes"] = [".pytest_cache/v"]
        result = run(tmp_path, records)
        assert result["decision"] == "supported"
        adequacy = next(c for c in result["checks"] if c["id"] == "contract_adequacy")
        assert adequacy["by_class"]["any-eq"] == {"mutants": 1, "killed": 0}

    @pytest.mark.parametrize("change,message", [
        (lambda c: c["adequacy"].update(by_class={"operator": {"mutants": 3, "killed": 3}}),
         "sum to the totals"),
        (lambda c: c["adequacy"].update(by_class={"x": {"mutants": 1, "killed": 2}}),
         "more mutants killed"),
        (lambda c: c["adequacy"].update(kill_vector_sha256="x"), "kill_vector_sha256"),
        (lambda c: c["acceptance"][0].update(run_writes=["/abs"]), "run_writes"),
        (lambda c: c["acceptance"][0].update(run_writes=["a", "a"]), "distinct"),
        (lambda c: c["acceptance"][0].update(ids=[]), "ids"),
    ])
    def test_malformed_contract_members(self, tmp_path, records, change, message):
        change(records["contract"])
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)

    @pytest.mark.parametrize("change,message", [
        (lambda g: g["results"][0].update(replay={"calls_intercepted": 1,
                                                  "distinct_calls": 2}), "distinct calls"),
        (lambda g: g["results"][0].update(collected=-1), "collected"),
        (lambda g: g.update(hunks=[{"path": "a.py", "lines": [3, 2], "mutants": 1,
                                    "killed": 0}]), "lines"),
        (lambda g: g.update(hunks=[{"path": "a.py", "lines": [1, 2], "mutants": 1,
                                    "killed": 2}]), "more mutants killed"),
    ])
    def test_malformed_grade_members(self, tmp_path, records, change, message):
        change(records["grade"])
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)


class TestTreeV2Digest:
    def test_an_execute_bit_is_in_the_digest(self, tmp_path, records):
        records["tree"]["executable"] = ["src/app.py"]
        with pytest.raises(CaseError, match="does not match"):
            run(tmp_path, records)

    def test_a_symlink_target_is_in_the_digest(self, tmp_path, records):
        from done_run import retree
        records["tree"]["symlinks"]["docs"] = "v1"
        retree(records["tree"])
        records["tree"]["symlinks"]["docs"] = "v2"
        with pytest.raises(CaseError, match="does not match"):
            run(tmp_path, records)

    def test_a_special_file_kind_is_in_the_digest(self, tmp_path, records):
        from done_run import retree
        records["tree"]["special"]["run/sock"] = "socket"
        retree(records["tree"])
        records["tree"]["special"]["run/sock"] = "fifo"
        with pytest.raises(CaseError, match="does not match"):
            run(tmp_path, records)

    @pytest.mark.parametrize("change,message", [
        (lambda t: t["symlinks"].update({"src/app.py": "x"}), "two kinds"),
        (lambda t: t["files"].update({"src/app.py/x": "0" * 64}), "under another"),
        (lambda t: t.update(executable=["missing"]), "executable"),
        (lambda t: t["special"].update({"dev": "door"}), "special"),
    ])
    def test_malformed_tree_entries(self, tmp_path, records, change, message):
        change(records["tree"])
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)


class TestProbeTimedOut:
    """A held-out probe the verifier stopped at its limit gave no answer to judge (review 4,
    R4-13): the grade says so with ``timed_out``, and that is not a wrong answer."""

    def second_probe(self, records):
        records["contract"]["acceptance"].append(
            {"id": "heldout-determinism", "argv": ["python", "-m", "pytest", "-q",
                                                   "/heldout", "-k", "again"]})
        records["grade"]["results"].append(
            {"id": "heldout-determinism", "argv": records["contract"]["acceptance"][2]["argv"],
             "exit": 0})

    def test_a_probe_that_timed_out(self, tmp_path, records):
        records["grade"]["results"][1].update(exit=124, timed_out=True)
        assert outcome(run(tmp_path, records)) == ("not_established", "probe_timed_out")

    def test_the_exit_alone_is_not_a_timeout(self, tmp_path, records):
        records["grade"]["results"][1]["exit"] = 124
        assert outcome(run(tmp_path, records)) == ("contradicted", "heldout_failed")

    def test_a_wrong_answer_beside_a_timed_out_probe_stands(self, tmp_path, records):
        self.second_probe(records)
        records["grade"]["results"][1].update(exit=124, timed_out=True)
        records["grade"]["results"][2]["exit"] = 1
        assert outcome(run(tmp_path, records)) == ("contradicted", "heldout_failed")

    def test_a_visible_failure_beside_a_timed_out_probe_stands(self, tmp_path, records):
        records["grade"]["results"][0]["exit"] = 1
        records["grade"]["results"][1].update(exit=124, timed_out=True)
        assert outcome(run(tmp_path, records)) == ("contradicted",
                                                   "acceptance_failed_in_verifier")

    def test_a_visible_command_that_timed_out_failed(self, tmp_path, records):
        """The agent can run a visible command itself; one that outran its limit failed."""
        records["grade"]["results"][0].update(exit=124, timed_out=True)
        assert outcome(run(tmp_path, records)) == ("contradicted",
                                                   "acceptance_failed_in_verifier")

    @pytest.mark.parametrize("change,message", [
        (lambda g: g["results"][1].update(exit=124, timed_out="yes"), "timed_out"),
        (lambda g: g["results"][1].update(exit=124, timed_out=False), "timed_out"),
        (lambda g: g["results"][1].update(timed_out=True), "timed_out"),
    ])
    def test_malformed_timeouts_refuse(self, tmp_path, records, change, message):
        change(records["grade"])
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)
