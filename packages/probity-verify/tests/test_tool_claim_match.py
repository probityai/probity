"""tool_claim_match/v1: each claimed run matches an observed exec after the last edit."""

import pytest

from done_run import PYTEST, build, decide, exec_event, honest_records
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
    events.append(exec_event({"id": f"e{step}", "time": "2026-10-17T00:03:00Z", "step": step,
                              **event}))
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


END = "2026-10-17T00:10:00Z"


def add_external(records, **entry):
    observation = records["observation"]
    steps = [item["step"] for item in observation["events"] + observation["external_mutations"]]
    step = max(steps) + 1
    observation["external_mutations"].append(
        {"id": f"o{step}", "step": step, "time": "2026-10-17T00:04:00Z", "type": "write",
         "location": "outside_workspace", **entry})


def set_run(records, **fields):
    records["observation"]["events"][1].update(fields)


def decide_with_contract(tmp_path, records):
    """Run with the done contract pinned as a fourth witness."""
    files, case, policy = build(records, CLAIM)
    raw = (__import__("done_run").encode)(records["contract"])
    digest = __import__("hashlib").sha256(raw).hexdigest()
    (tmp_path / "contract.json").write_bytes(raw)
    case["artifacts"]["contract"] = {"path": "contract.json", "length": len(raw),
                                     "sha256": digest}
    policy["witnesses"]["contract"] = {"artifact": "contract", "sha256": digest,
                                       "authority": "synthetic fixture"}
    policy["assessments"]["case-1"]["contract_witness"] = "contract"
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    return adjudicate(case, policy, tmp_path)


class TestOutsideMutations:
    def test_an_outside_write_after_the_run_is_an_edit(self, tmp_path, records):
        add_external(records, paths=["/usr/lib/python3/site-packages/app_patch.py"])
        assert run(tmp_path, records)["reason"] == "tool_claim_precedes_last_edit"

    def test_the_runs_own_outside_writes_are_not_edits(self, tmp_path, records):
        add_external(records, paths=["/tmp/pytest-of-agent/x"], origin="x1")
        assert run(tmp_path, records)["decision"] == "supported"


class TestShadowed:
    def test_an_executable_in_the_workspace(self, tmp_path, records):
        set_run(records, exe="/workspace/.venv/bin/python")
        result = run(tmp_path, records)
        assert outcome(result) == ("not_established", "tool_claim_shadowed")
        assert claim_status(result) == ["shadowed"]

    def test_an_executable_the_agent_wrote(self, tmp_path, records):
        set_run(records, exe="/opt/tools/python")
        records["observation"]["external_mutations"].append(
            {"id": "o0", "step": 0, "time": "2026-10-17T00:00:30Z", "type": "create",
             "paths": ["/opt/tools/python"], "location": "outside_workspace"})
        assert outcome(run(tmp_path, records)) == ("contradicted", "tool_claim_shadowed")

    def test_a_write_after_the_run_does_not_shadow_it(self, tmp_path, records):
        set_run(records, exe="/opt/tools/python")
        add_external(records, type="create", paths=["/opt/tools/python"], origin="x1")
        assert run(tmp_path, records)["decision"] == "supported"

    @pytest.mark.parametrize("key,value", [
        ("PYTHONPATH", "/workspace/src"), ("PATH", "/workspace/bin:/usr/bin"),
        ("PATH", ":/usr/bin"), ("LD_PRELOAD", "/workspace/hook.so"),
        ("LD_LIBRARY_PATH", "lib"), ("PYTHONSTARTUP", "/workspace/start.py"),
        ("PYTEST_ADDOPTS", "-p evil"), ("PYTEST_PLUGINS", "evil"),
        ("NODE_OPTIONS", "--require ./evil.js"),
    ])
    def test_a_loader_variable_that_reaches_agent_code(self, tmp_path, records, key, value):
        records["observation"]["events"][1]["env"][key] = value
        assert run(tmp_path, records)["reason"] == "tool_claim_shadowed"

    def test_a_preload_the_agent_wrote_outside(self, tmp_path, records):
        records["observation"]["events"][1]["env"]["LD_PRELOAD"] = "/tmp/hook.so"
        records["observation"]["external_mutations"].append(
            {"id": "o0", "step": 0, "time": "2026-10-17T00:00:30Z", "type": "write",
             "paths": ["/tmp/hook.so"], "location": "outside_workspace"})
        assert outcome(run(tmp_path, records)) == ("contradicted", "tool_claim_shadowed")

    def test_python_dash_m_without_a_safe_path(self, tmp_path, records):
        del records["observation"]["events"][1]["env"]["PYTHONSAFEPATH"]
        assert run(tmp_path, records)["reason"] == "tool_claim_shadowed"

    @pytest.mark.parametrize("argv", [
        ["python", "-P", "-m", "pytest", "-q", "tests"],
        ["python", "-Im", "pytest", "-q", "tests"],
    ])
    def test_python_flags_that_drop_the_working_directory(self, tmp_path, records, argv):
        del records["observation"]["events"][1]["env"]["PYTHONSAFEPATH"]
        set_run(records, argv=argv)
        records["claims"]["claims"][0]["argv"] = argv
        assert run(tmp_path, records)["decision"] == "supported"

    def test_safe_path_variable_is_ignored_under_dash_e(self, tmp_path, records):
        argv = ["python", "-E", "-m", "pytest", "-q", "tests"]
        set_run(records, argv=argv)
        records["claims"]["claims"][0]["argv"] = argv
        assert run(tmp_path, records)["reason"] == "tool_claim_shadowed"

    @pytest.mark.parametrize("argv", [["python", "-c", "import pytest"],
                                      ["python", "tests/run.py"], ["python", "-"]])
    def test_other_python_forms_put_a_workspace_directory_first(self, tmp_path, records,
                                                                argv):
        del records["observation"]["events"][1]["env"]["PYTHONSAFEPATH"]
        set_run(records, argv=argv)
        records["claims"]["claims"][0]["argv"] = argv
        assert run(tmp_path, records)["reason"] == "tool_claim_shadowed"

    def test_a_module_the_agent_wrote_shadows_for_certain(self, tmp_path, records):
        del records["observation"]["events"][1]["env"]["PYTHONSAFEPATH"]
        records["observation"]["events"][0]["path"] = "pytest.py"
        assert outcome(run(tmp_path, records)) == ("contradicted", "tool_claim_shadowed")

    def test_python_outside_the_workspace_is_not_shadowed(self, tmp_path, records):
        del records["observation"]["events"][1]["env"]["PYTHONSAFEPATH"]
        set_run(records, cwd="/srv/runner")
        assert run(tmp_path, records)["decision"] == "supported"

    def test_a_clear_run_beside_a_shadowed_one_matches(self, tmp_path, records):
        set_run(records, exe="/workspace/.venv/bin/python")
        add_event(records, type="exec", argv=PYTEST, exit=0)
        result = run(tmp_path, records)
        assert result["decision"] == "supported"
        assert next(c for c in result["checks"]
                    if c["id"] == "tool_claims")["claims"][0]["exec_ids"] == ["e4"]


class TestRunWrites:
    def same_shell(self, records, path):
        shell = add_event(records, type="exec",
                          argv=["sh", "-c", f"python -m pytest -q tests; echo x > {path}"],
                          exit=0)
        add_event(records, type="exec", argv=PYTEST, exit=0, origin=shell)
        add_event(records, type="write", path=path, origin=shell)

    def test_an_edit_inside_the_claimed_shell_call_is_caught(self, tmp_path, records):
        records["contract"]["acceptance"][0]["run_writes"] = [".pytest_cache"]
        self.same_shell(records, "src/app.py")
        assert run(tmp_path, records)["decision"] == "supported"
        assert decide_with_contract(tmp_path, records)["reason"] == (
            "tool_claim_precedes_last_edit")

    def test_sealed_run_writes_and_caches_are_the_runs_own(self, tmp_path, records):
        records["contract"]["acceptance"][0]["run_writes"] = ["coverage.xml"]
        self.same_shell(records, "coverage.xml")
        add_event(records, type="create", path="src/__pycache__/app.cpython-312.pyc",
                  origin="e4")
        assert decide_with_contract(tmp_path, records)["decision"] == "supported"

    def test_a_contract_without_run_writes_keeps_the_origin_rule(self, tmp_path, records):
        self.same_shell(records, "src/app.py")
        assert decide_with_contract(tmp_path, records)["decision"] == "supported"

    def test_a_pinned_contract_must_be_present(self, tmp_path, records):
        files, case, policy = build(records, CLAIM)
        case["artifacts"]["contract"] = {"path": "contract.json", "length": 2,
                                         "sha256": "0" * 64}
        policy["witnesses"]["contract"] = {"artifact": "contract", "sha256": "0" * 64,
                                           "authority": "synthetic fixture"}
        policy["assessments"]["case-1"]["contract_witness"] = "contract"
        for name, data in files.items():
            (tmp_path / name).write_bytes(data)
        assert adjudicate(case, policy, tmp_path)["reason"] == "contract_unavailable_or_unbound"


class TestAgentGaps:
    def test_an_agent_gap_contradicts_even_a_matched_record(self, tmp_path, records):
        records["observation"]["coverage"] = "incomplete"
        records["observation"]["gaps"] = [{"start": "2026-10-17T00:05:00Z", "end": END,
                                           "gap_cause": "agent"}]
        assert outcome(run(tmp_path, records)) == ("contradicted",
                                                   "tracer_terminated_prematurely")

    def test_a_host_gap_leaves_it_open(self, tmp_path, records):
        records["observation"]["coverage"] = "incomplete"
        records["observation"]["gaps"] = [{"start": "2026-10-17T00:05:00Z", "end": END,
                                           "gap_cause": "host"}]
        assert run(tmp_path, records)["reason"] == "observation_coverage_unestablished"


class TestObservationV3:
    @pytest.mark.parametrize("change,message", [
        (lambda o: o["events"][1].pop("exe"), "exe"),
        (lambda o: o["events"][1].update(cwd="relative"), "cwd"),
        (lambda o: o["events"][1]["env"].update(HOME="/root"), "env"),
        (lambda o: o.update(workspace_root="/workspace/../x"), "workspace_root"),
        (lambda o: o["external_mutations"].append(
            {"id": "o9", "step": 9, "time": "2026-10-17T00:04:00Z", "type": "write",
             "paths": ["/workspace/src/app.py"], "location": "outside_workspace"}),
         "names a workspace path"),
        (lambda o: o["external_mutations"].append(
            {"id": "o3", "step": 3, "time": "2026-10-17T00:04:00Z", "type": "write",
             "paths": ["/tmp/x"], "location": "outside_workspace"}), "unique"),
        (lambda o: o["external_mutations"].append(
            {"id": "o9", "step": 9, "time": "2026-10-17T00:04:00Z", "type": "read",
             "paths": ["/tmp/x"], "location": "outside_workspace"}), "type"),
        (lambda o: o["events"].append(
            {"id": "c9", "type": "connect", "time": "2026-10-17T00:04:00Z", "step": 9,
             "path": "x"}), "address"),
        (lambda o: o.update(coverage="incomplete", gaps=[
            {"start": "2026-10-17T00:05:00Z", "end": END}]), "gap_cause"),
    ])
    def test_malformed_v3_members_refuse(self, tmp_path, records, change, message):
        change(records["observation"])
        with pytest.raises(CaseError, match=message):
            run(tmp_path, records)

    def test_a_connect_event_with_an_address_is_read(self, tmp_path, records):
        add_event(records, type="connect", address="10.0.0.1:443")
        assert run(tmp_path, records)["decision"] == "supported"
