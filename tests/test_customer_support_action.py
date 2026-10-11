"""A favorable report cannot authorize an unsupported customer commitment."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from probity_verify import adjudicate
from probity_verify.bundle import create_bundle, replay_bundle
from probity_verify.common import CaseError
from probity_verify.core import canonical_json

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/customer-support-action"
SPEC = importlib.util.spec_from_file_location("support_example_adapter", EXAMPLE / "adapter.py")
assert SPEC is not None and SPEC.loader is not None
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)
SELECTED = {ADAPTER.CLAIM_TYPE: ADAPTER.adjudicate}


def inputs(tmp_path, variant="routine"):
    shutil.copytree(EXAMPLE / "cases" / variant, tmp_path, dirs_exist_ok=True)
    case = json.loads((tmp_path / "case.json").read_bytes())
    policy = json.loads((tmp_path / "policy.json").read_bytes())
    return case, policy


def replace_artifact(root, case, policy, role, raw, *, select=True):
    metadata = case["artifacts"][role]
    data = raw if isinstance(raw, bytes) else canonical_json(raw)
    (root / metadata["path"]).write_bytes(data)
    metadata.update(sha256=hashlib.sha256(data).hexdigest(), length=len(data))
    if select:
        policy["assessments"][case["case_id"]]["bindings"][role] = metadata["sha256"]


def check(case, policy, root):
    return adjudicate(case, policy, root, adapters=SELECTED)


@pytest.mark.parametrize("variant,decision,action", [
    ("routine", "supported", "APPROVE"),
    ("green-over-limit", "contradicted", "BLOCK"),
    ("needs-manager", "not_established", "HOLD_FOR_REVIEW"),
    ("exact-manager", "supported", "APPROVE"),
])
def test_worked_outcomes(tmp_path, variant, decision, action):
    case, policy = inputs(tmp_path, variant)
    result = check(case, policy, tmp_path)
    assert (result["decision"], result["action"]) == (decision, action)
    assert result["scope"]["advisory_report"] == {
        "schema_version": "synthetic-quality-report/v1", "status": "GREEN", "score": 94,
    }
    assert result["scope"]["observed_effect"] == "not_established"
    assert {item["id"] for item in result["checks"]} == set(ADAPTER.REQUIRED_CHECKS)


@pytest.mark.parametrize("field,new,reason", [
    ("recipient", "other@example.test", "manager_approval_binding_mismatch"),
    ("action_id", "different-action", "manager_approval_binding_mismatch"),
    ("request_id", "different-request", "manager_approval_binding_mismatch"),
    ("plan", "Other", "manager_approval_binding_mismatch"),
    ("discount_bps", 1700, "manager_approval_binding_mismatch"),
    ("draft_sha256", "0" * 64, "manager_approval_binding_mismatch"),
    ("action_sha256", "0" * 64, "manager_approval_binding_mismatch"),
    ("expires_at", "2026-10-10T20:00:00Z", "manager_approval_outside_window"),
    ("not_before", "2026-10-10T20:00:01Z", "manager_approval_outside_window"),
])
def test_manager_grant_is_exact_and_time_bound(tmp_path, field, new, reason):
    case, policy = inputs(tmp_path, "exact-manager")
    grant = json.loads((tmp_path / "manager_approval.json").read_bytes())
    grant[field] = new
    replace_artifact(tmp_path, case, policy, "manager_approval", grant)
    result = check(case, policy, tmp_path)
    assert (result["decision"], result["reason"], result["action"]) == ("contradicted", reason, "BLOCK")
    assert result["scope"]["evidence_decision"] == "supported"
    assert result["scope"]["authorization"] == "contradicted"


@pytest.mark.parametrize("field,new", [("approver_id", "unselected-manager"), ("approval_id", "unselected-grant")])
def test_unselected_authority_holds(tmp_path, field, new):
    case, policy = inputs(tmp_path, "exact-manager")
    grant = json.loads((tmp_path / "manager_approval.json").read_bytes())
    grant[field] = new
    replace_artifact(tmp_path, case, policy, "manager_approval", grant)
    result = check(case, policy, tmp_path)
    assert result["action"] == "HOLD_FOR_REVIEW"
    assert result["reason"] == "approval_not_selected"


def test_selected_consumed_snapshot_blocks(tmp_path):
    case, policy = inputs(tmp_path, "exact-manager")
    replace_artifact(tmp_path, case, policy, "approval_uses", {"consumed_approval_ids": ["grant-42"]})
    assert check(case, policy, tmp_path)["reason"] == "manager_approval_already_consumed"


def test_policy_and_source_changes_stay_visible_when_outcome_agrees(tmp_path):
    case, policy = inputs(tmp_path)
    before = check(case, policy, tmp_path)
    customer = json.loads((tmp_path / "customer.json").read_bytes())
    customer["tenure_months"] = 19
    replace_artifact(tmp_path, case, policy, "customer", customer, select=False)
    assert check(case, policy, tmp_path)["reason"] == "consumer_binding_mismatch"
    policy["assessments"][case["case_id"]]["bindings"]["customer"] = case["artifacts"]["customer"]["sha256"]
    after = check(case, policy, tmp_path)
    assert before["decision"] == after["decision"] == "supported"
    assert before["policy_sha256"] != after["policy_sha256"]
    assert before["scope"]["artifacts"] != after["scope"]["artifacts"]


def test_missing_data_and_incomplete_policy_hold(tmp_path):
    case, policy = inputs(tmp_path)
    assessment = policy["assessments"][case["case_id"]]
    assessment["required_checks"].remove("discount")
    assert check(case, policy, tmp_path)["reason"] == "incomplete_check_coverage"
    (tmp_path / "customer.json").unlink()
    assert check(case, policy, tmp_path)["reason"] == "artifact_unavailable_or_unbound"


@pytest.mark.parametrize("raw", [
    b'{"schema_version":"support-discount-action/v1","action_id":"a","action_id":"b"}',
    b'{"schema_version":"support-discount-action/v1","action_id":"a","request_id":"r","recipient":"x","plan":"Pro","discount_bps":true}',
    b'{"schema_version":"support-discount-action/v1","action_id":"a","request_id":"r","recipient":"x","plan":"Pro","discount_bps":1250}',
    b'{"schema_version":"support-discount-action/v1","action_id":"\\ud800","request_id":"r","recipient":"x","plan":"Pro","discount_bps":1200}',
    b'{}', b'null', b'{',
])
def test_malformed_artifact_refuses_instead_of_becoming_a_verdict(tmp_path, raw):
    case, policy = inputs(tmp_path)
    replace_artifact(tmp_path, case, policy, "action", raw)
    # A separate absent input must not mask the malformed available input.
    (tmp_path / "customer.json").unlink()
    with pytest.raises(CaseError):
        check(case, policy, tmp_path)
    (tmp_path / "case.json").write_bytes(canonical_json(case))
    (tmp_path / "policy.json").write_bytes(canonical_json(policy))
    run = subprocess.run([sys.executable, str(EXAMPLE / "consumer.py"), str(tmp_path / "case.json"),
                          "--policy", str(tmp_path / "policy.json"), "--json"], capture_output=True)
    assert run.returncode == 2
    assert run.stdout == b""
    assert b"customer-support-action:" in run.stderr


def test_portable_manager_bundle_replays_without_the_company_files(tmp_path):
    root = tmp_path / "inputs"
    inputs(root, "exact-manager")
    output = tmp_path / "approval.zip"
    created = create_bundle(root / "case.json", root / "policy.json", output, adapters=SELECTED)
    shutil.rmtree(root)
    assert replay_bundle(output, adapters=SELECTED) == created
    with zipfile.ZipFile(output) as archive:
        assert archive.read("artifacts/manager_approval.json")
        assert archive.read("policy.json")


@pytest.mark.parametrize("score", [True, 10**400, 1e309])
def test_invalid_report_score_refuses_without_overflow(tmp_path, score):
    case, policy = inputs(tmp_path)
    replace_artifact(tmp_path, case, policy, "report", {
        "schema_version": "synthetic-quality-report/v1", "status": "GREEN", "score": score,
    })
    with pytest.raises(CaseError):
        check(case, policy, tmp_path)


def test_timestamp_digits_have_one_ascii_wire_grammar(tmp_path):
    case, policy = inputs(tmp_path, "exact-manager")
    policy["assessments"][case["case_id"]]["clock"] = "２０２６-10-10T20:00:00Z"
    with pytest.raises(CaseError, match="ASCII UTC timestamp"):
        check(case, policy, tmp_path)


def _example_module(filename):
    spec = importlib.util.spec_from_file_location(f"support_{filename}", EXAMPLE / f"{filename}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_rederives_exact_inputs_and_detects_drift(tmp_path, monkeypatch):
    generator = _example_module("generate")
    monkeypatch.setattr(generator, "__file__", str(tmp_path / "generate.py"))
    assert generator.main([]) == 0
    assert generator.main(["--check"]) == 0
    (tmp_path / "cases/routine/draft.txt").write_bytes(b"changed")
    with pytest.raises(SystemExit) as exc:
        generator.main(["--check"])
    assert exc.value.code == 1


def test_example_cli_create_replay_and_projection(tmp_path, monkeypatch, capsys):
    # Script imports use the same explicit adapter module as the production CLI.
    monkeypatch.setitem(sys.modules, "adapter", ADAPTER)
    consumer = _example_module("consumer")
    root = tmp_path / "inputs"
    inputs(root)
    argv = [str(root / "case.json"), "--policy", str(root / "policy.json")]
    assert consumer.main(argv) == 0
    assert "Action permission: APPROVE" in capsys.readouterr().out
    output = tmp_path / "decision.zip"
    assert consumer.main(argv + ["--bundle", str(output), "--json"]) == 0
    projection = json.loads(capsys.readouterr().out)
    assert projection["action"] == "APPROVE"
    shutil.rmtree(root)
    assert consumer.main(["--replay", str(output), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == projection
    assert consumer.main(["--replay", str(tmp_path / "missing.zip")]) == 2
    assert capsys.readouterr().out == ""
    for invalid in ([], ["--replay", str(output), "--bundle", str(output)]):
        with pytest.raises(SystemExit) as exc:
            consumer.main(invalid)
        assert exc.value.code == 2


@pytest.mark.parametrize("bundle", [False, True])
def test_cli_cannot_bypass_control_budget_during_bundle_creation(tmp_path, monkeypatch, capsys, bundle):
    monkeypatch.setitem(sys.modules, "adapter", ADAPTER)
    consumer = _example_module("consumer")
    inputs(tmp_path)
    path = tmp_path / "case.json"
    path.write_bytes(path.read_bytes() + b" " * (1024 * 1024))
    argv = [str(path), "--policy", str(tmp_path / "policy.json"), "--json"]
    output = tmp_path / "decision.zip"
    if bundle:
        argv += ["--bundle", str(output)]
    assert consumer.main(argv) == 2
    assert capsys.readouterr().out == ""
    assert not output.exists()
