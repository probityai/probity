"""The decision line names vantage and witness scope, and a consumer can require EXTERNAL."""

import json
from pathlib import Path

import pytest
from done_run import decide, honest_records
from probity_verify import CaseError, adjudicate
from probity_verify.cli import main

ROOT = Path(__file__).resolve().parents[1] / "examples"
HONEST = ROOT / "done-receipt/honest"
SOURCE = ROOT / "source-coverage"


def argv(root, check, *extra):
    return [str(root / f"{check}.case.json"), "--policy", str(root / f"{check}.policy.json"),
            *extra]


def test_decision_line_names_vantage_and_witness_scope(capsys):
    assert main(argv(HONEST, "protected-paths")) == 0
    assert ("Decision: supported (vantage: independent, witness_scope: PEER)\n"
            in capsys.readouterr().out)


def test_unestablished_verdict_names_no_scope(capsys):
    assert main(argv(ROOT / "done-receipt/lost-events", "tool-claims")) == 0
    assert "Decision: not_established (vantage: unestablished)\n" in capsys.readouterr().out


def test_adapter_without_vantage_keeps_the_plain_line(capsys):
    assert main([str(SOURCE / "case.json"), "--policy", str(SOURCE / "policy-june.json")]) == 0
    assert "Decision: contradicted\n" in capsys.readouterr().out


def test_peer_receipt_is_held_under_an_external_requirement(capsys):
    assert main(argv(HONEST, "protected-paths", "--require-witness-scope", "EXTERNAL",
                     "--json")) == 0
    result = json.loads(capsys.readouterr().out)
    assert (result["decision"], result["reason"]) == ("not_established",
                                                      "witness_scope_below_required")
    assert result["required_witness_scope"] == "EXTERNAL"
    assert result["checks"][-1] == {
        "id": "witness_scope", "status": "unavailable", "required": "EXTERNAL",
        "observed": "PEER", "adapter_decision": "supported",
        "adapter_reason": "protected_paths_untouched"}


def test_external_receipt_meets_the_requirement(tmp_path):
    records = honest_records()
    for role in ("observation", "tree"):
        records[role]["witness_scope"] = "EXTERNAL"
    result = decide(tmp_path, records, "protected_paths/v1", require_witness_scope="EXTERNAL")
    assert (result["decision"], result["witness_scope"]) == ("supported", "EXTERNAL")


def test_contradiction_from_a_peer_witness_stands(tmp_path):
    records = honest_records()
    records["grade"]["results"][0]["exit"] = 1
    result = decide(tmp_path, records, "acceptance_observed/v1",
                    require_witness_scope="EXTERNAL")
    assert result["decision"] == "contradicted"
    assert result["reason"] != "witness_scope_below_required"
    assert result["required_witness_scope"] == "EXTERNAL"
    assert all(check["id"] != "witness_scope" for check in result["checks"])


def test_supported_from_a_peer_witness_is_held(tmp_path):
    result = decide(tmp_path, honest_records(), "protected_paths/v1",
                    require_witness_scope="EXTERNAL")
    assert result["decision"] == "not_established"
    assert result["reason"] == "witness_scope_below_required"
    assert result["checks"][-1]["adapter_decision"] == "supported"


def test_contradiction_from_an_adapter_stating_no_scope_stands(capsys):
    assert main([str(SOURCE / "case.json"), "--policy", str(SOURCE / "policy-june.json"),
                 "--require-witness-scope", "EXTERNAL", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "contradicted"


def test_adapter_that_states_no_scope_cannot_meet_external(capsys):
    assert main([str(SOURCE / "case-complete.json"), "--policy", str(SOURCE / "policy-complete.json"),
                 "--require-witness-scope", "EXTERNAL", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "not_established"
    assert result["checks"][-1]["observed"] == "unstated"


def test_not_established_is_unchanged_by_the_requirement(tmp_path):
    records = honest_records()
    records["observation"]["coverage"] = "unknown"
    result = decide(tmp_path, records, "tool_claim_match/v1",
                    require_witness_scope="EXTERNAL")
    assert result["reason"] == "observation_coverage_unestablished"
    assert result["required_witness_scope"] == "EXTERNAL"


def test_unknown_requirement_refuses(tmp_path):
    with pytest.raises(CaseError, match="PEER or EXTERNAL"):
        decide(tmp_path, honest_records(), "protected_paths/v1",
               require_witness_scope="GLOBAL")


def test_cli_rejects_an_unknown_requirement(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(argv(HONEST, "protected-paths", "--require-witness-scope", "GLOBAL"))
    assert exit_info.value.code == 2


def test_adapter_reporting_an_invalid_scope_refuses():
    case = json.loads((SOURCE / "case.json").read_text())
    policy = json.loads((SOURCE / "policy-june.json").read_text())
    policy["assessments"][case["case_id"]]["claim_type"] = "fixed/v1"

    def fixed(case, policy, root):
        return {"schema_version": "probity-decision/v1", "case_id": case["case_id"],
                "claim_type": "fixed/v1", "scope": {}, "checks": [],
                "decision": "supported", "reason": "fixed", "witness_scope": "GLOBAL"}

    with pytest.raises(CaseError, match="invalid decision envelope"):
        adjudicate(case, policy, SOURCE, adapters={"fixed/v1": fixed})
