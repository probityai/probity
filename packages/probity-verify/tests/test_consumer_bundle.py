"""Explicit code selection must survive creation and portable replay."""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from probity_verify.bundle import create_bundle, replay_bundle
from probity_verify.common import CaseError

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/source-coverage"
CLAIM = "selected_example/v1"


def _adapter(case, policy, root):
    from probity_verify.adapters.source_coverage import adjudicate
    original = policy["assessments"][case["case_id"]]["claim_type"]
    # The delegated built-in receives its own policy; the caller's selection stays intact.
    delegated = json.loads(json.dumps(policy))
    delegated["assessments"][case["case_id"]]["claim_type"] = "source_text_coverage/v1"
    result = adjudicate(case, delegated, root)
    result["claim_type"] = original
    return result


def _inputs(tmp_path):
    root = tmp_path / "inputs"
    root.mkdir()
    for name in ("case.json", "source.html", "report.txt"):
        shutil.copyfile(EXAMPLE / name, root / name)
    policy = json.loads((EXAMPLE / "policy-june.json").read_bytes())
    policy["assessments"]["source-coverage-demo"]["claim_type"] = CLAIM
    (root / "policy.json").write_text(json.dumps(policy))
    return root


def test_bundle_replays_without_original_sources(tmp_path):
    root = _inputs(tmp_path)
    first, second = tmp_path / "first.zip", tmp_path / "second.zip"
    adapters = {CLAIM: _adapter}
    decision = create_bundle(root / "case.json", root / "policy.json", first, adapters=adapters)
    create_bundle(root / "case.json", root / "policy.json", second, adapters=adapters)
    assert first.read_bytes() == second.read_bytes()
    shutil.rmtree(root)
    assert replay_bundle(first, adapters=adapters) == decision
    with pytest.raises(CaseError, match="unsupported claim_type"):
        replay_bundle(first)
    assert decision["decision"] == "contradicted"


def test_bundle_replay_refuses_changed_selected_code(tmp_path):
    root = _inputs(tmp_path)
    output = tmp_path / "decision.zip"
    create_bundle(root / "case.json", root / "policy.json", output, adapters={CLAIM: _adapter})

    def different(case, policy, artifacts):
        result = _adapter(case, policy, artifacts)
        result["reason"] = "different_implementation"
        return result

    with pytest.raises(CaseError, match="differs from replay"):
        replay_bundle(output, adapters={CLAIM: different})


def test_archive_cannot_choose_executable_code(tmp_path):
    root = _inputs(tmp_path)
    output = tmp_path / "decision.zip"
    with pytest.raises(CaseError, match="unsupported claim_type"):
        create_bundle(root / "case.json", root / "policy.json", output)
    assert not output.exists()
    create_bundle(root / "case.json", root / "policy.json", output, adapters={CLAIM: _adapter})
    with zipfile.ZipFile(output) as archive:
        assert not any(name.endswith(".py") for name in archive.namelist())


def test_create_keeps_one_code_selection_when_the_caller_mapping_changes(tmp_path):
    root = _inputs(tmp_path)
    output = tmp_path / "decision.zip"
    calls, selected = [], {}

    def replacement(*args):
        calls.append("replacement")
        return _adapter(*args)

    def original(*args):
        calls.append("original")
        selected[CLAIM] = replacement
        return _adapter(*args)

    selected[CLAIM] = original
    create_bundle(root / "case.json", root / "policy.json", output, adapters=selected)
    assert calls == ["original", "original"]
    assert selected[CLAIM] is replacement


@pytest.mark.parametrize("adapters", [[], "adapter", 1])
def test_bundle_entrypoints_refuse_non_mapping_selections_before_io(tmp_path, adapters):
    with pytest.raises(CaseError, match="adapters must be a mapping"):
        create_bundle(tmp_path / "absent.json", tmp_path / "absent-policy.json",
                      tmp_path / "out.zip", adapters=adapters)
    with pytest.raises(CaseError, match="adapters must be a mapping"):
        replay_bundle(tmp_path / "absent.zip", adapters=adapters)
