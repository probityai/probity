"""Consumer adapter selections must not escape their adjudication call."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from probity_verify import CaseError, adjudicate
from probity_verify.core import ADAPTERS

ROOT = Path(__file__).resolve().parents[1]
CLAIM_TYPE = "fixture_claim/v1"


def _inputs(claim_type: str = CLAIM_TYPE) -> tuple[dict, dict]:
    case = {"case_id": "consumer-case"}
    policy = {"assessments": {case["case_id"]: {"claim_type": claim_type}}}
    return case, policy


def _adapter(decision: str):
    """Return a scoped fixture callback with the public adapter signature."""
    def check(case, policy, artifact_root):
        return {
            "schema_version": "probity-decision/v1",
            "case_id": case["case_id"],
            "claim_type": policy["assessments"][case["case_id"]]["claim_type"],
            "decision": decision,
            "reason": "author-controlled adapter fixture",
            "scope": {"evidence": "fixture only"},
            "checks": [],
        }
    return check


@pytest.mark.parametrize("decision", ["supported", "contradicted", "not_established"])
def test_selected_adapter_keeps_the_envelope_and_exact_policy_binding(tmp_path, decision):
    case, policy = _inputs()
    original = copy.deepcopy((case, policy))
    selected = {CLAIM_TYPE: _adapter(decision)}
    result = adjudicate(case, policy, tmp_path, adapters=selected)
    assert result["decision"] == decision
    raw_policy = (json.dumps(policy, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False) + "\n").encode("utf-8")
    assert result["policy_sha256"] == hashlib.sha256(raw_policy).hexdigest()
    assert (case, policy) == original
    assert list(selected) == [CLAIM_TYPE]


def test_two_consumers_can_select_different_adapters_without_global_registration(tmp_path):
    case, policy = _inputs()
    original_registry = dict(ADAPTERS)
    first = adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: _adapter("supported")})
    second = adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: _adapter("contradicted")})
    assert (first["decision"], second["decision"]) == ("supported", "contradicted")
    assert ADAPTERS == original_registry
    with pytest.raises(CaseError, match="unsupported claim_type"):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("target", ["policy", "case", "source", "non_json"])
def test_adapter_control_mutation_is_refused_and_caller_inputs_stay_intact(tmp_path, target):
    case, policy = _inputs()
    case["artifacts"] = {"source": {"path": "source.json", "sha256": "a" * 64}}
    original = copy.deepcopy((case, policy))

    def changed(callback_case, callback_policy, root):
        assert callback_case is not case
        assert callback_policy is not policy
        result = _adapter("supported")(callback_case, callback_policy, root)
        if target == "policy":
            callback_policy["assessments"][case["case_id"]]["claim_type"] = "fixture_claim/v2"
        elif target == "case":
            callback_case["case_id"] = "rewritten-case"
        elif target == "source":
            callback_case["artifacts"]["source"]["sha256"] = "b" * 64
        else:
            callback_policy["injected"] = object()
        return result

    with pytest.raises(CaseError, match="adapter changed the case or consumer policy"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: changed})
    assert (case, policy) == original


def test_control_mutation_cannot_hide_behind_python_numeric_equality(tmp_path):
    case, policy = _inputs()
    policy["selected"] = True

    def changed(callback_case, callback_policy, root):
        callback_policy["selected"] = 1
        return _adapter("supported")(callback_case, callback_policy, root)

    with pytest.raises(CaseError, match="adapter changed the case or consumer policy"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: changed})
    assert policy["selected"] is True


def test_supplied_mapping_is_snapshotted_before_claim_selection(tmp_path):
    case, policy = _inputs()
    selected = {CLAIM_TYPE: _adapter("supported")}

    class ChangedCase(dict):
        def get(self, key, default=None):
            selected.clear()
            return super().get(key, default)

    result = adjudicate(ChangedCase(case), policy, tmp_path, adapters=selected)
    assert result["decision"] == "supported"
    assert selected == {}


def test_legacy_registry_is_snapshotted_and_remains_available(tmp_path, monkeypatch):
    case, policy = _inputs()
    first = _adapter("supported")
    later = _adapter("contradicted")
    monkeypatch.setitem(ADAPTERS, CLAIM_TYPE, first)

    class ChangedPolicy(dict):
        def get(self, key, default=None):
            ADAPTERS[CLAIM_TYPE] = later
            return super().get(key, default)

    result = adjudicate(case, ChangedPolicy(policy), tmp_path)
    assert result["decision"] == "supported"
    assert adjudicate(case, policy, tmp_path)["decision"] == "contradicted"


@pytest.mark.parametrize("claim_type", list(ADAPTERS))
def test_additional_adapter_cannot_replace_a_builtin(tmp_path, claim_type):
    case, policy = _inputs(claim_type)
    with pytest.raises(CaseError, match="collides"):
        adjudicate(case, policy, tmp_path, adapters={claim_type: _adapter("supported")})


def test_reserved_builtin_cannot_be_reintroduced_through_additions(tmp_path, monkeypatch):
    claim_type = "authority_anchor/v1"
    monkeypatch.delitem(ADAPTERS, claim_type)
    case, policy = _inputs(claim_type)
    with pytest.raises(CaseError, match="collides"):
        adjudicate(case, policy, tmp_path, adapters={claim_type: _adapter("supported")})


def test_additional_adapter_cannot_replace_a_legacy_registration(tmp_path, monkeypatch):
    case, policy = _inputs()
    monkeypatch.setitem(ADAPTERS, CLAIM_TYPE, _adapter("supported"))
    with pytest.raises(CaseError, match="collides"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: _adapter("contradicted")})


@pytest.mark.parametrize("mapping", [[], [(CLAIM_TYPE, _adapter("supported"))], "name", 1])
def test_non_mapping_configuration_is_refused(tmp_path, mapping):
    case, policy = _inputs()
    with pytest.raises(CaseError, match="must be a mapping"):
        adjudicate(case, policy, tmp_path, adapters=mapping)


@pytest.mark.parametrize("name", [None, 1, "", "fixture_claim", "fixture/v0", "fixture/v01",
                                 "fixture/v-1", "fixture/v1 ", "fixture claim/v1", "fixture/v\u0661"])
def test_unversioned_or_ambiguous_adapter_names_are_refused(tmp_path, name):
    case, policy = _inputs()
    with pytest.raises(CaseError, match="versioned claim identifiers"):
        adjudicate(case, policy, tmp_path, adapters={name: _adapter("supported")})


@pytest.mark.parametrize("callback", [None, 1, {}, "function"])
def test_non_callable_adapter_is_refused(tmp_path, callback):
    case, policy = _inputs()
    with pytest.raises(CaseError, match="must be callable"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: callback})


def test_an_unused_malformed_entry_is_not_silently_ignored(tmp_path):
    case, policy = _inputs()
    with pytest.raises(CaseError, match="must be callable"):
        adjudicate(case, policy, tmp_path,
                   adapters={CLAIM_TYPE: _adapter("supported"), "unused/v1": None})


def test_unknown_version_cannot_fall_back_to_a_supplied_adapter(tmp_path):
    case, policy = _inputs("fixture_claim/v2")
    with pytest.raises(CaseError, match="unsupported claim_type"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: _adapter("supported")})


@pytest.mark.parametrize("output", [None, [], "supported", 1])
def test_non_object_adapter_output_is_refused_without_a_verdict(tmp_path, output):
    case, policy = _inputs()
    with pytest.raises(CaseError, match="invalid decision envelope"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: lambda *_: output})


@pytest.mark.parametrize("change", [
    {"schema_version": "probity-decision/v2"}, {"case_id": "different"},
    {"claim_type": "fixture_claim/v2"}, {"decision": "APPROVE"},
    {"decision": []}, {"reason": None}, {"scope": []}, {"checks": {}},
])
def test_malformed_adapter_envelope_is_refused_without_a_verdict(tmp_path, change):
    case, policy = _inputs()

    def changed(*args):
        return {**_adapter("supported")(*args), **change}

    with pytest.raises(CaseError, match="invalid decision envelope"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: changed})


@pytest.mark.parametrize("target", ["case", "policy"])
def test_non_json_controls_are_refused_before_the_callback(tmp_path, target):
    case, policy = _inputs()
    (case if target == "case" else policy)["malformed"] = object()

    def must_not_run(*args):
        raise AssertionError("malformed controls must refuse before callback execution")

    with pytest.raises(CaseError, match="JSON-compatible values"):
        adjudicate(case, policy, tmp_path, adapters={CLAIM_TYPE: must_not_run})


RECIPES = json.loads((ROOT / "docs/recipe-source.json").read_text())["recipes"]


@pytest.mark.parametrize("recipe", RECIPES, ids=lambda recipe: recipe["case"])
def test_additional_selection_preserves_established_builtin_outputs(recipe):
    case_path = ROOT / recipe["case"]
    case = json.loads(case_path.read_text())
    policy = json.loads((ROOT / recipe["policy"]).read_text())

    def unselected(*args):
        raise AssertionError("an unrelated adapter must not run")

    original = adjudicate(case, policy, case_path.parent)
    assert original["decision"] == recipe["expected_decision"]
    assert adjudicate(case, policy, case_path.parent, adapters={}) == original
    assert adjudicate(case, policy, case_path.parent,
                      adapters={CLAIM_TYPE: unselected}) == original
