"""The verifier checks witness scope against the released agent-evidence-vocabulary registry."""

from importlib.resources import files

import pytest
import yaml

from done_run import build, decide, honest_records
from probity_verify import CaseError, adjudicate, core, vocabulary


def registry_scopes():
    text = files("agent_evidence_vocabulary").joinpath("vocabulary.yaml").read_text("utf-8")
    return yaml.safe_load(text)["evidence_dimensions"]["witness_scope"]["values"]


def test_accepted_scopes_are_registry_terms():
    assert set(core.WITNESS_SCOPES) <= set(registry_scopes())
    assert vocabulary.WITNESS_SCOPE_TERMS == tuple(registry_scopes())


def test_self_is_a_registry_term_the_verifier_refuses():
    assert "SELF" in vocabulary.WITNESS_SCOPE_TERMS
    assert "SELF" not in core.WITNESS_SCOPES


def test_term_refuses_a_value_the_registry_does_not_define():
    with pytest.raises(LookupError, match="not a evidence_dimensions.witness_scope term"):
        vocabulary.term("evidence_dimensions", "witness_scope", "INTERNAL")


def test_unknown_dimension_refuses():
    with pytest.raises(LookupError, match="no dimension"):
        vocabulary.terms("evidence_dimensions", "no_such_dimension")


@pytest.mark.parametrize("role", ["observation", "tree"])
def test_pin_with_a_scope_outside_the_vocabulary_is_rejected(tmp_path, role):
    records = honest_records()
    records[role]["witness_scope"] = "INTERNAL"
    with pytest.raises(CaseError, match=f"witness.{role}.witness_scope is not a vocabulary"):
        decide(tmp_path, records, "protected_paths/v1")


@pytest.mark.parametrize("role", ["observation", "tree"])
def test_record_with_a_scope_outside_the_vocabulary_is_rejected(tmp_path, role):
    """The consumer pin says PEER; only the signed record carries the unknown term."""
    records = honest_records()
    records[role]["witness_scope"] = "INTERNAL"
    files, case, policy = build(records, "protected_paths/v1")
    policy["witnesses"][role]["witness_scope"] = "PEER"
    for name, raw in files.items():
        (tmp_path / name).write_bytes(raw)
    with pytest.raises(CaseError, match=f"{role}.witness_scope is not a vocabulary 0.5.0 term"):
        adjudicate(case, policy, tmp_path)


def test_record_with_the_self_scope_is_rejected_as_refused(tmp_path):
    records = honest_records()
    records["observation"]["witness_scope"] = "SELF"
    with pytest.raises(CaseError, match="SELF is a vocabulary term the verifier refuses"):
        decide(tmp_path, records, "protected_paths/v1")


def test_requirement_outside_the_vocabulary_names_the_registry(tmp_path):
    with pytest.raises(CaseError, match="not a vocabulary 0.5.0 term"):
        decide(tmp_path, honest_records(), "protected_paths/v1",
               require_witness_scope="GLOBAL")
