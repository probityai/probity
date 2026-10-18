"""probity-tool-claims/v2: the agent's claimed runs and whether it asserted completion."""

import copy
import json

import pytest
from done_run import honest_records
from probity_verify import CaseError
from probity_verify.adapters import done_records


def encode(record: dict) -> bytes:
    return json.dumps(record).encode()


@pytest.fixture
def claims():
    return copy.deepcopy(honest_records()["claims"])


def test_the_honest_record_reads(claims):
    record = done_records.claims(encode(claims))
    assert record["completion"] == {"asserted": True, "basis": "both"}


@pytest.mark.parametrize("basis", ["final_text", "tool_claim", "both"])
def test_an_assertion_names_its_basis(claims, basis):
    claims["completion"] = {"asserted": True, "basis": basis}
    assert done_records.claims(encode(claims))["completion"]["basis"] == basis


def test_no_assertion_has_basis_none(claims):
    claims["completion"] = {"asserted": False, "basis": "none"}
    assert done_records.claims(encode(claims))["completion"]["asserted"] is False


@pytest.mark.parametrize("completion,message", [
    ({"asserted": True, "basis": "none"}, "basis"),
    ({"asserted": False, "basis": "final_text"}, "basis"),
    ({"asserted": "yes", "basis": "final_text"}, "asserted"),
    ({"asserted": True, "basis": "transcript"}, "basis"),
    ({"asserted": True}, "basis"),
    ({"asserted": True, "basis": "both", "extra": 1}, "completion"),
])
def test_a_malformed_completion_is_refused(claims, completion, message):
    claims["completion"] = completion
    with pytest.raises(CaseError, match=message):
        done_records.claims(encode(claims))


def test_completion_is_required(claims):
    del claims["completion"]
    with pytest.raises(CaseError, match="completion"):
        done_records.claims(encode(claims))


def test_the_v1_record_is_refused(claims):
    claims["schema_version"] = "probity-tool-claims/v1"
    del claims["completion"]
    with pytest.raises(CaseError, match="schema_version"):
        done_records.claims(encode(claims))
