"""done_receipt/v1: the receipt's verdict, derived again from the records it names."""

import copy
import hashlib

import pytest
from done_run import SCOPE, encode, honest_records
from probity_verify import CaseError, adjudicate
from probity_verify.adapters import done_receipt
from probity_verify.adapters.done_records import DONE_RECEIPT_PREDICATE

CLAIM = "done_receipt/v1"
ROLES = ("contract", "capability", "observation", "tree", "grade", "claims")
OBSERVED = {"observation", "tree", "grade"}
VERIFIER = "https://github.com/probityai/probity"


@pytest.fixture
def records():
    return honest_records()


def receipt_for(raw, records, verdict=("supported", "done_checks_supported")):
    return {"schema_version": "probity-done-receipt/v1", "claim_id": "case-1",
            "invocation_id": "call-1", "verifier": {"id": VERIFIER},
            "records": {role: {"sha256": hashlib.sha256(raw[role]).hexdigest()}
                        for role in ROLES},
            "checks": [], "verdict": {"decision": verdict[0], "reason": verdict[1],
                                      "vantage": "independent"}}


def build(tmp_path, records, change=None, verdict=("supported", "done_checks_supported"),
          statement=None, pins=None, require="PEER", **assessment):
    """Write a done-receipt case and adjudicate it.

    ``pins`` is called with the raw records, case and policy before the
    adjudication, to add witness pins; ``require`` is the required witness scope.
    """
    records = copy.deepcopy(records)
    raw = {role: encode(records[role]) for role in ROLES if role != "grade"}
    records["grade"]["contract_sha256"] = hashlib.sha256(raw["contract"]).hexdigest()
    raw["grade"] = encode(records["grade"])
    predicate = receipt_for(raw, records, verdict)
    if change is not None:
        change(predicate)
    raw["receipt"] = statement if statement is not None else done_receipt.encode_statement(
        predicate, records["tree"]["tree_sha256"])
    case = {"schema_version": "probity-case/v1", "case_id": "case-1", "artifacts": {}}
    fields = {"claim_type": CLAIM, "invocation_id": "call-1", "observed_party": "agent-1",
              "scope": SCOPE, **assessment}
    policy = {"schema_version": "probity-policy/v1", "witnesses": {},
              "assessments": {"case-1": fields}}
    for role, data in raw.items():
        (tmp_path / f"{role}.json").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        case["artifacts"][role] = {"path": f"{role}.json", "length": len(data),
                                   "sha256": digest}
        pin = {"artifact": role, "sha256": digest, "authority": "synthetic fixture"}
        if role in OBSERVED:
            pin.update(producer=records[role]["producer"], vantage=records[role]["vantage"],
                       witness_scope=records[role]["witness_scope"])
        policy["witnesses"][role] = pin
        fields[f"{role}_witness"] = role
    if pins is not None:
        pins(raw, case, policy)
    return adjudicate(case, policy, tmp_path, require_witness_scope=require)


def outcome(result):
    return result["decision"], result["reason"]


def test_an_honest_receipt_is_derived_again_and_names_its_verifier(tmp_path, records):
    result = build(tmp_path, records)
    assert outcome(result) == ("supported", "done_checks_supported")
    assert result["verifier_id"] == VERIFIER
    assert (result["vantage"], result["witness_scope"]) == ("independent", "PEER")
    derived = next(c for c in result["checks"] if c["id"] == "derived_verdict")
    assert [item["decision"] for item in derived["checks"]] == ["supported"] * 3


def test_the_decision_line_reports_the_verifier(tmp_path, records):
    from probity_verify.core import render_packet
    assert f"verifier_id: {VERIFIER}" in render_packet(build(tmp_path, records))


def test_a_receipt_claiming_more_than_its_records_give(tmp_path, records):
    records["grade"]["results"][0]["exit"] = 1
    result = build(tmp_path, records)
    assert outcome(result) == ("contradicted", "receipt_verdict_mismatch")
    derived = next(c for c in result["checks"] if c["id"] == "derived_verdict")["derived"]
    assert derived["reason"] == "acceptance_failed_in_verifier"


def test_a_contradicted_receipt_that_agrees_stands(tmp_path, records):
    records["grade"]["results"][1]["exit"] = 1
    result = build(tmp_path, records, verdict=("contradicted", "heldout_failed"))
    assert outcome(result) == ("contradicted", "heldout_failed")


def test_the_first_contradiction_in_check_order_names_the_verdict(tmp_path, records):
    records["grade"]["results"][0]["exit"] = 1
    records["observation"]["events"][0]["path"] = "tests/test_app.py"
    result = build(tmp_path, records, verdict=("contradicted", "protected_path_mutated"))
    assert outcome(result) == ("contradicted", "protected_path_mutated")


def test_a_not_established_check_leaves_the_receipt_open(tmp_path, records):
    records["observation"]["coverage"] = "unknown"
    result = build(tmp_path, records,
                   verdict=("not_established", "observation_coverage_unestablished"))
    assert outcome(result) == ("not_established", "observation_coverage_unestablished")


def test_a_record_the_receipt_does_not_name(tmp_path, records):
    def change(predicate):
        predicate["records"]["tree"]["sha256"] = "0" * 64
    assert build(tmp_path, records, change)["reason"] == "receipt_records_mismatch"


def test_a_subject_other_than_the_final_tree(tmp_path, records):
    predicate = None

    def capture(value):
        nonlocal predicate
        predicate = value
    build(tmp_path, records, capture)
    statement = done_receipt.encode_statement(predicate, "1" * 64)
    assert build(tmp_path, records, statement=statement)["reason"] == (
        "receipt_subject_mismatch")


def test_a_verifier_the_consumer_did_not_pin(tmp_path, records):
    result = build(tmp_path, records, verifier_ids=["https://example.org/other"])
    assert outcome(result) == ("not_established", "verifier_unpinned")
    assert build(tmp_path, records, verifier_ids=[VERIFIER])["decision"] == "supported"


def test_another_invocation(tmp_path, records):
    def change(predicate):
        predicate["invocation_id"] = "call-2"
    assert build(tmp_path, records, change)["reason"] == "receipt_context_mismatch"


@pytest.mark.parametrize("change,message", [
    (lambda p: p.pop("verifier"), "verifier.id: required"),
    (lambda p: p.update(verifier={}), "verifier.id: required"),
    (lambda p: p.update(verifier={"id": "probity"}), "URI"),
    (lambda p: p.update(verifier={"id": "https://x y"}), "URI"),
    (lambda p: p["records"].pop("grade"), "records"),
    (lambda p: p["verdict"].update(decision="passed"), "decision"),
])
def test_a_malformed_receipt_refuses(tmp_path, records, change, message):
    with pytest.raises(CaseError, match=message):
        build(tmp_path, records, change)


@pytest.mark.parametrize("predicate_type", [
    "https://probityai.github.io/probity/predicate/v1/done-receipt",
    "https://w3id.org/agent-evidence/predicate/v1/done-contract",
])
def test_only_the_done_receipt_predicate_type_is_read(tmp_path, records, predicate_type):
    predicate = None

    def capture(value):
        nonlocal predicate
        predicate = value
    build(tmp_path, records, capture)
    statement = done_receipt.encode_statement(predicate, records["tree"]["tree_sha256"])
    statement = statement.replace(DONE_RECEIPT_PREDICATE.encode(), predicate_type.encode())
    with pytest.raises(CaseError, match="predicateType"):
        build(tmp_path, records, statement=statement)


def test_verifier_ids_must_be_uris(tmp_path, records):
    with pytest.raises(CaseError, match="verifier_ids"):
        build(tmp_path, records, verifier_ids=["not a uri"])


def test_a_receipt_with_the_right_decision_and_another_reason(tmp_path, records):
    records["observation"]["events"][0]["path"] = "tests/test_app.py"
    result = build(tmp_path, records, verdict=("contradicted", "acceptance_failed_in_verifier"))
    assert outcome(result) == ("contradicted", "receipt_verdict_mismatch")


class TestCompletionClaimed:
    """The receipt says whether the agent claimed done; the claims record decides it."""

    def test_a_receipt_that_says_the_agent_claimed_done(self, tmp_path, records):
        result = build(tmp_path, records, lambda p: p.update(completion_claimed=True))
        assert outcome(result) == ("supported", "done_checks_supported")
        check = next(c for c in result["checks"] if c["id"] == "completion_claimed")
        assert check == {"id": "completion_claimed", "status": "met", "derived": True,
                         "reported": True}

    def test_no_passing_claim_is_no_completion_claim(self, tmp_path, records):
        records["claims"]["claims"] = []
        records["grade"]["results"][0]["exit"] = 1
        result = build(tmp_path, records, lambda p: p.update(completion_claimed=False),
                       verdict=("contradicted", "acceptance_failed_in_verifier"))
        assert outcome(result) == ("contradicted", "acceptance_failed_in_verifier")

    def test_a_failed_claim_is_no_completion_claim(self, tmp_path, records):
        records["claims"]["claims"][0]["exit"] = 1
        records["observation"]["events"][1]["exit"] = 1
        records["grade"]["results"][0]["exit"] = 1
        result = build(tmp_path, records, lambda p: p.update(completion_claimed=False),
                       verdict=("contradicted", "acceptance_failed_in_verifier"))
        assert outcome(result) == ("contradicted", "acceptance_failed_in_verifier")

    def test_a_completion_in_the_agents_text_is_a_claim_of_done(self, tmp_path, records):
        records["claims"]["claims"] = []
        records["claims"]["completion"] = {"claimed": True}
        records["grade"]["results"][0]["exit"] = 1
        result = build(tmp_path, records, lambda p: p.update(completion_claimed=True),
                       verdict=("contradicted", "acceptance_failed_in_verifier"))
        check = next(c for c in result["checks"] if c["id"] == "completion_claimed")
        assert check["derived"] is True
        result = build(tmp_path, records, lambda p: p.update(completion_claimed=False),
                       verdict=("contradicted", "acceptance_failed_in_verifier"))
        assert outcome(result) == ("contradicted", "receipt_completion_mismatch")

    @pytest.mark.parametrize("reported", [True, False])
    def test_a_receipt_misreporting_the_claim(self, tmp_path, records, reported):
        if reported:
            records["claims"]["claims"] = []
        result = build(tmp_path, records, lambda p: p.update(completion_claimed=reported))
        assert outcome(result) == ("contradicted", "receipt_completion_mismatch")

    def test_the_field_must_be_a_boolean(self, tmp_path, records):
        with pytest.raises(CaseError, match="completion_claimed"):
            build(tmp_path, records, lambda p: p.update(completion_claimed="yes"))
