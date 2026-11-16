"""``evaluation_claim/v1`` against the reference reader's own corpus, case by case.

tests/data/evaluation-claim is the claim_record corpus of probityai/agent-evidence-vectors at commit
7b8b97a7cee6f9c594faa41cf08066ac4318afef. Each case pins the reference reader's result, verdict and
set of refusal codes; the adapter must give the same three on every case, and every negative case's
repair must be admitted.
"""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import evaluation_claim
from agent_evidence_verify.common import CaseError

CORPUS = Path(__file__).parent / "data" / "evaluation-claim"
CASES = json.loads((CORPUS / "cases.json").read_text(encoding="utf-8"))["cases"]
RULES = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (CORPUS / "rules").glob("*.json")}
PROFILE_FILES = sorted((CORPUS / "profiles").glob("*.json"))
CASE_SET_FILES = sorted((CORPUS / "case-sets").glob("*.json"))


def _apply(doc, ops):
    out = copy.deepcopy(doc)
    for op in ops:
        node = out
        for step in op["path"][:-1]:
            node = node[step]
        last = op["path"][-1]
        if op["op"] == "set":
            node[last] = copy.deepcopy(op["value"])
        else:
            del node[last]
    return out


def _artifact(root: Path, name: str, body: bytes) -> dict:
    (root / name).write_bytes(body)
    return {"path": name, "length": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def _judge(tmp_path: Path, record, rule: dict, case_sets=None) -> dict:
    artifacts = {"record.json": _artifact(tmp_path, "record.json",
                                          json.dumps(record, ensure_ascii=False).encode("utf-8"))}
    profiles, sets = [], []
    for path in PROFILE_FILES:
        name = "profile-" + path.name
        artifacts[name] = _artifact(tmp_path, name, path.read_bytes())
        profiles.append(name)
    for index, body in enumerate(case_sets if case_sets is not None
                                 else [p.read_bytes() for p in CASE_SET_FILES]):
        name = f"case-set-{index}.json"
        artifacts[name] = _artifact(tmp_path, name, body)
        sets.append(name)
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "evaluation_claim/v1", "record": "record.json", "rule": rule,
        "profiles": profiles, "case_sets": sets}}}
    return adjudicate(case, policy, tmp_path)


def _summary(result: dict) -> dict:
    check = result["checks"][0]
    order = list(evaluation_claim.CODES)
    return {"result": check["result"], "verdict": check["verdict"],
            "reasons": sorted(set(check["codes"]), key=order.index)}


def test_the_corpus_is_the_pinned_copy() -> None:
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    for name, pinned in manifest["members"].items():
        assert "sha256:" + hashlib.sha256((CORPUS / name).read_bytes()).hexdigest() == pinned, name
    assert len(CASES) == 60


@pytest.mark.parametrize("vector", CASES, ids=[c["id"] for c in CASES])
def test_parity_with_the_reference_reader(tmp_path: Path, vector: dict) -> None:
    result = _judge(tmp_path, vector["record"], RULES[vector["rule"]])
    assert _summary(result) == vector["expected"]
    expected = vector["expected"]
    if expected["result"] == "REFUSED":
        assert (result["decision"], result["reason"]) == ("contradicted", expected["reasons"][0])
    elif expected["verdict"] == "pass":
        assert (result["decision"], result["reason"]) == ("supported", "claim_admitted_pass")
    else:
        assert (result["decision"], result["reason"]) == (
            "not_established", f"claim_admitted_{expected['verdict']}")
    if vector["kind"] == "negative":
        repaired = _judge(tmp_path, _apply(vector["record"], vector["repair"]),
                          RULES[vector.get("repair_rule", vector["rule"])])
        assert repaired["checks"][0]["result"] == "ADMITTED"


def _expect_case_set(expectations: list[tuple[str, str]]) -> dict:
    return {"schema": "aev-claim-case-set/v1", "name": "sample-expectations", "revision": "1",
            "cases": [{"id": cid, "requirement": "required", "expect": exp}
                      for cid, exp in expectations]}


def test_a_rewritten_expectation_table_is_a_case_set_the_rule_does_not_accept(tmp_path: Path) -> None:
    """Matrix row 9, CE-2: one flipped expectation must not keep the pinned case-set digest."""
    genuine = _expect_case_set([("e1", "verified"), ("e2", "falsified")])
    rewritten = _expect_case_set([("e1", "falsified"), ("e2", "falsified")])
    genuine_digest = evaluation_claim.digest_of(genuine)
    assert evaluation_claim.digest_of(rewritten) != genuine_digest
    rule = copy.deepcopy(RULES["conformance"])
    rule["case_sets"] = [genuine_digest]
    base = copy.deepcopy(CASES[0]["record"])
    coords = base["coordinates"]

    def record_over(case_set: dict) -> dict:
        record = copy.deepcopy(base)
        ref = {"name": "sample-expectations@1", "digest": evaluation_claim.digest_of(case_set)}
        record["coordinates"]["applicability"].update(case_set=ref, applicable=["e1", "e2"],
                                                      excluded=[])
        record["coordinates"]["population"].update(coverage_denominator=2, passed=["e1", "e2"],
                                                   failed=[], not_run=[])
        record["coordinates"]["bytes"]["case_set"] = dict(ref)
        return record

    assert coords["applicability"]["state"] == "value"
    bodies = [json.dumps(c).encode() for c in (genuine, rewritten)]
    admitted = _judge(tmp_path, record_over(genuine), rule, bodies)
    assert (admitted["decision"], admitted["reason"]) == ("supported", "claim_admitted_pass")
    refused = _judge(tmp_path, record_over(rewritten), rule, bodies)
    assert (refused["decision"], refused["reason"]) == ("contradicted", "CASE_SET_NOT_ACCEPTED")


@pytest.mark.parametrize("raw", [b'{"claim_type":1,"claim_type":2}', b'{"a":"\xff"}',
                                 b'{"verdict":"pass","n":9007199254740993}', b'{"n":1.5}'])
def test_bytes_the_strict_reader_refuses_are_a_malformed_record(tmp_path: Path, raw: bytes) -> None:
    rule = RULES["conformance"]
    body = tmp_path / "record.json"
    body.write_bytes(raw)
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {"record.json": {
        "path": "record.json", "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "evaluation_claim/v1", "record": "record.json", "rule": rule}}}
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["reason"]) == ("contradicted", "MALFORMED_RECORD")


def test_the_rule_is_the_consumers_input_and_a_bad_one_is_a_case_error(tmp_path: Path) -> None:
    rule = copy.deepcopy(RULES["conformance"])
    rule["case_sets"] = []
    with pytest.raises(CaseError, match="assessment.rule"):
        _judge(tmp_path, CASES[0]["record"], rule)


def test_an_unbound_record_is_not_established(tmp_path: Path) -> None:
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {"record.json": {
        "path": "missing.json", "length": 2, "sha256": hashlib.sha256(b"{}").hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "evaluation_claim/v1", "record": "record.json", "rule": RULES["conformance"]}}}
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["reason"]) == ("not_established", "record_unavailable")


def test_every_registered_adapter_is_documented() -> None:
    """The docs name every claim type the registry serves; a new adapter without a page turns red."""
    from agent_evidence_verify.core import ADAPTERS

    docs = "".join(p.read_text(encoding="utf-8")
                   for p in (Path(__file__).parents[1] / "docs").glob("*.md"))
    assert [claim for claim in ADAPTERS if claim not in docs] == []
