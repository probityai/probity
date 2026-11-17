"""``co_signed_receipt/v1``: the eight broken receipts, the valid ones, forged keys, and parity
with the admission rule set.

tests/data/co-signed-receipt is written by scripts/gen-signed-card-and-receipt-vectors.py with
fixed test keys; cases.json pins each case's decision, reason and evidence attribution. The eight
``broken-*`` receipts each carry signatures that verify (or, for the 129-character one, a valid
signature with one hex digit added), and each must be refused.

tests/data/co-signed-receipt-admission/manifest.json is the co-signed-receipt rule-set corpus of
agent-evidence-admission (probityai/agent-evidence-vectors packages/admission at commit
b1c54d70b048588c57f7e229737c50320ff35f92). The member rules here must refuse each of its receipts
under the same first code, and admit the ones it admits.
"""

import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import co_signed_receipt as reader

DATA = Path(__file__).parent / "data" / "co-signed-receipt"
INDEX = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))
CASES = {case["id"]: case for case in INDEX["cases"]}
ADMISSION = json.loads((Path(__file__).parent / "data" / "co-signed-receipt-admission" /
                        "manifest.json").read_text(encoding="utf-8"))
BROKEN = sorted(name for name in CASES if name.startswith("broken-"))


def _run(directory: Path, assessment: dict) -> dict:
    artifacts = {}
    for path in sorted(directory.iterdir()):
        body = path.read_bytes()
        artifacts[path.name] = {"path": path.name, "length": len(body),
                                "sha256": hashlib.sha256(body).hexdigest()}
    case = {"schema_version": "probity-case/v1", "case_id": directory.name, "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {directory.name: dict(assessment, claim_type=reader.CLAIM_TYPE)}}
    return adjudicate(case, policy, directory)


@pytest.mark.parametrize("name", sorted(CASES))
def test_vector(name: str) -> None:
    case = CASES[name]
    result = _run(DATA / name, case["assessment"])
    assert (result["decision"], result["reason"]) == (case["expect"]["decision"],
                                                       case["expect"]["reason"]), case["description"]
    assert result["checks"][0].get("evidence_attribution") == case["expect"].get(
        "evidence_attribution"), case["description"]


def test_all_eight_broken_receipts_are_refused() -> None:
    assert len(BROKEN) == 8
    decisions = [_run(DATA / name, CASES[name]["assessment"])["decision"] for name in BROKEN]
    assert decisions == ["contradicted"] * 8


@pytest.mark.parametrize("vector", ADMISSION["cases"], ids=[c["id"] for c in ADMISSION["cases"]])
def test_member_rules_agree_with_admission(vector: dict) -> None:
    try:
        reader.read(vector["text"].encode("utf-8"))
        code = None
    except reader.Refused as refusal:
        code = refusal.args[0]
    want = vector["expect"].get("code") if vector["expect"]["verdict"] == "refuse" else None
    assert code == want, vector["rationale"]


def test_every_refusal_code_has_a_vector() -> None:
    pinned = {case["expect"]["reason"] for case in INDEX["cases"]}
    pinned |= {c["expect"]["code"] for c in ADMISSION["cases"] if c["expect"]["verdict"] == "refuse"}
    own = set(reader.REASONS) - set(reader.IJSON_CODES)
    assert own <= pinned, sorted(own - pinned)


def test_unhashable_format_version_is_refused_not_raised() -> None:
    with pytest.raises(reader.Refused, match="version-unknown"):
        reader.read(b'{"formatVersion": [1]}')


def test_both_parties_are_asked_about_their_own_key() -> None:
    result = _run(DATA / "valid-co-signed-registry", CASES["valid-co-signed-registry"]["assessment"])
    receipt_check, agent, caller = result["checks"]
    assert receipt_check["signers"] == ["did:web:agent.example.test", "did:web:caller.example.test"]
    assert (agent["outcome"], caller["outcome"]) == ("authorized", "authorized")
    assert agent["key_set_sha256"] != caller["key_set_sha256"]
