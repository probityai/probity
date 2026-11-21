"""``evidence_sufficiency/v1`` gives each of 39 candidate cases the verdict its author wrote.

``tests/data/evidence-sufficiency/cases`` holds the section 7.4 candidate cases of the CoSAI WS4
containment paper, byte for byte as they sit in ``conformance/RFC-189/observed-effect/cases`` of
cosai-oasis/ws4-secure-design-agentic-systems (``feat/containment``, section 7.4 pinned at
``05bed163b211152fc1b969e3932847164c2efeb3``). Each case names one record of the Observed Effect
corpus by vector id and SHA-256; the records are the ones in ``tests/data/observed-effect``. The
expectation is read from the case file and never reaches the adapter.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.common import CaseError

DATA = Path(__file__).resolve().parent / "data"
CASES = sorted((DATA / "evidence-sufficiency" / "cases").glob("*.json"))
STATEMENTS = DATA / "observed-effect" / "statements"
# claim-level expectation -> the common decision a verdict stage gives
DECISION = {"pass": "supported", "absent": "supported", "fail": "contradicted",
            "present": "contradicted", "not_established": "not_established",
            "pending": "not_established"}


def _judge(case: dict[str, Any], tmp: Path, **override: Any) -> dict:
    ci = case["checker_input"]
    ref = ci["evidence"]["observed_effect"]
    raw = (STATEMENTS / f"{ref['vector']}.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ref["sha256"]
    (tmp / "envelope.json").write_bytes(raw)
    ctx = ci["context"]
    assessment: dict[str, Any] = {
        "claim_type": "evidence_sufficiency/v1", "envelope": "envelope.json",
        "observer_public_key": ctx["observer_public_key"], "claim_ref": ctx["claim_ref"],
        "property": {"name": ci["property"]["name"], "scope": ci["property"]["scope"]}}
    for key in ("anchored_commitment_digest", "producer_capability", "producer", "independence_evidence"):
        if ctx.get(key) is not None:
            assessment[key] = ctx[key]
    assessment.update(override)
    art = {"envelope.json": {"path": "envelope.json", "length": len(raw),
                             "sha256": hashlib.sha256(raw).hexdigest()}}
    return adjudicate({"schema_version": "probity-case/v1", "case_id": case["id"], "artifacts": art},
                      {"schema_version": "probity-policy/v1", "assessments": {case["id"]: assessment}}, tmp)


def test_there_are_39_cases():
    assert len(CASES) == 39


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_each_case_gets_its_authored_verdict(path, tmp_path):
    case = json.loads(path.read_text(encoding="utf-8"))
    want = case["expected"]
    if "processing_failure" in want:
        with pytest.raises(CaseError) as err:
            _judge(case, tmp_path)
        prefix = {"MalformedEvidence": "malformed_record: ",
                  "UnsupportedVerification": "unsupported_property: "}[want["processing_failure"]]
        assert str(err.value).startswith(prefix)
        for code in want.get("codes", []):
            assert code in str(err.value)
        return
    kind = want.get("verdict") or want["outcome"]
    result = _judge(case, tmp_path)
    assert result["decision"] == DECISION[kind]
    (check,) = result["checks"]
    assert check["verdict" if "verdict" in want else "outcome"] == kind
    assert check["unmet_obligation"] == want["unmet_obligation"]
    if want["unmet_obligation"]:
        assert result["reason"] == want["unmet_obligation"]
    assert result["scope"]["claim_ref"] == case["checker_input"]["context"]["claim_ref"]


def test_the_expectation_never_reaches_the_adapter(tmp_path):
    case = json.loads(CASES[0].read_text(encoding="utf-8"))
    result = _judge(case, tmp_path)
    assert "expected" not in result["scope"]
    assert "expected" not in result["checks"][0]


def test_a_wrong_pinned_key_leaves_the_property_not_established(tmp_path):
    case = next(json.loads(p.read_text()) for p in CASES if p.stem.endswith("OE-01-PASS"))
    result = _judge(case, tmp_path, observer_public_key="00" * 32)
    assert result["decision"] == "not_established"
    assert result["reason"] == "admissible_observation" or result["checks"][0]["unmet_obligation"]


def test_an_unknown_assessment_field_is_refused(tmp_path):
    case = json.loads(CASES[0].read_text(encoding="utf-8"))
    with pytest.raises(CaseError):
        _judge(case, tmp_path, surprise=1)


def test_a_relative_scope_is_refused(tmp_path):
    case = next(json.loads(p.read_text()) for p in CASES if p.stem.endswith("OE-01-PASS"))
    with pytest.raises(CaseError):
        _judge(case, tmp_path, property={"name": "no_write_in_scope", "scope": ["srv/app/"]})
