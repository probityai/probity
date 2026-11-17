"""agent_audit_record/v1 against every member of the agent audit record corpus.

tests/data/audit-record is corpora/vectors-agent-audit-record of probityai/agent-evidence-vectors at
3d5cfb198 (MANIFEST.json and the member files). Each member is judged through the public
``adjudicate`` entry point, under the corpus manifest as the trust document, and the check must
carry every field the member declares: the verdict and first code, the recomputed tier, the
consumption limit, the dating result of a retained record, and the joint result of a set. An open
(indeterminate) member must land on one of its listed readings.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import audit_record

DATA = Path(__file__).parent / "data" / "audit-record"
MANIFEST = json.loads((DATA / "MANIFEST.json").read_text(encoding="utf-8"))
MEMBERS = {entry["draftId"]: entry for entry in MANIFEST["vectors"]}


def shape_of(entry: dict[str, Any]) -> str:
    """What the consumer holds for a member: a retained record, a set, or one envelope."""
    expected = entry["expected"]
    return "retained" if "dating" in expected else "set" if "set" in expected else "envelope"


def _decide(entry: dict[str, Any], root: Path = DATA, trust: str = "MANIFEST.json") -> dict:
    files = {"record": entry["file"], "trust": trust}
    artifacts = {}
    for name, rel in files.items():
        data = (root / rel).read_bytes()
        artifacts[name] = {"path": rel, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assessment: dict[str, Any] = {"claim_type": audit_record.CLAIM_TYPE, "record": "record",
                                  "trust": "trust"}
    if "predicateType" in entry:
        assessment["predicate_type"] = entry["predicateType"]
    assessment["shape"] = shape_of(entry)
    case = {"schema_version": "probity-case/v1", "case_id": entry["draftId"], "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {entry["draftId"]: assessment}}
    return adjudicate(case, policy, root)


def _record_problems(expected: dict[str, Any], record: dict[str, Any]) -> list[str]:
    problems = []
    if (record["verdict"], record["codes"]) != (expected["verdict"], expected.get("codes", [])):
        problems.append(f"verdict {record['verdict']} {record['codes']}")
    if expected["verdict"] == "valid" and record.get("derivedTier") != expected.get("derivedTier"):
        problems.append(f"derivedTier {record.get('derivedTier')}")
    return problems


def problems_of(entry: dict[str, Any], check: dict[str, Any]) -> list[str]:
    """How the check departs from what the member declares; empty when it agrees."""
    expected = entry["expected"]
    if entry["kind"] == "indeterminate":
        allowed = {reading["verdict"] for reading in entry["readings"]}
        return [] if check["verdict"] in allowed else [f"verdict {check['verdict']} not in {allowed}"]
    if "set" in expected:
        out = []
        for index, record in enumerate(check["records"]):
            out += [f"record {index + 1}: {p}" for p in _record_problems(expected, record)]
        declared = expected["set"]
        got = check["set"]
        if (got["verdict"], got["codes"]) != (declared["verdict"], declared["codes"]):
            out.append(f"set {got['verdict']} {got['codes']}")
        if got["missing"] != declared.get("missing", []):
            out.append(f"missing {got['missing']}")
        limits = [r.get("withinLimit") for r in check["records"]]
        if "withinLimit" in declared and limits != declared["withinLimit"]:
            out.append(f"withinLimit {limits}")
        return out
    out = _record_problems(expected, check)
    if "dating" in expected and check.get("dating") != expected["dating"]:
        out.append(f"dating {check.get('dating')}")
    if entry["kind"] == "accept" and check.get("withinLimit") != expected.get("withinLimit"):
        out.append(f"withinLimit {check.get('withinLimit')}")
    return out


@pytest.mark.parametrize("draft_id", sorted(MEMBERS))
def test_member_agrees_with_the_corpus(draft_id: str) -> None:
    entry = MEMBERS[draft_id]
    found = _decide(entry)
    assert found["claim_type"] == audit_record.CLAIM_TYPE
    assert problems_of(entry, found["checks"][0]) == []


def test_every_member_is_read() -> None:
    agreed = [d for d, e in MEMBERS.items() if not problems_of(e, _decide(e)["checks"][0])]
    assert len(agreed) == len(MANIFEST["vectors"]) == sum(MANIFEST["counts"].values())


@pytest.mark.parametrize("on, past, code", [
    ("R19", "R3", "entry-received-after-anchor"),
    ("R20", "R6", "entry-received-before-issued"),
    ("R21", "R7", "entry-anchor-late"),
    ("R22", "R11", "entry-received-after-anchor"),
    ("R17", "R18", "entry-anchor-late"),
])
def test_each_dating_bound_is_a_pair(on: str, past: str, code: str) -> None:
    """On the bound the entry is well-formed and the record supported; one second past, refused."""
    assert _decide(MEMBERS[on])["decision"] == "supported"
    found = _decide(MEMBERS[past])
    assert (found["decision"], found["reason"]) == ("contradicted", code)


@pytest.mark.parametrize("draft_id", ["FR19", "FR20", "FR20a"])
def test_max_age_outside_the_ijson_range_is_refused(draft_id: str) -> None:
    found = _decide(MEMBERS[draft_id])
    assert (found["decision"], found["reason"]) == ("contradicted", "unsafe-integer")


def test_last_safe_max_age_and_skew_only_future_bound() -> None:
    assert _decide(MEMBERS["FR20b"])["decision"] == "supported"
    assert _decide(MEMBERS["FR18"])["decision"] == "supported"
    assert _decide(MEMBERS["FR9"])["reason"] == "evaluation-result-after-decision"


def test_a_trust_document_naming_another_observer_key_refuses_a_valid_record(tmp_path: Path) -> None:
    """The key comes from the consumer's trust document, never from the record."""
    trust = copy.deepcopy(MANIFEST)
    trust["keys"]["observer"]["publicKey"] = trust["keys"]["agent"]["publicKey"]
    (tmp_path / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
    entry = MEMBERS["A1"]
    (tmp_path / "statements").mkdir()
    (tmp_path / entry["file"]).write_bytes((DATA / entry["file"]).read_bytes())
    found = _decide(entry, tmp_path, "trust.json")
    assert found["decision"] == "contradicted"
    assert found["checks"][0]["verdict"] != "valid"


def test_an_unreadable_set_is_refused_as_a_set_not_read_as_an_envelope() -> None:
    entry = MEMBERS["X17"]
    found = _decide(entry)
    assert (found["decision"], found["reason"]) == ("contradicted", "set-unreadable")
    assert found["checks"][0]["shape"] == "set"


def test_a_retained_record_without_the_pinned_heads_dates_nothing(tmp_path: Path) -> None:
    trust = copy.deepcopy(MANIFEST)
    trust.pop("anchorTrust", None)
    (tmp_path / "trust.json").write_text(json.dumps(trust), encoding="utf-8")
    entry = MEMBERS["R1"]
    (tmp_path / "retained").mkdir()
    (tmp_path / entry["file"]).write_bytes((DATA / entry["file"]).read_bytes())
    check = _decide(entry, tmp_path, "trust.json")["checks"][0]
    assert "datedAt" not in check["dating"]
