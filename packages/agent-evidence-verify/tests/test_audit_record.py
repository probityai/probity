"""agent_audit_record/v1 against every member of the agent audit record corpus.

tests/data/audit-record is corpora/vectors-agent-audit-record of probityai/agent-evidence-vectors at
3d5cfb198 (MANIFEST.json and the member files). Each member is judged through the public
``adjudicate`` entry point, under the corpus manifest as the trust document, and the check must
carry every field the member declares: the verdict and first code, the recomputed tier, the
consumption limit, the dating result of a retained record, and the joint result of a set. An open
(indeterminate) member must land on one of its listed readings.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import audit_record
from agent_evidence_verify.common import CaseError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


def _set_size(entry: dict[str, Any]) -> int:
    """How many records a set member's file holds, read off the file, not off the check."""
    records = json.loads((DATA / entry["file"]).read_bytes()).get("records")
    return len(records) if isinstance(records, list) else 0


def problems_of(entry: dict[str, Any], check: dict[str, Any]) -> list[str]:
    """How the check departs from what the member declares; empty when it agrees."""
    expected = entry["expected"]
    if entry["kind"] == "indeterminate":
        allowed = {reading["verdict"] for reading in entry["readings"]}
        return [] if check["verdict"] in allowed else [f"verdict {check['verdict']} not in {allowed}"]
    if "set" in expected:
        out = []
        held = _set_size(entry)
        if expected["set"]["codes"] != ["set-unreadable"] and len(check["records"]) != held:
            out.append(f"{len(check['records'])} records judged of the {held} the set holds")
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


# Hostile inputs: each was a crash, a wrong verdict or a shape the bytes chose before the reader
# and the adapter were fixed (probityai/agent-evidence-vectors scripts/auditrecord-hostile-input-test.py
# holds the reference reader to the same answers).


def _decide_bytes(body: bytes, shape: str, tmp_path: Path, trust: bytes | None = None) -> dict:
    (tmp_path / "record.json").write_bytes(body)
    (tmp_path / "trust.json").write_bytes(trust if trust is not None else (DATA / "MANIFEST.json").read_bytes())
    artifacts = {}
    for name, rel in (("record", "record.json"), ("trust", "trust.json")):
        data = (tmp_path / rel).read_bytes()
        artifacts[name] = {"path": rel, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    assessment = {"claim_type": audit_record.CLAIM_TYPE, "record": "record", "trust": "trust", "shape": shape}
    case = {"schema_version": "probity-case/v1", "case_id": "hostile", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"hostile": assessment}}
    return adjudicate(case, policy, tmp_path)


def _unsigned(payload: bytes) -> dict[str, Any]:
    return {"payload": base64.b64encode(payload).decode(), "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"keyid": "unknown", "sig": base64.b64encode(bytes(64)).decode()}]}


def test_the_shape_is_the_consumers_and_is_required(tmp_path: Path) -> None:
    """R7's dating fails; stripped to its envelope it must not pass because the bytes changed shape."""
    entry = MEMBERS["R7"]
    retained = (DATA / entry["file"]).read_bytes()
    assert _decide_bytes(retained, "retained", tmp_path)["reason"] == "entry-anchor-late"
    stripped = json.dumps(json.loads(retained)["envelope"]).encode()
    found = _decide_bytes(stripped, "retained", tmp_path)
    assert (found["decision"], found["reason"]) == ("contradicted", "retained-unreadable")
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {"c": {"claim_type": audit_record.CLAIM_TYPE, "record": "r", "trust": "t"}}}
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)
    with pytest.raises(CaseError, match="assessment.shape"):
        _decide_bytes(retained, "bundle", tmp_path)


@pytest.mark.parametrize("payload, code", [
    (b'{"a":"\\ud800"}', "not-parseable"),
    (b'{"\\udc00":1}', "not-parseable"),
    (b'{"a":' * 5000 + b"1" + b"}" * 5000, "nesting-too-deep"),
    (b'{"a":' * 500000 + b"1" + b"}" * 500000, "nesting-too-deep"),
    (b'{"n":1' + b"0" * 4300 + b"}", "unsafe-integer"),
    (b'{"a":NaN}', "not-parseable"),
    (b'{"a":[-Infinity]}', "not-parseable"),
])
def test_a_hostile_unsigned_payload_is_judged_not_raised(payload: bytes, code: str, tmp_path: Path) -> None:
    found = _decide_bytes(json.dumps(_unsigned(payload)).encode(), "envelope", tmp_path)
    assert (found["decision"], found["reason"]) == ("contradicted", code)


#: The corpus's published observer test key (gen_vectors.py derives it from this fixed seed).
OBSERVER_SEED = bytes.fromhex("00" * 31 + "33")


def _signed(statement: dict[str, Any]) -> bytes:
    reader = audit_record.reader
    canonical = reader.canonical_bytes(statement)
    key = Ed25519PrivateKey.from_private_bytes(OBSERVER_SEED)
    envelope = _unsigned(canonical)
    envelope["signatures"][0]["sig"] = base64.b64encode(
        key.sign(reader.pae(reader.PAYLOAD_TYPE, canonical))).decode()
    return json.dumps(envelope).encode()


def test_the_test_key_signs_a_member_the_reader_accepts(tmp_path: Path) -> None:
    statement = json.loads(base64.b64decode(json.loads((DATA / MEMBERS["A1"]["file"]).read_bytes())["payload"]))
    assert _decide_bytes(_signed(statement), "envelope", tmp_path)["decision"] == "supported"


@pytest.mark.parametrize("issued_at", ["2026-W38-6T11:04:11Z", "20260919T110411Z", "2026-09-19T11:04:11,5Z",
                                       "2026-09-19T11:04:11+0000", "2026-09-19 11:04:11Z"])
def test_a_signed_time_value_that_is_not_rfc3339_is_malformed(issued_at: str, tmp_path: Path) -> None:
    """A1 re-signed with issuedAt in an ISO 8601 form RFC 3339 does not allow."""
    statement = json.loads(base64.b64decode(json.loads((DATA / MEMBERS["A1"]["file"]).read_bytes())["payload"]))
    statement["predicate"]["issuedAt"] = issued_at
    found = _decide_bytes(_signed(statement), "envelope", tmp_path)
    assert (found["decision"], found["reason"]) == ("contradicted", "timestamp-malformed")


def test_the_rfc3339_lowercase_separator_and_zone_read(tmp_path: Path) -> None:
    statement = json.loads(base64.b64decode(json.loads((DATA / MEMBERS["A1"]["file"]).read_bytes())["payload"]))
    statement["predicate"]["issuedAt"] = statement["predicate"]["issuedAt"].lower()
    assert _decide_bytes(_signed(statement), "envelope", tmp_path)["decision"] == "supported"


@pytest.mark.parametrize("within, entry", [(3 * 10**11, "well-formed"), (2**53 - 1, "well-formed"),
                                           (2**53, "malformed")])
def test_any_anchor_within_is_judged_exactly(within: int, entry: str, tmp_path: Path) -> None:
    bundle = json.loads((DATA / MEMBERS["R1"]["file"]).read_bytes())
    bundle["retention"]["anchorWithin"] = within
    check = _decide_bytes(json.dumps(bundle).encode(), "retained", tmp_path)["checks"][0]
    assert check["dating"]["entry"] == entry


def test_an_issued_at_in_year_one_dates_without_overflow(tmp_path: Path) -> None:
    bundle = json.loads((DATA / MEMBERS["R2"]["file"]).read_bytes())
    statement = json.loads(base64.b64decode(bundle["envelope"]["payload"]))
    statement["predicate"]["issuedAt"] = "0001-01-01T00:00:00Z"
    envelope = _unsigned(audit_record.reader.canonical_bytes(statement))
    digest = hashlib.sha256(audit_record.reader.canonical_bytes(envelope)).hexdigest()
    bundle = {"envelope": envelope, "retention": dict(bundle["retention"], envelopeDigest=digest)}
    found = _decide_bytes(json.dumps(bundle).encode(), "retained", tmp_path)
    assert (found["decision"], found["reason"]) == ("contradicted", "signature-invalid")


def test_a_deep_retained_record_is_unreadable_not_raised(tmp_path: Path) -> None:
    bundle = json.loads((DATA / MEMBERS["R1"]["file"]).read_bytes())
    bundle["envelope"]["deep"] = json.loads('{"a":' * 900 + "1" + "}" * 900)
    found = _decide_bytes(json.dumps(bundle).encode(), "retained", tmp_path)
    assert (found["decision"], found["reason"]) == ("contradicted", "retained-unreadable")


@pytest.mark.parametrize("change", [
    lambda t: t.update(keys=[]),
    lambda t: t["keys"]["observer"].update(publicKey=7),
    lambda t: t.update(predicateType=["x"]),
    lambda t: t.update(anchorTrust={"treeHeads": [{"logId": "zz"}]}),
    lambda t: t.update(anchorTrust={"blockHeaders": [{"height": 1, "header": "00"}]}),
])
def test_an_unreadable_trust_document_is_the_consumers_error(change: Any, tmp_path: Path) -> None:
    trust = copy.deepcopy(MANIFEST)
    change(trust)
    with pytest.raises(CaseError, match="assessment.trust"):
        _decide_bytes((DATA / MEMBERS["R1"]["file"]).read_bytes(), "retained", tmp_path,
                      json.dumps(trust).encode())
