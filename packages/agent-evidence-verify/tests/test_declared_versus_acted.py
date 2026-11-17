"""``declared_versus_acted/v1`` on trajectories written by agent-evidence-observer's own recorder.

tests/data/declared-versus-acted was written by scripts/gen-declared-versus-acted-fixtures.py with
``probity_observer.resolution.ResolutionObserver`` and a witness key from a fixed seed. Each scenario
pins the decision, the reason and, through its calls, the denominator.
"""

import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.common import CaseError

DATA = Path(__file__).parent / "data" / "declared-versus-acted"
CASES = json.loads((DATA / "cases.json").read_text(encoding="utf-8"))


def run(folder: Path, row: dict, **changes) -> dict:
    names = ["trajectory.jsonl", "head.json"] + row["evidence"]
    artifacts = {}
    for name in names:
        body = (folder / name).read_bytes()
        artifacts[name] = {"path": name, "sha256": hashlib.sha256(body).hexdigest(), "length": len(body)}
    assessment = {"claim_type": "declared_versus_acted/v1", "trajectory": "trajectory.jsonl",
                  "head": "head.json", "trajectory_id": row["trajectory_id"],
                  "witness_key": row["witness_key"], "zone": row["zone"], "evidence": row["evidence"]}
    if row["key_authority"] is not None:
        assessment["key_authority"] = row["key_authority"]
    assessment.update(changes)
    case = {"schema_version": "probity-case/v1", "case_id": row["case"], "artifacts": artifacts}
    return adjudicate(case, {"schema_version": "probity-policy/v1",
                             "assessments": {row["case"]: assessment}}, folder)


@pytest.mark.parametrize("row", CASES, ids=lambda r: r["case"])
def test_every_scenario_reaches_its_decision_and_reason(row):
    result = run(DATA / row["case"], row)
    assert (result["decision"], result["reason"]) == (row["expected"], row["reason"])


def test_the_planted_undeclared_call_is_counted_and_named():
    row = next(r for r in CASES if r["case"] == "planted-undeclared-call")
    result = run(DATA / row["case"], row)
    assert result["scope"]["denominator"] == {"events": 3, "resolutions": 1, "calls": 2, "calls_bound": 1,
                                              "calls_contradicted": 1, "calls_unestablished": 0}
    bad = [c for c in result["checks"] if c["id"] == "call" and c["status"] == "fail"]
    assert [c["endpoint"] for c in bad] == ["https://collector.example.net/a2a"]


def test_no_calls_prints_the_denominator():
    row = next(r for r in CASES if r["case"] == "no-calls")
    result = run(DATA / row["case"], row)
    assert result["scope"]["denominator"]["calls"] == 0 and result["scope"]["denominator"]["events"] == 1


@pytest.mark.parametrize("change,reason", [
    ({"trajectory_id": "dva-another"}, "trajectory_head_other_trajectory"),
    ({"witness_key": "00" * 32}, "trajectory_head_other_key"),
])
def test_a_head_under_another_trajectory_or_key_is_contradicted(change, reason):
    row = next(r for r in CASES if r["case"] == "all-calls-bound")
    result = run(DATA / row["case"], row, **change)
    assert (result["decision"], result["reason"]) == ("contradicted", reason)


def test_an_edited_event_breaks_the_chain(tmp_path):
    row = next(r for r in CASES if r["case"] == "all-calls-bound")
    for name in ["head.json"] + row["evidence"]:
        (tmp_path / name).write_bytes((DATA / row["case"] / name).read_bytes())
    lines = (DATA / row["case"] / "trajectory.jsonl").read_bytes().splitlines(keepends=True)
    lines[1] = lines[1].replace(b"chat.example.com", b"chat.example.org")
    (tmp_path / "trajectory.jsonl").write_bytes(b"".join(lines))
    result = run(tmp_path, row)
    assert result["decision"] == "contradicted" and result["reason"].startswith("trajectory_")


def test_a_malformed_policy_is_a_case_error():
    row = next(r for r in CASES if r["case"] == "all-calls-bound")
    for change in ({"witness_key": "xyz"}, {"zone": ""}, {"canonicalization": "c14n"}, {"evidence": "jwks.json"}):
        with pytest.raises(CaseError):
            run(DATA / row["case"], row, **change)


def _copy(tmp_path: Path, row: dict, trajectory: bytes | None = None, head: bytes | None = None) -> Path:
    for name in ["trajectory.jsonl", "head.json"] + row["evidence"]:
        (tmp_path / name).write_bytes((DATA / row["case"] / name).read_bytes())
    if trajectory is not None:
        (tmp_path / "trajectory.jsonl").write_bytes(trajectory)
    if head is not None:
        (tmp_path / "head.json").write_bytes(head)
    return tmp_path


@pytest.mark.parametrize("old,new,reason", [(b"\n", b"\r", "trajectory_entry_malformed"),
                                            (b"\n", b"\r\n", "trajectory_entry_not_canonical")])
def test_a_line_ends_at_newline_and_nothing_else(tmp_path, old, new, reason):
    # bytes.splitlines also splits on \r, so these bytes once verified as the observer's trajectory
    # while a reader splitting on \n alone refused them: two readers, two verdicts.
    row = next(r for r in CASES if r["case"] == "all-calls-bound")
    raw = (DATA / row["case"] / "trajectory.jsonl").read_bytes()
    mutated = raw.replace(old, new, 1) if new == b"\r" else raw.replace(old, new)
    result = run(_copy(tmp_path, row, trajectory=mutated), row)
    assert (result["decision"], result["reason"]) == ("contradicted", reason)


def test_a_head_signature_has_one_base64_spelling(tmp_path):
    row = next(r for r in CASES if r["case"] == "all-calls-bound")
    head = json.loads((DATA / row["case"] / "head.json").read_text())
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body = head["signature"].rstrip("=")
    respelled = body[:-1] + alphabet[alphabet.index(body[-1]) ^ 1] + "=="  # same 64 bytes, other unused bits
    import base64
    assert base64.b64decode(respelled) == base64.b64decode(head["signature"])
    result = run(_copy(tmp_path, row, head=json.dumps(dict(head, signature=respelled)).encode()), row)
    assert (result["decision"], result["reason"]) == ("contradicted", "trajectory_head_signature_invalid")


@pytest.mark.parametrize("endpoint", [
    "https://collector.example.net\\@chat.example.com/a2a",  # urllib3 (requests) connects to collector
    "https://chat.example.com:443@collector.example.net/a2a",
    "https://chat.example.com%2F/a2a", "https://chat.example.com\t/a2a", "chat.example.com:99999"])
def test_an_endpoint_clients_read_differently_is_never_declared(endpoint):
    from agent_evidence_verify.adapters import declared_versus_acted
    with pytest.raises(ValueError):
        declared_versus_acted._endpoint(endpoint)


def test_the_backslash_endpoint_scenario_is_counted_as_contradicted():
    row = next(r for r in CASES if r["case"] == "endpoint-backslash-userinfo")
    result = run(DATA / row["case"], row)
    assert result["scope"]["denominator"]["calls_contradicted"] == 1
    assert [c["reason"] for c in result["checks"] if c["id"] == "call"] == ["call_endpoint_malformed"]


def test_a_resolution_with_a_malformed_time_is_a_malformed_event(tmp_path):
    from agent_evidence_verify.adapters import declared_versus_acted
    event = {"kind": "resolution", "name": "chat.example.com", "svcb": [], "sig": None, "jwks": None,
             "dnssec_chain_sha256": None, "at": "yesterday"}
    assert not declared_versus_acted._event_shape(event)
    assert declared_versus_acted._event_shape(dict(event, at="2026-11-15T20:59:00Z"))
