"""lifecycle_binding/v1: the binding-scope vectors and the domain-separation attacks, on our own bytes.

Every vector is built by lifecycle_builder.py from keys derived under a neutral seed label. V1 to V8 and
C0 are the cases a first-pair, unauthenticated or order-dependent reading gets wrong; A1 to A13 rebuild
the domain-separation attacks against this profile's six-tag registry.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import lifecycle_builder as b
import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import lifecycle_binding as lb


def _bind(name: str, blob: bytes) -> dict:
    return {"path": name, "length": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}


def _judge(tmp_path: Path, records: Any, revocation: dict | None = None, bindings: dict | None = None,
           raw: bytes | None = None, **extra: Any) -> dict:
    files = {"records.json": raw if raw is not None else json.dumps(records).encode(),
             "bindings.json": json.dumps(bindings or b.BINDINGS).encode(),
             "revocation.json": json.dumps(revocation or b.ACTIVE).encode(), **extra.pop("files", {})}
    for name, blob in files.items():
        (tmp_path / name).write_bytes(blob)
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {name: _bind(name, blob) for name, blob in files.items()}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "lifecycle_binding/v1", "records": "records.json", "bindings": "bindings.json",
        "revocation": "revocation.json", **extra}}}
    return adjudicate(case, policy, tmp_path)


DECISION_OF = {"satisfied": "supported", "failure": "contradicted"}


@pytest.mark.parametrize("name", sorted(b.vectors()))
def test_binding_scope_vector(tmp_path: Path, name: str) -> None:
    records, revocation, expected = b.vectors()[name]
    result = _judge(tmp_path, records, revocation)
    assert result["reason"] == expected
    assert result["decision"] == DECISION_OF.get(expected, "not_established")


def test_verdict_does_not_depend_on_array_order(tmp_path: Path) -> None:
    for i, (records, revocation, _) in enumerate(b.vectors().values()):
        (tmp_path / f"f{i}").mkdir()
        (tmp_path / f"r{i}").mkdir()
        forward = _judge(tmp_path / f"f{i}", records, revocation)
        backward = _judge(tmp_path / f"r{i}", list(reversed(records)), revocation)
        assert (forward["decision"], forward["reason"]) == (backward["decision"], backward["reason"])


def test_five_states_are_reported_and_missing_is_never_satisfied(tmp_path: Path) -> None:
    d, ci = b.decision(), b.control("c-issuer")
    result = _judge(tmp_path, [d, ci])
    assert (result["decision"], result["reason"]) == ("not_established", "missing")
    assert set(result["scope"]["evidence_states"]) == set(lb.STATES)
    assert result["scope"]["does_not_establish"].startswith("that the executed bytes")


def test_missing_decision_record_is_missing(tmp_path: Path) -> None:
    records = [b.control("c-issuer"), b.execution("e-1")]
    assert _judge(tmp_path, records)["reason"] == "missing"


def test_empty_set_is_never_satisfied(tmp_path: Path) -> None:
    assert (_judge(tmp_path, [])["decision"], _judge(tmp_path, [])["reason"]) == ("not_established", "empty_denominator")


def test_duplicate_decision_identity_makes_every_citing_group_indeterminate(tmp_path: Path) -> None:
    records = b.complete() + [b.decision()]
    assert _judge(tmp_path, records)["reason"] == "indeterminate"


def test_duplicate_identity_across_groups_is_indeterminate_in_both(tmp_path: Path) -> None:
    records = b.complete() + [b.control("e-1", instruction="pause-9")]
    result = _judge(tmp_path, records)
    assert {g["instruction"]: g["state"] for g in result["checks"]} == {"pause-1": "indeterminate",
                                                                         "pause-9": "indeterminate"}


def test_repeated_member_is_refused(tmp_path: Path) -> None:
    raw = json.dumps(b.complete()).encode().replace(b'"verb": "release"', b'"verb": "release", "verb": "hold"', 1)
    assert _judge(tmp_path, None, raw=raw)["reason"] == "no_duplicate_member"


def test_published_action_bytes_are_recomputed_per_pointer_convention(tmp_path: Path) -> None:
    action = b'{"op": "release", "target": "t-1"}'
    digest = "sha256:" + hashlib.sha256(b'{"op":"release","target":"t-1"}').hexdigest()
    d = b.decision()
    records = [d, b.control("c-issuer", digest), b.execution("e-1", digest)]
    (tmp_path / "ok").mkdir()
    ok = _judge(tmp_path / "ok", records, files={"action.json": action}, actions={"e-1": "action.json"})
    assert ok["reason"] == "satisfied"
    (tmp_path / "raw").mkdir()
    raw = _judge(tmp_path / "raw", records, files={"action.json": action}, actions={"e-1": "action.json"},
                 pointer_conventions={"executed_action_digest": "raw"})
    assert (raw["decision"], raw["reason"]) == ("contradicted", "failure")


def test_revocation_snapshot_is_required(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="revocation"):
        files = {"records.json": json.dumps(b.complete()).encode(), "bindings.json": json.dumps(b.BINDINGS).encode()}
        for name, blob in files.items():
            (tmp_path / name).write_bytes(blob)
        case = {"schema_version": "probity-case/v1", "case_id": "c",
                "artifacts": {name: _bind(name, blob) for name, blob in files.items()}}
        policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
            "claim_type": "lifecycle_binding/v1", "records": "records.json", "bindings": "bindings.json"}}}
        adjudicate(case, policy, tmp_path)


# --- A1 to A13 on our own bytes ------------------------------------------------------------------------

def _with(index: int, artifact: dict) -> list[dict]:
    records = b.complete()
    records[index] = artifact
    return records


def test_a1_one_body_under_two_hash_tags_gives_two_currents() -> None:
    body = b.decision()
    as_control = dict(body, artifact_type="control")
    assert lb.hash_preimage(body)[:60] != lb.hash_preimage(as_control)[:60]
    assert hashlib.sha256(lb.hash_preimage(body)).digest() != hashlib.sha256(
        lb.tag("control", "hash") + lb.hash_preimage(body).split(b"\n", 1)[1]).digest()


def test_a2_decision_retyped_as_execution_is_refused(tmp_path: Path) -> None:
    d = b.decision()
    retyped = b.retag(d, artifact_type="execution", record_id="e-x", decision_ref={"record_id": "d-1"},
                      instruction_id="pause-1", executed_action_digest=b.X, producer="executor")
    result = _judge(tmp_path, b.complete()[:3] + [retyped])
    assert (result["decision"], result["reason"]) == ("contradicted", "failure")
    assert "does not recompute" in result["checks"][0]["detail"]


def test_a3_decision_signature_replayed_on_a_control_is_refused(tmp_path: Path) -> None:
    records = b.complete()
    control = copy.deepcopy(records[1])
    forged_sig = b.key("governor").sign(lb.tag("decision", "signature") + b"\n"
                                        + lb.jcs_canonical._value({"current": control["integrity"]["current"],
                                                                   "suite": "ed25519"}).encode())
    control["integrity"]["signature"]["value"] = forged_sig.hex()
    assert _judge(tmp_path, _with(1, control))["reason"] == "failure"


def test_a5_untagged_hash_is_refused(tmp_path: Path) -> None:
    control = copy.deepcopy(b.complete()[1])
    untagged = hashlib.sha256(lb.hash_preimage(control).split(b"\n", 1)[1]).hexdigest()
    control["integrity"]["current"] = "sha256:" + untagged
    control["integrity"]["signature"]["value"] = b.key("governor").sign(
        lb.signature_preimage(control, "ed25519")).hex()
    assert _judge(tmp_path, _with(1, control))["reason"] == "failure"


@pytest.mark.parametrize("change", [{"artifact_type": "approval"}, {"artifact_type": "Control"},
                                    {"lifecycle_version": "v2"}, {"lifecycle_version": "V1"}])
def test_a6_a7_a9_unregistered_or_case_folded_tag_fails_closed(tmp_path: Path, change: dict) -> None:
    result = _judge(tmp_path, _with(1, b.retag(b.complete()[1], **change)))
    assert (result["decision"], result["reason"]) == ("contradicted", "unregistered_tag")
    with pytest.raises(lb.Refused):
        lb.tag("Control", "hash")


@pytest.mark.parametrize("separator", [b"\r\n", b"\n\n"])
def test_a8_crlf_or_extra_lf_preimage_is_refused(tmp_path: Path, separator: bytes) -> None:
    control = copy.deepcopy(b.complete()[1])
    body = lb.hash_preimage(control).split(b"\n", 1)[1]
    control["integrity"]["current"] = "sha256:" + hashlib.sha256(lb.tag("control", "hash") + separator + body).hexdigest()
    control["integrity"]["signature"]["value"] = b.key("governor").sign(
        lb.signature_preimage(control, "ed25519")).hex()
    assert _judge(tmp_path, _with(1, control))["reason"] == "failure"


def test_a9_version_rewritten_after_signing_is_refused(tmp_path: Path) -> None:
    sealed = b.seal(dict(b.complete()[1], note="v1 body"))
    rewritten = b.retag(sealed, note="rewritten")
    assert _judge(tmp_path, _with(1, rewritten))["reason"] == "failure"


def test_a11a_wire_alg_is_informative_only(tmp_path: Path) -> None:
    control = copy.deepcopy(b.complete()[1])
    control["integrity"]["signature"]["alg"] = "ml-dsa-65"
    assert _judge(tmp_path, _with(1, control))["reason"] == "satisfied"


def test_a11b_signature_over_another_suite_id_is_refused(tmp_path: Path) -> None:
    control = b.seal(b.complete()[1], suite="ed448")
    assert _judge(tmp_path, _with(1, control))["reason"] == "failure"


PENDING = {
    "A4": "head-witness signature replayed as a record signature: VERIFY-LIFECYCLE-BINDING head witnesses",
    "A10": "freshness replay against the signed witnessed_at: VERIFY-LIFECYCLE-BINDING head witnesses",
    "A12": "witness tag version against the head's declared version: VERIFY-LIFECYCLE-BINDING head witnesses",
    "A13": "witness suite against the trust-store binding: VERIFY-LIFECYCLE-BINDING head witnesses",
}


def test_pending_attacks_are_named_with_their_row() -> None:
    """A4, A10, A12 and A13 need head witnesses, which this profile version does not read."""
    assert sorted(PENDING) == ["A10", "A12", "A13", "A4"]
    assert all("VERIFY-LIFECYCLE-BINDING" in why for why in PENDING.values())


def test_registry_is_exactly_six_tags() -> None:
    assert sorted(lb.TAGS) == sorted(f"agent-evidence/lifecycle-binding/v1/{t}/{p}"
                                     for t in ("decision", "control", "execution") for p in ("hash", "signature"))


def test_v2_names_the_disagreeing_authorizations(tmp_path: Path) -> None:
    records, revocation, _ = b.vectors()["V2-receiver-disagrees"]
    assert "authorizing records in the group disagree" in _judge(tmp_path, records, revocation)["checks"][0]["detail"]


# --- authority that comes from the executor itself -----------------------------------------------------

def test_receiver_side_control_alone_is_never_an_authorization(tmp_path: Path) -> None:
    """The receiver side is the executor's side: its control records what it received, not what was allowed."""
    result = _judge(tmp_path, [b.decision(), b.control("c-receiver", side="receiver"), b.execution("e-1")])
    assert (result["decision"], result["reason"]) == ("not_established", "missing")
    assert "issuer-side control" in result["checks"][0]["detail"]


def test_issuer_control_signed_by_the_executor_is_self_authorized(tmp_path: Path) -> None:
    result = _judge(tmp_path, [b.decision(), b.control("c-issuer", producer="executor"), b.execution("e-1")])
    assert (result["decision"], result["reason"]) == ("contradicted", "failure")
    assert result["checks"][0]["detail"].startswith("self_authorized")


def test_executor_key_bound_under_a_second_producer_name_is_self_authorized(tmp_path: Path) -> None:
    alias = {**b.BINDINGS, "governor-2": b.BINDINGS["executor"]}
    control = b.seal(dict(b.control("c-issuer"), producer="governor-2"), signer="executor")
    result = _judge(tmp_path, [b.decision(), control, b.execution("e-1")], revocation={**b.ACTIVE, "governor-2":
                                                                                      {"state": "active"}},
                    bindings=alias)
    assert (result["decision"], result["reason"]) == ("contradicted", "failure")
    assert result["checks"][0]["detail"].startswith("self_authorized")


def test_issuer_control_with_an_executor_receiver_control_is_satisfied(tmp_path: Path) -> None:
    assert _judge(tmp_path, b.complete())["reason"] == "satisfied"


# --- action bytes the consumer names ---------------------------------------------------------------------

def test_named_action_bytes_that_are_unavailable_are_missing(tmp_path: Path) -> None:
    files = {"records.json": json.dumps(b.complete()).encode(), "bindings.json": json.dumps(b.BINDINGS).encode(),
             "revocation.json": json.dumps(b.ACTIVE).encode()}
    for name, blob in files.items():
        (tmp_path / name).write_bytes(blob)
    artifacts = {name: _bind(name, blob) for name, blob in files.items()}
    artifacts["action.json"] = _bind("action.json", b"{}")
    case = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": artifacts}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": {
        "claim_type": "lifecycle_binding/v1", "records": "records.json", "bindings": "bindings.json",
        "revocation": "revocation.json", "actions": {"e-1": "action.json"}}}}
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["reason"]) == ("not_established", "missing")
    assert "action bytes" in result["checks"][0]["detail"]


def test_action_naming_no_record_is_a_case_error(tmp_path: Path) -> None:
    from agent_evidence_verify import CaseError
    with pytest.raises(CaseError, match="names no record"):
        _judge(tmp_path, b.complete(), files={"action.json": b"{}"}, actions={"e-404": "action.json"})


@pytest.mark.parametrize("entry", [{"public_key_hex": 5, "suite": "ed25519"},
                                   {"public_key_hex": "AB" * 32, "suite": "ed25519"},
                                   {"public_key_hex": "ab" * 31, "suite": "ed25519"},
                                   {"public_key_hex": "ab" * 32, "suite": None}])
def test_malformed_key_binding_is_a_case_error(tmp_path: Path, entry: dict) -> None:
    from agent_evidence_verify import CaseError
    with pytest.raises(CaseError, match="bindings"):
        _judge(tmp_path, b.complete(), bindings={**b.BINDINGS, "governor": entry})
