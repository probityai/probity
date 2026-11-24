"""probity-records: signatures, chain, checkpoint and the two published readers."""

from __future__ import annotations

import json

import pytest

from probity_records import (
    BINDING_MALFORMED,
    TOOL_CALL_RECORD,
    Journal,
    Signer,
    args_sha256,
    build_approval_binding,
    build_uncertain_effect,
    canonical,
    embed_approval_binding,
    judge_approval_binding,
    judge_uncertain_effect,
    key_id,
    permit_id,
    sign_approval,
    tool_call_predicate,
    verify_approval,
    verify_journal,
)
from probity_records.authority import Trust
from probity_records.clock import SystemClock
from probity_records.quorum import approval_policy

SYSTEM_CLOCK = SystemClock()  # these cases judge windows against the host's time

ARGS = {"amount_cents": 4000, "customer_id": "alice", "payee_account": "acct-alice"}


def _approval(signer: Signer, digest: str, who: str = "human:ops") -> dict:
    return {"approvalId": "appr-1", "approver": who, "event": "tools/call",
            "expiresAt": "2099-01-01T00:00:00Z", "issuedAt": "2026-01-01T00:00:00Z",
            "keyId": signer.key_id, "outcome": "approved", "payloadSha256": digest, "phase": "pre-execution",
            "principal": "customer:alice", "requestId": "req-1", "target": "acct-alice", "tool": "refund_payment"}


def _binding(approver: Signer, payload_args: dict, consumed: list[str], who: str = "human:ops", *,
             issued: tuple[str, ...] = ("appr-1",), enforcement: str = "enforce",
             approval: dict | None = None) -> tuple[dict, bytes]:
    approval = {**_approval(approver, args_sha256(ARGS), who), **(approval or {})}
    use = {k: approval[k] for k in ("approvalId", "event", "phase", "principal", "target", "tool")}
    use["usedAt"] = "2026-06-01T00:00:00Z"
    return build_approval_binding(approval, use, canonical(payload_args), consumed,
                                  {who: approver.key_id}, "2026-06-01T00:00:00Z",
                                  {"releaseId": "r1", "lookup": "ok", "graceSeconds": 300,
                                   "firstServedAt": "2026-01-01T00:00:00Z",
                                   "lastServedAt": "2099-01-01T00:00:00Z"},
                                  issued=issued, enforcement=enforcement)  # type: ignore[arg-type]


def test_permit_id_is_stable_and_bound_to_each_input() -> None:
    a = permit_id("pause", "call-1", "ab" * 32)
    assert a == permit_id("pause", "call-1", "ab" * 32)
    assert len({a, permit_id("pause2", "call-1", "ab" * 32), permit_id("pause", "call-2", "ab" * 32),
                permit_id("pause", "call-1", "cd" * 32)}) == 4


def test_approval_signature_binds_body_and_approver() -> None:
    approver, other = Signer.generate(), Signer.generate()
    signed = sign_approval(approver, _approval(approver, "00" * 32))
    assert verify_approval(signed, {"human:ops": approver.public_pem()}) == signed["body"]
    assert verify_approval(signed, {"human:ops": other.public_pem()}) is None
    tampered = {**signed, "body": {**signed["body"], "payloadSha256": "11" * 32}}
    assert verify_approval(tampered, {"human:ops": approver.public_pem()}) is None


def test_approval_binding_reader_allows_bound_and_refuses_replay_and_mutation() -> None:
    approver = Signer.generate()
    assert judge_approval_binding(*_binding(approver, ARGS, []))["decision"] == "allow"
    assert judge_approval_binding(*_binding(approver, ARGS, ["appr-1"]))["reason"] == "approval_replayed"
    mutated = {**ARGS, "amount_cents": 400000}
    assert judge_approval_binding(*_binding(approver, mutated, []))["reason"] == "payload_mismatch"


def test_builder_writes_the_servers_registers_and_mode_never_a_default() -> None:
    record, _ = _binding(Signer.generate(), ARGS, ["appr-0", "appr-0"], issued=("appr-2", "appr-1", "appr-1"))
    assert record["issuedApprovalIds"] == ["appr-1", "appr-2"]
    assert record["consumedApprovalIds"] == ["appr-0"]
    assert record["enforcement"] == "enforce"
    assert record["approval"]["outcome"] == "approved" and record["approval"]["requestId"] == "req-1"
    # the builder never adds the presented approval to the server's register on the server's behalf
    unissued, _ = _binding(Signer.generate(), ARGS, [], issued=())
    assert unissued["issuedApprovalIds"] == []


def test_approval_binding_reader_holds_issuance_outcome_and_mode() -> None:
    approver = Signer.generate()
    assert judge_approval_binding(*_binding(approver, ARGS, [], issued=("appr-0",)))["reason"] == "approval_not_issued"
    assert judge_approval_binding(*_binding(approver, ARGS, [], issued=()))["reason"] == "approval_not_issued"
    for outcome in ("denied", "rejected", None):
        verdict = judge_approval_binding(*_binding(approver, ARGS, [], approval={"outcome": outcome}))
        assert verdict == {"decision": "deny", "reason": "approval_not_granted"}, outcome
    corrected = judge_approval_binding(*_binding(approver, ARGS, [], approval={"outcome": "approved-with-corrections"}))
    assert corrected == {"decision": "allow", "reason": "bound"}
    for mode in ("observe", "monitor"):
        verdict = judge_approval_binding(*_binding(approver, ARGS, [], enforcement=mode))
        assert verdict == {"decision": "deny", "reason": "approval_not_enforced"}, mode


def test_builder_refuses_an_approval_without_a_request_or_an_unknown_mode() -> None:
    approver = Signer.generate()
    for request_id in (None, "", 7):
        with pytest.raises(ValueError, match="^approval_request_id_missing$"):
            _binding(approver, ARGS, [], approval={"requestId": request_id})
    for mode in ("enforced", "", "ENFORCE", "observe-only"):
        with pytest.raises(ValueError, match="^enforcement must be one of"):
            _binding(approver, ARGS, [], enforcement=mode)
    for issued in ("appr-1", ("appr-1", 1), ("",)):
        with pytest.raises(ValueError, match="^issued must be a list of approval identifiers$"):
            _binding(approver, ARGS, [], issued=issued)
    with pytest.raises(ValueError, match="^consumed must be a list of approval identifiers$"):
        _binding(approver, ARGS, "appr-0")  # type: ignore[arg-type]


def test_a_record_the_reader_cannot_read_is_a_deny_not_an_exception() -> None:
    record, payload = _binding(Signer.generate(), ARGS, [])
    no_request = {**record, "approval": {k: v for k, v in record["approval"].items() if k != "requestId"},
                  "presentedApprovals": [{k: v for k, v in record["approval"].items() if k != "requestId"}]}
    for broken in (no_request, {**record, "approval": []}, {**record, "use": {**record["use"], "usedAt": "never"}},
                   {k: v for k, v in record.items() if k != "policyRelease"}, {**record, "use": "x"}):
        assert judge_approval_binding(broken, payload) == {"decision": "deny", "reason": BINDING_MALFORMED}


def _effect(outcome: str, reply: str, owner_effects: int) -> dict:
    return build_uncertain_effect(record_id="r", action="refund_payment", operation_id="op",
                                  idempotency_key="k", args_sha256_hex=args_sha256(ARGS),
                                  attempts=[{"dispatchedAt": "2026-06-01T00:00:01+00:00", "reply": reply}],
                                  owner_id="bank", owner_effects=owner_effects, outcome=outcome,
                                  as_of="2026-06-01T00:00:05+00:00")


def test_uncertain_effect_reader() -> None:
    assert judge_uncertain_effect(_effect("committed", "confirmed", 1))["decision"] == "supported"
    assert judge_uncertain_effect(_effect("unknown", "connection_lost", 1))["decision"] == "supported"
    lie = judge_uncertain_effect(_effect("committed", "connection_lost", 1))
    assert (lie["decision"], lie["reason"]) == ("contradicted", "outcome_settled_without_authority")


def _embedded(approver: Signer, who: str = "human:ops") -> dict:
    record, payload = _binding(approver, ARGS, [], who)
    sig = sign_approval(approver, record["approval"])["sig"]
    return embed_approval_binding(record, payload, sig)


def _trust(*approvers: tuple[str, Signer], threshold: int = 1) -> Trust:
    policy = approval_policy("refunds", {who: s.public_pem() for who, s in approvers}, threshold)
    return Trust(quorum_policies={"refunds": policy})


def _write_run(journal: Journal, approver: Signer, outcome: str, reply: str) -> str:
    pid = permit_id("pause", "call-1", args_sha256(ARGS))
    common = {"run_id": "run", "tool_call_id": "call-1", "tool": "refund_payment",
              "args_sha256_hex": args_sha256(ARGS), "permit_id": pid}
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason="bound",
        approval_bindings=[_embedded(approver)], threshold=1, approval_policy="refunds", **common))
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS),
                   tool_call_predicate(phase="intent", **common))
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="effect", outcome=outcome, uncertain_effect=_effect(outcome, reply, 1), **common))
    return pid


def test_journal_verifies_offline_and_reports_denominator(tmp_path) -> None:
    gate, approver = Signer.generate(), Signer.generate()
    journal = Journal(tmp_path, gate, clock=SYSTEM_CLOCK)
    _write_run(journal, approver, "committed", "confirmed")
    trust = _trust(("human:ops", approver))
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert (report["verdict"], report["verified"], report["records"]) == ("PASS", 3, 3), report["failures"]
    assert verify_journal(tmp_path, [gate.public_pem()], trust=trust)["verdict"] == "NOT_ESTABLISHED"
    unpinned = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint())
    assert any("authority_trust_not_pinned:approval" in f for f in unpinned["failures"])


def test_tamper_truncation_and_wrong_key_fail(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate, clock=SYSTEM_CLOCK)
    _write_run(journal, Signer.generate(), "committed", "confirmed")
    checkpoint = journal.checkpoint()
    assert verify_journal(tmp_path, [Signer.generate().public_pem()], checkpoint)["verified"] == 0
    lines = journal.path.read_text().splitlines()
    journal.path.write_text("\n".join(lines[:2]) + "\n")
    report = verify_journal(tmp_path, [gate.public_pem()], checkpoint)
    assert report["verdict"] == "FAIL"
    assert any(f.startswith("checkpoint_count_mismatch:") for f in report["failures"])
    assert any("open_intent_no_effect_record" in f for f in report["failures"])
    env = json.loads(lines[0])
    env["payload"] = env["payload"][:-8] + "AAAAAAA="
    journal.path.write_text(json.dumps(env) + "\n" + "\n".join(lines[1:]) + "\n")
    assert verify_journal(tmp_path, [gate.public_pem()], checkpoint)["verdict"] == "FAIL"


def test_effect_record_claiming_success_after_lost_reply_fails(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate, clock=SYSTEM_CLOCK)
    approver = Signer.generate()
    _write_run(journal, approver, "committed", "connection_lost")
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=_trust(("human:ops", approver)))
    assert report["verdict"] == "FAIL"
    assert any("outcome_settled_without_authority" in f for f in report["failures"])


def test_key_id_matches_agent_evidence_verify() -> None:
    from agent_evidence_verify.dsse import key_id as verifier_key_id
    signer = Signer.generate()
    assert key_id(signer.public) == verifier_key_id(signer.public)


def _allow(journal: Journal, bindings: list[dict], threshold: int) -> None:
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason="bound", approval_bindings=bindings, threshold=threshold,
        approval_policy="refunds", run_id="run", tool_call_id="call-1", tool="refund_payment",
        args_sha256_hex=args_sha256(ARGS), permit_id=permit_id("pause", "call-1", args_sha256(ARGS))))


def test_allow_is_recounted_under_the_pinned_policy(tmp_path) -> None:
    gate, ops, lead = Signer.generate(), Signer.generate(), Signer.generate()
    journal = Journal(tmp_path, gate, clock=SYSTEM_CLOCK)
    _allow(journal, [_embedded(ops)], 2)
    report = verify_journal(tmp_path, [gate.public_pem()], trust=_trust(("human:ops", ops), ("human:lead", lead), threshold=2))
    assert any("approvals_below_threshold:1:2" in f for f in report["failures"]), report["failures"]


def test_authority_cannot_lower_the_threshold_or_fabricate_approvers(tmp_path) -> None:
    gate, ops, lead, forger = Signer.generate(), Signer.generate(), Signer.generate(), Signer.generate()
    trust = _trust(("human:ops", ops), ("human:lead", lead), threshold=2)
    # the authority writes threshold 1 although the auditor pinned 2
    journal = Journal(tmp_path / "low", gate, clock=SYSTEM_CLOCK)
    _allow(journal, [_embedded(ops)], 1)
    report = verify_journal(tmp_path / "low", [gate.public_pem()], trust=trust)
    assert any("threshold_not_pinned:1:2" in f for f in report["failures"]), report["failures"]
    # the authority signs a second "human:ops" approval with its own key: the pinned key refuses it
    fake = _embedded(forger, "human:lead")
    journal = Journal(tmp_path / "forged", gate, clock=SYSTEM_CLOCK)
    _allow(journal, [_embedded(ops), fake], 2)
    report = verify_journal(tmp_path / "forged", [gate.public_pem()], trust=trust)
    assert report["verdict"] == "FAIL"
    assert any("approval_signature_unverified" in f or "approval_key_id_is_not_the_pinned_key" in f
               for f in report["failures"]), report["failures"]
    # the same approver twice counts once
    journal = Journal(tmp_path / "twice", gate, clock=SYSTEM_CLOCK)
    _allow(journal, [_embedded(ops), _embedded(ops)], 2)
    report = verify_journal(tmp_path / "twice", [gate.public_pem()], trust=trust)
    assert any("duplicate_approver" in f for f in report["failures"]), report["failures"]
    # two real approvers pass
    journal = Journal(tmp_path / "ok", gate, clock=SYSTEM_CLOCK)
    _allow(journal, [_embedded(ops), _embedded(lead, "human:lead")], 2)
    report = verify_journal(tmp_path / "ok", [gate.public_pem()], trust=trust)
    assert not report["failures"], report["failures"]


def test_append_reads_only_new_bytes_and_sees_other_writers(tmp_path) -> None:
    gate = Signer.generate()
    a, b = Journal(tmp_path, gate, clock=SYSTEM_CLOCK), Journal(tmp_path, gate, clock=SYSTEM_CLOCK)
    for n in range(5):
        (a if n % 2 else b).append("t", f"s{n}", "00" * 32, {"n": n})
    seqs = [s["predicate"]["seq"] for s in a.statements()]
    assert seqs == [1, 2, 3, 4, 5]
    report = verify_journal(tmp_path, [gate.public_pem()], a.checkpoint())
    assert report["verdict"] == "PASS", report["failures"]
