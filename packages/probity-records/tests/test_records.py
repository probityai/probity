"""probity-records: signatures, chain, checkpoint and the two published readers."""

from __future__ import annotations

import json

from probity_records import (
    TOOL_CALL_RECORD, Journal, Signer, args_sha256, build_approval_binding, build_uncertain_effect,
    canonical, embed_approval_binding, judge_approval_binding, judge_approval_binding_on_disk, judge_uncertain_effect, key_id,
    permit_id, sign_approval, tool_call_predicate, verify_approval, verify_journal,
)

ARGS = {"amount_cents": 4000, "customer_id": "alice", "payee_account": "acct-alice"}


def _approval(signer: Signer, digest: str) -> dict:
    return {"approvalId": "appr-1", "approver": "human:ops", "event": "tools/call",
            "expiresAt": "2099-01-01T00:00:00Z", "issuedAt": "2026-01-01T00:00:00Z",
            "keyId": signer.key_id, "payloadSha256": digest, "phase": "pre-execution",
            "principal": "customer:alice", "target": "acct-alice", "tool": "refund_payment"}


def _binding(approver: Signer, payload_args: dict, consumed: list[str]) -> tuple[dict, bytes]:
    approval = _approval(approver, args_sha256(ARGS))
    use = {k: approval[k] for k in ("approvalId", "event", "phase", "principal", "target", "tool")}
    use["usedAt"] = "2026-06-01T00:00:00Z"
    return build_approval_binding(approval, use, canonical(payload_args), consumed,
                                  {"human:ops": approver.key_id}, "2026-06-01T00:00:00Z",
                                  {"releaseId": "r1", "lookup": "ok", "graceSeconds": 300,
                                   "firstServedAt": "2026-01-01T00:00:00Z",
                                   "lastServedAt": "2099-01-01T00:00:00Z"})


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


def _write_run(journal: Journal, approver: Signer, outcome: str, reply: str) -> str:
    pid = permit_id("pause", "call-1", args_sha256(ARGS))
    record, payload = _binding(approver, ARGS, [])
    common = {"run_id": "run", "tool_call_id": "call-1", "tool": "refund_payment",
              "args_sha256_hex": args_sha256(ARGS), "permit_id": pid}
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason="bound",
        approval_bindings=[embed_approval_binding(record, payload)], threshold=1, **common))
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS),
                   tool_call_predicate(phase="intent", **common))
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="effect", outcome=outcome, uncertain_effect=_effect(outcome, reply, 1), **common))
    return pid


def test_journal_verifies_offline_and_reports_denominator(tmp_path) -> None:
    gate, approver = Signer.generate(), Signer.generate()
    journal = Journal(tmp_path, gate)
    _write_run(journal, approver, "committed", "confirmed")
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint())
    assert (report["verdict"], report["verified"], report["records"]) == ("PASS", 3, 3), report["failures"]
    assert verify_journal(tmp_path, [gate.public_pem()])["verdict"] == "NOT_ESTABLISHED"


def test_tamper_truncation_and_wrong_key_fail(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    _write_run(journal, Signer.generate(), "committed", "confirmed")
    checkpoint = journal.checkpoint()
    assert verify_journal(tmp_path, [Signer.generate().public_pem()], checkpoint)["verified"] == 0
    lines = journal.path.read_text().splitlines()
    journal.path.write_text("\n".join(lines[:2]) + "\n")
    report = verify_journal(tmp_path, [gate.public_pem()], checkpoint)
    assert report["verdict"] == "FAIL"
    assert any(f.startswith("checkpoint_count") for f in report["failures"])
    assert any("open_intent_no_effect_record" in f for f in report["failures"])
    env = json.loads(lines[0])
    env["payload"] = env["payload"][:-8] + "AAAAAAA="
    journal.path.write_text(json.dumps(env) + "\n" + "\n".join(lines[1:]) + "\n")
    assert verify_journal(tmp_path, [gate.public_pem()], checkpoint)["verdict"] == "FAIL"


def test_effect_record_claiming_success_after_lost_reply_fails(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    _write_run(journal, Signer.generate(), "committed", "connection_lost")
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint())
    assert report["verdict"] == "FAIL"
    assert any("outcome_settled_without_authority" in f for f in report["failures"])


def test_key_id_matches_agent_evidence_verify() -> None:
    from agent_evidence_verify.dsse import key_id as verifier_key_id
    signer = Signer.generate()
    assert key_id(signer.public) == verifier_key_id(signer.public)


def test_in_memory_reader_agrees_with_the_file_reader() -> None:
    approver = Signer.generate()
    cases = [_binding(approver, ARGS, []), _binding(approver, ARGS, ["appr-1"]),
             _binding(approver, {**ARGS, "amount_cents": 400000}, [])]
    record, payload = _binding(approver, ARGS, [])
    cases.append(({**record, "trustedKeys": {"human:ops": "00" * 32}}, payload))
    cases.append(({**record, "use": {**record["use"], "principal": "someone-else"}}, payload))
    for record, payload in cases:
        assert judge_approval_binding(record, payload) == judge_approval_binding_on_disk(record, payload)


def test_allow_needs_its_threshold_of_reader_allowed_bindings(tmp_path) -> None:
    gate, approver = Signer.generate(), Signer.generate()
    journal = Journal(tmp_path, gate)
    record, payload = _binding(approver, ARGS, [])
    pid = permit_id("pause", "call-1", args_sha256(ARGS))
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason="bound", approval_bindings=[embed_approval_binding(record, payload)],
        threshold=2, run_id="run", tool_call_id="call-1", tool="refund_payment",
        args_sha256_hex=args_sha256(ARGS), permit_id=pid))
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint())
    assert any("reader_allows_1_of_2" in f for f in report["failures"]), report["failures"]


def test_append_reads_only_new_bytes_and_sees_other_writers(tmp_path) -> None:
    gate = Signer.generate()
    a, b = Journal(tmp_path, gate), Journal(tmp_path, gate)
    for n in range(5):
        (a if n % 2 else b).append("t", f"s{n}", "00" * 32, {"n": n})
    seqs = [s["predicate"]["seq"] for s in a.statements()]
    assert seqs == [1, 2, 3, 4, 5]
    report = verify_journal(tmp_path, [gate.public_pem()], a.checkpoint())
    assert report["verdict"] == "PASS", report["failures"]
