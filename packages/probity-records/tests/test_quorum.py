"""M-of-N approvals: distinct approver keys, bound to one request, fetched and retried while pending."""

from __future__ import annotations

from probity_records import (
    QUORUM_ALLOW, TOOL_CALL_RECORD, Journal, Signer, StillPending, Trust, args_sha256, await_quorum, count_votes,
    issue_grant, permit_id, raw_public, request_hash, sign_vote, tool_call_predicate, verify_journal,
    grant_evidence, GRANT_ALLOW,
)

AT = "2026-06-01T00:00:00Z"
ARGS = {"amount_cents": 90000, "customer_id": "cust-alice"}


def _setup():
    keys = {name: Signer.generate() for name in ("ops", "finance", "legal")}
    policy = {"policyId": "refund-large", "threshold": 2,
              "approvers": {f"human:{n}": raw_public(k) for n, k in keys.items()}}
    pid = permit_id("pause", "c1", args_sha256(ARGS))
    req = request_hash("refund_payment", args_sha256(ARGS), pid)
    return keys, policy, pid, req


def _vote(keys, name, req, decision="approve", policy_id="refund-large"):
    return sign_vote(keys[name], approver=f"human:{name}", policy_id=policy_id, request=req,
                     issued_at="2026-05-31T00:00:00Z", expires_at="2099-06-02T00:00:00Z", decision=decision)


def test_two_of_three_approves_one_of_three_does_not() -> None:
    keys, policy, _, req = _setup()
    assert count_votes(policy, req, [_vote(keys, "ops", req), _vote(keys, "finance", req)], AT).status == "approved"
    assert count_votes(policy, req, [_vote(keys, "ops", req)], AT).status == "pending"
    two_no = [_vote(keys, "ops", req, "reject"), _vote(keys, "legal", req, "reject")]
    assert count_votes(policy, req, two_no, AT).status == "refused"


def test_one_key_never_counts_twice_and_foreign_votes_are_ignored() -> None:
    keys, policy, _, req = _setup()
    dup = count_votes(policy, req, [_vote(keys, "ops", req), _vote(keys, "ops", req)], AT)
    assert (dup.status, dup.ignored) == ("pending", ("vote_duplicate_approver",))
    impostor = sign_vote(keys["ops"], approver="human:finance", policy_id="refund-large", request=req,
                         issued_at="2026-05-31T00:00:00Z", expires_at="2099-06-02T00:00:00Z")
    other_req = _vote(keys, "legal", "ab" * 32)
    result = count_votes(policy, req, [_vote(keys, "ops", req), impostor, other_req], AT)
    assert result.status == "pending"
    assert set(result.ignored) == {"vote_signature_unverified", "vote_for_another_request"}
    late = count_votes(policy, req, [_vote(keys, "ops", req), _vote(keys, "legal", req)], "2099-06-03T00:00:00Z")
    assert late.status == "pending"


def test_fetch_handler_pending_is_retried_until_quorum() -> None:
    keys, policy, _, req = _setup()
    answers = [StillPending(), [_vote(keys, "finance", req)]]
    slept: list[float] = []

    def fetch(request: str):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    result = await_quorum(policy, req, supplied=[_vote(keys, "ops", req)], fetch=fetch, clock=lambda: AT,
                          attempts=3, wait_seconds=0.5, sleep=slept.append)
    assert (result.status, result.approvers, slept) == ("approved", ("human:finance", "human:ops"), [0.5])
    never = await_quorum(policy, req, fetch=lambda r: [], clock=lambda: AT, attempts=2, sleep=slept.append)
    assert never.status == "pending"


def test_quorum_record_verifies_offline_against_the_pinned_policy(tmp_path) -> None:
    keys, policy, pid, req = _setup()
    gate = Signer.generate()
    result = count_votes(policy, req, [_vote(keys, "ops", req), _vote(keys, "legal", req)], AT)
    common = {"run_id": "run", "tool_call_id": "c1", "tool": "refund_payment",
              "args_sha256_hex": args_sha256(ARGS), "permit_id": pid}
    journal = Journal(tmp_path, gate)
    journal.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason=QUORUM_ALLOW, authority=result.evidence(policy, req), **common))
    trust = Trust(quorum_policies={"refund-large": policy})
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert report["verdict"] == "PASS", report["failures"]
    weaker = {**policy, "threshold": 1}
    lax = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(),
                         trust=Trust(quorum_policies={"refund-large": weaker}))
    assert any("quorum_policy_differs_from_pinned" in f for f in lax["failures"])
    one = count_votes(policy, req, [_vote(keys, "ops", req)], AT)
    short = Journal(tmp_path / "short", gate)
    short.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason=QUORUM_ALLOW, authority=one.evidence(policy, req), **common))
    failures = verify_journal(tmp_path / "short", [gate.public_pem()], short.checkpoint(), trust=trust)["failures"]
    assert any("quorum_pending" in f for f in failures), failures


def test_grant_that_requires_approval_is_satisfied_by_a_quorum(tmp_path) -> None:
    keys, policy, pid, req = _setup()
    root, agent, gate = Signer.generate(), Signer.generate(), Signer.generate()
    tools = {"refund_payment": {"approval": "required", "args": {
        "amount_cents": {"type": "range", "min": 1, "max": 100000}, "customer_id": {"type": "wildcard"}}}}
    chain = [issue_grant(root, grant_id="g", holder_key=raw_public(agent), tools=tools,
                         not_before="2026-01-01T00:00:00Z", expires_at="2099-12-31T00:00:00Z")]
    evidence = {**grant_evidence(chain, ARGS),
                "quorum": count_votes(policy, req, [_vote(keys, "ops", req), _vote(keys, "finance", req)],
                                      AT).evidence(policy, req)}
    journal = Journal(tmp_path, gate)
    journal.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason=GRANT_ALLOW, authority=evidence,
        grant_digest=evidence["grantDigest"], run_id="run", tool_call_id="c1", tool="refund_payment",
        args_sha256_hex=args_sha256(ARGS), permit_id=pid))
    trust = Trust(grant_root_key_ids=frozenset({root.key_id}), quorum_policies={"refund-large": policy})
    assert verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)["verdict"] == "PASS"
