"""Governance workflow: exceptions with owner, rationale and expiry under a quorum, and signed steps."""

from __future__ import annotations

import pytest

from probity_records import (
    EXCEPTION_ALLOW, GOVERNANCE_STEP, TOOL_CALL_RECORD, Journal, Signer, Trust, args_sha256, check_exception_call,
    count_votes, exception_body, exception_digest, exception_evidence, permit_id, raw_public, route_by_risk,
    sign_vote, step_predicate, tool_call_predicate, verify_journal,
)

ARGS = {"amount_cents": 250000, "customer_id": "cust-alice"}


def _policy():
    keys = {n: Signer.generate() for n in ("risk", "cfo", "legal")}
    return keys, {"policyId": "exceptions-high", "threshold": 2,
                  "approvers": {f"human:{n}": raw_public(k) for n, k in keys.items()}}


def _exception(expires="2099-01-01T00:00:00Z"):
    return exception_body(exception_id="EX-1", owner="human:risk", rationale="Year-end goodwill refunds",
                          tool="refund_payment", args={"amount_cents": {"type": "range", "max": 300000},
                                                       "customer_id": {"type": "pattern", "pattern": "cust-*"}},
                          not_before="2026-01-01T00:00:00Z", expires_at=expires, policy_id="exceptions-high",
                          requested_by="agent:refunds")


def _votes(keys, policy, digest, names=("risk", "cfo")):
    votes = [sign_vote(keys[n], approver=f"human:{n}", policy_id=policy["policyId"], request=digest,
                       issued_at="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z") for n in names]
    return count_votes(policy, digest, votes, "2026-06-01T00:00:00Z")


def _record(tmp_path, body, votes, policy, args=ARGS):
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    ev = exception_evidence(body, votes, policy, args)
    journal.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(args), tool_call_predicate(
        phase="authorize", decision="allow", reason=EXCEPTION_ALLOW, authority=ev,
        exception_digest=ev["exceptionDigest"], run_id="run", tool_call_id="c1", tool="refund_payment",
        args_sha256_hex=args_sha256(args), permit_id=permit_id("p", "c1", args_sha256(args))))
    return gate, journal


def test_exception_needs_owner_rationale_and_window() -> None:
    with pytest.raises(ValueError, match="owner_and_rationale"):
        exception_body(exception_id="x", owner="", rationale="r", tool="t", args={}, not_before="2026-01-01T00:00:00Z",
                       expires_at="2027-01-01T00:00:00Z", policy_id="p", requested_by="a")
    body = _exception("2026-07-01T00:00:00Z")
    assert check_exception_call(body, "refund_payment", ARGS, "2026-06-01T00:00:00Z") == "ok"
    assert check_exception_call(body, "refund_payment", ARGS, "2026-08-01T00:00:00Z") == "exception_expired"
    assert check_exception_call(body, "refund_payment", {**ARGS, "amount_cents": 400000},
                                "2026-06-01T00:00:00Z") == "exception_constraint_violation:amount_cents"


def test_approved_exception_verifies_offline(tmp_path) -> None:
    keys, policy = _policy()
    body = _exception()
    gate, journal = _record(tmp_path, body, _votes(keys, policy, exception_digest(body)), policy)
    trust = Trust(quorum_policies={"exceptions-high": policy})
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert report["verdict"] == "PASS", report["failures"]


def test_expired_or_underapproved_exception_fails_offline(tmp_path) -> None:
    keys, policy = _policy()
    trust = Trust(quorum_policies={"exceptions-high": policy})
    expired = _exception("2026-07-01T00:00:00Z")  # the record's own time is now, after expiry
    gate, journal = _record(tmp_path / "a", expired, _votes(keys, policy, exception_digest(expired)), policy)
    failures = verify_journal(tmp_path / "a", [gate.public_pem()], journal.checkpoint(), trust=trust)["failures"]
    assert any("exception_expired" in f for f in failures), failures
    body = _exception()
    gate, journal = _record(tmp_path / "b", body, _votes(keys, policy, exception_digest(body), ("risk",)), policy)
    failures = verify_journal(tmp_path / "b", [gate.public_pem()], journal.checkpoint(), trust=trust)["failures"]
    assert any("exception_quorum_pending" in f for f in failures), failures


def test_workflow_steps_are_signed_records_with_risk_routing(tmp_path) -> None:
    keys, policy = _policy()
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    intake = "ab" * 32
    route = route_by_risk("high", {"high": "exceptions-high", "low": "single-approver"})
    with pytest.raises(ValueError, match="no_route_for_risk_tier"):
        route_by_risk("unknown", {"high": "exceptions-high"})
    journal.append(GOVERNANCE_STEP, "intake:agent-7", intake,
                   step_predicate(kind="intake", subject_digest=intake, actor="human:pm", rationale="new refunds agent"))
    journal.append(GOVERNANCE_STEP, "route:agent-7", intake,
                   step_predicate(kind="risk_route", subject_digest=intake, actor="system:router", risk_tier="high",
                                  policy_id=route, refs={"intake": "1"}))
    votes = _votes(keys, policy, intake)
    journal.append(GOVERNANCE_STEP, "approval:agent-7", intake,
                   step_predicate(kind="approval", subject_digest=intake, actor="quorum:exceptions-high",
                                  decision="approve", quorum_evidence=votes.evidence(policy, intake)))
    journal.append(GOVERNANCE_STEP, "attest:agent-7", intake,
                   step_predicate(kind="attestation", subject_digest=intake, actor="human:legal",
                                  decision="attest", rationale="DPIA reviewed"))
    trust = Trust(quorum_policies={"exceptions-high": policy})
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert (report["verdict"], report["verified"]) == ("PASS", 4), report["failures"]
    journal.append(GOVERNANCE_STEP, "exception:agent-7", intake,
                   {**step_predicate(kind="exception", subject_digest=intake, actor="human:risk"), "owner": None})
    failures = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)["failures"]
    assert any("exception_step_needs_owner_rationale_expiry" in f for f in failures)
