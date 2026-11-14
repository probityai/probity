"""M-of-N beyond one approver: proposer separation, roles, deputies, add-only policy delegation."""

from __future__ import annotations

import pytest

from probity_records import (
    GRANT_ALLOW, TOOL_CALL_RECORD, Journal, Signer, Trust, args_sha256, verify_grant_allow, grant_evidence,
    issue_grant, permit_id, raw_public, tool_call_predicate, verify_journal,
)
from probity_records.quorum import count, request_hash, sign_deputy, sign_vote, widening_problem

AT = "2026-06-01T00:00:00Z"
W = {"issued_at": "2026-05-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"}
ARGS = {"amount_cents": 90000}
NAMES = ("alice", "bob", "carol", "dave")


def _setup(threshold=2, roles=None):
    keys = {n: Signer.generate() for n in NAMES}
    policy = {"approvers": {n: raw_public(k) for n, k in keys.items() if n != "dave"}, "policyId": "pay",
              "proposerBound": True, "threshold": threshold}
    if roles:
        policy["roles"] = roles
    pid = permit_id("p", "c1", args_sha256(ARGS))
    req = request_hash("pay", args_sha256(ARGS), pid, proposer="alice", history="ab" * 32)
    return keys, policy, pid, req


def _v(keys, who, req, **kw):
    return sign_vote(keys[who], approver=who, policy_id="pay", request=req, **W, **kw)


def test_one_of_three_is_refused_where_two_are_required_and_the_proposer_never_counts() -> None:
    keys, policy, _, req = _setup()
    assert count(policy, req, [_v(keys, "bob", req)], AT, proposer="alice").status == "pending"
    own = count(policy, req, [_v(keys, "alice", req), _v(keys, "bob", req)], AT, proposer="alice")
    assert own.status == "pending" and "vote_by_proposer" in own.ignored
    assert count(policy, req, [_v(keys, "bob", req), _v(keys, "carol", req)], AT, proposer="alice").status == "approved"
    # with alice proposing, one rejection leaves 1 of the 2 remaining approvers: refused at once
    assert count(policy, req, [_v(keys, "bob", req, decision="reject")], AT, proposer="alice").status == "refused"


def test_one_person_cannot_fill_two_required_roles() -> None:
    roles = {"finance": {"members": ["bob", "carol"], "min": 1}, "security": {"members": ["bob", "alice"], "min": 1}}
    keys, policy, _, req = _setup(roles=roles)
    twice = count(policy, req, [_v(keys, "bob", req, role="finance"), _v(keys, "bob", req, role="security")], AT,
                  proposer="alice")
    assert twice.status != "approved" and "vote_duplicate_approver" in twice.ignored
    wrong = count(policy, req, [_v(keys, "carol", req, role="security")], AT, proposer="alice")
    assert "vote_role_not_held" in wrong.ignored
    ok = count(policy, req, [_v(keys, "carol", req, role="finance"), _v(keys, "bob", req, role="security")], AT,
               proposer="alice")
    assert ok.status == "approved"
    no_sec = count(policy, req, [_v(keys, "carol", req, role="finance"), _v(keys, "bob", req, role="finance")], AT,
                   proposer="alice")
    assert no_sec.status == "pending"  # threshold met, security role empty


def test_a_deputy_counts_as_the_delegator_once_and_never_as_a_second_vote() -> None:
    keys, policy, _, req = _setup()
    dep = sign_deputy(keys["bob"], delegator="bob", deputy="dave", deputy_key=raw_public(keys["dave"]),
                      policy_id="pay", roles=[], not_before="2026-05-01T00:00:00Z", expires_at="2026-07-01T00:00:00Z")
    by_dave = sign_vote(keys["dave"], approver="dave", policy_id="pay", request=req, deputy_for=dep, **W)
    assert count(policy, req, [by_dave, _v(keys, "carol", req)], AT, proposer="alice").status == "approved"
    both = count(policy, req, [by_dave, _v(keys, "bob", req)], AT, proposer="alice")
    assert both.status == "pending" and "vote_duplicate_approver" in both.ignored
    carol_dep = sign_deputy(keys["bob"], delegator="bob", deputy="carol", deputy_key=raw_public(keys["carol"]),
                            policy_id="pay", roles=[], not_before="2026-05-01T00:00:00Z",
                            expires_at="2026-07-01T00:00:00Z")
    double = sign_vote(keys["carol"], approver="carol", policy_id="pay", request=req, deputy_for=carol_dep, **W)
    assert "deputy_is_an_approver" in count(policy, req, [double], AT, proposer="alice").ignored
    forged = {**dep, "body": {**dep["body"], "expiresAt": "2099-01-01T00:00:00Z"}}
    late = sign_vote(keys["dave"], approver="dave", policy_id="pay", request=req, deputy_for=forged, **W)
    assert "deputy_delegation_unverified" in count(policy, req, [late], AT, proposer="alice").ignored


def test_policy_delegation_is_add_only() -> None:
    _, policy, _, _ = _setup()
    extra = {**policy, "approvers": {**policy["approvers"], "erin": "eA=="}}
    assert widening_problem({**policy, "threshold": 1}, policy) == "child_lowers_threshold"
    assert widening_problem(extra, policy) == "child_lowers_threshold"  # one added approver needs +1 threshold
    assert widening_problem({**extra, "threshold": 3}, policy) is None
    fewer = {**policy, "approvers": {k: v for k, v in policy["approvers"].items() if k != "carol"}}
    assert widening_problem(fewer, policy) == "child_removes_approver"
    assert widening_problem({**policy, "proposerBound": False}, policy) == "child_unbinds_proposer"
    assert widening_problem(None, policy) == "child_drops_quorum"


def test_grant_carried_quorum_verifies_offline_and_widening_delegation_is_refused(tmp_path) -> None:
    keys, policy, pid, req = _setup()
    root, agent, sub, gate = (Signer.generate() for _ in range(4))
    tools = {"pay": {"approval": "required", "quorum": policy, "args": {"amount_cents": {"type": "range", "max": 10**6}}}}
    parent = issue_grant(root, grant_id="g", holder_key=raw_public(agent), tools=tools, max_depth=1,
                         not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="child_lowers_threshold:pay"):
        issue_grant(agent, grant_id="c", holder_key=raw_public(sub), parent=parent,
                    tools={"pay": {**tools["pay"], "quorum": {**policy, "threshold": 1}}},
                    not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    chain = [parent]
    assert verify_grant_allow(chain, "pay", ARGS, AT, {root.key_id})["decision"] == "needs_approval"

    def record(directory, votes, proposer="alice"):
        result = count(policy, req, votes, AT, proposer=proposer)
        quorum = result.evidence(policy, req, proposer=proposer, history="ab" * 32)
        quorum["votes"] = list(votes)  # what a dishonest authority would write: every vote it got
        evidence = {**grant_evidence(chain, ARGS), "quorum": quorum}
        j = Journal(directory, gate)
        j.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(ARGS), tool_call_predicate(
            phase="authorize", decision="allow", reason=GRANT_ALLOW, authority=evidence,
            grant_digest=evidence["grantDigest"], run_id="r", tool_call_id="c1", tool="pay",
            args_sha256_hex=args_sha256(ARGS), permit_id=pid))
        return verify_journal(directory, [gate.public_pem()], j.checkpoint(),
                              trust=Trust(grant_root_key_ids=frozenset({root.key_id})))

    passed = record(tmp_path / "ok", [_v(keys, "bob", req), _v(keys, "carol", req)])
    assert passed["verdict"] == "PASS", passed["failures"]
    under = record(tmp_path / "under", [_v(keys, "bob", req)])
    assert any("grant_approval_quorum_pending" in f for f in under["failures"]), under["failures"]
    own = record(tmp_path / "own", [_v(keys, "alice", req), _v(keys, "bob", req)])
    assert any("grant_approval_quorum_vote_invalid:vote_by_proposer" in f for f in own["failures"]), own["failures"]
    # a record that drops the proposer changes the request hash, so the votes no longer match
    dropped = record(tmp_path / "dropped", [_v(keys, "bob", req), _v(keys, "carol", req)], proposer=None)
    assert dropped["verdict"] == "FAIL", dropped["failures"]
