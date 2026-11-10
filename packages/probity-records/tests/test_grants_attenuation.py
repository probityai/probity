"""Attenuating grants: CEL conditions, depth, context binding, shared budgets, grant-to-effect walk."""

from __future__ import annotations

import pytest

from probity_records import (
    GRANT_ALLOW, TOOL_CALL_RECORD, Journal, Signer, Trust, args_sha256, verify_grant_allow,
    build_uncertain_effect, check_constraint, grant_evidence, issue_grant, narrows, permit_id, raw_public,
    tool_call_predicate, verify_journal,
)
from probity_records.grants import GRANT_DOMAIN
from probity_records.core import _b64, canonical
from probity_records.walk import grant_walk, mint_grant_permit
from probity_records.core import verify_permit

AT = "2026-06-01T00:00:00Z"
NB, EXP = "2026-01-01T00:00:00Z", "2099-12-31T00:00:00Z"
ARGS = {"amount_cents": {"type": "range", "min": 1, "max": 4000},
        "currency": {"type": "cel", "expr": "value in ['USD', 'EUR']"}}
TOOLS = {"refund": {"approval": "none", "args": ARGS, "when": ["args.amount_cents < 3000 || args.currency == 'USD'"]}}
CALL = {"amount_cents": 2500, "currency": "EUR"}
CTX = {"workflowId": "refunds-42", "runId": "r1", "toolCallId": "c1"}
WF = {"workflowId": {"type": "pattern", "pattern": "refunds-*"}}


def _root(root: Signer, holder: Signer, **kw) -> dict:
    kw.setdefault("max_depth", 2)
    return issue_grant(root, grant_id="g-root", holder_key=raw_public(holder), tools=TOOLS,
                       not_before=NB, expires_at=EXP, **kw)


def _child(holder: Signer, sub: Signer, parent: dict, tools=TOOLS, **kw) -> dict:
    return issue_grant(holder, grant_id="g-child", holder_key=raw_public(sub), tools=tools, parent=parent,
                       not_before=NB, expires_at=EXP, **kw)


def test_cel_constraint_checks_and_only_conjunction_narrows() -> None:
    c = {"type": "cel", "expr": "value.startsWith('cust-') && size(value) < 12"}
    assert check_constraint(c, "cust-alice") and not check_constraint(c, "cust-alice-and-bob")
    assert not check_constraint(c, 7)  # a type error is a refusal, never an admit
    assert not check_constraint({"type": "cel", "expr": "1 + 1"}, "x")  # a non-boolean result refuses
    assert narrows(c, c)
    assert narrows({"type": "all", "of": [c, {"type": "pattern", "pattern": "cust-a*"}]}, c)
    assert not narrows({"type": "cel", "expr": "value.startsWith('cust-')"}, c)
    with pytest.raises(ValueError, match="cel_compile_failed"):
        check_constraint({"type": "cel", "expr": "value ==="}, "x")
    assert check_constraint({"type": "cel", "expr": "value == 3"}, 3.0)  # JCS cannot tell 3.0 from 3


def test_when_condition_spans_arguments_and_a_child_keeps_every_parent_condition() -> None:
    root, agent, sub = Signer.generate(), Signer.generate(), Signer.generate()
    chain = [_root(root, agent)]
    assert verify_grant_allow(chain, "refund", CALL, AT, {root.key_id})["decision"] == "allow"
    over = verify_grant_allow(chain, "refund", {"amount_cents": 3500, "currency": "EUR"}, AT, {root.key_id})
    assert over["reason"] == "condition_violation:0"
    dropped = {"refund": {**TOOLS["refund"], "when": []}}
    with pytest.raises(ValueError, match="child_drops_condition"):
        _child(agent, sub, chain[0], tools=dropped)
    added = {"refund": {**TOOLS["refund"], "when": [*TOOLS["refund"]["when"], "args.amount_cents <= 100"]}}
    child = _child(agent, sub, chain[0], tools=added)
    assert verify_grant_allow([*chain, child], "refund", CALL, AT, {root.key_id})["reason"] == "condition_violation:1"


def test_depth_bounds_delegation_and_a_forged_deep_chain_is_refused() -> None:
    root, a, b, c = (Signer.generate() for _ in range(4))
    flat = _root(root, a, max_depth=0)
    with pytest.raises(ValueError, match="parent_forbids_delegation"):
        _child(a, b, flat)
    parent = _root(root, a, max_depth=1)
    with pytest.raises(ValueError, match="child_depth_wider_than_parent"):
        _child(a, b, parent, max_depth=1)
    child = _child(a, b, parent)
    forged_body = {**child["body"], "grantId": "deeper", "holderKey": raw_public(c), "issuerKey": raw_public(b),
                   "parent": __import__("probity_records").grant_digest(child["body"])}
    forged = {"body": forged_body, "sig": _b64(b.sign(GRANT_DOMAIN + canonical(forged_body)))}
    verdict = verify_grant_allow([parent, child, forged], "refund", CALL, AT, {root.key_id})
    assert verdict["reason"] == "parent_forbids_delegation:2"


def test_context_binds_the_grant_to_a_workflow() -> None:
    root, agent, sub = Signer.generate(), Signer.generate(), Signer.generate()
    chain = [_root(root, agent, context=WF)]
    ok = verify_grant_allow(chain, "refund", CALL, AT, {root.key_id}, ctx=CTX)
    assert ok["decision"] == "allow"
    other = verify_grant_allow(chain, "refund", CALL, AT, {root.key_id}, ctx={**CTX, "workflowId": "payroll-1"})
    assert other["reason"] == "context_violation:workflowId"
    assert verify_grant_allow(chain, "refund", CALL, AT, {root.key_id})["reason"] == "context_violation:workflowId"
    with pytest.raises(ValueError, match="child_drops_context"):
        _child(agent, sub, chain[0])
    with pytest.raises(ValueError, match="child_widens_context"):
        _child(agent, sub, chain[0], context={"workflowId": {"type": "wildcard"}})


def test_use_after_expiry_and_before_start_are_refused() -> None:
    root, agent = Signer.generate(), Signer.generate()
    g = issue_grant(root, grant_id="g", holder_key=raw_public(agent), tools=TOOLS,
                    not_before="2026-05-01T00:00:00Z", expires_at="2026-06-01T00:00:00Z")
    assert verify_grant_allow([g], "refund", CALL, "2026-06-01T00:00:01Z", {root.key_id})["reason"].startswith(
        "grant_outside_window")
    assert verify_grant_allow([g], "refund", CALL, "2026-04-30T23:59:59Z", {root.key_id})["decision"] == "deny"


def _effect(args: dict) -> dict:
    return build_uncertain_effect(record_id="r", action="refund", operation_id="op", idempotency_key="k",
                                  args_sha256_hex=args_sha256(args),
                                  attempts=[{"dispatchedAt": "2026-06-01T00:00:01+00:00", "reply": "confirmed"}],
                                  owner_id="bank", owner_effects=1, outcome="committed",
                                  as_of="2026-06-01T00:00:05+00:00")


def _journal(tmp_path, gate: Signer, chain: list, calls: list, effect_grant=None) -> Journal:
    journal = Journal(tmp_path, gate)
    for n, args in enumerate(calls):
        pid = permit_id("p", f"c{n}", args_sha256(args))
        common = {"run_id": "r1", "tool_call_id": f"c{n}", "tool": "refund", "args_sha256_hex": args_sha256(args),
                  "permit_id": pid}
        verdict = verify_grant_allow(chain, "refund", args, AT, {r for r in ROOTS}, ctx=CTX)
        journal.append(TOOL_CALL_RECORD, f"tool-call:c{n}", args_sha256(args), tool_call_predicate(
            phase="authorize", decision="allow", reason=GRANT_ALLOW, authority=grant_evidence(chain, args, CTX),
            grant_digest=verdict["grantDigest"], **common))
        journal.append(TOOL_CALL_RECORD, f"tool-call:c{n}", args_sha256(args), tool_call_predicate(
            phase="intent", grant_digest=verdict["grantDigest"], **common))
        journal.append(TOOL_CALL_RECORD, f"tool-call:c{n}", args_sha256(args), tool_call_predicate(
            phase="effect", outcome="committed", uncertain_effect=_effect(args),
            grant_digest=effect_grant or verdict["grantDigest"], **common))
    return journal


ROOTS: set[str] = set()


def test_grant_to_effect_walk_passes_offline_and_a_swapped_grant_fails(tmp_path) -> None:
    gate, root, agent, sub = (Signer.generate() for _ in range(4))
    ROOTS.clear()
    ROOTS.add(root.key_id)
    parent = _root(root, agent, context=WF)
    child = _child(agent, sub, parent, context=WF)
    chain = [parent, child]
    journal = _journal(tmp_path / "ok", gate, chain, [CALL])
    trust = Trust(grant_root_key_ids=frozenset({root.key_id}))
    report = verify_journal(tmp_path / "ok", [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert report["verdict"] == "PASS", report["failures"]
    pid = permit_id("p", "c0", args_sha256(CALL))
    walk = grant_walk(report["statements"], pid)
    assert walk["ok"] and walk["outcome"] == "committed" and len(walk["grantChain"]) == 2
    assert (walk["authorize"], walk["intent"], walk["effect"]) == (1, 2, 3)
    permit = mint_grant_permit(gate, permit=pid, tool="refund", args_sha256_hex=args_sha256(CALL), chain=chain,
                               ctx=CTX, issued_at=AT)
    claims = verify_permit(permit, gate.public_pem())
    assert claims["grantDigest"] == walk["grantDigest"] and claims["grantChain"] == walk["grantChain"]
    swapped = _journal(tmp_path / "bad", gate, chain, [CALL], effect_grant="ab" * 32)
    bad = verify_journal(tmp_path / "bad", [gate.public_pem()], swapped.checkpoint(), trust=trust)
    assert "line_3:effect_grant_differs_from_permit" in bad["failures"]
    assert "effect_names_another_grant" in grant_walk(bad["statements"], pid)["problems"]


def test_verifier_recounts_budget_from_the_journal(tmp_path) -> None:
    gate, root, agent = (Signer.generate() for _ in range(3))
    ROOTS.clear()
    ROOTS.add(root.key_id)
    chain = [_root(root, agent, context=WF, budget={"uses": 2})]
    calls = [{"amount_cents": n, "currency": "USD"} for n in (1, 2, 3)]
    journal = _journal(tmp_path, gate, chain, calls)
    trust = Trust(grant_root_key_ids=frozenset({root.key_id}))
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert report["verdict"] == "FAIL"
    assert [f for f in report["failures"] if "budget" in f] == [
        f"line_7:grant_budget_exceeded:{__import__('probity_records').grant_digest(chain[0]['body'])[:12]}"]
