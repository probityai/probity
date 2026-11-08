"""Capability grants: per-call constraints, closed-world arguments, narrowing-only delegation."""

from __future__ import annotations

import pytest

from probity_records import (
    GRANT_ALLOW, TOOL_CALL_RECORD, Journal, Signer, Trust, args_sha256, authorize_under_grant, check_constraint,
    grant_evidence, issue_grant, narrows, permit_id, raw_public, tool_call_predicate, verify_journal,
)

AT = "2026-06-01T00:00:00Z"
TOOLS = {"refund_payment": {"approval": "none", "args": {
    "amount_cents": {"type": "range", "min": 1, "max": 4000},
    "customer_id": {"type": "pattern", "pattern": "cust-*"},
    "payee_account": {"type": "regex", "regex": "acct-[a-z]+"}}}}
CALL = {"amount_cents": 4000, "customer_id": "cust-alice", "payee_account": "acct-alice"}


def _root(issuer: Signer, holder: Signer, tools=TOOLS) -> dict:
    return issue_grant(issuer, grant_id="g-root", holder_key=raw_public(holder), tools=tools,
                       not_before="2026-01-01T00:00:00Z", expires_at="2099-12-31T00:00:00Z")


@pytest.mark.parametrize(("c", "good", "bad"), [
    ({"type": "exact", "value": 3}, 3, True),
    ({"type": "one_of", "values": ["a", "b"]}, "a", "c"),
    ({"type": "not_one_of", "values": ["root"]}, "bob", "root"),
    ({"type": "range", "min": 0, "max": 10}, 10, 11),
    ({"type": "pattern", "pattern": "staging-*"}, "staging-1", "prod-1"),
    ({"type": "regex", "regex": "[a-z]+"}, "abc", "abc1"),
    ({"type": "cidr", "network": "10.0.0.0/8"}, "10.1.2.3", "11.0.0.1"),
    ({"type": "url_pattern", "schemes": ["https"], "hosts": ["*.example.com"], "pathPrefix": "/api/"},
     "https://a.example.com/api/x", "https://a.example.com/admin"),
    ({"type": "url_safe"}, "https://example.com/x", "http://169.254.169.254/latest"),
    ({"type": "url_safe"}, "https://example.com/x", "https://user@example.com/"),
    ({"type": "subpath", "root": "/srv/data"}, "/srv/data/a.txt", "/srv/data/../etc/passwd"),
    ({"type": "shlex", "allow": ["ls"]}, "ls -la /tmp", "ls; rm -rf /"),
    ({"type": "contains", "values": ["x"]}, ["x", "y"], ["y"]),
    ({"type": "subset", "values": ["x", "y"]}, ["x"], ["z"]),
    ({"type": "all", "of": [{"type": "range", "min": 0}, {"type": "range", "max": 5}]}, 5, 6),
    ({"type": "any", "of": [{"type": "exact", "value": "a"}, {"type": "exact", "value": "b"}]}, "b", "c"),
    ({"type": "not", "of": {"type": "exact", "value": "a"}}, "b", "a"),
    ({"type": "wildcard"}, None, None),
])
def test_each_constraint_type_checks(c, good, bad) -> None:
    assert check_constraint(c, good)
    if c["type"] != "wildcard":
        assert not check_constraint(c, bad)


def test_narrowing_is_proved_or_refused() -> None:
    assert narrows({"type": "range", "min": 1, "max": 100}, {"type": "range", "min": 0, "max": 4000})
    assert not narrows({"type": "range", "min": 0, "max": 5000}, {"type": "range", "min": 0, "max": 4000})
    assert narrows({"type": "pattern", "pattern": "cust-a*"}, {"type": "pattern", "pattern": "cust-*"})
    assert not narrows({"type": "pattern", "pattern": "*"}, {"type": "pattern", "pattern": "cust-*"})
    assert narrows({"type": "one_of", "values": [5, 6]}, {"type": "range", "max": 10})
    assert narrows({"type": "subpath", "root": "/srv/data/a"}, {"type": "subpath", "root": "/srv/data"})
    assert not narrows({"type": "subpath", "root": "/srv"}, {"type": "subpath", "root": "/srv/data"})
    assert narrows({"type": "cidr", "network": "10.1.0.0/16"}, {"type": "cidr", "network": "10.0.0.0/8"})
    assert not narrows({"type": "regex", "regex": "a"}, {"type": "regex", "regex": "a|b"})
    assert narrows({"type": "url_safe", "hosts": ["api.example.com"]}, {"type": "url_safe"})
    assert not narrows({"type": "url_safe", "denyPrivate": False}, {"type": "url_safe"})
    assert not narrows({"type": "wildcard"}, {"type": "exact", "value": 1})


def test_out_of_scope_call_refused_with_no_human_in_the_loop() -> None:
    root, agent = Signer.generate(), Signer.generate()
    chain = [_root(root, agent)]
    roots = {root.key_id}
    assert authorize_under_grant(chain, "refund_payment", CALL, AT, roots)["decision"] == "allow"
    over = authorize_under_grant(chain, "refund_payment", {**CALL, "amount_cents": 400000}, AT, roots)
    assert (over["decision"], over["reason"]) == ("deny", "constraint_violation:amount_cents")
    extra = authorize_under_grant(chain, "refund_payment", {**CALL, "memo": "x"}, AT, roots)
    assert extra["reason"] == "argument_not_granted:memo"
    assert authorize_under_grant(chain, "delete_account", {}, AT, roots)["reason"] == "tool_not_granted"
    assert authorize_under_grant(chain, "refund_payment", CALL, "2100-01-01T00:00:00Z", roots)["decision"] == "deny"
    assert authorize_under_grant(chain, "refund_payment", CALL, AT, {"other"})["reason"] == "grant_root_untrusted"


def test_child_narrows_and_widening_child_is_refused() -> None:
    root, agent, sub = Signer.generate(), Signer.generate(), Signer.generate()
    parent = _root(root, agent)
    narrow = {"refund_payment": {"approval": "none", "args": {
        **TOOLS["refund_payment"]["args"], "amount_cents": {"type": "range", "min": 1, "max": 500}}}}
    child = issue_grant(agent, grant_id="g-child", holder_key=raw_public(sub), tools=narrow, parent=parent,
                        not_before="2026-02-01T00:00:00Z", expires_at="2026-11-30T00:00:00Z")
    verdict = authorize_under_grant([parent, child], "refund_payment", {**CALL, "amount_cents": 501}, AT, {root.key_id})
    assert verdict["reason"] == "constraint_violation:amount_cents"
    wide = {"refund_payment": {"approval": "none", "args": {
        **TOOLS["refund_payment"]["args"], "amount_cents": {"type": "range", "min": 1, "max": 400000}}}}
    with pytest.raises(ValueError, match="child_widens_constraint"):
        issue_grant(agent, grant_id="g-wide", holder_key=raw_public(sub), tools=wide, parent=parent,
                    not_before="2026-02-01T00:00:00Z", expires_at="2026-11-30T00:00:00Z")
    # A forged widening child, signed by the parent holder without the issue-time check, is still refused.
    forged = dict(child)
    forged_body = {**child["body"], "tools": wide}
    from probity_records.core import _b64, canonical
    from probity_records.grants import GRANT_DOMAIN
    forged = {"body": forged_body, "sig": _b64(agent.sign(GRANT_DOMAIN + canonical(forged_body)))}
    refused = authorize_under_grant([parent, forged], "refund_payment", CALL, AT, {root.key_id})
    assert refused["reason"].startswith("child_widens_constraint")
    with pytest.raises(ValueError, match="child_adds_argument"):
        issue_grant(agent, grant_id="g-x", holder_key=raw_public(sub), parent=parent,
                    tools={"refund_payment": {"args": {"memo": {"type": "wildcard"}}}},
                    not_before="2026-02-01T00:00:00Z", expires_at="2026-11-30T00:00:00Z")
    stranger = Signer.generate()
    with pytest.raises(ValueError, match="child_not_issued_by_parent_holder"):
        issue_grant(stranger, grant_id="g-y", holder_key=raw_public(sub), tools=narrow, parent=parent,
                    not_before="2026-02-01T00:00:00Z", expires_at="2026-11-30T00:00:00Z")


def test_grant_allow_record_verifies_offline_and_a_tampered_one_fails(tmp_path) -> None:
    gate, root, agent = Signer.generate(), Signer.generate(), Signer.generate()
    chain = [_root(root, agent)]
    journal = Journal(tmp_path, gate)
    verdict = authorize_under_grant(chain, "refund_payment", CALL, AT, {root.key_id})
    common = {"run_id": "run", "tool_call_id": "c1", "tool": "refund_payment",
              "args_sha256_hex": args_sha256(CALL), "permit_id": permit_id("p", "c1", args_sha256(CALL))}
    journal.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(CALL), tool_call_predicate(
        phase="authorize", decision="allow", reason=GRANT_ALLOW, authority=grant_evidence(chain, CALL),
        grant_digest=verdict["grantDigest"], **common))
    trust = Trust(grant_root_key_ids=frozenset({root.key_id}))
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert (report["verdict"], report["verified"]) == ("PASS", 1), report["failures"]
    assert verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint())["verdict"] == "FAIL"
    other = Trust(grant_root_key_ids=frozenset({Signer.generate().key_id}))
    assert verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=other)["verdict"] == "FAIL"
    bad = Journal(tmp_path / "bad", gate)
    over = {**CALL, "amount_cents": 400000}
    bad.append(TOOL_CALL_RECORD, "tool-call:c2", args_sha256(over), tool_call_predicate(
        phase="authorize", decision="allow", reason=GRANT_ALLOW, authority=grant_evidence(chain, over),
        grant_digest=verdict["grantDigest"], **{**common, "args_sha256_hex": args_sha256(over)}))
    failures = verify_journal(tmp_path / "bad", [gate.public_pem()], bad.checkpoint(), trust=trust)["failures"]
    assert any("grant_deny:constraint_violation:amount_cents" in f for f in failures), failures
