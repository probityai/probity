"""Signed revocation: keys, permits and grants, append-only lists, root rotation, last-known-good cache."""

from __future__ import annotations

import pytest

from probity_records import (
    TOOL_CALL_RECORD, Journal, RevocationError, RevocationState, Signer, Trust,
    verify_grant_allow, grant_digest, issue_grant, raw_public, sign_approval, sign_revocations,
    tool_call_predicate, verify_approval_live, verify_journal,
)
from test_records import ARGS, _approval, _trust, _write_run

PAST = "2000-01-01T00:00:00Z"


def _list(root: Signer, seq: int, entries: list, previous=None) -> dict:
    return sign_revocations(root, list_id="rl", seq=seq, issued_at=PAST, entries=entries, previous=previous)


def test_revoked_approver_approval_is_refused() -> None:
    root, approver = Signer.generate(), Signer.generate()
    signed = sign_approval(approver, _approval(approver, "00" * 32))
    pems = {"human:ops": approver.public_pem()}
    clean = RevocationState.from_lists([], {root.key_id})
    assert verify_approval_live(signed, pems, clean, "2026-06-01T00:00:00Z") == signed["body"]
    state = RevocationState.from_lists(
        [_list(root, 1, [{"kind": "key", "id": approver.key_id, "revokedAt": "2026-05-01T00:00:00Z",
                          "reason": "laptop lost"}])], {root.key_id})
    assert verify_approval_live(signed, pems, state, "2026-06-01T00:00:00Z") is None
    assert verify_approval_live(signed, pems, state, "2026-04-01T00:00:00Z") == signed["body"]


def test_records_signed_after_revocation_fail_offline(tmp_path) -> None:
    root, gate, approver = Signer.generate(), Signer.generate(), Signer.generate()
    journal = Journal(tmp_path, gate)
    _write_run(journal, approver, "committed", "confirmed")
    lists = [_list(root, 1, [{"kind": "key", "id": gate.key_id, "revokedAt": PAST, "reason": "compromised"}])]
    trust = Trust(revocations=RevocationState.from_lists(lists, {root.key_id}))
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=trust)
    assert report["verdict"] == "FAIL"
    assert sum("signer_key_revoked" in f for f in report["failures"]) == 3
    approver_out = Trust(revocations=RevocationState.from_lists(
        [_list(root, 1, [{"kind": "key", "id": approver.key_id, "revokedAt": PAST, "reason": "left"}])],
        {root.key_id}), quorum_policies=_trust(("human:ops", approver)).quorum_policies)
    failures = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=approver_out)["failures"]
    assert any("approver_key_revoked" in f for f in failures), failures
    pid = journal.statements()[0]["predicate"]["permitId"]
    permit_out = Trust(revocations=RevocationState.from_lists(
        [_list(root, 1, [{"kind": "permit", "id": pid, "revokedAt": PAST, "reason": "cancelled"}])], {root.key_id}))
    failures = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=permit_out)["failures"]
    assert sum("permit_revoked" in f for f in failures) == 3
    clean = Trust(revocations=RevocationState.from_lists([], {root.key_id}),
                  quorum_policies=_trust(("human:ops", approver)).quorum_policies)
    assert verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint(), trust=clean)["verdict"] == "PASS"


def test_lists_are_signed_ordered_and_append_only() -> None:
    root, other = Signer.generate(), Signer.generate()
    first = _list(root, 1, [{"kind": "permit", "id": "p1", "revokedAt": PAST, "reason": "x"}])
    with pytest.raises(RevocationError, match="signer_not_a_root"):
        RevocationState.from_lists([_list(other, 1, [])], {root.key_id})
    dropped = _list(root, 2, [], previous=first)
    with pytest.raises(RevocationError, match="drops_entry"):
        RevocationState.from_lists([first, dropped], {root.key_id})
    with pytest.raises(RevocationError, match="out_of_order"):
        RevocationState.from_lists([first, _list(root, 2, first["body"]["entries"])], {root.key_id})
    tampered = {**first, "body": {**first["body"], "entries": []}}
    with pytest.raises(RevocationError, match="signature_unverified"):
        RevocationState.from_lists([tampered], {root.key_id})


def test_root_rotation_hands_over_to_the_successor() -> None:
    old, new = Signer.generate(), Signer.generate()
    first = _list(old, 1, [{"kind": "key", "id": old.key_id, "revokedAt": PAST, "reason": "rotation",
                            "successor": raw_public(new)}])
    second = _list(new, 2, first["body"]["entries"], previous=first)
    state = RevocationState.from_lists([first, second], {old.key_id})
    assert state.roots == frozenset({new.key_id}) and state.seq == 2
    with pytest.raises(RevocationError, match="signer_not_a_root"):
        RevocationState.from_lists([first, _list(old, 2, first["body"]["entries"], previous=first)], {old.key_id})


def test_revoking_a_parent_grant_revokes_its_descendants() -> None:
    root, agent, sub, rev = (Signer.generate() for _ in range(4))
    tools = {"t": {"args": {"n": {"type": "range", "max": 10}}}}
    parent = issue_grant(root, grant_id="p", holder_key=raw_public(agent), tools=tools, max_depth=1,
                         not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    child = issue_grant(agent, grant_id="c", holder_key=raw_public(sub), tools=tools, parent=parent,
                        not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    state = RevocationState.from_lists(
        [_list(rev, 1, [{"kind": "grant", "id": grant_digest(parent["body"]), "revokedAt": PAST, "reason": "x"}])],
        {rev.key_id})
    verdict = verify_grant_allow([parent, child], "t", {"n": 1}, "2026-06-01T00:00:00Z", {root.key_id},
                                    set(state.revoked_grants()), state.key_revoked)
    assert verdict["reason"] == "grant_revoked:0"
    key_state = RevocationState.from_lists(
        [_list(rev, 1, [{"kind": "key", "id": agent.key_id, "revokedAt": PAST, "reason": "x"}])], {rev.key_id})
    verdict = verify_grant_allow([parent, child], "t", {"n": 1}, "2026-06-01T00:00:00Z", {root.key_id},
                                    set(), key_state.key_revoked)
    assert verdict["reason"] == "grant_issuer_key_revoked:1"


