"""Defects in the approver-list change, found by an independent review and kept as permanent tests.

Each test is the record a correct reader must accept or the input a correct writer must refuse. Each one fails on the
commit under review; the fix proposals are in the review verdict. The TypeScript twin gives the same verdict on every
case here, so a fix lands in both readers and in the shared vectors together.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest
from probity_records import verify_journal
from probity_records.erasure import EnvelopeError, seal
from probity_records.erasure_vectors import KEYS, LEAF, SCHEMA, record
from probity_records.identity_vectors import base, second_approver

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g  # noqa: E402

FULL = base()["principals"]
CAROL = second_approver()[0]


def named(*who: str) -> dict:
    """The block naming ``who`` (keys of WHO); one name takes the single form."""
    block = copy.deepcopy(FULL)
    members = []
    for n, w in enumerate(who):
        member = copy.deepcopy(FULL["approver"] if n == 0 else CAROL)
        member["subject"] = g.WHO[w]
        members.append(member)
    block["approver"] = members[0] if len(members) == 1 else members
    return block


def refreshed(block: dict, index: int | None = None) -> dict:
    """The block with one approver's credential refreshed: a new token, the same person."""
    out = copy.deepcopy(block)
    member = out["approver"] if index is None else out["approver"][index]
    member["tokenDigest"] = "ab" * 32
    return out


def two_of_two(block: dict) -> dict:
    return g.identity_call("authorize", block, decision="allow", reason="bound", threshold=2,
                           approval_policy="refunds2of2",
                           approval_bindings=[g.binding(g.OPS, g.WHO["ops"]), g.binding(g.LEAD, g.WHO["lead"])])


def deny_of_two(block: dict) -> dict:
    """A deny resting on two people's denials; a deny counts nobody."""
    bindings = [g.binding(g.OPS, g.WHO["ops"], approval={"outcome": "denied"}),
                g.binding(g.LEAD, g.WHO["lead"], approval={"outcome": "denied"})]
    return g.identity_call("authorize", block, decision="deny", reason="approval_denied", threshold=1,
                           approval_policy="refunds1of2", approval_bindings=bindings)


def failures(tmp_path: Path, records: list[dict]) -> list[str]:
    trust, _ = g.approvers_trust()
    j = g.identity_case(tmp_path, records)
    return verify_journal(tmp_path, [g.GATE.public_pem()], j.checkpoint(), trust=trust)["failures"]


def test_a_deny_of_two_naming_one_approver_stays_strict(tmp_path: Path) -> None:
    """A deny counts nobody: its approver principal may name any approver whose binding it carries. Before the change
    this journal verified under a strict auditor; requiring every binding's approver named is a behaviour change the
    changelog does not state (it speaks only of an approval that COUNTED two or more people)."""
    assert failures(tmp_path, [deny_of_two(named("ops"))]) == []


def test_an_approver_list_credential_refresh_keeps_the_permits_parties(tmp_path: Path) -> None:
    """A credential may be refreshed between a permit's records and the parties may not change (issuer and subject per
    role). The single form tolerates a refresh; the list form compares whole credentials, so a refresh reads as other
    parties."""
    found = failures(tmp_path, [two_of_two(named("ops", "lead")),
                                g.identity_call("intent", refreshed(named("ops", "lead"), 1))])
    assert not any("principals_differ_from_permit" in f for f in found), found


def test_the_single_form_refresh_control_keeps_the_permits_parties(tmp_path: Path) -> None:
    """The control for the test above: the single form, one approval, the same refresh."""
    allow = g.identity_call("authorize", named("ops"), decision="allow", reason="bound", threshold=1,
                            approval_policy="refunds1of2", approval_bindings=[g.binding(g.OPS, g.WHO["ops"])])
    found = failures(tmp_path, [allow, g.identity_call("intent", refreshed(named("ops")))])
    assert not any("principals_differ_from_permit" in f for f in found), found


def test_the_same_approvers_in_another_order_are_the_same_parties(tmp_path: Path) -> None:
    """identity.py: the list's order is the writer's and the verdict never depends on it. The permit's parties check
    compares the list in order, so an intent naming the same two approvers reversed is refused."""
    found = failures(tmp_path, [two_of_two(named("ops", "lead")), g.identity_call("intent", named("lead", "ops"))])
    assert not any("principals_differ_from_permit" in f for f in found), found


def test_seal_refuses_an_approver_list_under_one_subject_key() -> None:
    """A subject key is one person's: destroying it erases that person. An approver list sealed under the one approver
    key puts several people under it, so erasing one erases the others and whoever holds it reads them all. Until
    sealing is per member, seal refuses rather than mix subjects."""
    both = record(principals={"user": record()["principals"]["user"],
                              "approver": [{"issuer": "https://idp.example", "subject": "carol"},
                                           {"issuer": "https://idp.example", "subject": "dave"}]})
    with pytest.raises(EnvelopeError) as err:
        seal(SCHEMA, both, KEYS, {"name": "act.1", "sha256": "f" * 64}, "user", leaf=LEAF)
    assert err.value.code == "field_names_several_subjects"
