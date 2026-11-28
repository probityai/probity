"""Second independent review of the approver-list change: the attacks, kept as permanent tests.

The first group fails on the commit under review (one report split between the two readers' inputs is pinned in
``node/probity-records-verify/test/many-approvers-r5.test.ts``; its fixture is regenerated and compared here). The
second group are attacks the change withstood; they stay as regression guards.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from probity_records import verify_journal
from probity_records.digests import principals_digest
from probity_records.erasure import (
    KEPT,
    PAYLOAD,
    EnvelopeError,
    Rule,
    Schema,
    member_subject,
    open_sealed,
    seal,
)
from probity_records.erasure_vectors import KEYS, LEAF, MEMBER_KEYS, SCHEMA, record
from probity_records.identity import check_principals
from probity_records.identity_vectors import base, second_approver

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g

FULL = base()["principals"]
CAROL = second_approver()[0]
CALL = {"name": "act.1", "sha256": "f" * 64}
FIXTURE = (Path(__file__).resolve().parents[3] / "node" / "probity-records-verify" / "test" / "fixtures"
           / "many-approvers-r5.json")
PAIR = [{"issuer": "https://idp.example", "subject": "carol"}, {"issuer": "https://idp.example", "subject": "dave"}]


def named(*who: str) -> dict:
    block = copy.deepcopy(FULL)
    members = []
    for n, w in enumerate(who):
        member = copy.deepcopy(FULL["approver"] if n == 0 else CAROL)
        member["subject"] = g.WHO.get(w, w)
        members.append(member)
    block["approver"] = members[0] if len(members) == 1 else members
    return block


def with_approver(block: dict, value: object) -> dict:
    out = copy.deepcopy(block)
    out["approver"] = value
    return out


def allow(block: dict, policy: str = "refunds2of2", threshold: int = 2, bindings: list | None = None) -> dict:
    both = [g.binding(g.OPS, g.WHO["ops"]), g.binding(g.LEAD, g.WHO["lead"])]
    return g.identity_call("authorize", block, decision="allow", reason="bound", threshold=threshold,
                           approval_policy=policy, approval_bindings=bindings or both)


def deny(block: dict) -> dict:
    bindings = [g.binding(g.OPS, g.WHO["ops"], approval={"outcome": "denied"}),
                g.binding(g.LEAD, g.WHO["lead"], approval={"outcome": "denied"})]
    return g.identity_call("authorize", block, decision="deny", reason="approval_denied", threshold=1,
                           approval_policy="refunds1of2", approval_bindings=bindings)


def one_allow() -> dict:
    return allow(named("ops"), "refunds1of2", 1, [g.binding(g.OPS, g.WHO["ops"])])


def pair_strings(reverse: bool = False) -> list[str]:
    """An approver "list" of two strings that spell one principal's issuer and subject: no principal at all."""
    pair = [FULL["approver"]["issuer"], g.WHO["ops"]]
    return pair[::-1] if reverse else pair


def split_rows() -> dict[str, list[dict]]:
    """The journals of the node fixture. P1 and P2: the allow names one approver in the single form, the intent's
    approver is two strings. C1 and C2 are controls both readers agree on."""
    return {
        "P1": [one_allow(), g.identity_call("intent", with_approver(named("ops"), pair_strings()))],
        "P2": [one_allow(), g.identity_call("intent", with_approver(named("ops"), pair_strings(reverse=True)))],
        "C1": [allow(named("ops", "lead")), g.identity_call("intent", named("lead", "ops"))],
        "C2": [deny(named("lead", "ops"))],
    }


def report(tmp_path: Path, records: list[dict]) -> tuple[dict, list[str], dict]:
    trust, _ = g.approvers_trust()
    j = g.identity_case(tmp_path, records)
    checkpoint = j.checkpoint()
    lines = [line for line in j.path.read_text().splitlines() if line.strip()]
    full = verify_journal(tmp_path, [g.GATE.public_pem()], checkpoint, trust=trust)
    return {k: full[k] for k in ("verdict", "records", "verified", "failures", "checkpoint")}, lines, checkpoint


def failures(tmp_path: Path, records: list[dict]) -> list[str]:
    return report(tmp_path, records)[0]["failures"]


def build_fixture(tmp_path: Path) -> list[dict]:
    _, doc = g.approvers_trust()
    rows = []
    for vid, records in split_rows().items():
        where = tmp_path / vid
        where.mkdir()
        expected, lines, checkpoint = report(where, records)
        rows.append({"id": vid, "journal": lines, "checkpoint": checkpoint, "keys": [g.GATE.public_pem().decode()],
                     "trust": doc, "expected": expected})
    return rows


# ---- defects --------------------------------------------------------------------------------------------------
def test_the_node_fixture_is_this_readers_report(tmp_path: Path) -> None:
    """The TypeScript twin must return this report field for field (many-approvers-r5.test.ts reads the fixture).
    It does not for P1 and P2: its ``parties`` spells one principal as the array [issuer, subject], which a list of
    those two strings equals, so it reports no ``principals_differ_from_permit`` where this reader does."""
    assert json.loads(FIXTURE.read_text()) == build_fixture(tmp_path)


@pytest.mark.parametrize("reverse", [False, True])
def test_two_strings_are_not_the_party_they_spell(tmp_path: Path, reverse: bool) -> None:
    """This reader's half of the split: an approver written as [issuer, subject] strings names no party, so the
    intent is not the permit's parties (and is refused as malformed). Green here; the node test is the red half."""
    found = failures(tmp_path, [one_allow(), g.identity_call("intent", with_approver(named("ops"),
                                                                                     pair_strings(reverse)))])
    assert "line_2:principals_differ_from_permit:intent" in found, found


def listed() -> dict:
    return record(approver=["carol@example.com", "dave@example.com"],
                  principals={"user": record()["principals"]["user"], "approver": PAIR})


def test_seal_refuses_one_key_under_two_member_subjects() -> None:
    """A subject key is one person's. The same key bytes passed as ``approver.0`` and ``approver.1`` are one key
    over the list under two names: destroying it erases both approvers and its holder reads both, which is what
    per-member sealing exists to prevent. The shortest way to silence ``field_names_several_subjects`` is exactly
    this map, so seal must refuse it."""
    one_key = {"user": KEYS["user"], member_subject(0): KEYS["approver"], member_subject(1): KEYS["approver"]}
    with pytest.raises(EnvelopeError) as err:
        seal(SCHEMA, listed(), one_key, CALL, "user", leaf=LEAF)
    assert err.value.code == "field_names_several_subjects"


ROLES_SCHEMA = Schema("example-vote-roles@2", (
    Rule("record_kind", KEPT), Rule("approver", PAYLOAD, "approver", personal=True),
    Rule("approver_roles", PAYLOAD, "approver", personal=True),
))  # fmt: skip


def test_one_approvers_own_list_still_seals_under_that_approvers_key() -> None:
    """Before the change this record sealed: one approver, whose field happens to hold a list (the roles they voted
    in). The change reads every list under the approver role as several people and refuses it ("lists 2
    approvers"), though the changelog says a record with no approver list seals byte for byte as before."""
    vote = {"record_kind": "vote", "approver": "carol@example.com", "approver_roles": ["finance", "security"]}
    sealed = seal(ROLES_SCHEMA, vote, KEYS, CALL, "approver", leaf=LEAF)
    assert sealed.erasure["roles"] == {"approver": "approver", "approver_roles": "approver"}


def test_one_approvers_own_list_is_never_split_over_other_peoples_keys() -> None:
    """With member keys present the same misreading mixes subjects, the defect per-member sealing set out to close:
    carol's second role is sealed under dave's key, so erasing dave destroys carol's data and dave's key reads it."""
    vote = {"record_kind": "vote", "approver": ["carol@example.com", "dave@example.com"],
            "approver_roles": ["finance", "security"]}  # carol's two roles; dave is the second approver
    try:
        roles = seal(ROLES_SCHEMA, vote, {**KEYS, **MEMBER_KEYS}, CALL, "approver", leaf=LEAF).erasure["roles"]
    except EnvelopeError:
        return  # refusing is sound: the schema does not say whose list this is
    assert roles.get("approver_roles.1") != member_subject(1), roles


# ---- attacks that held ----------------------------------------------------------------------------------------
def test_a_deny_naming_both_people_in_either_order_is_strict(tmp_path: Path) -> None:
    assert failures(tmp_path / "a", [deny(named("ops", "lead"))]) == []
    assert failures(tmp_path / "b", [deny(named("lead", "ops"))]) == []


def test_a_deny_list_naming_a_person_with_no_binding_is_refused(tmp_path: Path) -> None:
    assert failures(tmp_path, [deny(named("ops", "human:mallory"))]) == ["line_1:principal_approver_not_an_approval_signer"]


def expired_lead() -> list[dict]:
    return [g.binding(g.OPS, g.WHO["ops"]),
            g.binding(g.LEAD, g.WHO["lead"], approval={"expiresAt": "2026-05-01T00:00:00Z"})]


def test_an_expired_approval_is_not_counted_so_its_approver_cannot_be_listed(tmp_path: Path) -> None:
    """One of two approvals had expired when it was used: a 1-of-2 allow holds on the other. The list may not name
    the person whose approval did not count, and naming the counted one alone is strict."""
    listed_both = failures(tmp_path / "a", [allow(named("ops", "lead"), "refunds1of2", 1, expired_lead())])
    assert listed_both == ["line_1:principal_approver_not_an_approval_signer"]
    assert failures(tmp_path / "b", [allow(named("ops"), "refunds1of2", 1, expired_lead())]) == []


def test_an_expired_approval_cannot_make_a_two_of_two(tmp_path: Path) -> None:
    found = failures(tmp_path, [allow(named("ops", "lead"), "refunds2of2", 2, expired_lead())])
    assert "line_1:approvals_below_threshold:1:2" in found
    assert "line_1:principal_approver_not_an_approval_signer" in found


def test_a_one_of_two_that_two_people_gave_needs_both_named(tmp_path: Path) -> None:
    assert failures(tmp_path / "a", [allow(named("ops"), "refunds1of2", 1)]) == [
        "line_1:principals_below_strict:approvers-partial"]
    assert failures(tmp_path / "b", [allow(named("ops", "lead"), "refunds1of2", 1)]) == []


@pytest.mark.parametrize("approver", [
    pytest.param(lambda b: [b["approver"][0], b["approver"][0], b["approver"][1]], id="one-person-twice-among-three"),
    pytest.param(lambda b: [b["approver"][0]], id="list-of-one"),
    pytest.param(lambda b: None, id="null"),
    pytest.param(lambda b: [1, b["approver"][0]], id="a-number-and-a-principal"),
])
def test_a_malformed_intent_list_is_refused_and_is_not_the_permits_parties(tmp_path: Path, approver) -> None:
    both = named("ops", "lead")
    found = failures(tmp_path, [allow(both), g.identity_call("intent", with_approver(both, approver(both)))])
    assert "line_2:principals_differ_from_permit:intent" in found
    assert any(f.startswith("line_2:principal_approver") for f in found), found


def test_a_member_whose_credential_expired_refuses_the_block() -> None:
    v = next(c for c in json.loads((Path(__file__).resolve().parent.parent / "vectors" / "shared"
                                    / "identity.json").read_text()) if c["id"] == "ID41")
    block = copy.deepcopy(v["principals"])
    block["approver"][1]["expiresAt"] = "2026-11-08T11:59:59Z"
    assert check_principals(block, v["at"], v["pins"], set(v["approvers"])) == (
        ["principal_approver:principal_expired"], None)


def test_the_digest_orders_members_by_bytes_not_by_utf16_units() -> None:
    """U+FF5E sorts before U+1F600 by UTF-8 bytes and after it by UTF-16 code units; a reader that sorted the
    members as strings would give the other order. Both written orders have this one digest (pinned for the twin)."""
    block = copy.deepcopy(FULL)
    first, second = copy.deepcopy(FULL["approver"]), copy.deepcopy(FULL["approver"])
    first["subject"], second["subject"] = "～", "\U0001f600"
    block["approver"] = [first, second]
    swapped = with_approver(block, [second, first])
    assert principals_digest(block) == principals_digest(swapped)
    assert principals_digest(block) == json.loads(FIXTURE.with_name("many-approvers-r5-digest.json").read_text())["digest"]


def test_one_approver_erased_then_both() -> None:
    keys = {"user": KEYS["user"], **MEMBER_KEYS}
    sealed = seal(SCHEMA, listed(), keys, CALL, "user", leaf=LEAF)
    one = open_sealed(sealed.kept, sealed.erasure, sealed.blobs, {k: v for k, v in keys.items() if k != "approver.1"})
    assert one.fields["principals"]["approver"] == [PAIR[0], None]
    assert one.erased == ("approver.1", "principals.approver.1")
    none = open_sealed(sealed.kept, sealed.erasure, sealed.blobs, {"user": KEYS["user"]})
    assert "approver" not in none.fields["principals"]
    assert len(none.erased) == 4
