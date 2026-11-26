"""Four-principal identity block: conformance vectors, act grading, escrowed-token re-verification."""

from __future__ import annotations

import hashlib

from probity_records import (
    TOOL_CALL_RECORD,
    Journal,
    Signer,
    Trust,
    args_sha256,
    permit_id,
    tool_call_predicate,
    verify_journal,
)
from probity_records.clock import SystemClock
from probity_records.identity import check_principals, strict_shortfall, verify_token
from probity_records.identity_vectors import (
    ISSUER,
    base,
    check,
    second_approver,
    vectors,
)

SYSTEM_CLOCK = SystemClock()  # these cases judge windows against the host's time

ALL = ("user", "agent", "sponsor", "approver")
EXPECTED = {
    "ID1": ([], "strict"), "ID2": ([], "basic"), "ID3": ([], "basic"),
    "ID4": (["principal_agent:principal_thumbprint_mismatch"], None),
    "ID5": ([f"principal_{r}:principal_expired" for r in ALL], None),
    "ID6": (["principal_user:principal_member_missing"], None),
    "ID7": ([f"principal_{r}:principal_issuer_untrusted" for r in ALL], None),
    "ID8": ([f"principal_{r}:principal_key_not_pinned" for r in ALL], None),
    "ID9": (["principal_act_names_another_agent"], None),
    "ID10": (["principal_approver_not_an_approval_signer"], None),
    "ID11": (["principal_agent:principal_kid_mismatch"], None),
    "ID12": (["principal_agent:principal_key_invalid"], None),
    "ID13": ([f"principal_{r}:principal_not_yet_valid" for r in ALL], None),
    "ID14": (["principals_need_user_and_agent"], None),
    "ID15": (["principal_agent:principal_cnf_invalid"], None),
    "ID16": (["principal_agent:principal_cnf_invalid"], None),
    # autonomous: no person in the session
    "ID17": ([], "autonomous"), "ID18": ([], "autonomous"),
    "ID19": (["principals_need_sponsor"], None),
    "ID20": (["principal_sponsor_not_registered"], None),
    "ID21": (["principals_standing_grant_expired"], None),
    "ID22": (["principals_standing_grant_unreviewed"], None),
    "ID23": (["principals_autonomous_has_user"], None),
    "ID24": (["principals_need_session"], None),
    "ID25": (["principals_standing_grant_not_held_by_agent"], None),
    "ID26": (["principals_sponsor_not_the_grant_sponsor"], None),
    "ID27": (["principals_standing_grant_unknown"], None),
    "ID28": (["principals_sponsors_not_pinned"], None),
    "ID29": (["principals_session_not_started"], None),
    "ID30": (["principal_approver_without_approval"], None),
    "ID31": (["principal_sponsor:principal_not_yet_valid"], None),
    "ID32": (["principals_need_approver"], None),
    "ID33": (["principals_session_malformed"], None),
    "ID34": (["principals_standing_grant_not_held_by_agent"], None),
    "ID35": ([f"principal_{r}:principal_key_not_pinned" for r in ("user", "agent", "sponsor", "approver")], None),
    "ID36": ([], "strict"),
    "ID37": ([], "strict"),
    "ID38": ([], "strict"),
    "ID39": (["principal_approver_without_approval"], None),
    "ID40": ([], "basic"),
    # many approvers: a list of at least two principals, each a counted signer
    "ID41": ([], "strict"),
    "ID42": ([], "basic"),
    "ID43": (["principal_approver_duplicate"], None),
    "ID44": (["principal_approver_list_too_short"], None),
    "ID45": (["principal_approver_not_an_approval_signer"], None),
    "ID46": (["principal_approver:principal_thumbprint_mismatch"], None),
    "ID47": (["principal_approver:principal_malformed"], None),
    "ID48": (["principal_approver_without_approval"], None),
    "ID49": ([], "autonomous"),
    "ID50": (["principals_need_every_approver"], None),
    "ID51": (["principal_approver_list_too_short"], None),
}
#: The vectors whose escrowed tokens are refused, by role (every other token verifies).
TOKEN_REFUSALS = {"ID36": {"user": "token_type_mismatch:id-jag"}, "ID37": {"agent": "token_not_yet_valid"}}


def test_every_vector_has_its_expected_outcome_and_is_deterministic() -> None:
    vs = vectors()
    assert {v["id"]: (v["expected"]["problems"], v["expected"]["grade"]) for v in vs} == EXPECTED
    assert vs == vectors() and check(vs) == []
    assert vs[0]["expected"]["act"] == "act-chain" and vs[1]["expected"]["act"] == "act-absent"
    assert all(t is None for t in vs[0]["expected"]["tokens"].values())
    for v in vs:
        refused = {role: why for role, why in v["expected"]["tokens"].items() if why is not None}
        if v["id"] in TOKEN_REFUSALS:
            assert refused == TOKEN_REFUSALS[v["id"]], v["id"]


def test_escrowed_tokens_reverify_and_a_swapped_claim_is_refused() -> None:
    v = base()
    user = v["principals"]["user"]
    assert verify_token({**user, "subject": "mallory@example.com"}, v["tokens"]["user"], v["jwks"]) == \
        "token_claim_mismatch:subject"
    assert verify_token(user, v["tokens"]["agent"], v["jwks"]) == "token_digest_mismatch"
    head, body, sig = v["tokens"]["user"].split(".")
    forged = f"{head}.{body}.{'B' if sig[0] != 'B' else 'C'}{sig[1:]}"
    assert verify_token({**user, "tokenDigest": hashlib.sha256(forged.encode()).hexdigest()},
                        forged, v["jwks"]) == "token_signature_unverified"
    assert verify_token({**v["principals"]["agent"], "source": "id-jag"}, v["tokens"]["agent"], v["jwks"]) == \
        "token_typ_not_id_jag"
    assert verify_token(user, v["tokens"]["user"], {"keys": []}) == "jwks_digest_mismatch"


def test_strict_needs_all_four_and_the_act_chain() -> None:
    v = base()
    pins = {ISSUER: frozenset(v["pins"][ISSUER])}
    assert check_principals(v["principals"], v["at"], pins, {"bob@example.com"}) == ([], "strict")
    no_act = {**v["principals"], "user": {k: x for k, x in v["principals"]["user"].items() if k != "act"}}
    assert check_principals(no_act, v["at"], pins, {"bob@example.com"}) == ([], "basic")


def _without(block: dict, *roles: str) -> dict:
    return {r: p for r, p in block.items() if r not in roles}


def test_strict_names_the_approver_exactly_when_an_approval_admitted_the_call() -> None:
    """The rule the gateway applies at the writer (B1 DESIGN.md): strict is user, agent and sponsor, the user's act
    chain names the agent, and the approver present if and only if an approval admitted the call."""
    v = base()
    pins = {ISSUER: frozenset(v["pins"][ISSUER])}
    block = v["principals"]
    unapproved = _without(block, "approver")
    # a call no human approved is strict without an approver (it was basic, so a strict writer refused it)
    assert check_principals(unapproved, v["at"], pins, None) == ([], "strict")
    # an approver no approval counts is a false statement, refused whatever the profile
    assert check_principals(block, v["at"], pins, None) == (["principal_approver_without_approval"], None)
    assert check_principals(block, v["at"], pins, set()) == (["principal_approver_without_approval"], None)
    # an approval that admitted the call with its approver unnamed is basic, never strict
    assert check_principals(unapproved, v["at"], pins, {"bob@example.com"}) == ([], "basic")
    # sponsor and act chain stay required for strict on both sides of the approval
    assert check_principals(_without(block, "sponsor", "approver"), v["at"], pins, None) == ([], "basic")
    assert check_principals(_without(block, "sponsor"), v["at"], pins, {"bob@example.com"}) == ([], "basic")
    no_act = {**unapproved, "user": {k: x for k, x in unapproved["user"].items() if k != "act"}}
    assert check_principals(no_act, v["at"], pins, None) == ([], "basic")


def test_strict_names_every_approver_an_approval_counted() -> None:
    """An approval of two signers is strict only when the block names both: the single form names one of them and is
    basic (``approvers-partial``); the list names both; a list never names a person twice or one person alone."""
    v = base()
    pins = {ISSUER: frozenset(v["pins"][ISSUER])}
    block = v["principals"]
    bob = block["approver"]
    carol = second_approver()[0]
    both = {"bob@example.com", "carol@example.com"}
    assert check_principals(block, v["at"], pins, both) == ([], "basic")
    assert strict_shortfall(block, both) == "approvers-partial"
    listed = {**block, "approver": [bob, carol]}
    assert check_principals(listed, v["at"], pins, both) == ([], "strict")
    assert strict_shortfall(listed, both) is None
    # the order of the list is the writer's; the verdict does not depend on it
    assert check_principals({**block, "approver": [carol, bob]}, v["at"], pins, both) == ([], "strict")
    # one approval counted, the list names its signer and a second person who signed nothing
    assert check_principals(listed, v["at"], pins, {"bob@example.com"}) == \
        (["principal_approver_not_an_approval_signer"], None)
    assert check_principals({**block, "approver": [bob, bob]}, v["at"], pins, both) == \
        (["principal_approver_duplicate"], None)
    for short in ([], [bob]):
        assert check_principals({**block, "approver": short}, v["at"], pins, both) == \
            (["principal_approver_list_too_short"], None)
    assert check_principals(listed, v["at"], pins, None) == (["principal_approver_without_approval"], None)
    # the shortfalls keep their order: an absent approver is named before a partial list
    assert strict_shortfall(_without(block, "approver"), both) == "approver-absent"


def test_a_deny_counts_nobody_so_strict_needs_no_approver_named() -> None:
    """A deny may name any approver whose binding it carries and counts none of them: naming one of two is strict, as
    it was before the list form; naming none is still ``approver-absent``; a name outside the bindings is refused."""
    v = base()
    pins = {ISSUER: frozenset(v["pins"][ISSUER])}
    block = v["principals"]
    both = {"bob@example.com", "carol@example.com"}
    assert check_principals(block, v["at"], pins, both, counted=set()) == ([], "strict")
    assert strict_shortfall(block, both, set()) is None
    assert strict_shortfall(_without(block, "approver"), both, set()) == "approver-absent"
    assert check_principals(block, v["at"], pins, {"carol@example.com"}, counted=set()) == \
        (["principal_approver_not_an_approval_signer"], None)


def test_journal_checks_principals_at_the_record_time(tmp_path) -> None:
    gate = Signer.generate()
    v = base()
    args = {"x": 1}
    j = Journal(tmp_path, gate, clock=SYSTEM_CLOCK)
    j.append(TOOL_CALL_RECORD, "tool-call:c1", args_sha256(args), tool_call_predicate(
        phase="intent", run_id="r", tool_call_id="c1", tool="t", args_sha256_hex=args_sha256(args),
        permit_id=permit_id("p", "c1", args_sha256(args)), principals=v["principals"]))
    pins = {ISSUER: frozenset(v["pins"][ISSUER])}
    failures = verify_journal(tmp_path, [gate.public_pem()], j.checkpoint(),
                              trust=Trust(identity_issuers=pins))["failures"]
    # the journal stamps its own clock, after the fixture credentials expired
    assert "line_1:principal_user:principal_expired" in failures
    unpinned = verify_journal(tmp_path, [gate.public_pem()], j.checkpoint())["failures"]
    assert "line_1:principals_but_no_trust_pinned" in unpinned
