"""Four-principal identity block: conformance vectors, act grading, escrowed-token re-verification."""

from __future__ import annotations

import hashlib

from probity_records import TOOL_CALL_RECORD, Journal, Signer, Trust, args_sha256, permit_id, tool_call_predicate
from probity_records import verify_journal
from probity_records.identity import check_principals, verify_token
from probity_records.identity_vectors import ISSUER, base, check, vectors

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
}


def test_every_vector_has_its_expected_outcome_and_is_deterministic() -> None:
    vs = vectors()
    assert {v["id"]: (v["expected"]["problems"], v["expected"]["grade"]) for v in vs} == EXPECTED
    assert vs == vectors() and check(vs) == []
    assert vs[0]["expected"]["act"] == "act-chain" and vs[1]["expected"]["act"] == "act-absent"
    assert all(t is None for t in vs[0]["expected"]["tokens"].values())


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


def test_journal_checks_principals_at_the_record_time(tmp_path) -> None:
    gate = Signer.generate()
    v = base()
    args = {"x": 1}
    j = Journal(tmp_path, gate)
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
