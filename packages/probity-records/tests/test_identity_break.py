"""Attacks on the identity check that the verifier must refuse, each kept as a permanent test.

Each test builds the records an attacker would write and runs them through the shipped verifier. On the commit
before these fixes every attack was accepted; the cases beside each attack are the valid records that must still
verify.
"""

from __future__ import annotations

import copy
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
from probity_records.identity import check_principals, sponsor_id, verify_token
from probity_records.identity_vectors import (
    EXP,
    ISSUER,
    _jwk,
    _key,
    _principal,
    _token,
    base,
)
from probity_records.quorum import approval_policy
from probity_records.revocation import RevocationState, sign_revocations

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g

PINS = {ISSUER: frozenset(base()["pins"][ISSUER])}


def _unapproved() -> dict:
    """The fixture block of a call no human approved: every principal but the approver."""
    return {role: p for role, p in base()["principals"].items() if role != "approver"}


def _now_block(principals: dict) -> dict:
    """The fixture principals with a validity window around now (the journal stamps its own clock)."""
    t = datetime.now(UTC)
    out = copy.deepcopy(principals)
    for p in out.values():
        p["issuedAt"] = (t - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        p["expiresAt"] = (t + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    return out


def _call(phase: str, principals: dict | None, **kw) -> dict:
    args = {"x": 1}
    return tool_call_predicate(
        phase=phase,
        run_id="r",
        tool_call_id="c1",
        tool="t",
        args_sha256_hex=args_sha256(args),
        permit_id=permit_id("p", "c1", args_sha256(args)),
        principals=principals,
        **kw,
    )


def _failures(tmp_path, preds: list[dict], trust: Trust) -> list[str]:
    gate = Signer.generate()
    j = Journal(tmp_path, gate, clock=SystemClock())
    for pred in preds:
        j.append(
            TOOL_CALL_RECORD,
            f"tool-call:{pred['toolCallId']}",
            pred["argsSha256"],
            pred,
        )
    return verify_journal(tmp_path, [gate.public_pem()], j.checkpoint(), trust=trust)[
        "failures"
    ]


def _revocations(*entries: dict) -> RevocationState:
    root = Signer.generate()
    signed = sign_revocations(
        root,
        list_id="idp",
        seq=1,
        issued_at="2026-01-01T00:00:00Z",
        entries=[{"reason": "test", **e} for e in entries],
    )
    return RevocationState.from_lists([signed], [root.key_id])


def test_a_suspended_sponsor_is_refused_when_a_person_is_in_the_session(
    tmp_path,
) -> None:
    block = _now_block(_unapproved())
    allow = _call("authorize", block, decision="allow", reason="no_approval_required")
    state = _revocations(
        {
            "kind": "sponsor",
            "id": sponsor_id(ISSUER, "owner@example.com"),
            "revokedAt": "2026-01-01T00:00:00Z",
        }
    )
    failures = _failures(
        tmp_path, [allow], Trust(identity_issuers=PINS, revocations=state)
    )
    assert failures == ["line_1:principals_sponsor_revoked"]
    other = _revocations(
        {
            "kind": "sponsor",
            "id": sponsor_id(ISSUER, "someone-else@example.com"),
            "revokedAt": "2026-01-01T00:00:00Z",
        }
    )
    assert (
        _failures(
            tmp_path / "ok", [allow], Trust(identity_issuers=PINS, revocations=other)
        )
        == []
    )


def test_strict_refuses_an_authorize_record_with_no_principals(tmp_path) -> None:
    failures = _failures(
        tmp_path,
        [_call("authorize", None, decision="allow", reason="no_approval_required")],
        Trust(identity_issuers=PINS, identity_profile="strict"),
    )
    assert failures == ["line_1:principals_missing"]
    named = _failures(
        tmp_path / "s",
        [
            _call(
                "authorize",
                _now_block(_unapproved()),
                decision="allow",
                reason="no_approval_required",
            )
        ],
        Trust(identity_issuers=PINS, identity_profile="strict"),
    )
    assert named == []
    basic = _failures(
        tmp_path / "b",
        [_call("authorize", None, decision="allow", reason="no_approval_required")],
        Trust(identity_issuers=PINS),
    )
    assert basic == []


def test_an_intent_naming_another_agent_than_its_allow_is_refused(tmp_path) -> None:
    good = _now_block(_unapproved())
    swapped = copy.deepcopy(good)
    swapped["agent"]["subject"] = "agent-payroll"
    swapped["user"]["act"] = {"sub": "agent-payroll"}
    refreshed = copy.deepcopy(good)
    refreshed["agent"]["tokenDigest"] = (
        "ab" * 32
    )  # a refreshed credential for the same parties is fine
    trust = Trust(identity_issuers=PINS)
    allow = _call("authorize", good, decision="allow", reason="no_approval_required")
    assert "line_2:principals_differ_from_permit:intent" in _failures(
        tmp_path, [allow, _call("intent", swapped)], trust
    )
    assert not [
        f
        for f in _failures(tmp_path / "ok", [allow, _call("intent", refreshed)], trust)
        if "principal" in f
    ]
    # a re-issued allow for the same permit is held to the parties of the first
    retry = _call("authorize", swapped, decision="allow", reason="not_run_retry")
    assert "line_2:principals_differ_from_permit:authorize" in _failures(
        tmp_path / "r", [allow, retry], trust
    )
    # a later record that names no parties claims none
    assert not [
        f
        for f in _failures(tmp_path / "n", [allow, _call("intent", None)], trust)
        if "principal" in f
    ]
    # an intent answers to the approvals its allow counted: naming an approver the allow did not count is refused
    claimed = _call("intent", _now_block(base()["principals"]))
    assert "line_2:principal_approver_without_approval" in _failures(
        tmp_path / "a", [allow, claimed], trust
    )


def test_the_approver_principal_must_be_a_counted_approver(tmp_path) -> None:
    policy = approval_policy(
        "refunds1of2",
        {g.WHO["ops"]: g.OPS.public_pem(), g.WHO["lead"]: g.LEAD.public_pem()},
        1,
    )
    trust = Trust(identity_issuers=PINS, quorum_policies={"refunds1of2": policy})

    def journal(directory, approver: str) -> list[str]:
        block = _now_block(base()["principals"])
        block["approver"]["subject"] = approver
        pred = tool_call_predicate(
            phase="authorize",
            decision="allow",
            reason="bound",
            threshold=1,
            approval_policy="refunds1of2",
            approval_bindings=[
                g.binding(g.OPS, g.WHO["ops"]),
                g.binding(g.LEAD, g.WHO["lead"], consumed=("appr-1",)),
            ],
            run_id="run",
            tool_call_id="a1",
            tool="refund_payment",
            args_sha256_hex=args_sha256(g.AARGS),
            permit_id=permit_id("pause", "a1", args_sha256(g.AARGS)),
            principals=block,
        )
        return _failures(directory, [pred], trust)

    # lead's approval is a replay: the reader refuses it, the allow holds on ops alone
    assert journal(tmp_path / "lead", g.WHO["lead"]) == [
        "line_1:principal_approver_not_an_approval_signer"
    ]
    assert journal(tmp_path / "ops", g.WHO["ops"]) == []


def test_an_intent_of_an_approved_allow_may_name_the_approver_that_allow_counted(
    tmp_path,
) -> None:
    policy = approval_policy(
        "refunds1of2",
        {g.WHO["ops"]: g.OPS.public_pem(), g.WHO["lead"]: g.LEAD.public_pem()},
        1,
    )
    trust = Trust(
        identity_issuers=PINS,
        quorum_policies={"refunds1of2": policy},
        identity_profile="strict",
    )
    block = _now_block(base()["principals"])
    block["approver"]["subject"] = g.WHO["ops"]
    common = {
        "run_id": "run",
        "tool_call_id": "a1",
        "tool": "refund_payment",
        "args_sha256_hex": args_sha256(g.AARGS),
        "permit_id": permit_id("pause", "a1", args_sha256(g.AARGS)),
        "principals": block,
    }
    allow = tool_call_predicate(phase="authorize", decision="allow", reason="bound", threshold=1,
                                approval_policy="refunds1of2", approval_bindings=[g.binding(g.OPS, g.WHO["ops"])],
                                **common)  # fmt: skip
    failures = _failures(
        tmp_path, [allow, tool_call_predicate(phase="intent", **common)], trust
    )
    assert [f for f in failures if "principal" in f] == []


def test_a_pin_written_as_a_string_is_not_a_substring_match() -> None:
    v = base()
    thumb = v["principals"]["agent"]["keyThumbprint"]
    problems, _ = check_principals(
        v["principals"], v["at"], {ISSUER: "x" + thumb + "x"}, {"bob@example.com"}
    )
    assert "principal_agent:principal_key_not_pinned" in problems
    for pins in ([thumb], (thumb,), {thumb}, frozenset({thumb})):
        assert check_principals(
            v["principals"], v["at"], {ISSUER: pins}, {"bob@example.com"}
        ) == ([], "strict")


def test_a_token_whose_typ_names_another_credential_type_is_refused() -> None:
    v = base()
    as_access = {**v["principals"]["user"], "source": "jwt-access-token"}
    assert (
        verify_token(as_access, v["tokens"]["user"], v["jwks"])
        == "token_type_mismatch:id-jag"
    )
    as_login = {**v["principals"]["agent"], "source": "id-token"}
    assert (
        verify_token(as_login, v["tokens"]["agent"], v["jwks"])
        == "token_type_mismatch:jwt-access-token"
    )
    # each token verifies as the credential it is; a plain JWT typ names no credential type
    for role in ("user", "agent", "sponsor"):
        assert verify_token(v["principals"][role], v["tokens"][role], v["jwks"]) is None


def test_a_token_not_yet_valid_at_the_record_time_is_refused() -> None:
    v = base()
    priv = _key("probity-identity-vectors/issuer-key-1")
    jwk = _jwk(priv, "k1")
    claims = {
        "iss": ISSUER,
        "iat": EXP - 600,
        "exp": EXP,
        "nbf": EXP - 60,
        "jti": "nbf",
        "sub": "agent-refunds",
        "client_id": "agent-refunds",
        "aud": "https://api.example.com",
    }
    tok = _token(priv, "k1", claims, "at+jwt")
    p = _principal(tok, jwk, {"keys": [jwk]}, "jwt-access-token", claims)
    assert verify_token(p, tok, {"keys": [jwk]}, at=v["at"]) == "token_not_yet_valid"
    assert verify_token(p, tok, {"keys": [jwk]}, at="2026-11-08T12:19:00Z") is None
    assert verify_token(p, tok, {"keys": [jwk]}) is None
