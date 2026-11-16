"""Attacks on the identity check that the verifier must refuse, each kept as a permanent test.

Each test builds the records an attacker would write and runs them through the shipped verifier. On
the commit before these fixes every one of them was accepted.
"""

from __future__ import annotations

import copy
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
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
from probity_records.identity import check_principals, principal_id, verify_token
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
from probity_records.revocation import (
    RevocationError,
    RevocationState,
    sign_revocations,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g

PINS = {ISSUER: frozenset(base()["pins"][ISSUER])}


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
    return tool_call_predicate(phase=phase, run_id="r", tool_call_id="c1", tool="t", args_sha256_hex=args_sha256(args),
                               permit_id=permit_id("p", "c1", args_sha256(args)), principals=principals, **kw)


def _failures(tmp_path, preds: list[dict], trust: Trust) -> list[str]:
    gate = Signer.generate()
    j = Journal(tmp_path, gate)
    for pred in preds:
        j.append(TOOL_CALL_RECORD, f"tool-call:{pred['toolCallId']}", pred["argsSha256"], pred)
    return verify_journal(tmp_path, [gate.public_pem()], j.checkpoint(), trust=trust)["failures"]


def _revocations(*entries: dict) -> RevocationState:
    root = Signer.generate()
    signed = sign_revocations(root, list_id="idp", seq=1, issued_at="2026-01-01T00:00:00Z",
                              entries=[{"reason": "test", **e} for e in entries])
    return RevocationState.from_lists([signed], [root.key_id])


def test_a_pinned_idp_key_revoked_before_the_record_cannot_sign_it(tmp_path) -> None:
    v = base()
    state = _revocations({"kind": "key", "id": v["principals"]["agent"]["keyThumbprint"],
                          "revokedAt": "2026-01-01T00:00:00Z"})
    failures = _failures(tmp_path, [_call("intent", _now_block(v["principals"]))],
                         Trust(identity_issuers=PINS, revocations=state))
    assert "line_1:principal_agent:principal_key_revoked" in failures


def test_a_suspended_sponsor_is_refused(tmp_path) -> None:
    v = base()
    state = _revocations({"kind": "principal", "id": principal_id(v["principals"]["sponsor"]),
                          "revokedAt": "2026-01-01T00:00:00Z"})
    assert state.principal_revoked(f"{ISSUER}#owner@example.com", "2026-06-01T00:00:00Z")
    failures = _failures(tmp_path, [_call("intent", _now_block(v["principals"]))],
                         Trust(identity_issuers=PINS, revocations=state))
    assert failures.count("line_1:principal_sponsor:principal_revoked") == 1


def test_a_revocation_list_cannot_drop_a_principal_entry() -> None:
    root = Signer.generate()
    first = sign_revocations(root, list_id="idp", seq=1, issued_at="2026-01-01T00:00:00Z",
                             entries=[{"kind": "principal", "id": f"{ISSUER}#owner@example.com",
                                       "revokedAt": "2026-01-01T00:00:00Z", "reason": "suspended"}])
    second = sign_revocations(root, list_id="idp", seq=2, issued_at="2026-01-02T00:00:00Z", entries=[], previous=first)
    with pytest.raises(RevocationError, match="drops_entry:principal"):
        RevocationState.from_lists([first, second], [root.key_id])


def test_strict_refuses_an_authorize_record_with_no_principals(tmp_path) -> None:
    failures = _failures(tmp_path, [_call("authorize", None, decision="allow", reason="no_approval_required")],
                         Trust(identity_issuers=PINS, identity_profile="strict"))
    assert failures == ["line_1:principals_required_by_profile"]
    basic = _failures(tmp_path / "b", [_call("authorize", None, decision="allow", reason="no_approval_required")],
                      Trust(identity_issuers=PINS))
    assert basic == []


def test_an_intent_naming_another_agent_than_its_allow_is_refused(tmp_path) -> None:
    good = _now_block(base()["principals"])
    swapped = copy.deepcopy(good)
    swapped["agent"]["subject"] = "agent-payroll"
    swapped["user"]["act"] = {"sub": "agent-payroll"}
    refreshed = copy.deepcopy(good)
    refreshed["agent"]["tokenDigest"] = "ab" * 32  # a refreshed credential for the same parties is fine
    trust = Trust(identity_issuers=PINS)
    allow = _call("authorize", good, decision="allow", reason="no_approval_required")
    assert "line_2:intent_principals_differ_from_permit" in _failures(tmp_path, [allow, _call("intent", swapped)], trust)
    assert not [f for f in _failures(tmp_path / "ok", [allow, _call("intent", refreshed)], trust) if "principal" in f]


def test_the_approver_principal_must_be_a_counted_approver(tmp_path) -> None:
    policy = approval_policy("refunds1of2", {g.WHO["ops"]: g.OPS.public_pem(), g.WHO["lead"]: g.LEAD.public_pem()}, 1)
    trust = Trust(identity_issuers=PINS, quorum_policies={"refunds1of2": policy})

    def journal(directory, approver: str) -> list[str]:
        block = _now_block(base()["principals"])
        block["approver"]["subject"] = approver
        pred = tool_call_predicate(
            phase="authorize", decision="allow", reason="bound", threshold=1, approval_policy="refunds1of2",
            approval_bindings=[g.binding(g.OPS, g.WHO["ops"]), g.binding(g.LEAD, g.WHO["lead"], consumed=("appr-1",))],
            run_id="run", tool_call_id="a1", tool="refund_payment", args_sha256_hex=args_sha256(g.AARGS),
            permit_id=permit_id("pause", "a1", args_sha256(g.AARGS)), principals=block)
        return _failures(directory, [pred], trust)

    # lead's approval is a replay: the reader refuses it, the allow holds on ops alone
    assert journal(tmp_path / "lead", g.WHO["lead"]) == ["line_1:principal_approver_not_an_approval_signer"]
    assert journal(tmp_path / "ops", g.WHO["ops"]) == []


def test_a_credential_for_another_deployment_is_refused_when_audiences_are_pinned(tmp_path) -> None:
    v = base()
    block = _now_block(v["principals"])
    for p in block.values():
        p["audience"] = ["https://other-tenant.example.org"]
    auds = {r: frozenset(["https://api.example.com"]) for r in ("user", "agent")}
    failures = _failures(tmp_path, [_call("intent", block)], Trust(identity_issuers=PINS, identity_audiences=auds))
    assert {"line_1:principal_user:principal_audience_not_pinned",
            "line_1:principal_agent:principal_audience_not_pinned"} <= set(failures)


def test_a_pin_written_as_a_string_is_not_a_substring_match() -> None:
    v = base()
    thumb = v["principals"]["agent"]["keyThumbprint"]
    problems, _ = check_principals(v["principals"], v["at"], {ISSUER: "x" + thumb + "x"}, {"bob@example.com"})
    assert "principal_agent:principal_key_not_pinned" in problems


def test_a_token_whose_typ_names_another_credential_type_is_refused() -> None:
    v = base()
    as_access = {**v["principals"]["user"], "source": "jwt-access-token"}
    assert verify_token(as_access, v["tokens"]["user"], v["jwks"]) == "token_typ_names_another_source:id-jag"
    as_login = {**v["principals"]["agent"], "source": "id-token"}
    assert verify_token(as_login, v["tokens"]["agent"], v["jwks"]) == \
        "token_typ_names_another_source:jwt-access-token"


def test_a_token_not_yet_valid_at_the_record_time_is_refused() -> None:
    v = base()
    priv = _key("probity-identity-vectors/issuer-key-1")
    jwk = _jwk(priv, "k1")
    claims = {"iss": ISSUER, "iat": EXP - 600, "exp": EXP, "nbf": EXP - 60, "jti": "nbf", "sub": "agent-refunds",
              "client_id": "agent-refunds", "aud": "https://api.example.com"}
    tok = _token(priv, "k1", claims, "at+jwt")
    p = _principal(tok, jwk, {"keys": [jwk]}, "jwt-access-token", claims)
    assert verify_token(p, tok, {"keys": [jwk]}, at=v["at"]) == "token_not_yet_valid"
    assert verify_token(p, tok, {"keys": [jwk]}) is None
