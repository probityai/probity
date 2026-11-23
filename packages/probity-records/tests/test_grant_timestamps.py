"""Grant timestamps: one RFC 3339 grammar with an explicit UTC offset, refused (never thrown) when a grant breaks it.

A grant's ``notBefore``, ``expiresAt`` and ``reviewBy`` name instants. A timestamp with no offset names no instant,
so a verifier that compares it with an aware time either throws (Python) or reads it in its own zone; both are
wrong. Every check that reads a grant refuses such a body with ``grant_timestamp_offset_missing`` and any other
non-RFC 3339 value with ``grant_timestamp_invalid``: at issue, in the time-independent chain check, in the
per-use window check and in the offline grant verdict a journal re-runs. The chain is signed by a forger who holds
the issuing key, so nothing upstream filtered the body.
"""

from __future__ import annotations

from typing import Any

import pytest
from probity_records import Signer, issue_grant, raw_public, verify_chain, verify_grant_allow
from probity_records.core import _b64, canonical
from probity_records.grants import GRANT_DOMAIN, chain_problem, grant_digest, ts, validate_body
from probity_records.possession import cnf_for_signer

AT = "2026-06-01T00:00:00Z"
TOOLS = {"refund": {"args": {"amount_cents": {"type": "range", "min": 1, "max": 100}}}}
CALL = {"amount_cents": 5}


def _body(issuer: Signer, holder: Signer, **over: Any) -> dict[str, Any]:
    body = {"cnf": cnf_for_signer(holder), "context": {}, "expiresAt": "2099-01-01T00:00:00Z", "grantId": "g",
            "holderKey": raw_public(holder), "issuerKey": raw_public(issuer), "maxDepth": 1,
            "notBefore": "2026-01-01T00:00:00Z", "parent": None, "tools": TOOLS}
    body.update(over)
    return body


def _forge(issuer: Signer, body: dict[str, Any]) -> dict[str, Any]:
    """Signed over any body, every validation skipped: what a holder of the issuing key can send."""
    return {"body": body, "sig": _b64(issuer.sign(GRANT_DOMAIN + canonical(body)))}


#: (member, value, the code validate_body names)
BAD = [
    ("notBefore", "2026-01-01T00:00:00", "grant_timestamp_offset_missing"),
    ("expiresAt", "2099-01-01T00:00:00", "grant_timestamp_offset_missing"),
    ("expiresAt", "2099-01-01T00:00:00.123456", "grant_timestamp_offset_missing"),
    ("notBefore", "2026-01-01", "grant_timestamp_invalid"),
    ("notBefore", "2026-01-01 00:00:00+00:00", "grant_timestamp_invalid"),
    ("notBefore", "20260101T000000Z", "grant_timestamp_invalid"),
    ("notBefore", "2026-01-01T00:00:00z", "grant_timestamp_invalid"),
    ("notBefore", "2026-01-01T00:00:00.1234567Z", "grant_timestamp_invalid"),
    ("notBefore", "2026-13-01T00:00:00Z", "grant_timestamp_invalid"),
    ("notBefore", "2026-02-30T00:00:00Z", "grant_timestamp_invalid"),
    ("notBefore", "2026-01-01T24:00:00Z", "grant_timestamp_invalid"),
    ("notBefore", "2026-01-01T23:59:60Z", "grant_timestamp_invalid"),
    ("notBefore", "2026-01-01T00:00:00+24:00", "grant_timestamp_invalid"),
    ("notBefore", "2026-01-01T00:00:00+0000", "grant_timestamp_invalid"),
    ("notBefore", 1767225600, "grant_timestamp_invalid"),
    ("notBefore", None, "grant_timestamp_invalid"),
    ("expiresAt", ["2099-01-01T00:00:00Z"], "grant_timestamp_invalid"),
]


@pytest.mark.parametrize(("member", "value", "code"), BAD)
def test_validate_body_refuses_a_timestamp_with_no_offset_or_another_grammar(member, value, code) -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    with pytest.raises(ValueError) as caught:
        validate_body(_body(issuer, holder, **{member: value}))
    assert str(caught.value) == f"{code}:{member}"


@pytest.mark.parametrize("member", ["notBefore", "expiresAt"])
def test_validate_body_refuses_a_grant_with_no_window_member(member) -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    body = _body(issuer, holder)
    del body[member]
    with pytest.raises(ValueError) as caught:
        validate_body(body)
    assert str(caught.value) == f"grant_timestamp_invalid:{member}"


def test_issue_grant_refuses_an_offsetless_window() -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    with pytest.raises(ValueError, match="grant_timestamp_offset_missing:notBefore"):
        issue_grant(issuer, grant_id="g", holder_key=raw_public(holder), cnf=cnf_for_signer(holder), tools=TOOLS,
                    not_before="2026-01-01T00:00:00", expires_at="2099-01-01T00:00:00Z")


@pytest.mark.parametrize(("member", "value", "code"), BAD)
def test_a_root_with_a_bad_timestamp_is_refused_by_every_chain_check(member, value, code) -> None:
    root, holder = Signer.generate(), Signer.generate()
    chain = [_forge(root, _body(root, holder, **{member: value}))]
    want = f"grant_invalid:0:{code}:{member}"
    assert chain_problem(chain, {root.key_id}) == want
    assert verify_chain(chain, {root.key_id}, AT) == (None, want)
    verdict = verify_grant_allow(chain, "refund", CALL, AT, {root.key_id})
    assert (verdict["decision"], verdict["reason"]) == ("deny", want)


def test_a_child_with_an_offsetless_window_is_refused_not_compared_with_its_parent() -> None:
    root, a, b = Signer.generate(), Signer.generate(), Signer.generate()
    parent = issue_grant(root, grant_id="p", holder_key=raw_public(a), cnf=cnf_for_signer(a), tools=TOOLS,
                         max_depth=1, not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")
    child = _forge(a, _body(a, b, maxDepth=0, parent=grant_digest(parent["body"]),
                            expiresAt="2098-01-01T00:00:00"))
    want = "grant_invalid:1:grant_timestamp_offset_missing:expiresAt"
    assert chain_problem([parent, child], {root.key_id}) == want
    assert verify_chain([parent, child], {root.key_id}, AT) == (None, want)


def test_an_offsetless_review_date_is_refused_as_such() -> None:
    root, holder = Signer.generate(), Signer.generate()
    body = _body(root, holder, sponsor={"issuer": "https://idp.example.com", "subject": "owner@example.com"},
                 reviewBy="2027-01-01T00:00:00")
    with pytest.raises(ValueError, match="^grant_timestamp_offset_missing:reviewBy$"):
        validate_body(body)


@pytest.mark.parametrize("at", ["2026-06-01T00:00:00", "2026-06-01", "yesterday", "None"])
def test_a_use_time_that_names_no_instant_is_refused_not_thrown(at) -> None:
    root, holder = Signer.generate(), Signer.generate()
    chain = [issue_grant(root, grant_id="g", holder_key=raw_public(holder), cnf=cnf_for_signer(holder), tools=TOOLS,
                         not_before="2026-01-01T00:00:00Z", expires_at="2099-01-01T00:00:00Z")]
    assert verify_chain(chain, {root.key_id}, at) == (None, "grant_use_time_invalid")


def test_offsets_other_than_z_compare_as_instants() -> None:
    assert ts("2026-06-01T02:00:00+02:00") == ts("2026-06-01T00:00:00Z") == ts("2026-05-31T19:30:00-04:30")
    root, holder = Signer.generate(), Signer.generate()
    chain = [issue_grant(root, grant_id="g", holder_key=raw_public(holder), cnf=cnf_for_signer(holder), tools=TOOLS,
                         not_before="2026-06-01T02:00:00+02:00", expires_at="2026-06-01T03:00:00+02:00")]
    assert verify_chain(chain, {root.key_id}, "2026-06-01T00:00:00Z")[1] == "ok"
    assert verify_chain(chain, {root.key_id}, "2026-05-31T23:59:59Z")[1] == "grant_outside_window:0"
