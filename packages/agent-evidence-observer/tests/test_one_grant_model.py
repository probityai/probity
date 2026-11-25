"""One grant model: an exact request is a probity_records capability grant presented with a permit.

The observer once signed its own exact-request record whose window was exclusive at ``expiresAt`` while every
capability-grant verifier admits a call at ``notBefore <= at <= expiresAt``. These cases pin the one answer: the
observer's exact request is a capability grant, so the two verdicts are the same verdict at every instant, the
window is inclusive at both ends, and nothing outside the one request is admitted.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from probity_records import Signer
from probity_records.grants import raw_public, verify_grant_allow
from probity_records.possession import cnf_for_signer

from probity_observer.exact_grant import (
    ActionRequest,
    ExactGrantRefused,
    exact_call,
    mint_exact_permit,
    issue_exact_grant,
    verify_exact_grant,
    verify_exact_permit,
)

NOT_BEFORE = datetime(2026, 11, 24, 18, 0, 0, tzinfo=UTC)
EXPIRES_AT = NOT_BEFORE + timedelta(minutes=5)


def _iso(at: datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def _request(**changes: str) -> ActionRequest:
    fields = {
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "request_id": "request-1",
        "tenant_id": "tenant-1",
        "principal_id": "principal-1",
        "tool_id": "local.write-file",
        "target_path": "/work/out.txt",
        "content_sha256": "ab" * 32,
    }
    fields.update(changes)
    return ActionRequest(**fields)


def _grant(issuer: Signer, holder: Signer, request: ActionRequest) -> dict:
    return issue_exact_grant(issuer, request, holder_key=raw_public(holder), cnf=cnf_for_signer(holder),
                             not_before=_iso(NOT_BEFORE), expires_at=_iso(EXPIRES_AT))


@pytest.mark.parametrize(
    ("at", "admitted"),
    [
        (NOT_BEFORE - timedelta(seconds=1), False),
        (NOT_BEFORE, True),
        (NOT_BEFORE + timedelta(minutes=2), True),
        (EXPIRES_AT, True),
        (EXPIRES_AT + timedelta(seconds=1), False),
    ],
)
def test_the_exact_request_verdict_is_the_capability_grant_verdict_at_every_instant(at: datetime,
                                                                                      admitted: bool) -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    tool, args, ctx = exact_call(request)
    records = verify_grant_allow([grant], tool, args, _iso(at), {issuer.key_id}, ctx=ctx)
    assert (records["decision"] == "allow") is admitted
    if admitted:
        assert verify_exact_grant([grant], request, {issuer.key_id}, at=_iso(at)) == records["grantDigest"]
    else:
        with pytest.raises(ExactGrantRefused) as caught:
            verify_exact_grant([grant], request, {issuer.key_id}, at=_iso(at))
        assert caught.value.reason == records["reason"]


def test_the_window_is_inclusive_at_expires_at() -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    assert verify_exact_grant([grant], request, {issuer.key_id}, at=_iso(EXPIRES_AT))


@pytest.mark.parametrize(
    "field",
    ["run_id", "attempt_id", "request_id", "tenant_id", "principal_id", "tool_id", "target_path",
     "content_sha256"],
)
def test_a_request_differing_in_any_field_is_refused(field: str) -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    other = {"target_path": "/work/other.txt", "content_sha256": "cd" * 32}.get(field, f"other-{field}")
    with pytest.raises(ExactGrantRefused):
        verify_exact_grant([grant], _request(**{field: other}), {issuer.key_id}, at=_iso(NOT_BEFORE))


def test_a_grant_from_an_unpinned_issuer_is_refused() -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    with pytest.raises(ExactGrantRefused):
        verify_exact_grant([grant], request, {Signer.generate().key_id}, at=_iso(NOT_BEFORE))


def test_the_permit_names_the_exact_call_under_the_grant() -> None:
    issuer, holder, authority = Signer.generate(), Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    permit = mint_exact_permit(authority, [grant], request, issued_at=_iso(EXPIRES_AT))
    claims = verify_exact_permit(permit, authority.public_pem(), [grant], request, {issuer.key_id})
    assert claims["grantDigest"] == verify_exact_grant([grant], request, {issuer.key_id}, at=_iso(EXPIRES_AT))
    with pytest.raises(ExactGrantRefused):
        verify_exact_permit(permit, authority.public_pem(), [grant], _request(request_id="request-2"),
                            {issuer.key_id})
    with pytest.raises(ExactGrantRefused):
        verify_exact_permit(permit, Signer.generate().public_pem(), [grant], request, {issuer.key_id})
