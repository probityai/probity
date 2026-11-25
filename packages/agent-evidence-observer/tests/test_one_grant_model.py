"""One grant model: an exact request is a probity_records capability grant presented with a permit.

The observer once signed its own exact-request record whose window was exclusive at ``expiresAt`` while every
capability-grant verifier admits a call at ``notBefore <= at <= expiresAt``. These cases pin the one answer: the
observer's exact request is a capability grant, so the two verdicts are the same verdict at every instant, the
window is inclusive at both ends, and nothing outside the one request is admitted.
"""

from __future__ import annotations

import copy
from dataclasses import asdict
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from fixture_records import load, materialize, pinned_keys, signing_keys
from probity_records import Signer
from probity_records.grants import raw_public, verify_grant_allow
from probity_records.possession import cnf_for_signer

from probity_observer.crypto import VerificationError, digest
from probity_observer.exact_grant import (
    BINDING_DOMAIN,
    ActionRequest,
    AuthorizedAction,
    ExactGrantRefused,
    GrantPolicy,
    exact_call,
    issue_exact_grant,
    mint_exact_permit,
    utc_clock,
    validate_utc_time,
    verify_authorized_packet,
    verify_exact_grant,
    verify_exact_permit,
    verify_grant,
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


def _policy(issuer: Signer, **changes: int) -> GrantPolicy:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = issuer.public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return GrantPolicy(raw.hex(), **changes)


def test_the_policy_names_the_issuer_by_its_records_key_id() -> None:
    issuer = Signer.generate()
    assert _policy(issuer).key_id == issuer.key_id


@pytest.mark.parametrize("value", ["", "AB" * 32, "ab" * 31, "zz" * 32])
def test_a_policy_with_a_malformed_issuer_key_is_refused(value: str) -> None:
    with pytest.raises(VerificationError):
        GrantPolicy(value)


@pytest.mark.parametrize("value", [0, -1, 3601, True, 1.5, "300"])
def test_a_policy_with_a_bad_duration_is_refused(value: object) -> None:
    with pytest.raises(VerificationError):
        GrantPolicy("ab" * 32, value)  # type: ignore[arg-type]


def test_verify_grant_returns_the_authorized_action_and_the_leaf_digest() -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    action = verify_grant([grant], request, _policy(issuer), now=NOT_BEFORE)
    assert isinstance(action, AuthorizedAction)
    assert action.request == request
    assert action.issuer_key == _policy(issuer).issuer_key
    assert (action.issued_at, action.expires_at) == (NOT_BEFORE, EXPIRES_AT)
    assert action.grant_digest == verify_exact_grant([grant], request, {issuer.key_id}, at=_iso(NOT_BEFORE))


@pytest.mark.parametrize(("at", "admitted"), [(NOT_BEFORE - timedelta(seconds=1), False), (NOT_BEFORE, True),
                                              (EXPIRES_AT, True), (EXPIRES_AT + timedelta(seconds=1), False)])
def test_verify_grant_has_the_inclusive_window(at: datetime, admitted: bool) -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    if admitted:
        verify_grant([grant], request, _policy(issuer), now=at)
    else:
        with pytest.raises(VerificationError):
            verify_grant([grant], request, _policy(issuer), now=at)


def test_verify_grant_refuses_a_window_longer_than_the_policy() -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    verify_grant([grant], request, _policy(issuer, max_validity_seconds=300), now=NOT_BEFORE)
    with pytest.raises(VerificationError, match="exceeds policy"):
        verify_grant([grant], request, _policy(issuer, max_validity_seconds=299), now=NOT_BEFORE)


def test_verify_grant_refuses_an_unpinned_issuer_and_another_request() -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    grant = _grant(issuer, holder, request)
    with pytest.raises(VerificationError):
        verify_grant([grant], request, _policy(Signer.generate()), now=NOT_BEFORE)
    with pytest.raises(VerificationError):
        verify_grant([grant], _request(request_id="request-2"), _policy(issuer), now=NOT_BEFORE)


def test_verify_grant_refuses_a_bare_grant_that_is_not_a_chain() -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    request = _request()
    with pytest.raises(VerificationError):
        verify_grant(_grant(issuer, holder, request), request, _policy(issuer), now=NOT_BEFORE)  # type: ignore[arg-type]


def test_time_validation_refuses_naive_offset_and_finer_than_declared_precision() -> None:
    assert validate_utc_time(NOT_BEFORE, "now") == NOT_BEFORE
    with pytest.raises(VerificationError):
        validate_utc_time(NOT_BEFORE.replace(tzinfo=None), "now")
    with pytest.raises(VerificationError):
        validate_utc_time(NOT_BEFORE.astimezone(timezone(timedelta(hours=1))), "now")
    with pytest.raises(VerificationError):
        validate_utc_time(NOT_BEFORE.replace(microsecond=1000), "now")
    assert validate_utc_time(NOT_BEFORE.replace(microsecond=1000), "now", precision="milliseconds")
    with pytest.raises(VerificationError):
        validate_utc_time(NOT_BEFORE.replace(microsecond=1), "now", precision="milliseconds")
    with pytest.raises(VerificationError):
        validate_utc_time(NOT_BEFORE, "now", precision="minutes")  # type: ignore[arg-type]


def test_utc_clock_is_aware_utc_at_second_precision() -> None:
    now = utc_clock()
    assert now.utcoffset() == timedelta(0) and now.microsecond == 0


def _bound_packet(tmp_path: Path, issuer: Signer, holder: Signer) -> tuple[dict, dict, Path, ActionRequest, str, str]:
    """The sealed-write record with one observer binding to a new-model grant for its one write."""
    record = materialize("sealed-write", tmp_path)
    packet = copy.deepcopy(load(record / "packet.json"))
    write = packet["claim"]["writes"][0]
    request = _request(run_id=packet["authority"]["intervalId"], request_id=write["requestId"],
                       target_path=write["path"], content_sha256=write["contentDigest"])
    at = packet["commitment"]["committedAt"]
    when = datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    grant = issue_exact_grant(issuer, request, holder_key=raw_public(holder), cnf=cnf_for_signer(holder),
                              not_before=at, expires_at=_iso(when + timedelta(minutes=5)))
    action = verify_grant([grant], request, _policy(issuer), now=when)
    observer_key, witness_key = pinned_keys(record)
    observer, _ = signing_keys(record)
    payload = {"grantDigest": action.grant_digest, "claimDigest": digest("probity-claim-v0", packet["claim"]),
               "intervalId": request.run_id, "request": asdict(request), "authorizedAt": at}
    packet["authorizationBinding"] = {"keyid": observer_key, "payload": payload,
                                      "signature": observer.sign(BINDING_DOMAIN, payload)}
    return grant, packet, record, request, observer_key, witness_key


def test_a_packet_bound_to_a_new_model_grant_verifies(tmp_path: Path) -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    grant, packet, record, request, observer_key, witness_key = _bound_packet(tmp_path, issuer, holder)
    when = datetime.strptime(packet["commitment"]["committedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    result = verify_authorized_packet([grant], request, _policy(issuer), packet, record / "history.jsonl",
                                      observer_key, witness_key, now=when, workspace=record / "workspace")
    assert result["authorization"]["status"] == "verified"
    assert result["authorization"]["grantDigest"] == packet["authorizationBinding"]["payload"]["grantDigest"]
    assert "profile" not in result["authorization"]
    assert result["claim"]["writes"][0]["requestId"] == request.request_id


def test_a_packet_with_no_binding_or_another_issuer_is_refused(tmp_path: Path) -> None:
    issuer, holder = Signer.generate(), Signer.generate()
    grant, packet, record, request, observer_key, witness_key = _bound_packet(tmp_path, issuer, holder)
    when = datetime.strptime(packet["commitment"]["committedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    bare = {k: v for k, v in packet.items() if k != "authorizationBinding"}
    with pytest.raises(VerificationError, match="no valid authorization binding"):
        verify_authorized_packet([grant], request, _policy(issuer), bare, record / "history.jsonl", observer_key,
                                 witness_key, now=when)
    with pytest.raises(VerificationError):
        verify_authorized_packet([grant], request, _policy(Signer.generate()), packet, record / "history.jsonl",
                                 observer_key, witness_key, now=when)
    forged = copy.deepcopy(packet)
    forged["authorizationBinding"]["payload"]["grantDigest"] = "00" * 32
    with pytest.raises(VerificationError, match="differs from the grant or native claim"):
        verify_authorized_packet([grant], request, _policy(issuer), forged, record / "history.jsonl", observer_key,
                                 witness_key, now=when)
