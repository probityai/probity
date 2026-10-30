"""Bind a public reference authorization to one brokered file replacement.

This profile is a local reference integration, not APS, MCP, A2A, DSSE, or
Observed Effect conformance. An explicit issuer grants one exact request; an
observer authenticates that grant before invoking :class:`~.broker.Broker`.
The observer signs a separate grant-to-claim binding when the interval seals.
Native packets and their restricted JSON signing bytes remain unchanged.

The binding attests the observer's dispatch time. Its post-action signature
does not establish cryptographic proof that the grant was witnessed before
the effect. The native prior commitment still covers native authority only.
Different keys and local objects do not establish independent custody.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict
from datetime import datetime
from typing import Any

from . import broker as native_broker
from .broker import Broker
from .crypto import (
    SigningKey,
    canonical,
    digest,
    strict_loads,
)
from .grant_records import (  # noqa: F401
    BINDING_DOMAIN,
    BINDING_FIELDS,
    GRANT_DOMAIN,
    GRANT_FIELDS,
    HEX_DIGEST,
    IDENTIFIER,
    LOGGER,
    MAX_VALIDITY_SECONDS,
    PROFILE,
    UTC_SECOND,
    ActionRequest,
    AuthorizedAction,
    GrantPolicy,
    _authenticate,
    _binding_payload,
    _binding_record,
    _dispatch_chronology,
    _exact_effect,
    _grant_object,
    _hex_digest,
    _identifier,
    _native_claim,
    _packet_object,
    _parse_timestamp,
    _payload,
    _refuse,
    _target,
    _target_syntax,
    _timestamp,
    _verify_binding,
    _window,
    utc_clock,
    validate_utc_time,
    verify_authorized_packet,
    verify_grant,
)
from .records import WriteResult


def issue_grant(
    request: ActionRequest,
    issuer_key: SigningKey,
    *,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Sign one exact action request under the public local reference profile.

    Parameters
    ----------
    request : ActionRequest
        Validated invocation identity and exact replacement-byte digest.
    issuer_key : SigningKey
        Explicit authority signer. It must be different from the observer and
        witness keys used with :class:`AuthorizedBroker`.
    issued_at, expires_at : datetime
        Aware UTC datetimes at second precision. Expiration must follow issuance
        by at most one hour. :func:`verify_grant` applies the consumer's usually
        shorter duration policy and the supplied reference time.

    Returns
    -------
    dict[str, Any]
        Canonical-profile grant with the exact payload, issuer public key,
        and Ed25519 signature. No private key bytes are included.

    Raises
    ------
    VerificationError
        If timestamps or their duration are outside the public profile.
    """
    validate_utc_time(issued_at, "issued_at")
    validate_utc_time(expires_at, "expires_at")
    _window(issued_at, expires_at, MAX_VALIDITY_SECONDS)
    payload = {
        "profile": PROFILE,
        "request": asdict(request),
        "issuedAt": _timestamp(issued_at),
        "expiresAt": _timestamp(expires_at),
    }
    return {
        **payload,
        "issuerKey": issuer_key.public_hex,
        "signature": issuer_key.sign(GRANT_DOMAIN, payload),
    }


def _broker_request(
    broker: Broker, request: ActionRequest, policy: GrantPolicy
) -> None:
    """Check the reference broker's native interval, scope, and key boundaries."""
    authority = broker.authority
    if authority["intervalId"] != request.run_id:
        _refuse("action run differs from the broker interval")
    if authority != {
        "intervalId": request.run_id,
        "scope": "/work",
        "operation": "write-file",
    }:
        _refuse("protected action requires the minimal /work write-file broker profile")
    keys = {broker.observer_key.public_hex, broker.witness.public_hex}
    if policy.issuer_key in keys:
        _refuse("issuer, observer, and witness keys must differ")


class AuthorizedBroker:
    """Authorize an exact finite action before the native broker applies it.

    Parameters
    ----------
    broker : Broker
        Native broker configured for ``/work`` file writes, with an interval ID
        matching the expected request's ``run_id``. Call
        :meth:`~probity_observer.broker.Broker.begin` before :meth:`write`.
    grant : Mapping[str, Any]
        Signed grant captured into this wrapper's private immutable bytes.
    policy : GrantPolicy
        Explicit issuer key pin and validity-duration policy. Its issuer must
        differ from both native observer and witness keys.
    expected_request : ActionRequest
        Immutable consumer-selected invocation identity, including tenant,
        principal, tool, target, attempt, and exact content digest.
    clock : Callable[[], datetime], optional
        UTC second-precision reference clock used on every call to
        :meth:`write`. Defaults to :func:`utc_clock`.

    Notes
    -----
    This wrapper is one path into a local broker. A holder of the underlying
    broker or workspace can bypass it; the offline reader rejects extra
    recorded effects but cannot discover every omitted or transient effect.
    The observer remains ``PEER`` and ``artifact``. A separate key does not
    establish an independent operator. Consumer replay is handled by the
    existing :class:`~.admission.AdmissionStore`, not by this wrapper.
    """

    def __init__(
        self,
        broker: Broker,
        grant: Mapping[str, Any],
        policy: GrantPolicy,
        expected_request: ActionRequest,
        *,
        clock: Callable[[], datetime] = utc_clock,
    ) -> None:
        _broker_request(broker, expected_request, policy)
        self.broker = broker
        self.policy = policy
        self.expected_request = expected_request
        self.clock = clock
        self._grant = canonical(_grant_object(grant))
        self._authority_digest = digest("probity-authority-v0", broker.authority)
        self._observer_key = broker.observer_key.public_hex
        self._witness_key = broker.witness.public_hex
        self._authorization: AuthorizedAction | None = None
        self._authorized_at: datetime | None = None
        self._check_native_binding()

    def _check_native_binding(self) -> None:
        """Refuse mutation of the native authority, its initial digest, or keys."""
        current = digest("probity-authority-v0", self.broker.authority)
        if (
            current != self._authority_digest
            or self.broker._authority_digest != current
        ):
            _refuse("broker authority changed from its initial commitment")
        actual_keys = (
            self.broker.observer_key.public_hex,
            self.broker.witness.public_hex,
        )
        if actual_keys != (self._observer_key, self._witness_key):
            _refuse("broker signing keys changed after authorization configuration")

    def _check_dispatch_time(self, reference: datetime) -> None:
        """Check the dispatch clock against this begun interval before the effect."""
        if not self.broker._begin or not self.broker._started:
            _refuse("protected action requires a begun native interval")
        committed_at = _parse_timestamp(
            self.broker._begin["committedAt"], "committedAt"
        )
        observed_at = _parse_timestamp(native_broker.utc_now(), "observerNow")
        if not committed_at <= reference <= observed_at:
            _refuse("authorization dispatch time is outside the native interval")

    def write(self, request: ActionRequest, content: bytes) -> WriteResult:
        """Check issuer, all request fields, bytes, and time before applying work.

        Parameters
        ----------
        request : ActionRequest
            Exact invocation. A changed tenant, principal, tool, target, run,
            attempt, idempotency key, or content digest is refused.
        content : bytes
            Actual replacement bytes. Their SHA-256 must equal the grant's
            signed ``content_sha256`` before native dispatch.

        Returns
        -------
        WriteResult
            Native durable-file result, including exact-retry classification.

        Raises
        ------
        VerificationError
            If authorization fails before dispatch. The native broker's own
            coverage or storage exceptions propagate without being rewritten.
        """
        self._check_native_binding()
        if request != self.expected_request:
            _refuse("invocation differs from the expected action")
        if not isinstance(content, bytes):
            _refuse("protected action content must be bytes")
        if hashlib.sha256(content).hexdigest() != request.content_sha256:
            _refuse("content digest differs from the authorized action")
        reference = self.clock()
        authorization = verify_grant(
            strict_loads(self._grant), request, self.policy, now=reference
        )
        self._check_dispatch_time(reference)
        result = self.broker.write(request.request_id, request.target_path, content)
        if self._authorization is None:
            self._authorization, self._authorized_at = authorization, reference
        return result

    def seal(self) -> dict[str, Any]:
        """Seal the native interval and sign its exact link to the verified grant.

        Returns
        -------
        dict[str, Any]
            Native packet plus ``authorizationBinding``. The signed binding
            links the entire grant, exact request, observer-reported dispatch
            time, native interval, and native claim digest.

        Raises
        ------
        VerificationError
            If no authorized effect completed through this wrapper.

        Notes
        -----
        The additional observer signature is produced after the effect. It
        authenticates an attestation about ordering, not an independently
        witnessed prior commitment to the grant. Use
        :func:`verify_authorized_packet` before native consumer admission.
        """
        self._check_native_binding()
        if self._authorization is None or self._authorized_at is None:
            _refuse("protected action has no completed authorized effect")
        packet = self.broker.seal()
        payload = _binding_payload(self._authorization, packet, self._authorized_at)
        packet["authorizationBinding"] = {
            "payload": payload,
            "keyid": self.broker.observer_key.public_hex,
            "signature": self.broker.observer_key.sign(BINDING_DOMAIN, payload),
        }
        return packet


