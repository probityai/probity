"""An exact request as a capability grant, and the permit that presents it.

The one grant model (probity-records ``docs/one-name.md`` section 3): an exact request is a
``probity_records`` capability grant whose one tool fixes every argument with an ``exact`` constraint and whose
context fixes the run, attempt, request, tenant and principal, presented with a permit for the call. Its window is
inclusive at both ends, as every capability-grant verifier reads it, so the observer and the records verifiers give
one answer at every instant. Nothing here issues a call, invokes a broker or decides when an action may run.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Mapping, Sequence, Set
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, NoReturn

from probity_records.core import Signer, args_sha256, sign_permit, verify_permit
from probity_records.grants import issue_grant, ts, verify_grant_allow
from probity_records.walk import grant_permit_claims

from .crypto import VerificationError, canonical, digest, strict_loads, verify_signature
from .verify import verify_packet

LOGGER = logging.getLogger(__name__)

BINDING_DOMAIN = "probity-protected-action-binding-v0"

BINDING_FIELDS = frozenset({"payload", "keyid", "signature"})

MAX_VALIDITY_SECONDS = 3600

UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

IDENTIFIER = re.compile(r"[!-~]{1,128}\Z")


class ExactGrantRefused(VerificationError):
    """An exact request a grant chain or permit does not authorize; ``reason`` is the records verifier's reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _refuse(reason: str) -> NoReturn:
    """Log a bounded refusal without request contents or private key material."""
    LOGGER.warning("exact request refused: %s", reason)
    raise VerificationError(reason)


def _identifier(value: Any, name: str) -> None:
    """Require a finite, nonempty, printable ASCII identifier without spaces."""
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        _refuse(f"{name} must be a nonempty printable ASCII identifier")


def _hex_digest(value: Any, name: str) -> None:
    """Require the exact lowercase hexadecimal representation of 32 bytes."""
    if not isinstance(value, str) or HEX_DIGEST.fullmatch(value) is None:
        _refuse(f"{name} must be a lowercase SHA-256-sized hexadecimal value")


def _target(value: Any) -> None:
    """Validate the literal local profile path without decoding or resolving it."""
    _target_syntax(value)
    if "\\" in value:
        _refuse("target_path must be a normalized literal path under /work")
    if any(part in {"", ".", ".."} for part in value[1:].split("/")):
        _refuse("target_path must be a normalized literal path under /work")


def _target_syntax(value: Any) -> None:
    """Check finite printable literal path syntax before inspecting segments."""
    if not isinstance(value, str) or not value.isascii() or len(value) > 256:
        _refuse("target_path must be a normalized literal path under /work")
    if not value.startswith("/work/"):
        _refuse("target_path must be a normalized literal path under /work")
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        _refuse("target_path must be a normalized literal path under /work")


@dataclass(frozen=True, slots=True)

class ActionRequest:
    """Immutable exact invocation identity for one local file replacement.

    ``run_id``, ``attempt_id`` and ``request_id`` are the logical run, the invocation attempt and the broker
    idempotency key; ``tenant_id`` and ``principal_id`` the tenant and requesting principal the relying party chose;
    ``tool_id`` the locally configured tool; ``target_path`` a normalized literal absolute path beneath ``/work``
    (no URL decoding, filesystem resolution or alias conversion); ``content_sha256`` the SHA-256 of the exact bytes
    to write there. Identifiers are 1 to 128 printable ASCII characters without spaces. ``VerificationError`` when a
    field is outside the profile.
    """

    run_id: str
    attempt_id: str
    request_id: str
    tenant_id: str
    principal_id: str
    tool_id: str
    target_path: str
    content_sha256: str

    def __post_init__(self) -> None:
        for name in ("run_id", "attempt_id", "request_id", "tenant_id", "principal_id", "tool_id"):
            _identifier(getattr(self, name), name)
        _target(self.target_path)
        _hex_digest(self.content_sha256, "content_sha256")


def exact_call(request: ActionRequest) -> tuple[str, dict[str, str], dict[str, str]]:
    """The call a grant judges for ``request``: its tool, its arguments and its call context."""
    args = {"contentSha256": request.content_sha256, "targetPath": request.target_path}
    ctx = {"attemptId": request.attempt_id, "principalId": request.principal_id, "requestId": request.request_id,
           "runId": request.run_id, "tenantId": request.tenant_id}
    return request.tool_id, args, ctx


def _exact(values: Mapping[str, str]) -> dict[str, dict[str, str]]:
    return {name: {"type": "exact", "value": value} for name, value in values.items()}


def issue_exact_grant(issuer: Signer, request: ActionRequest, *, holder_key: str, cnf: Mapping[str, str],
                      not_before: str, expires_at: str) -> dict[str, Any]:
    """A root capability grant that admits ``request`` and nothing else, from ``not_before`` to ``expires_at``
    inclusive, held by ``holder_key`` and presented by the key ``cnf`` confirms. No further delegation."""
    tool, args, ctx = exact_call(request)
    return issue_grant(issuer, grant_id=request.request_id, holder_key=holder_key, cnf=cnf,
                       tools={tool: {"args": _exact(args)}}, context=_exact(ctx),
                       not_before=not_before, expires_at=expires_at, max_depth=0)


def verify_exact_grant(chain: list[Mapping[str, Any]], request: ActionRequest, root_key_ids: Set[str], *, at: str,
                       revoked_grants: set[str] | None = None, key_revoked: Any = None) -> str:
    """The leaf grant digest when ``chain``, rooted in a pinned issuer, admits ``request`` at ``at`` (RFC 3339, the
    window inclusive at both ends); ``ExactGrantRefused`` with the records verifier's reason otherwise."""
    tool, args, ctx = exact_call(request)
    verdict = verify_grant_allow(chain, tool, args, at, set(root_key_ids), revoked_grants, key_revoked, ctx=ctx)
    if verdict["decision"] != "allow":
        LOGGER.warning("exact request refused: %s", verdict["reason"])
        raise ExactGrantRefused(verdict["reason"])
    return str(verdict["grantDigest"])


def mint_exact_permit(authority: Signer, chain: list[Mapping[str, Any]], request: ActionRequest, *,
                      issued_at: str, permit_id: str | None = None) -> dict[str, Any]:
    """The authority's permit for ``request`` under ``chain``, issued at ``issued_at``. ``permit_id`` defaults to
    the request id, the broker's idempotency key."""
    tool, args, ctx = exact_call(request)
    claims = grant_permit_claims(permit=permit_id or request.request_id, tool=tool, args_sha256_hex=args_sha256(args),
                                 chain=list(chain), ctx=ctx, issued_at=issued_at)
    return sign_permit(authority, claims)


def verify_exact_permit(permit: Any, authority_pem: bytes, chain: list[Mapping[str, Any]], request: ActionRequest,
                        root_key_ids: Set[str], *, revoked_grants: set[str] | None = None,
                        key_revoked: Any = None) -> dict[str, Any]:
    """The permit's claims when the pinned authority signed a permit for exactly ``request`` under ``chain`` and
    the chain admits the request at the permit's ``issuedAt``; ``ExactGrantRefused`` otherwise."""
    claims = verify_permit(permit, authority_pem)
    if claims is None:
        _refuse_permit("permit_signature_invalid")
    tool, args, ctx = exact_call(request)
    digest = verify_exact_grant(chain, request, root_key_ids, at=str(claims.get("issuedAt")),
                                revoked_grants=revoked_grants, key_revoked=key_revoked)
    expected = grant_permit_claims(permit=str(claims.get("permitId")), tool=tool, args_sha256_hex=args_sha256(args),
                                   chain=list(chain), ctx=ctx, issued_at=str(claims.get("issuedAt")),
                                   revocation_seq=claims.get("revocationSeq"))
    named = {k: v for k, v in claims.items() if k in expected}
    if named != expected or expected["grantDigest"] != digest:
        _refuse_permit("permit_names_another_call")
    return dict(claims)


def _refuse_permit(reason: str) -> NoReturn:
    LOGGER.warning("exact request refused: %s", reason)
    raise ExactGrantRefused(reason)


@dataclass(frozen=True, slots=True)
class GrantPolicy:
    """The issuer key and the longest grant window a consumer accepts.

    ``issuer_key`` is the raw Ed25519 public key as 64 lowercase hexadecimal characters, acquired outside the
    candidate grant (copying it from the candidate would remove the authentication this policy enforces).
    ``max_validity_seconds`` is an integer from 1 to 3600; booleans are refused. ``VerificationError`` when either
    is malformed.
    """

    issuer_key: str
    max_validity_seconds: int = 300

    def __post_init__(self) -> None:
        _hex_digest(self.issuer_key, "issuer_key")
        valid = type(self.max_validity_seconds) is int
        if not valid or not 1 <= self.max_validity_seconds <= MAX_VALIDITY_SECONDS:
            _refuse("max_validity_seconds must be an integer from 1 to 3600")

    @property
    def key_id(self) -> str:
        """The records key id of the issuer: the SHA-256 of its raw public key."""
        return hashlib.sha256(bytes.fromhex(self.issuer_key)).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorizedAction:
    """An exact request a pinned issuer's grant chain admitted at the reference time.

    ``grant_digest`` is the leaf grant's digest from the records verifier, the value the observer binds to the
    native claim. ``issued_at`` and ``expires_at`` are the leaf's ``notBefore`` and ``expiresAt``, the window
    inclusive at both ends. Authentication does not establish an actual effect, issuer entitlement beyond policy,
    or current freshness.
    """

    request: ActionRequest
    issuer_key: str
    issued_at: datetime
    expires_at: datetime
    grant_digest: str


def utc_clock() -> datetime:
    """The current UTC time rounded down to whole seconds."""
    return datetime.now(UTC).replace(microsecond=0)


def validate_utc_time(value: Any, name: str, *, precision: Literal["seconds", "milliseconds"] = "seconds") -> datetime:
    """An aware UTC datetime at the declared precision, refused (never rounded) when finer."""
    if not isinstance(precision, str) or precision not in {"seconds", "milliseconds"}:
        _refuse("UTC time precision is unsupported")
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        _refuse(f"{name} must be a timezone-aware UTC datetime")
    if precision == "seconds" and value.microsecond:
        _refuse(f"{name} must use UTC second precision")
    if precision == "milliseconds" and value.microsecond % 1000:
        _refuse(f"{name} must use UTC millisecond precision")
    return value


def _timestamp(value: datetime, precision: str = "seconds") -> str:
    """RFC 3339 text of a validated UTC datetime, at whole seconds or milliseconds."""
    return value.isoformat(timespec=precision).replace("+00:00", "Z")


def _parse_timestamp(value: Any, name: str) -> datetime:
    """A canonical UTC second-precision timestamp, refused otherwise."""
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        _refuse(f"{name} must use canonical UTC second precision")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _chain_object(chain: Any) -> list[dict[str, Any]]:
    """A canonical private snapshot of a grant chain, refused when it is not a list of grants."""
    if not isinstance(chain, list) or not chain:
        _refuse("grant chain must be a nonempty list of grants")
    try:
        return strict_loads(canonical(chain))
    except VerificationError:
        _refuse("grant chain is outside the restricted JSON profile")


def verify_grant(chain: Sequence[Mapping[str, Any]], expected_request: ActionRequest, policy: GrantPolicy, *,
                 now: datetime, reference_precision: Literal["seconds", "milliseconds"] = "seconds") -> AuthorizedAction:
    """Authenticate an exact request at an explicit consumer reference time.

    ``chain`` is the grant chain, rooted in the issuer ``policy`` pins; ``now`` an aware UTC datetime at
    ``reference_precision``, admitted inside the leaf window inclusive at both ends. The leaf window may not exceed
    ``policy.max_validity_seconds``. ``VerificationError`` with a bounded reason otherwise.
    """
    reference = validate_utc_time(now, "now", precision=reference_precision)
    snapshot = _chain_object(chain)
    digest_hex = verify_exact_grant(snapshot, expected_request, {policy.key_id},
                                    at=_timestamp(reference, reference_precision))
    body = snapshot[-1]["body"]
    issued_at, expires_at = ts(body["notBefore"]), ts(body["expiresAt"])
    if (expires_at - issued_at).total_seconds() > policy.max_validity_seconds:
        _refuse("grant validity window exceeds policy")
    return AuthorizedAction(expected_request, policy.issuer_key, issued_at.astimezone(UTC),
                            expires_at.astimezone(UTC), digest_hex)


def _binding_payload(authorization: AuthorizedAction, packet: Mapping[str, Any], reference: datetime) -> dict[str, Any]:
    """The exact signed relation from a grant to a native bounded claim."""
    return {
        "grantDigest": authorization.grant_digest,
        "claimDigest": digest("probity-claim-v0", packet["claim"]),
        "intervalId": authorization.request.run_id,
        "request": asdict(authorization.request),
        "authorizedAt": _timestamp(reference),
    }


def _binding_record(packet: Mapping[str, Any], observer_key: str) -> dict[str, Any]:
    """One exact binding envelope under the externally pinned observer key."""
    binding = packet.get("authorizationBinding")
    if not isinstance(binding, dict) or set(binding) != BINDING_FIELDS:
        _refuse("packet has no valid authorization binding")
    if binding["keyid"] != observer_key:
        _refuse("authorization binding key differs from the pinned observer key")
    return binding


def _verify_binding(packet: Mapping[str, Any], authorization: AuthorizedAction, observer_key: str) -> datetime:
    """Authenticate the observer binding and its exact link to the native claim; its dispatch time."""
    binding = _binding_record(packet, observer_key)
    payload = binding["payload"]
    if not isinstance(payload, dict) or "authorizedAt" not in payload:
        _refuse("authorization binding payload is malformed")
    reference = _parse_timestamp(payload["authorizedAt"], "authorizedAt")
    if payload != _binding_payload(authorization, packet, reference):
        _refuse("authorization binding differs from the grant or native claim")
    try:
        verify_signature(observer_key, BINDING_DOMAIN, payload, binding["signature"])
    except (VerificationError, TypeError):
        _refuse("authorization binding signature does not verify under the pinned key")
    return reference


def _exact_effect(claim: Mapping[str, Any], request: ActionRequest) -> None:
    """Exactly one native accepted effect, matching the authorized call."""
    writes = claim["writes"]
    if len(writes) != 1:
        _refuse("protected action requires exactly one recorded effect")
    write = writes[0]
    if (write["requestId"], write["path"], write["contentDigest"]) != (
            request.request_id, request.target_path, request.content_sha256):
        _refuse("recorded effect differs from the authorized action")


def _dispatch_chronology(packet: Mapping[str, Any], reference: datetime) -> None:
    """The reported dispatch time lies within the signed native interval."""
    committed_at = _parse_timestamp(packet["commitment"]["committedAt"], "committedAt")
    sealed_at = _parse_timestamp(packet["claim"]["sealedAt"], "sealedAt")
    if not committed_at <= reference <= sealed_at:
        _refuse("authorization dispatch time is outside the native interval")


def _packet_object(packet: Any) -> dict[str, Any]:
    """Canonical packet bytes captured before the several signed relations are checked."""
    if not isinstance(packet, dict):
        _refuse("protected action packet is malformed")
    return strict_loads(canonical(packet))


def _native_claim(packet: dict[str, Any], history: Path, observer: str, witness: str,
                  workspace: Path | None) -> dict[str, Any]:
    """Native verification with its reasons kept and malformed input normalized."""
    try:
        return verify_packet(packet, history, observer, witness, workspace)
    except VerificationError as exc:
        LOGGER.warning("exact request refused: %s", exc)
        raise
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        _refuse("protected action packet is malformed")


def verify_authorized_packet(chain: Sequence[Mapping[str, Any]], expected_request: ActionRequest, policy: GrantPolicy,
                             packet: dict[str, Any], history_path: Path, pinned_observer_key: str,
                             pinned_witness_key: str, *, now: datetime,
                             workspace: Path | None = None) -> dict[str, Any]:
    """Verify exact authorization separately from native observation consistency.

    ``chain``, ``expected_request``, ``policy`` and ``now`` are the inputs of :func:`verify_grant`; ``packet`` the
    native packet carrying the observer-signed ``authorizationBinding``; ``history_path`` the retained native
    history; the two pinned keys the consumer's observer and witness keys, which must differ from the issuer's.
    Returns ``authorization`` (status, grant digest, reference and dispatch times, ordering evidence, whether the
    current workspace was compared) and the unchanged native ``claim``. This reader keeps no replay state; call it
    before the operator runtime's admission store. Passing record checks do not establish complete capture or
    independent operator custody. ``VerificationError`` with the original reason on any failure.
    """
    snapshot = _chain_object(chain)
    candidate = _packet_object(packet)
    authorization = verify_grant(snapshot, expected_request, policy, now=now)
    if policy.issuer_key in {pinned_observer_key, pinned_witness_key}:
        _refuse("issuer, observer, and witness keys must differ")
    claim = _native_claim(candidate, history_path, pinned_observer_key, pinned_witness_key, workspace)
    if candidate["authority"] != {"intervalId": expected_request.run_id, "scope": "/work", "operation": "write-file"}:
        _refuse("native authority differs from the protected action profile")
    dispatch_time = _verify_binding(candidate, authorization, pinned_observer_key)
    verify_grant(snapshot, expected_request, policy, now=dispatch_time)
    _dispatch_chronology(candidate, dispatch_time)
    _exact_effect(claim, expected_request)
    return {
        "authorization": {
            "status": "verified",
            "grantDigest": authorization.grant_digest,
            "referenceTime": _timestamp(now),
            "authorizedAt": _timestamp(dispatch_time),
            "orderingEvidence": "observer-attested-dispatch-time",
            "currentWorkspaceCompared": workspace is not None,
        },
        "claim": claim,
    }
