"""An exact request as a capability grant, and the permit that presents it.

The one grant model (probity-records ``docs/one-name-ruling.md`` section 3): an exact request is a
``probity_records`` capability grant whose one tool fixes every argument with an ``exact`` constraint and whose
context fixes the run, attempt, request, tenant and principal, presented with a permit for the call. Its window is
inclusive at both ends, as every capability-grant verifier reads it, so the observer and the records verifiers give
one answer at every instant. Nothing here issues a call, invokes a broker or decides when an action may run.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Set
from dataclasses import dataclass
from typing import Any, NoReturn

from probity_records.core import Signer, args_sha256, sign_permit, verify_permit
from probity_records.grants import issue_grant, verify_grant_allow
from probity_records.walk import grant_permit_claims

from .crypto import VerificationError

LOGGER = logging.getLogger(__name__)

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
