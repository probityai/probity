"""Verify the signatures of an A2A agent card over the bytes the server sent."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from joserfc import jws
from joserfc.errors import JoseError

from agent_evidence_a2a._ijson import IJsonError, parse_i_json
from agent_evidence_a2a.canonical import CardCanonicalizationError, served_signing_bytes
from agent_evidence_a2a.trust import TrustStore

DEFAULT_ALGORITHMS: Final[tuple[str, ...]] = ("ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "EdDSA")
_BASE64URL: Final = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True, kw_only=True, slots=True)
class Finding:
    """One reason a card or a signature was not accepted, or a note about one."""

    check_id: str
    message: str
    severity: str = "error"
    signature_index: int | None = None


@dataclass(frozen=True, kw_only=True, slots=True)
class CardVerdict:
    """The outcome of verifying a card: accepted only when the signer policy is met with no error finding."""

    accepted: bool
    findings: tuple[Finding, ...] = ()
    verified_kids: frozenset[str] = field(default_factory=frozenset)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_header(protected: str) -> dict[str, Any] | None:
    if not _BASE64URL.fullmatch(protected):
        return None
    try:
        text = base64.urlsafe_b64decode(protected + "=" * (-len(protected) % 4)).decode("utf-8")
        header = parse_i_json(text, max_depth=8)
    except (ValueError, IJsonError):
        return None
    return header if isinstance(header, dict) else None


def _struct(index: int, detail: str) -> Finding:
    message = f"signatures[{index}]: {detail}"
    return Finding(check_id="CARD-SIGN-003", message=message, signature_index=index)


def _structure_problem(
    sig: Any, index: int, algorithms: tuple[str, ...]
) -> tuple[Finding | None, dict[str, Any] | None]:
    if (
        not isinstance(sig, dict)
        or not isinstance(sig.get("protected"), str)
        or not isinstance(sig.get("signature"), str)
    ):
        return _struct(index, "a signature needs string members 'protected' and 'signature'"), None
    header = _decode_header(sig["protected"])
    if header is None:
        return _struct(index, "protected header is not unpadded base64url JSON object without repeated names"), None
    if not _BASE64URL.fullmatch(sig["signature"]):
        return _struct(index, "signature value is not unpadded base64url (RFC 7515 section 2)"), header
    if "crit" in header:
        return _struct(index, "protected header names crit extensions this verifier does not understand"), header
    if not isinstance(header.get("kid"), str) or "alg" not in header:
        return _struct(
            index, "protected header needs both alg and kid (a kid outside the protected header is unsigned)"
        ), header
    if header["alg"] not in algorithms:
        return _struct(index, f"alg {header['alg']!r} is not an accepted asymmetric algorithm"), header
    return None, header


def _judge_signature(
    sig: Any, index: int, payload: bytes, trust: TrustStore, now: datetime, algorithms: tuple[str, ...]
) -> tuple[Finding | None, str | None, bool]:
    """Return ``(finding, verified kid, is_key_status)``; key status marks unknown or expired kids."""
    problem, header = _structure_problem(sig, index, algorithms)
    if problem is not None or header is None:
        return problem, None, False
    kid = header["kid"]
    trusted = trust.get(kid)
    if trusted is None:
        msg = f"signatures[{index}]: kid {kid!r} is not in the pinned trust store (unknown or revoked)"
        return Finding(check_id="CARD-SIGN-004", message=msg, signature_index=index), None, True
    reason = trusted.invalid_reason(now)
    if reason is not None:
        msg = f"signatures[{index}]: pinned key {kid!r} {reason}"
        return Finding(check_id="CARD-SIGN-004", message=msg, signature_index=index), None, True
    token = f"{sig['protected']}.{_b64(payload)}.{sig['signature']}"
    try:
        jws.deserialize_compact(token, trusted.key, algorithms=[header["alg"]])
    except (JoseError, ValueError, TypeError):
        msg = f"signatures[{index}]: the signature does not verify over the served card with 'signatures' removed"
        return Finding(check_id="CARD-SIGN-002", message=msg, signature_index=index), None, False
    return None, kid, False


def _parse_signed_card(served: str | bytes) -> tuple[bytes, list[Any]] | CardVerdict:
    """Return the recomputed signed payload and the signature list, or the rejecting verdict."""
    try:
        payload = served_signing_bytes(served)
        text = served.decode("utf-8") if isinstance(served, bytes) else served
        signatures = parse_i_json(text).get("signatures")
    except (CardCanonicalizationError, IJsonError) as exc:
        message = f"the served card has no RFC 8785 canonical form ({exc}); it MUST NOT be trusted"
        return CardVerdict(accepted=False, findings=(Finding(check_id="CARD-SIGN-001", message=message),))
    if not isinstance(signatures, list) or not signatures:
        return CardVerdict(
            accepted=False, findings=(Finding(check_id="CARD-SIGN-003", message="the card carries no signatures"),)
        )
    return payload, signatures


def _settle_findings(
    findings: list[Finding], status_notes: list[Finding], *, policy_met: bool, verified: int, threshold: int
) -> list[Finding]:
    """Fold the key-status notes into the findings: informational once the policy is met, else errors."""
    if policy_met:
        return [
            *findings,
            *(
                Finding(check_id=f.check_id, message=f.message, severity="info", signature_index=f.signature_index)
                for f in status_notes
            ),
        ]
    settled = [*findings, *status_notes]
    if not settled:
        message = f"only {verified} distinct signer(s) verified; the policy needs {threshold}"
        settled.append(Finding(check_id="CARD-SIGN-004", message=message))
    return settled


def _judge_all(
    signatures: list[Any], payload: bytes, trust: TrustStore, clock: datetime, algorithms: tuple[str, ...]
) -> tuple[list[Finding], list[Finding], set[str]]:
    """Judge every signature; return the failures, the key-status notes and the signers that verified."""
    findings: list[Finding] = []
    status_notes: list[Finding] = []
    verified: set[str] = set()
    for index, sig in enumerate(signatures):
        finding, kid, is_status = _judge_signature(sig, index, payload, trust, clock, algorithms)
        if kid is not None:
            verified.add(kid)
        if finding is not None:
            (status_notes if is_status else findings).append(finding)
    return findings, status_notes, verified


def verify_served_card(
    served: str | bytes,
    trust: TrustStore,
    *,
    now: datetime | None = None,
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS,
    threshold: int = 1,
    required_kids: frozenset[str] = frozenset(),
) -> CardVerdict:
    """Verify a card's signatures over *served*, the bytes the server sent.

    The signed payload is recomputed from the served document (never from a parsed object model),
    so a member appended after signing, a repeated member name and a default-valued field kept in
    the signed bytes all fail. A signature whose ``kid`` is unknown or expired is a note, not a
    failure, once *threshold* distinct signers verify, which is how key rotation reads.

    Args:
        served: The agent card response body.
        trust: The pinned keys.
        now: The verification clock; the current UTC time when omitted.
        algorithms: The accepted ``alg`` values.
        threshold: How many distinct signers must verify.
        required_kids: Signers that must be among those that verified.
    """
    clock = now or datetime.now(UTC)
    parsed = _parse_signed_card(served)
    if isinstance(parsed, CardVerdict):
        return parsed
    payload, signatures = parsed
    findings, status_notes, verified = _judge_all(signatures, payload, trust, clock, algorithms)
    policy_met = len(verified) >= threshold and required_kids <= verified
    findings = _settle_findings(
        findings, status_notes, policy_met=policy_met, verified=len(verified), threshold=threshold
    )
    errors = [f for f in findings if f.severity == "error"]
    return CardVerdict(accepted=policy_met and not errors, findings=tuple(findings), verified_kids=frozenset(verified))
