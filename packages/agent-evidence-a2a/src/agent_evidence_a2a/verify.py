"""Verify the signatures of an A2A agent card over the bytes the server sent."""

from __future__ import annotations

import base64
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal, cast

from joserfc.errors import JoseError
from joserfc.jwk import Key

from agent_evidence_a2a._ijson import IJsonError, parse_i_json
from agent_evidence_a2a.canonical import (
    MAX_CARD_BYTES,
    CardCanonicalizationError,
    non_jcs_forms,
    signed_parts,
)
from agent_evidence_a2a.detached import (
    DEFAULT_ALGORITHMS,
    MAX_HEADER_B64,
    MAX_HEADER_BYTES,
    CardRegistry,
    HeaderRefused,
    check_detached,
)
from agent_evidence_a2a.trust import KeyLookup, PinnedKey, TrustStore, outside_window

#: ``(label, payload)`` pairs of the signing payloads a producer would get by deviating from RFC 8785.
type Alternatives = tuple[tuple[str, bytes], ...]

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


def _member_problem(sig: Any, index: int) -> Finding | None:
    """The member's own shape: two string members within the bounds the registry verifies under."""
    if (
        not isinstance(sig, dict)
        or not isinstance(sig.get("protected"), str)
        or not isinstance(sig.get("signature"), str)
    ):
        return _struct(index, "a signature needs string members 'protected' and 'signature'")
    if len(sig["protected"]) > MAX_HEADER_B64:
        return _struct(index, f"protected header decodes to more than {MAX_HEADER_BYTES} bytes")
    if len(sig["signature"]) > MAX_CARD_BYTES:
        return _struct(index, f"signature value is longer than a served card may be ({MAX_CARD_BYTES} bytes)")
    return None


def _header_problem(header: dict[str, Any], index: int, algorithms: tuple[str, ...]) -> Finding | None:
    """The decoded protected header: no crit, a signed kid and alg, an accepted alg, well-formed parameters."""
    if "crit" in header:
        return _struct(index, "protected header names crit extensions this verifier does not understand")
    if "b64" in header and header["b64"] is not True:
        # RFC 7797 (an unencoded payload) is not part of A2A section 8.4: the card signature signs the
        # base64url form of the JCS bytes.  joserfc refuses such a header at verification, and that
        # refusal is not a statement about the signature.
        return _struct(
            index,
            "protected header sets b64 to a value other than true; an A2A card signature signs the "
            "base64url JCS payload, so RFC 7797 does not apply",
        )
    if not isinstance(header.get("kid"), str) or "alg" not in header:
        return _struct(
            index, "protected header needs both alg and kid (a kid outside the protected header is unsigned)"
        )
    if header["alg"] not in algorithms:
        return _struct(index, f"alg {header['alg']!r} is not an accepted asymmetric algorithm")
    try:
        CardRegistry(algorithms=list(algorithms), strict_check_header=False).check_header(header)
    except JoseError as exc:
        # A registered parameter with a value of the wrong form (a jku that is not a URL, an x5c
        # that is not a list of strings): the header is malformed, which is not a bad signature.
        return _struct(index, f"protected header has a malformed registered parameter ({exc})")
    return None


def _structure_problem(
    sig: Any, index: int, algorithms: tuple[str, ...]
) -> tuple[Finding | None, dict[str, Any] | None]:
    member = _member_problem(sig, index)
    if member is not None:
        return member, None
    header = _decode_header(sig["protected"])
    if header is None:
        return _struct(index, "protected header is not unpadded base64url JSON object without repeated names"), None
    if not _BASE64URL.fullmatch(sig["signature"]):
        return _struct(index, "signature value is not unpadded base64url (RFC 7515 section 2)"), header
    return _header_problem(header, index, algorithms), header


@dataclass(frozen=True, kw_only=True, slots=True)
class SignatureJudgement:
    """The verdict on one member of a card's ``signatures`` array."""

    finding: Finding | None = None
    """Why the signature was not accepted, or ``None`` when it verified or could not be anchored."""
    verified_kid: str | None = None
    """The signer, when the signature verified over the section 8.4.3 payload."""
    key_status: bool = False
    """The finding is about the pinned key, not the signature: its ``kid`` is unknown or the key is
    outside its validity window.  Beside a verifying signer that is key rotation (section 8.4.3)."""
    unanchored: bool = False
    """The signature passed every structural check, but there was no trust store to decide it."""


def _finding(check_id: str, index: int, detail: str) -> Finding:
    return Finding(check_id=check_id, message=f"signatures[{index}]: {detail}", signature_index=index)


def _verifies(sig: dict[str, Any], payload: bytes, key: Key, alg: str) -> bool:
    return check_detached(sig["protected"], sig["signature"], payload, key, (alg,))


def _key_for(kid: str, index: int, lookup: KeyLookup, now: datetime) -> PinnedKey | SignatureJudgement:
    """The pinned key a signature by *kid* is verified with, or the CARD-SIGN-004 judgement refusing one."""
    pinned = lookup(kid)
    if pinned is None:
        detail = f"kid {kid!r} is not in the pinned trust store (unknown or revoked); it MUST NOT be trusted"
        return SignatureJudgement(finding=_finding("CARD-SIGN-004", index, detail), key_status=True)
    try:
        reason = outside_window(pinned, now)
    except TypeError as exc:
        detail = (
            f"pinned key {kid!r} has a validity window that cannot be compared with the verification "
            f"clock ({exc}); it MUST NOT be used to verify the signature"
        )
        return SignatureJudgement(finding=_finding("CARD-SIGN-004", index, detail))
    if reason is not None:
        detail = f"pinned key {kid!r} {reason}; it MUST NOT be used to verify the signature"
        return SignatureJudgement(finding=_finding("CARD-SIGN-004", index, detail), key_status=True)
    return pinned


def _crypto(
    sig: dict[str, Any], *, kid: str, index: int, key: PinnedKey, alg: str, payload: bytes, alternatives: Alternatives
) -> SignatureJudgement:
    """CARD-SIGN-001 and -002: verify over the payload, then name the non-JCS form a failure verifies over."""
    try:
        if _verifies(sig, payload, key.key, alg):
            return SignatureJudgement(verified_kid=kid)
    except HeaderRefused as exc:
        # The header cannot be verified at all, whatever the payload: a structural finding, not a bad signature.
        return SignatureJudgement(finding=_struct(index, f"protected header cannot be verified ({exc})"))
    for label, form in alternatives:
        if _verifies(sig, form, key.key, alg):
            detail = (
                f"the signature verifies over {label} but not over the RFC 8785 payload; the producer did not "
                "canonicalize with JCS, and a conformant verifier rejects this card"
            )
            return SignatureJudgement(finding=_finding("CARD-SIGN-001", index, detail))
    detail = "the signature does not verify over the served card with 'signatures' removed (RFC 8785)"
    return SignatureJudgement(finding=_finding("CARD-SIGN-002", index, detail))


def judge_signature(
    signature: object,
    *,
    index: int,
    payload: bytes,
    lookup: KeyLookup | None,
    now: datetime,
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS,
    alternatives: Alternatives = (),
) -> SignatureJudgement:
    """Judge one member of a served card's ``signatures`` array: CARD-SIGN-001 to -004.

    This is the one judge of a card signature: :func:`verify_served_card` and any CARD-SIGN
    gate built on this package both call it, so they cannot disagree on a signature.

    Args:
        signature: The member exactly as parsed from the served card; anything but an object
            with string ``protected`` and ``signature`` members is a CARD-SIGN-003 finding.
        index: Its position in the array, named in every message.
        payload: The section 8.4.3 payload, from :func:`signed_parts` of the same bytes.
        lookup: Resolves a ``kid`` to its pinned key (``TrustStore.get`` or any
            :data:`KeyLookup`).  ``None`` means no trust store at all, which is not a store that
            lacks the ``kid``: only the structural checks run, and a sound signature comes back
            ``unanchored``.
        now: The verification clock.
        algorithms: The accepted ``alg`` values.
        alternatives: ``(label, payload)`` pairs of non-JCS forms (:func:`non_jcs_forms`); a
            signature that fails over *payload* and verifies over one is a CARD-SIGN-001 finding
            naming the form, instead of CARD-SIGN-002.
    """
    problem, header = _structure_problem(signature, index, algorithms)
    if problem is not None or header is None:
        return SignatureJudgement(finding=problem)
    if lookup is None:
        return SignatureJudgement(unanchored=True)
    kid = header["kid"]
    key = _key_for(kid, index, lookup, now)
    if isinstance(key, SignatureJudgement):
        return key
    sig = cast("dict[str, Any]", signature)
    return _crypto(sig, kid=kid, index=index, key=key, alg=header["alg"], payload=payload, alternatives=alternatives)


@dataclass(frozen=True, kw_only=True, slots=True)
class SignedCard:
    """A served card that carries signatures, read from one parse of the served bytes."""

    payload: bytes
    """The section 8.4.3 signing payload."""
    signatures: tuple[object, ...]
    """The members of the card's ``signatures`` array exactly as parsed; each goes to :func:`judge_signature`."""
    alternatives: Alternatives
    """The non-JCS forms the card could have been signed over (:func:`non_jcs_forms`), minus the real payload."""


@dataclass(frozen=True, kw_only=True, slots=True)
class UnreadableCard:
    """A served card no signature can be judged on, and why."""

    kind: Literal["uncanonicalizable", "unsigned", "malformed"]
    """``uncanonicalizable``: no RFC 8785 form (CARD-SIGN-001).  ``unsigned``: no ``signatures`` member, or an
    empty array; signing is optional, so a caller chooses what an unsigned card means.  ``malformed``: a
    ``signatures`` member that is not an array (CARD-SIGN-003)."""
    finding: Finding
    """What :func:`verify_served_card` reports for this card."""


def read_signed_card(served: str | bytes) -> SignedCard | UnreadableCard:
    """Read a served card's signatures, signing payload and non-JCS forms from one parse.

    This is the one card-level precondition read: :func:`verify_served_card` and any CARD-SIGN
    gate built on this package both call it, as they both call :func:`judge_signature` and
    :func:`settle_signatures`, so they cannot disagree on a card that has no signature to judge.
    """
    try:
        parts = signed_parts(served)
    except CardCanonicalizationError as exc:
        message = (
            f"the served card has no RFC 8785 canonical form ({exc}); "
            "no signature over it can be verified and it MUST NOT be trusted"
        )
        return UnreadableCard(kind="uncanonicalizable", finding=Finding(check_id="CARD-SIGN-001", message=message))
    signatures = parts.signatures
    if signatures is None or signatures == []:
        finding = Finding(check_id="CARD-SIGN-003", message="the card carries no signatures")
        return UnreadableCard(kind="unsigned", finding=finding)
    if not isinstance(signatures, list):
        message = "the served card's 'signatures' member is not an array of JWS objects (A2A section 8.4.2)"
        return UnreadableCard(kind="malformed", finding=Finding(check_id="CARD-SIGN-003", message=message))
    alternatives = tuple((label, form) for label, form in non_jcs_forms(served) if form != parts.payload)
    return SignedCard(payload=parts.payload, signatures=tuple(signatures), alternatives=alternatives)


def _shortfall(verified: set[str], *, threshold: int, required_kids: frozenset[str], explained: bool) -> list[Finding]:
    """The signer-policy findings for a card whose policy is not met.

    The distinct-signer count is stated for a threshold above 1, and under the default threshold
    of 1 only when no signature finding already says why nothing verified (*explained*).
    """
    findings: list[Finding] = []
    if len(verified) < threshold and (threshold > 1 or not explained):
        message = f"only {len(verified)} distinct signer kid(s) verified; the policy needs {threshold}"
        findings.append(Finding(check_id="CARD-SIGN-004", message=message))
    missing = sorted(required_kids - verified)
    if missing:
        names = ", ".join(repr(kid) for kid in missing)
        message = f"required signer(s) did not contribute a verifying signature: {names}"
        findings.append(Finding(check_id="CARD-SIGN-004", message=message))
    return findings


def _as_note(finding: Finding) -> Finding:
    return Finding(
        check_id=finding.check_id, message=finding.message, severity="info", signature_index=finding.signature_index
    )


def _sorted_judgements(
    judgements: Sequence[SignatureJudgement],
) -> tuple[set[str], list[Finding], list[Finding]]:
    """The signers that verified, the signature failures, and the findings about a pinned key."""
    verified: set[str] = set()
    failures: list[Finding] = []
    key_findings: list[Finding] = []
    for judged in judgements:
        if judged.verified_kid is not None:
            verified.add(judged.verified_kid)
        if judged.finding is not None:
            (key_findings if judged.key_status else failures).append(judged.finding)
    return verified, failures, key_findings


def _settleable(judgements: Sequence[SignatureJudgement], threshold: int) -> None:
    if threshold < 1:
        raise ValueError(f"a signer threshold must be at least 1, not {threshold}")
    if any(judged.unanchored for judged in judgements):
        raise ValueError("a signature judged with no trust store is undecided; there is no signer policy to apply")


def settle_signatures(
    judgements: Sequence[SignatureJudgement], *, threshold: int = 1, required_kids: frozenset[str] = frozenset()
) -> CardVerdict:
    """Apply the card-level signer policy to the judgement of every signature on one card.

    This is the one card-level policy: :func:`verify_served_card` and any CARD-SIGN gate built
    on this package both call it, as they both call :func:`judge_signature`, so they cannot disagree on a
    card either.

    *threshold* counts distinct signers: two verifying signatures by one ``kid`` count once.
    Each ``kid`` in *required_kids* must be among them.  A key-status finding (an unknown
    ``kid``, a pinned key outside its validity window) is the key rotation A2A section 8.4.3
    describes once the policy is met, and is kept as an ``info`` note; otherwise it is an error.

    Args:
        judgements: One :func:`judge_signature` result per member of the card's ``signatures``.
        threshold: How many distinct signers must verify; at least 1.
        required_kids: Signers that must be among those that verified.

    Raises:
        ValueError: *threshold* is below 1, or a judgement was made with no trust store
            (``unanchored``), which leaves nothing to settle.
    """
    _settleable(judgements, threshold)
    verified, failures, key_findings = _sorted_judgements(judgements)
    met = len(verified) >= threshold and required_kids <= verified
    if met:
        findings: tuple[Finding, ...] = (*failures, *(_as_note(finding) for finding in key_findings))
    else:
        explained = bool(failures or key_findings)
        shortfall = _shortfall(verified, threshold=threshold, required_kids=required_kids, explained=explained)
        findings = (*failures, *key_findings, *shortfall)
    accepted = met and all(finding.severity != "error" for finding in findings)
    return CardVerdict(accepted=accepted, findings=findings, verified_kids=frozenset(verified))


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
        threshold: How many distinct signers must verify (:func:`settle_signatures`).
        required_kids: Signers that must be among those that verified.

    Raises:
        ValueError: *threshold* is below 1.
    """
    clock = now or datetime.now(UTC)
    card = read_signed_card(served)
    if isinstance(card, UnreadableCard):
        return CardVerdict(accepted=False, findings=(card.finding,))
    judgements = [
        judge_signature(
            sig,
            index=index,
            payload=card.payload,
            lookup=trust.get,
            now=clock,
            algorithms=algorithms,
            alternatives=card.alternatives,
        )
        for index, sig in enumerate(card.signatures)
    ]
    return settle_signatures(judgements, threshold=threshold, required_kids=required_kids)
