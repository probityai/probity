"""Verify one detached JWS the way an A2A agent card signature is verified (A2A section 8.4).

The byte-level layer under :mod:`agent_evidence_a2a.verify`: the algorithms accepted, the one
joserfc registry every card signature is verified with, and the check itself.  It judges no
card and names no CARD-SIGN requirement; :mod:`agent_evidence_a2a.verify` does that.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from joserfc import jws
from joserfc.errors import (
    ConflictAlgorithmError,
    DecodeError,
    ExceededSizeError,
    InvalidHeaderValueError,
    JoseError,
    MissingAlgorithmError,
    MissingCritHeaderError,
    MissingHeaderError,
    UnsupportedAlgorithmError,
    UnsupportedHeaderError,
)
from joserfc.jwa import EdDSAAlgorithm, JWSAlgModel
from joserfc.jwk import Key
from joserfc.jws import JWSRegistry

from agent_evidence_a2a.canonical import MAX_CARD_BYTES

#: Every registered asymmetric JWS algorithm (RFC 7518, RFC 8037, RFC 9864).  ``none`` and the HMAC
#: ``HS*`` algorithms carry no provenance, and accepting ``HS*`` beside ``RS*`` is the alg-confusion attack.
DEFAULT_ALGORITHMS: Final[tuple[str, ...]] = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
    "Ed25519",
    "Ed448",
)
#: The longest protected header a signature may carry, in decoded bytes.  A header is a handful of
#: short parameters (an ``x5c`` chain of a leaf and a few intermediates is a few KiB); a larger one is
#: hostile.  A caller that reads headers on its own should use this same bound, so its static checks
#: and this judge agree on which headers are too long.
MAX_HEADER_BYTES: Final = 64 * 1024
#: The longest unpadded base64url text that decodes to at most :data:`MAX_HEADER_BYTES`.
MAX_HEADER_B64: Final = (4 * MAX_HEADER_BYTES + 2) // 3


#: What joserfc raises when it refuses the protected header itself while verifying.  None of these says
#: the signature is wrong, so none may be read as CARD-SIGN-002.  A key that cannot verify the
#: ``alg`` (a ``KeyParameterError``, a bad curve or length) and a bad signature stay "does not verify".
_HEADER_REFUSALS: Final = (
    ConflictAlgorithmError,
    DecodeError,
    ExceededSizeError,
    InvalidHeaderValueError,
    MissingAlgorithmError,
    MissingCritHeaderError,
    MissingHeaderError,
    UnsupportedAlgorithmError,
    UnsupportedHeaderError,
)


class HeaderRefused(ValueError):
    """joserfc refused a signature's protected header at verification time."""


class _EdDSAWithoutWarning(EdDSAAlgorithm):
    """The polymorphic ``EdDSA`` algorithm, minus joserfc's RFC 9864 deprecation warning.

    RFC 9864 deprecates the name ``EdDSA`` for ``Ed25519`` and ``Ed448``; cards in the field
    still sign with it, and over an Ed25519 or Ed448 key the check is the same, so the warning
    names a choice this verifier makes on purpose.  Removing it from the algorithm, rather than
    filtering it around each call, leaves the process-wide warning filters alone:
    ``warnings.catch_warnings`` swaps that global list and is not thread-safe on Python 3.12.
    """

    security_warning = ""


class CardRegistry(JWSRegistry):
    """The joserfc registry every card signature is verified with.

    joserfc's defaults cap the protected header at 512 bytes, the payload at 128,000 and the
    signature at 1,024, and a cap it hits reads as "does not verify".  :func:`judge_signature`
    refuses a protected header longer than :data:`MAX_HEADER_BYTES` and a signature value longer
    than :data:`MAX_CARD_BYTES` (it is a substring of a served card) as a structural CARD-SIGN-003
    finding before any crypto, and the payload is passed detached, so no payload cap applies.  The
    caps here are those same bounds, so a size refusal never becomes CARD-SIGN-002.

    ``strict_check_header`` is off because RFC 7515 section 4 says a header parameter a verifier
    does not understand is ignored unless ``crit`` names it, and :func:`judge_signature` refuses
    every ``crit`` header itself.
    """

    # joserfc declares this a plain class attribute, not a ClassVar, and a ClassVar override of it fails type
    # checking; the dict is shared by design (one algorithm table for every registry) and never mutated.
    algorithms: dict[str, JWSAlgModel] = {  # noqa: RUF012
        **JWSRegistry.algorithms,
        "EdDSA": _EdDSAWithoutWarning(),
    }
    max_header_length = MAX_HEADER_B64
    max_payload_length = MAX_CARD_BYTES
    max_signature_length = MAX_CARD_BYTES


def check_detached(protected: str, signature: str, payload: bytes, key: Key, algorithms: Sequence[str]) -> bool:
    """Whether the detached JWS verifies; raises :class:`HeaderRefused` when joserfc refuses the header."""
    registry = CardRegistry(algorithms=list(algorithms), strict_check_header=False)
    try:
        jws.deserialize_compact(f"{protected}..{signature}", key, payload=payload, registry=registry)
    except _HEADER_REFUSALS as exc:
        raise HeaderRefused(str(exc) or type(exc).__name__) from exc
    except (JoseError, ValueError, TypeError):
        return False
    return True


def verify_detached(
    protected: str, signature: str, payload: bytes, key: Key, *, algorithms: Sequence[str] = DEFAULT_ALGORITHMS
) -> bool:
    """Whether a detached JWS verifies over *payload* with *key* under one of *algorithms*.

    The byte-level check under :func:`judge_signature`, for a caller that resolves its key some
    other way (an ``x5c`` leaf, say).  *protected* and *signature* are the base64url members as
    served.  Any failure (a bad signature, an ``alg`` outside *algorithms*, a malformed member)
    is ``False``, never an exception, and so is a protected header past :data:`MAX_HEADER_BYTES`,
    which :func:`judge_signature` reports as CARD-SIGN-003 before it calls this.
    """
    try:
        return check_detached(protected, signature, payload, key, algorithms)
    except HeaderRefused:
        return False
