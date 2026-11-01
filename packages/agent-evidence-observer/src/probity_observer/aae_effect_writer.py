"""Write one local action after an unsigned AAE kernel decision, and sign its link.

The kernel's PERMIT does not authenticate its issuer. The signed link is made
after the effect and retains PEER scope; consumers check it with
``probity_observer.aae_binding.verify_effect_link``.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .aae_binding import DOMAIN, effect_link_payload, verify_local_decision
from .broker import Broker
from .crypto import SigningKey, VerificationError
from .grant_records import ActionRequest
from .records import WriteResult


def write_local_action(
    mandate: Any,
    transaction: Any,
    record: dict[str, Any],
    request: ActionRequest,
    content: bytes,
    broker: Broker,
    *,
    pinned_mandate_digest: str,
) -> WriteResult:
    """Check the consumer-pinned kernel decision before a native broker write.

    Parameters
    ----------
    mandate, transaction, record : Any
        Retained unsigned AAE kernel inputs and the claimed native core record.
    request : ActionRequest
        Consumer-selected exact invocation identity and content digest.
    content : bytes
        File replacement bytes; checked before the broker is called.
    broker : Broker
        Begun local observer broker. A caller retaining the underlying broker
        or writable workspace can bypass this one dispatch path.
    pinned_mandate_digest : str
        Mandate digest selected by the consumer outside the candidate record.

    Returns
    -------
    WriteResult
        Native broker result. The issuer of an unsigned mandate remains
        unauthenticated; this is not a full AAE JWS authorization decision.

    Raises
    ------
    VerificationError
        If the core, exact invocation, content, consumer pin or broker authority
        does not match. No write is attempted for these mismatches.
    """
    verify_local_decision(mandate, transaction, record, request, pinned_mandate_digest)
    if hashlib.sha256(content).hexdigest() != request.content_sha256:
        raise VerificationError(
            "AAE write content differs from the expected local action"
        )
    authority = {
        "intervalId": request.run_id,
        "scope": "/work",
        "operation": "write-file",
    }
    if broker.authority != authority:
        raise VerificationError(
            "AAE write broker authority differs from the local action"
        )
    return broker.write(request.request_id, request.target_path, content)


def sign_effect_link(
    record: dict[str, Any],
    request: ActionRequest,
    packet: dict[str, Any],
    observer: SigningKey,
) -> dict[str, Any]:
    """Sign a post-effect link; consumers still replay and verify every input."""
    payload = effect_link_payload(record, request, packet)
    return {
        "payload": payload,
        "keyid": observer.public_hex,
        "signature": observer.sign(DOMAIN, payload),
    }
