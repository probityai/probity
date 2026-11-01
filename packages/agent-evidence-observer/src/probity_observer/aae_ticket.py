"""Replay an unsigned native AAE decision before one actual HTTP ticket effect.

The kernel input remains unsigned. A separate signed local grant and service key
bind the permitted ticket effect; neither authenticates the AAE mandate issuer.
"""
from __future__ import annotations

import json
from typing import Any

from .aae_enforce import canonical_bytes
from .aae_ticket_records import (  # noqa: F401
    DECISION_DOMAIN,
    decision_commitment,
    ticket_decision_digest,
    ticket_transaction,
    verify_aae_ticket_result,
)
from .crypto import VerificationError, digest
from .ticket_service import TicketStore


class AaeTicketStore(TicketStore):
    """Freeze native inputs and commit their replay before initialization/dispatch.

    All native inputs are host configuration, never mutable POST fields. The
    mandate pin is separately selected; the local host, key and clock are trusted.
    """

    def __init__(self, *args: Any, mandate: Any, transaction: Any, record: Any,
                 pinned_mandate_digest: str, **kwargs: Any) -> None:
        if "decision_digest" in kwargs:
            raise VerificationError("AAE ticket commitment must come from native replay")
        super().__init__(*args, **kwargs)
        commitment = decision_commitment(mandate, transaction, record, self.request,
                                          pinned_mandate_digest, require_permit=False)
        self._decision_bytes = canonical_bytes([mandate, transaction, record])
        self._mandate_pin = pinned_mandate_digest
        self.configuration["decisionDigest"] = commitment
        from .ticket_state import DOMAIN
        self.configuration_digest = digest(DOMAIN + "-configuration", self.configuration)

    def dispatch(self, candidate: Any) -> dict[str, Any]:
        """Replay before fresh or cached admission, then use the native gate."""
        mandate, transaction, record = json.loads(self._decision_bytes)
        commitment = ticket_decision_digest(mandate, transaction, record, self.request, self._mandate_pin)
        if commitment != self.configuration["decisionDigest"]:
            raise VerificationError("AAE ticket frozen decision commitment differs")
        return super().dispatch(candidate)


