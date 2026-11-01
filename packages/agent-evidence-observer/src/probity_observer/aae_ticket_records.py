"""Decision commitment and reader for the AAE decision joined to one HTTP ticket record.

A reader recomputes the native kernel decision from its own inputs, derives the
committed decision digest, and requires the ticket completion and read-back to
carry it. Nothing here runs a ticket store or admits an action.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime
from typing import Any

from .aae_enforce import DIGEST, canonical_bytes, enforce_check, native_digest
from .crypto import VerificationError, digest
from .grant_records import ActionRequest, GrantPolicy
from .ticket_state import verify_ticket_result

DECISION_DOMAIN = "probity-aae-http-ticket-decision-v0"

def ticket_transaction(request: ActionRequest) -> dict[str, Any]:
    """Map exact ticket invocation fields without reusing the file-write action."""
    if request.tool_id != "ticket-update" or not request.target_path.startswith("/work/tickets/"):
        raise VerificationError("AAE ticket action is unsupported")
    return {"action": {"verb": "ticket-update", "targetKind": "native-ticket"},
            **{name: value for name, value in asdict(request).items()}}

def decision_commitment(mandate: Any, transaction: Any, record: Any,
                         request: ActionRequest, pinned_mandate_digest: str, *,
                         require_permit: bool) -> str:
    """Commit a replayed kernel result; admission separately requires PERMIT."""
    if not isinstance(pinned_mandate_digest, str) or DIGEST.fullmatch(pinned_mandate_digest) is None:
        raise VerificationError("AAE ticket mandate pin differs")
    if native_digest("mandate", mandate) != pinned_mandate_digest:
        raise VerificationError("AAE ticket mandate differs from consumer pin")
    if canonical_bytes(transaction) != canonical_bytes(ticket_transaction(request)):
        raise VerificationError("AAE ticket transaction differs from expected request")
    actual = enforce_check(mandate, transaction)
    if not isinstance(record, dict) or canonical_bytes(record.get("core")) != canonical_bytes(actual["core"]) or record.get("core_digest") != actual["core_digest"]:
        raise VerificationError("AAE ticket core differs from native replay")
    if actual["core_digest"] is None or (require_permit and actual["verdict"] != "PERMIT"):
        raise VerificationError("AAE ticket dispatch requires replayed PERMIT")
    index = actual["grant_index"]
    grants = mandate.get("grants") if isinstance(mandate, dict) else None
    if type(index) is not int or not isinstance(grants, list) or not 0 <= index < len(grants):
        raise VerificationError("AAE ticket grant selection differs")
    constraints = grants[index].get("constraints")
    if not isinstance(constraints, list) or not all(any(isinstance(item, dict) and item.get("type") == "exact" and item.get("field") == name and isinstance(item.get("value"), str) and item["value"] == value for item in constraints) for name, value in transaction.items() if name != "action"):
        raise VerificationError("AAE ticket dispatch requires exact request constraints")
    return digest(DECISION_DOMAIN, {"profile": DECISION_DOMAIN, "mandateDigest": pinned_mandate_digest, "coreDigest": actual["core_digest"], "transactionDigest": actual["core"]["transaction_digest"]})

def ticket_decision_digest(mandate: Any, transaction: Any, record: Any,
                           request: ActionRequest, pinned_mandate_digest: str) -> str:
    """Recompute native PERMIT, exact constraints and a separate consumer pin."""
    return decision_commitment(mandate, transaction, record, request,
                                pinned_mandate_digest, require_permit=True)

def verify_aae_ticket_result(mandate: Any, transaction: Any, record: Any,
                            receipt: Mapping[str, Any], readback: Mapping[str, Any],
                            request: ActionRequest, policy: GrantPolicy,
                            service_key: str, grant: Mapping[str, Any], *,
                            now: datetime, pinned_mandate_digest: str) -> dict[str, Any]:
    """Require native decision join before admitting signed completion/read-back."""
    commitment = ticket_decision_digest(mandate, transaction, record, request, pinned_mandate_digest)
    result = verify_ticket_result(receipt, readback, request, policy, service_key, grant,
                                  now=now, decision_digest=commitment)
    return {**result, "kernelVerdict": "PERMIT", "issuerAuthentication": "not-established",
            "decisionDigest": commitment, "linkage": "verified", "execution": "recorded-native-ticket-update"}
