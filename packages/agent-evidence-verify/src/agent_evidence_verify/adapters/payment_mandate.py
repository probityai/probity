"""Agent payment mandate: is a payment inside the mandate its principal signed.

The reader judges an agent-payment-mandate/v1 record, the evidence pack of an agent-initiated
payment: the mandate, the credential the agent presented, the charge that ran and the receipt that
binds them. It recomputes the mandate digest and the execution digest instead of trusting the fields
that claim them, and refuses a charge that leaves the mandate in amount, currency, merchant, time or
token, a single-use token used twice, and a pack whose post-checkout actions are not all recorded.

An x402 record (scheme x402-exact-evm-eip3009) carries the facilitator request in x402 v2 field
names. The reader recomputes the EIP-712 digest of the EIP-3009 TransferWithAuthorization under
the requirement's token domain and recovers the signer from the signature itself. A field that names
a signer is never read: the verifying key is the one the signature recovers to, and the record's
from must equal it. The signed authorization is then held to the requirement and to the mandate,
and the settled transfer, the nonce the token contract consumed and the facilitator's response are
held to the authorization.

Every rule is a refusal code; a record is accepted only when none fires, and a refusal names the
first rule that fired, in the order of PROFILE_CHECKS. The rule code is a port of the corpus's own
reader at agent-evidence-vectors feat/x402-mandate-cases-1121 (paymentmandate.py), so a
disagreement between the two readers shows up as N < M in the Action's reference stage.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from .. import evmsig
from ..json_input import parse_json

SUITE = "agent-payment-mandate/v1"
ACCEPTED, REJECTED = "accepted", "rejected"
ACCEPT_REASON = "mandate_chain_holds"
MAX_RECORD_BYTES = 1 << 20
HEX64 = re.compile(r"^[0-9a-f]{64}$")
X402_SCHEME = "x402-exact-evm-eip3009"
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_NONCE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_SIGNATURE = re.compile(r"^0x[0-9a-fA-F]{130}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canon(value: object) -> bytes:
    """The bytes a digest in a record is taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_of(value: object) -> str:
    return _sha(canon(value))


def _get(record: dict[str, Any], path: str) -> Any:
    node: Any = record
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _unsigned(r: dict[str, Any]) -> bool:
    sig = _get(r, "mandate.signature")
    return not (
        isinstance(sig, dict)
        and sig.get("key_id")
        and HEX64.match(str(sig.get("value_sha256", "")))
    )


def _digest_mismatch(r: dict[str, Any]) -> bool:
    return bool(_get(r, "mandate.digest") != digest_of(_get(r, "mandate.terms")))


def _not_bound(r: dict[str, Any]) -> bool:
    return bool(_get(r, "credential.mandate_digest") != _get(r, "mandate.digest"))


def _expired(r: dict[str, Any]) -> bool:
    return str(_get(r, "execution.executed_at")) > str(_get(r, "mandate.terms.expires_at"))


def _over_limit(r: dict[str, Any]) -> bool:
    return int(_get(r, "execution.amount_minor")) > int(_get(r, "mandate.terms.max_amount_minor"))


def _currency(r: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.currency") != _get(r, "mandate.terms.currency"))


def _merchant(r: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.merchant") != _get(r, "mandate.terms.merchant"))


def _token_mismatch(r: dict[str, Any]) -> bool:
    return bool(_get(r, "execution.token_id") != _get(r, "credential.token_id"))


def _replayed(r: dict[str, Any]) -> bool:
    return bool(_get(r, "credential.single_use")) and (
        _get(r, "execution.token_id") in (_get(r, "credential.consumed_token_ids") or [])
    )


def _receipt_unbound(r: dict[str, Any]) -> bool:
    return bool(
        _get(r, "receipt.mandate_digest") != _get(r, "mandate.digest")
        or _get(r, "receipt.execution_digest") != digest_of(_get(r, "execution"))
    )


def _post_checkout_missing(r: dict[str, Any]) -> bool:
    required = set(_get(r, "post_checkout.required") or [])
    return not required <= set(_get(r, "post_checkout.recorded") or [])


def _never(_r: dict[str, Any]) -> bool:
    return False


# --- x402 exact on EVM with EIP-3009 --------------------------------------------------


def _x(r: dict[str, Any], path: str) -> Any:
    return _get(r, "credential.facilitator_request." + path)


def _same_address(a: Any, b: Any) -> bool:
    """EVM addresses compare as 20 bytes; the EIP-55 letter case is an encoding."""
    return (
        isinstance(a, str) and isinstance(b, str) and bool(_ADDRESS.match(a))
        and a.lower() == b.lower() and bool(_ADDRESS.match(b))
    )  # fmt: skip


def _decimal(value: Any) -> int | None:
    return int(value) if isinstance(value, str) and _DECIMAL.match(value) else None


def _whole(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _unix(stamp: Any) -> int | None:
    try:
        return int(datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _x_expired(r: dict[str, Any]) -> bool:
    settled, expiry = _whole(_get(r, "execution.block_timestamp")), _unix(
        _get(r, "mandate.terms.expires_at")
    )
    return settled is None or expiry is None or settled > expiry


def _x_over_limit(r: dict[str, Any]) -> bool:
    value, ceiling = _decimal(_x(r, "paymentPayload.payload.authorization.value")), _whole(
        _get(r, "mandate.terms.max_amount_minor")
    )
    return value is None or ceiling is None or value > ceiling


def _x_currency(r: dict[str, Any]) -> bool:
    required = _x(r, "paymentRequirements.asset")
    return not (
        _same_address(_x(r, "paymentPayload.accepted.asset"), required)
        and _same_address(required, _get(r, "mandate.terms.currency"))
    )


def _x_merchant(r: dict[str, Any]) -> bool:
    pay_to = _x(r, "paymentRequirements.payTo")
    return not (
        _same_address(_x(r, "paymentPayload.payload.authorization.to"), pay_to)
        and _same_address(_x(r, "paymentPayload.accepted.payTo"), pay_to)
        and _same_address(pay_to, _get(r, "mandate.terms.merchant"))
    )


def _x_network(r: dict[str, Any]) -> bool:
    required = _x(r, "paymentRequirements.network")
    return not (
        isinstance(required, str)
        and _x(r, "paymentPayload.accepted.network") == required
        and _get(r, "mandate.terms.network") == required
    )


def _x_not_offer_amount(r: dict[str, Any]) -> bool:
    required = _decimal(_x(r, "paymentRequirements.amount"))
    return (
        required is None
        or _decimal(_x(r, "paymentPayload.payload.authorization.value")) != required
        or _decimal(_x(r, "paymentPayload.accepted.amount")) != required
    )


def _x_outside_window(r: dict[str, Any]) -> bool:
    """EIP-3009 settles only when validAfter < block time < validBefore, both strict."""
    settled = _whole(_get(r, "execution.block_timestamp"))
    after = _decimal(_x(r, "paymentPayload.payload.authorization.validAfter"))
    before = _decimal(_x(r, "paymentPayload.payload.authorization.validBefore"))
    return settled is None or after is None or before is None or not after < settled < before


def _x_signature(r: dict[str, Any]) -> bytes | None:
    text = _x(r, "paymentPayload.payload.signature")
    return bytes.fromhex(text[2:]) if isinstance(text, str) and _SIGNATURE.match(text) else None


def _x_not_canonical(r: dict[str, Any]) -> bool:
    signature = _x_signature(r)
    return signature is None or not evmsig.is_low_s(signature)


def _x_signer(r: dict[str, Any]) -> str | None:
    """The address the signature recovers to under the requirement's token domain."""
    authorization = _x(r, "paymentPayload.payload.authorization")
    signature = _x_signature(r)
    if not isinstance(authorization, dict) or signature is None:
        return None
    try:
        digest = evmsig.eip3009_digest(
            authorization,
            _x(r, "paymentRequirements.network"),
            _x(r, "paymentRequirements.asset"),
            _x(r, "paymentRequirements.extra.name"),
            _x(r, "paymentRequirements.extra.version"),
        )
    except ValueError:
        return None
    return evmsig.recover(digest, signature)


def _x_not_signer(r: dict[str, Any]) -> bool:
    return not _same_address(_x_signer(r), _x(r, "paymentPayload.payload.authorization.from"))


def _x_not_mandated(r: dict[str, Any]) -> bool:
    return not _same_address(
        _x(r, "paymentPayload.payload.authorization.from"), _get(r, "mandate.terms.agent_payer")
    )


def _x_other_nonce(r: dict[str, Any]) -> bool:
    nonce = _x(r, "paymentPayload.payload.authorization.nonce")
    used = _get(r, "execution.authorization_used.nonce")
    return not (
        _same_address(
            _get(r, "execution.authorization_used.authorizer"),
            _x(r, "paymentPayload.payload.authorization.from"),
        )
        and isinstance(nonce, str) and bool(_NONCE.match(nonce))
        and isinstance(used, str) and used.lower() == nonce.lower()
    )  # fmt: skip


def _x_transfer_differs(r: dict[str, Any]) -> bool:
    auth = "paymentPayload.payload.authorization."
    value = _decimal(_x(r, auth + "value"))
    return not (
        _same_address(_get(r, "execution.transfer.from"), _x(r, auth + "from"))
        and _same_address(_get(r, "execution.transfer.to"), _x(r, auth + "to"))
        and value is not None
        and _decimal(_get(r, "execution.transfer.value")) == value
        and _same_address(_get(r, "execution.asset"), _x(r, "paymentRequirements.asset"))
        and _get(r, "execution.network") == _x(r, "paymentRequirements.network")
    )


def _x_replayed(r: dict[str, Any]) -> bool:
    nonce = str(_x(r, "paymentPayload.payload.authorization.nonce")).lower()
    return nonce in {str(n).lower() for n in (_get(r, "execution.nonces_used_before") or [])}


def _x_receipt_unbound(r: dict[str, Any]) -> bool:
    response = _get(r, "receipt.settlement_response")
    if _receipt_unbound(r) or not isinstance(response, dict):
        return True
    amount = response.get("amount")
    return not (
        response.get("success") is True
        and response.get("transaction") == _get(r, "execution.transaction")
        and response.get("network") == _get(r, "execution.network")
        and _same_address(response.get("payer"), _x(r, "paymentPayload.payload.authorization.from"))
        and (amount is None or _decimal(amount) == _decimal(_get(r, "execution.transfer.value")))
    )


Check = Callable[[dict[str, Any]], bool]

# (code, check for the AP2, Verifiable Intent and shared-token records, check for x402)
PROFILE_CHECKS: tuple[tuple[str, Check, Check], ...] = (
    ("mandate_unsigned", _unsigned, _unsigned),
    ("mandate_digest_mismatch", _digest_mismatch, _digest_mismatch),
    ("credential_not_bound_to_mandate", _not_bound, _not_bound),
    ("mandate_expired", _expired, _x_expired),
    ("amount_over_limit", _over_limit, _x_over_limit),
    ("currency_mismatch", _currency, _x_currency),
    ("merchant_mismatch", _merchant, _x_merchant),
    ("network_mismatch", _never, _x_network),
    ("amount_not_offer_amount", _never, _x_not_offer_amount),
    ("authorization_outside_validity_window", _never, _x_outside_window),
    ("signature_not_canonical", _never, _x_not_canonical),
    ("payer_not_authorization_signer", _never, _x_not_signer),
    ("payer_not_mandated_agent", _never, _x_not_mandated),
    ("token_not_the_executed_token", _token_mismatch, _x_other_nonce),
    ("settlement_not_the_authorization", _never, _x_transfer_differs),
    ("single_use_token_replayed", _replayed, _x_replayed),
    ("receipt_not_bound_to_execution", _receipt_unbound, _x_receipt_unbound),
    ("post_checkout_action_missing", _post_checkout_missing, _post_checkout_missing),
)

RULES = tuple(code for code, _, _ in PROFILE_CHECKS)


def decide(record: dict[str, Any]) -> tuple[str, str]:
    """(decision, reason): the first rule that fires, else accepted."""
    x402 = record.get("scheme") == X402_SCHEME
    for code, card, chain in PROFILE_CHECKS:
        if (chain if x402 else card)(record):
            return REJECTED, code
    return ACCEPTED, ACCEPT_REASON


def judge(case_path: Path) -> tuple[str, str]:
    """(decision, reason) for the case.json at case_path."""
    record = parse_json(case_path.read_bytes(), max_bytes=MAX_RECORD_BYTES,
                        max_depth=32, max_nodes=32768)
    if not isinstance(record, dict):
        raise TypeError("case: expected a JSON object")
    return decide(record)
