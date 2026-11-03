"""Offline reader for protected-dispatch bundles.

A reader authenticates the signed configuration, prior commitment and state
records, the native packet, the ledger receipts and the retained history, and
checks that one permitted request produced one recorded replacement. Nothing
here consumes a permit, holds pending intent or dispatches a write.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, NoReturn

from .crypto import (
    VerificationError,
    digest,
    strict_loads,
    verify_signature,
)
from .grant_records import (
    ActionRequest,
    GrantPolicy,
    verify_authorized_packet,
    verify_grant,
)
from .history import read_history, verify_checkpoint
from .ledger import verify_ledger_receipts

LOGGER = logging.getLogger(__name__)

STATE_DOMAIN = "probity-protected-dispatch-state-v0"

PRIOR_DOMAIN = "probity-protected-dispatch-prior-v0"

CONFIG_DOMAIN = "probity-protected-dispatch-config-v0"

STATE_FIELDS = frozenset(
    {
        "format",
        "configuration",
        "phase",
        "beforeRoot",
        "checkpoint",
        "grant",
        "prior",
        "priorCheckpoint",
        "result",
        "packet",
    }
)

def _refuse(reason: str) -> NoReturn:
    """Raise a finite refusal without logging secrets or candidate contents."""
    LOGGER.warning("protected dispatch refused: %s", reason)
    raise VerificationError(reason)

def _decision_configuration(value: str | None) -> dict[str, str]:
    """Preserve legacy configurations while binding an optional decision."""
    if value is None:
        return {}
    if not isinstance(value, str) or len(value) != 64:
        _refuse("decision digest must be a lowercase SHA-256-sized value")
    if any(character not in "0123456789abcdef" for character in value):
        _refuse("decision digest must be a lowercase SHA-256-sized value")
    return {"decisionDigest": value}

def _authenticated(record: Any, public_key: str, domain: str) -> dict[str, Any]:
    """Authenticate a strict signature envelope under an external key pin."""
    if not isinstance(record, dict) or set(record) != {"payload", "keyid", "signature"}:
        _refuse("dispatch signature envelope has unexpected fields")
    if record["keyid"] != public_key or not isinstance(record["payload"], dict):
        _refuse("dispatch signature envelope differs from the pinned key")
    verify_signature(public_key, domain, record["payload"], record["signature"])
    return record["payload"]

def _check_prefix(
    entries: list[dict[str, Any]], retained: dict[str, Any], key: str
) -> None:
    """Require a separately retained signed prefix to survive a restart."""
    count = retained.get("count")
    if type(count) is not int or not 1 <= count <= len(entries):
        _refuse("authorization history is shorter than the retained head")
    verify_checkpoint(entries[:count], retained, key)

def _state_payload(record: Any, observer: str) -> dict[str, Any]:
    """Apply one fixed state schema to online and offline verification."""
    state = _authenticated(record, observer, STATE_DOMAIN)
    if set(state) != STATE_FIELDS or state["format"] != STATE_DOMAIN:
        _refuse("dispatch state has unexpected fields")
    root = state["beforeRoot"]
    if (
        not isinstance(root, str)
        or len(root) != 64
        or any(character not in "0123456789abcdef" for character in root)
    ):
        _refuse("dispatch state has an invalid before root")
    return state

def _verify_prior(
    state: dict[str, Any],
    packet: dict[str, Any],
    request: ActionRequest,
    policy: GrantPolicy,
    observer: str,
) -> None:
    """Authenticate exact grant/native-begin ordering without upgrading custody."""
    prior = _authenticated(state["prior"], observer, PRIOR_DOMAIN)
    required = {
        "profile",
        "configurationDigest",
        "grantDigest",
        "request",
        "nativeCommitmentDigest",
        "nativeStartCheckpoint",
        "authorizedAt",
    }
    if set(prior) != required or prior["profile"] != PRIOR_DOMAIN:
        _refuse("prior authorization has unexpected fields")
    reference = datetime.fromisoformat(prior["authorizedAt"].replace("Z", "+00:00"))
    action = verify_grant(state["grant"], request, policy, now=reference)
    native = {key: packet["commitment"][key] for key in ("preimage", "committedAt")}
    expected = {
        "profile": PRIOR_DOMAIN,
        "configurationDigest": digest(CONFIG_DOMAIN, state["configuration"]),
        "grantDigest": action.grant_digest,
        "request": asdict(request),
        "nativeCommitmentDigest": digest("probity-prior-commitment-v0", native),
        "nativeStartCheckpoint": packet["startCheckpoint"],
        "authorizedAt": prior["authorizedAt"],
    }
    if (
        prior != expected
        or not packet["commitment"]["committedAt"]
        <= prior["authorizedAt"]
        <= packet["authorizationBinding"]["payload"]["authorizedAt"]
    ):
        _refuse("prior authorization differs from the native dispatch relation")

def _verify_complete(
    directory: Path,
    state: dict[str, Any],
    request: ActionRequest,
    policy: GrantPolicy,
    observer: str,
    witness: str,
    workspace: Path | None,
) -> dict[str, Any]:
    """Cross-check the completed authorization journal with the native packet."""
    packet = state["packet"]
    if (
        not isinstance(packet, dict)
        or strict_loads((directory / "packet.json").read_bytes()) != packet
    ):
        _refuse("retained native packet differs from the completed result")
    if (
        packet["claim"]["beforeRoot"] != state["beforeRoot"]
        or packet["commitment"]["preimage"]["beforeRoot"] != state["beforeRoot"]
    ):
        _refuse("native before root differs from the retained initialization")
    entries = read_history(directory / "authorization.jsonl")
    verify_checkpoint(entries[:2], state["priorCheckpoint"], witness)
    expected = {
        "kind": "dispatch-completed",
        "packetDigest": digest("probity-protected-dispatch-packet-v0", packet),
        "result": state["result"],
    }
    if (
        entries[1]["event"]
        != {"kind": "grant-before-dispatch", "prior": state["prior"]}
        or entries[-1]["event"] != expected
    ):
        _refuse("authorization journal differs from the completed result")
    _verify_prior(state, packet, request, policy, observer)
    prior_checkpoint = {
        key: state["prior"]["payload"]["nativeStartCheckpoint"][key]
        for key in ("count", "head", "keyid", "signature")
    }
    verify_checkpoint(
        read_history(directory / "history.jsonl")[:1], prior_checkpoint, witness
    )
    verify_ledger_receipts(
        directory / "witness-ledger.jsonl",
        packet["startCheckpoint"],
        packet["checkpoint"],
        witness,
    )
    dispatch = datetime.fromisoformat(
        packet["authorizationBinding"]["payload"]["authorizedAt"].replace("Z", "+00:00")
    )
    verified = verify_authorized_packet(
        state["grant"],
        request,
        policy,
        packet,
        directory / "history.jsonl",
        observer,
        witness,
        now=dispatch,
        workspace=workspace,
    )
    write = packet["claim"]["writes"][0]
    result = {
        "request_id": request.request_id,
        "path": request.target_path,
        "before_root": write["beforeRoot"],
        "after_root": write["afterRoot"],
        "replayed": False,
    }
    if state["result"] != result:
        _refuse("completed response differs from the recorded effect")
    return verified

def verify_dispatch_bundle(
    directory: Path,
    expected_request: ActionRequest,
    policy: GrantPolicy,
    observer_key: str,
    witness_key: str,
    retained_authorization_head: dict[str, Any],
    *,
    workspace: Path | None = None,
    execution_digest: str | None = None,
    decision_digest: str | None = None,
) -> dict[str, Any]:
    """Verify the witnessed grant relation and exactly one completed native effect.

    Parameters
    ----------
    directory : Path
        Retained host-side dispatch bundle. Candidate key files are not trust
        anchors; all pins and the retained head are selected separately.
    expected_request, policy, observer_key, witness_key
        Exact consumer action, issuer policy, and distinct role key pins.
    retained_authorization_head : dict[str, Any]
        Authorization checkpoint acquired outside the current candidate. It
        detects rollback only as far as that externally retained prefix.
    workspace : Path | None, optional
        If supplied, compare current durable target bytes to the native claim.
    execution_digest, decision_digest : str | None, optional
        Separately selected launch and decision bindings. A present decision
        digest must match; this generic verifier does not replay its semantics.

    Returns
    -------
    dict[str, Any]
        Combined authorization/native verification and the signed prior grant
        relation. Local witness order is authenticated; wall-clock truth,
        independent operation, complete effect capture, and production custody
        remain separate questions.
    """
    if len({policy.issuer_key, observer_key, witness_key}) != 3:
        _refuse("issuer, observer, and witness keys must differ")
    state = _state_payload(
        strict_loads((directory / "dispatch-state.json").read_bytes()), observer_key
    )
    configured = {
        "request": asdict(expected_request),
        "policy": asdict(policy),
        "observerKey": observer_key,
        "witnessKey": witness_key,
        "executionDigest": execution_digest,
        **_decision_configuration(decision_digest),
    }
    if state.get("configuration") != configured or state.get("phase") != "complete":
        _refuse("dispatch bundle differs from the expected completed action")
    entries = read_history(directory / "authorization.jsonl")
    if len(entries) != 3:
        _refuse("completed authorization history has an invalid population")
    verify_checkpoint(entries, state["checkpoint"], witness_key)
    _check_prefix(entries, retained_authorization_head, witness_key)
    initial = {
        "kind": "dispatch-created",
        "configurationDigest": digest(CONFIG_DOMAIN, configured),
        "beforeRoot": state["beforeRoot"],
    }
    if entries[0]["event"] != initial:
        _refuse("dispatch initialization differs from the retained journal")
    verified = _verify_complete(
        directory, state, expected_request, policy, observer_key, witness_key, workspace
    )
    return {
        **verified,
        "priorAuthorization": state["prior"],
        "orderingEvidence": "local-witnessed-grant-before-host-dispatch",
        "witnessScope": "PEER",
        "evidence_vantage": "artifact",
    }
