"""EXTERNAL witness scope, earned only from a verified witness co-signature.

A record's ``witness_scope`` and its consumer pin are claims. Neither can make
a record ``EXTERNAL``: a host that writes ``EXTERNAL`` into its own record would
otherwise get it whenever the consumer pins ``EXTERNAL``, and an honest
launcher writes ``PEER`` into every record because its own receipt requires the
records to match it. So the scope is never read from the record. A pin that says
``EXTERNAL`` names the keys and operators the consumer trusts and the artifact
holding the witness's ``probity-witnessed-record/v1`` bundle. The bundle is
checked by agent-evidence-observer's ``verify_witnessed_record``, the one
implementation of the witness formats, which requires:

1. valid signatures from both pinned keys, host and witness (2-of-2);
2. a witness checkpoint that verifies under the pinned witness key;
3. the record's leaf included in that checkpoint;
4. when the consumer retains an earlier checkpoint, a proof that the new one
   extends it;
5. different operators named for the two keys.

This module adds one rule of its own: the bundle's verified payload must be the
pinned record's exact bytes. Only then is the earned scope the verifier's
answer (``EXTERNAL``, or ``PEER`` when one operator holds both keys). Every other
outcome earns ``PEER``, so a failed or missing co-signature never turns a
``contradicted`` verdict into an error.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..common import CaseError, _artifact, _object, _string
from ..vocabulary import EXTERNAL, PEER

try:  # requirements-witness.txt; without it no record reaches EXTERNAL.
    from probity_observer.witness import scope as observer_scope
    from probity_observer.witness.checkpoint import EquivocationError, WitnessError
except ImportError:  # pragma: no cover - exercised by installs without the witness verifier
    observer_scope = None

PUBLIC_KEY = re.compile(r"[0-9a-f]{64}\Z")
UNAVAILABLE = ("the witness verifier is not installed (install agent-evidence-observer[witness]"
               " from requirements-witness.txt)")


def _key_pin(value: Any, label: str) -> dict:
    pin = _object(value, label, {"public_key", "operator"})
    if not isinstance(pin["public_key"], str) or PUBLIC_KEY.fullmatch(pin["public_key"]) is None:
        raise CaseError(f"{label}.public_key: expected a lowercase hex Ed25519 public key")
    if not _string(pin["operator"], f"{label}.operator").strip():
        raise CaseError(f"{label}.operator: expected a nonempty operator name")
    return pin


def parse(value: Any, label: str) -> dict:
    """Validate the consumer's witness pin for an EXTERNAL scope pin."""
    pin = _object(value, label, {"bundle", "host", "witness"},
                  {"retained_checkpoint", "consistency"})
    for key in ("bundle", "retained_checkpoint", "consistency"):
        if key in pin:
            _string(pin[key], f"{label}.{key}")
    if "consistency" in pin and "retained_checkpoint" not in pin:
        raise CaseError(f"{label}.consistency: needs a retained_checkpoint")
    host = _key_pin(pin["host"], f"{label}.host")
    witness = _key_pin(pin["witness"], f"{label}.witness")
    if host["public_key"] == witness["public_key"]:
        raise CaseError(f"{label}: the host and witness pins name one key")
    return pin


def _read(case: dict, root: Path, artifact_id: str) -> bytes | None:
    artifacts = case["artifacts"]
    if artifact_id not in artifacts:
        raise CaseError(f"unknown artifact: {artifact_id}")
    data, _ = _artifact(root, artifacts[artifact_id], f"artifacts.{artifact_id}")
    return data


def _json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _outcome(config: dict, status: str, scope: str, reason: str, **extra: Any) -> dict:
    return {**config, "status": status, "witness_scope": scope, "reason": reason, **extra}


def earn(case: dict, root: Path, record: bytes | None, config: dict) -> dict:
    """Verify a pinned record's witness bundle and return the scope it earns.

    Raises:
        CaseError: The pin names an artifact the case does not hold, or an
            artifact does not match its case binding.
    """
    bundle_bytes = _read(case, root, config["bundle"])
    retained = (_read(case, root, config["retained_checkpoint"])
                if "retained_checkpoint" in config else None)
    proof_bytes = (_read(case, root, config["consistency"])
                   if "consistency" in config else None)
    if observer_scope is None:
        return _outcome(config, "unavailable", PEER, UNAVAILABLE)
    if record is None:
        return _outcome(config, "unavailable", PEER, "the witnessed record is unbound")
    if bundle_bytes is None or ("retained_checkpoint" in config and retained is None) or (
            "consistency" in config and proof_bytes is None):
        return _outcome(config, "unavailable", PEER, "a witness artifact is unavailable")
    bundle = _json(bundle_bytes)
    consistency = _json(proof_bytes) if proof_bytes is not None else None
    if bundle is None or (proof_bytes is not None and consistency is None):
        return _outcome(config, "refused", PEER, "a witness artifact is not UTF-8 JSON")
    try:
        verdict = observer_scope.verify_witnessed_record(
            bundle,
            observer_scope.KeyPin(**config["host"]),
            observer_scope.KeyPin(**config["witness"]),
            retained,
            consistency,
        )
    except EquivocationError as exc:
        return _outcome(config, "equivocation", PEER, str(exc))
    except WitnessError as exc:
        return _outcome(config, "refused", PEER, str(exc))
    if verdict.payload != record:
        return _outcome(config, "refused", PEER,
                        "the witnessed payload is not the pinned record")
    return _outcome(config, "verified", verdict.witness_scope,
                    "co-signed by a separate operator" if verdict.witness_scope == EXTERNAL
                    else "one operator holds the host and witness keys",
                    claim_id=verdict.claim_id, index=verdict.index,
                    checkpoint_size=verdict.checkpoint.size)
