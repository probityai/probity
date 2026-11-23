"""Build lifecycle-binding/v1 record sets from neutral, deterministic keys.

Keys are derived from the label ``aev-lifecycle-binding-vectors/<name>``; nothing here is copied from any
other project's fixtures. The record shape and pre-images are the ones ``lifecycle_binding.py`` documents.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from agent_evidence_verify.adapters import lifecycle_binding as lb
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SEED = "aev-lifecycle-binding-vectors/"
X = "sha256:" + hashlib.sha256(b"action X").hexdigest()
Y = "sha256:" + hashlib.sha256(b"action Y").hexdigest()


def key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256((SEED + name).encode()).digest())


def public_hex(name: str) -> str:
    return key(name).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


PRODUCERS = ("governor", "executor")
BINDINGS = {p: {"public_key_hex": public_hex(p), "suite": "ed25519"} for p in PRODUCERS}
ACTIVE = {p: {"state": "active"} for p in PRODUCERS}


def seal(artifact: dict, signer: str | None = None, suite: str = "ed25519") -> dict:
    """Write integrity.current and a signature by ``signer`` (default: the producer)."""
    artifact = copy.deepcopy(artifact)
    artifact["integrity"] = {k: v for k, v in artifact.get("integrity", {}).items()
                             if k not in ("current", "signature")}
    artifact["integrity"]["current"] = "sha256:" + hashlib.sha256(lb.hash_preimage(artifact)).hexdigest()
    sig = key(signer or artifact["producer"]).sign(lb.signature_preimage(artifact, suite))
    artifact["integrity"]["signature"] = {"alg": "ed25519", "value": sig.hex()}
    return artifact


def decision(rid: str = "d-1") -> dict:
    return seal({"lifecycle_version": "v1", "artifact_type": "decision", "record_id": rid,
                 "producer": "governor", "integrity": {}, "verb": "release"})


def control(rid: str, digest: str = X, side: str = "issuer", instruction: str = "pause-1",
            producer: str | None = None, decision_id: str = "d-1") -> dict:
    return seal({"lifecycle_version": "v1", "artifact_type": "control", "record_id": rid,
                 "producer": producer or ("governor" if side == "issuer" else "executor"),
                 "integrity": {}, "decision_ref": {"record_id": decision_id}, "instruction_id": instruction,
                 "boundary_side": side, "authorized_action_digest": digest})


def execution(rid: str, digest: str = X, instruction: str = "pause-1", decision_id: str = "d-1",
              signer: str | None = None) -> dict:
    return seal({"lifecycle_version": "v1", "artifact_type": "execution", "record_id": rid,
                 "producer": "executor", "integrity": {}, "decision_ref": {"record_id": decision_id},
                 "instruction_id": instruction, "executed_action_digest": digest}, signer)


def complete() -> list[dict]:
    return [decision(), control("c-issuer"), control("c-receiver", side="receiver"), execution("e-1")]


def vectors() -> dict[str, tuple[list[dict], dict, str]]:
    """Binding-scope vectors: (records, revocation snapshot, expected overall state)."""
    d, ci, cr = decision(), control("c-issuer"), control("c-receiver", side="receiver")
    honest = execution("e-1")
    forged = execution("e-1", signer="unbound")
    unsigned = copy.deepcopy(honest)
    unsigned["integrity"]["signature"]["value"] = "00" * 64
    revoked = {**ACTIVE, "executor": {"state": "revoked"}}
    return {
        "V1-cross-instruction": ([d, ci, cr, execution("e-1", instruction="pause-2")], ACTIVE, "not_evaluated"),
        "V2-receiver-disagrees": ([d, ci, control("c-receiver", Y, side="receiver"), honest], ACTIVE, "failure"),
        "V3-duplicate-execution-identity": ([d, ci, cr, execution("e-1"), execution("e-1", Y)], ACTIVE,
                                            "indeterminate"),
        "V3b-duplicate-execution-identity-reordered": ([d, ci, cr, execution("e-1", Y), execution("e-1")], ACTIVE,
                                                       "indeterminate"),
        "V4-revoked-executor-binding": ([d, ci, cr, honest], revoked, "not_evaluated"),
        "V5-execution-sealed-by-an-unbound-key": ([d, ci, cr, forged], ACTIVE, "failure"),
        "V6-unsigned-execution-valid-self-hash": ([d, ci, cr, unsigned], ACTIVE, "failure"),
        "V7-honest-execution-revoked-executor": ([d, ci, cr, honest], revoked, "not_evaluated"),
        "V8-duplicate-identity-executions-other-action": (
            [d, ci, cr, honest, execution("e-2", Y), execution("e-2", Y)], ACTIVE, "indeterminate"),
        "C0-honest-execution": ([d, ci, cr, honest], ACTIVE, "satisfied"),
    }


def retag(artifact: dict, **changes: Any) -> dict:
    """A copy with members changed and nothing re-sealed."""
    out = copy.deepcopy(artifact)
    out.update(changes)
    return out
