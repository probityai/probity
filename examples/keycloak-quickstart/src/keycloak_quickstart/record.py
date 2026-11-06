"""Record one agent action as a signed agent audit record that carries the principal.

The action is a real append to a ledger file. The observer that seals the record
is this process, with a throwaway Ed25519 key: a stand-in for a witness below the
agent, so the posture, evaluation and observer members are fixtures. What the
quickstart exercises is the principal member and its bindings to the agent.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any

from agent_evidence_vectors.auditrecord import (
    PAYLOAD_TYPE,
    STATEMENT_TYPE,
    canonical_bytes,
    commitment_digest,
    jcs_digest,
    pae,
    request_digest,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PREDICATE_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-audit-record"
LEDGER_PATH = "/srv/ledger/settlements.jsonl"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stamp(moment: datetime.datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def keyid(key: Ed25519PrivateKey) -> str:
    return sha256_hex(raw_public(key))[:32]


def append_ledger(ledger: Path, line: str) -> tuple[str, str]:
    """Append ``line`` to ``ledger`` and return the digests of its bytes before and after."""
    before = ledger.read_bytes() if ledger.exists() else b""
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_bytes(before + line.encode() + b"\n")
    return sha256_hex(before), sha256_hex(ledger.read_bytes())


def build_predicate(
    principal: dict[str, Any],
    *,
    agent_key: Ed25519PrivateKey,
    observer_key: Ed25519PrivateKey,
    before_root: str,
    after_root: str,
    arguments: bytes,
    now: datetime.datetime,
) -> dict[str, Any]:
    """The audit record predicate for one permitted write by the token's client."""
    second = datetime.timedelta(seconds=1)
    reported = now
    pred: dict[str, Any] = {
        "recordId": f"urn:uuid:{hashlib.sha256(arguments).hexdigest()[:32]}",
        "tier": "authoritative",
        "hashAlgorithm": "sha256",
        "agent": {
            "id": f"{principal['issuer']}#client/{principal['clientId']}",
            "credentialDigest": principal["tokenDigest"],
            "authentication": "oauth-access-token",
            "signers": [keyid(agent_key)],
        },
        "delegation": {
            "subject": principal["subject"],
            "subjectKind": "system",
            "authorityDigest": jcs_digest(
                {"audience": principal["audience"], "clientId": principal["clientId"]}
            ),
        },
        "resource": {
            "kind": "tool",
            "id": "mcp://files/write",
            "binding": "digest-bound",
            "argumentsDigest": sha256_hex(arguments),
        },
        "decision": {
            "action": "write",
            "requestDigest": "",
            "reported": "permit",
            "decisionPointId": f"{principal['issuer']}#decision-point",
            "policyDigest": sha256_hex(b"policy/ledger-writers"),
            "reportedAt": stamp(reported),
        },
        "effect": {
            "observed": "occurred",
            "interval": {
                "beforeRoot": before_root,
                "afterRoot": after_root,
                "baseResolution": "supplied",
                "openedAt": stamp(reported - second),
                "sealedAt": stamp(reported + 4 * second),
            },
            "pathScope": ["/srv/ledger/"],
            "writes": [],
        },
        "agreement": "agree",
        "correlation": {
            "id": f"urn:uuid:corr-{sha256_hex(arguments)[:16]}",
            "scope": "cross-party",
            "timeBasis": "asserted",
        },
        "posture": {
            "reported": "allowlist",
            "reportedDigest": sha256_hex(b"posture/allowlist"),
            "observed": "allowlist",
            "observedDigest": sha256_hex(b"posture/allowlist"),
            "assessedAt": stamp(reported - datetime.timedelta(hours=1)),
            "agreement": "agree",
        },
        "remediation": [],
        "observation": {
            "vantage": "below-observed",
            "coverage": {"scopeComplete": True, "gaps": []},
            "priorCommitment": {
                "committedAt": stamp(reported - 4 * second),
                "witnessNonce": sha256_hex(b"nonce/observer-chosen"),
                "commitmentDigest": "",
                "keyid": keyid(observer_key),
                "sig": "",
            },
        },
        "fieldEvidence": {
            "agent": "producer-asserted",
            "correlation": "producer-asserted",
            "decision": "producer-asserted",
            "delegation": "producer-asserted",
            "posture": "substrate-covered",
            "remediation": "substrate-covered",
            "resource": "substrate-covered",
        },
        "doesNotAssert": [
            "that this record has been or will be retained for any period",
            "that the reported decision is the decision the policy engine evaluated",
        ],
        "issuedAt": stamp(reported + 9 * second),
        "evaluation": {
            "status": "evaluated",
            "inputs": [
                {
                    "input": "policy-source",
                    "lastResult": stamp(reported - datetime.timedelta(hours=2)),
                    "maxAge": 86400,
                },
                {
                    "input": "standing-source",
                    "lastResult": stamp(reported - datetime.timedelta(minutes=2)),
                    "maxAge": 3600,
                },
            ],
        },
        "principal": principal,
    }
    request = request_digest(pred)
    pred["decision"]["requestDigest"] = request
    pred["effect"]["writes"] = [
        {
            "path": LEDGER_PATH,
            "preStateDigest": before_root,
            "postStateDigest": after_root,
            "requestDigest": request,
            "inScope": True,
        }
    ]
    commitment = pred["observation"]["priorCommitment"]
    commitment["commitmentDigest"] = commitment_digest(pred, commitment)
    commitment["sig"] = base64.b64encode(
        observer_key.sign(commitment["commitmentDigest"].encode("ascii"))
    ).decode()
    return pred


def statement(pred: dict[str, Any]) -> dict[str, Any]:
    corr = pred["correlation"]["id"]
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": corr, "digest": {"sha256": pred["decision"]["requestDigest"]}},
            {"name": corr + "/after", "digest": {"sha256": pred["effect"]["interval"]["afterRoot"]}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": pred,
    }


def seal(stmt: dict[str, Any], observer_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Wrap ``stmt`` in a DSSE envelope signed by the observer."""
    payload = canonical_bytes(stmt)
    sig = observer_key.sign(pae(PAYLOAD_TYPE, payload))
    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"keyid": keyid(observer_key), "sig": base64.b64encode(sig).decode()}],
    }


def load_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))


def save_key(path: Path, key: Ed25519PrivateKey) -> None:
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_text(raw.hex() + "\n")


def decode_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    return json.loads(base64.b64decode(envelope["payload"]))
