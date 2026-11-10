"""Write the cbor_receipt_chain/v1 example: a six-receipt stream, its profile, the case and the policy.

Run from this directory: ``python3 generate.py``. The signing key is derived from a fixed public
label, so the bytes are the same on every run and carry no trust outside this example.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tests"))

import receipt_chain_builder as rb  # noqa: E402

CASE_ID = "receipt-chain-six-allowed-calls"


def write(name: str, data: bytes) -> dict:
    (HERE / name).write_bytes(data)
    return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def render(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def main() -> None:
    key = rb.seed_key("cbor-receipt-chain-example")
    receipts = rb.chain(rb.NEUTRAL, key, 6)
    artifacts = {"profile.json": write("profile.json", render(rb.NEUTRAL)),
                 "chain.jsonl": write("chain.jsonl", rb.stream(rb.NEUTRAL, receipts))}
    write("case.json", render({"schema_version": "probity-case/v1", "case_id": CASE_ID,
                               "artifacts": artifacts}))
    write("policy.json", render({"schema_version": "probity-policy/v1", "assessments": {CASE_ID: {
        "claim_type": "cbor_receipt_chain/v1", "records": "chain.jsonl", "profile": "profile.json",
        "signer_keys": [rb.public_hex(key)], **rb.head(receipts)}}}))


if __name__ == "__main__":
    main()
