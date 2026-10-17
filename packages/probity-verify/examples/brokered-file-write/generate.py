"""Generate disclosed synthetic records with deterministic test-only keys.

These are wire controls, not native workload or independent-operator evidence.
Private seeds in this source are public fixture material, never production keys.
This generator does not use Verify's record parser, digests or signing helpers.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).parent
UTC = "2026-10-06T00:00:00Z"
GENESIS = "0" * 64


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(domain, value):
    return hashlib.sha256(domain.encode("ascii") + b"\0" + encode(value)).hexdigest()


def key(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def public(private):
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def sign(private, domain, value):
    return base64.b64encode(private.sign(domain.encode("ascii") + b"\0" + encode(value))).decode("ascii")


def bind(files, *, completion=True, report_content=None, intended_content=None, state="sealed", target=True):
    content = hashlib.sha256(b"retained result\n").hexdigest()
    files = dict(files)
    report = {"schema_version": "brokered-file-write-report/v1", "interval_id": "fixture-interval",
              "request_id": "write-1", "path": "/work/result.txt", "content_sha256": report_content or content,
              "completion_recorded": completion}
    files["report.json"] = encode(report)
    roles = {"report": "report.json", "history": "history.jsonl", "ledger": "ledger.jsonl", "head": "head.json"}
    if state == "sealed":
        roles["packet"] = "packet.json"
    if target:
        roles["target"] = "result.txt"
    metadata = {role: {"path": name, "length": len(files[name]),
                      "sha256": hashlib.sha256(files[name]).hexdigest()} for role, name in roles.items()}
    selector = lambda role: {"artifact": role, "sha256": metadata[role]["sha256"]}
    record = {"state": state, **{role: selector(role) for role in roles if role not in {"report", "target"}}}
    context = {"interval_id": "fixture-interval", "request_id": "write-1", "path": "/work/result.txt",
               "authority_scope": "/work", "intended_content_sha256": intended_content or content}
    case = {"schema_version": "probity-case/v1", "case_id": "broker-fixture", "artifacts": metadata}
    policy = {"schema_version": "probity-policy/v1", "witnesses": {"broker": {
              "observer_key": public(key(1)), "witness_key": public(key(2)), "witness_scope": "PEER", "record": record}},
              "assessments": {"broker-fixture": {"claim_type": "brokered_file_write/v1", "context": context,
                "broker_witness": "broker", "report": selector("report"),
                "retained_target": {**selector("target"), "captured_at": UTC} if target else None}}}
    return {name: files[name] for name in roles.values()}, case, policy


def build(*, state="sealed", completion=True, write=True, pending=False, gap=False,
          report_content=None, intended_content=None, target=True, extension=False, event_transform=None):
    observer, witness = key(1), key(2)
    content = b"retained result\n"
    content_sha = hashlib.sha256(content).hexdigest()
    authority = {"intervalId": "fixture-interval", "scope": "/work", "operation": "write-file"}
    before = digest("probity-file-tree-v0", {})
    after = digest("probity-file-tree-v0", {"result.txt": content_sha}) if write else before
    preimage = {"authorityDigest": digest("probity-authority-v0", authority), "beforeRoot": before,
                "intervalId": authority["intervalId"], "witnessNonce": "a" * 64}
    prior_payload = {"preimage": preimage, "committedAt": UTC}
    prior = {**prior_payload, "keyid": public(observer),
             "signature": sign(observer, "probity-prior-commitment-v0", prior_payload)}
    events = [{"kind": "begin", "commitment": prior,
               "commitmentDigest": digest("probity-prior-commitment-v0", prior_payload)}]
    if write or pending:
        intent = {"kind": "write-intent", "requestId": "write-1", "path": "/work/result.txt",
                  "contentDigest": content_sha, "beforeRoot": before}
        events.append(intent)
        if not pending:
            events.append({**intent, "kind": "write", "afterRoot": after})
    if gap:
        events.append({"kind": "gap", "reason": "workspace changed outside the broker"})
    if event_transform:
        events = event_transform(events)
    writes = [event for event in events if event["kind"] == "write"]
    gaps = [event["reason"] for event in events if event["kind"] == "gap"]
    claim = {"format": "probity-observer-prototype-v0", "intervalId": authority["intervalId"],
             "authorityDigest": preimage["authorityDigest"], "beforeRoot": before, "afterRoot": after,
             "writes": writes, "coverage": {"scope": "/work", "observedPopulation": "broker-write-calls-with-valid-request-id",
                 "knownGaps": gaps, "noDetectedGap": not gaps, "unmediatedEffects": "not-established"},
             "witnessScope": "PEER", "doesNotAssert": ["reads", "transient-writes", "file-modes", "network-effects", "host-operator-independence"],
             "sealedAt": UTC}
    if state == "sealed":
        events.append({"kind": "seal", "claimDigest": digest("probity-claim-v0", claim)})
    entries = []
    for event in events:
        body = {"sequence": len(entries) + 1, "previous": entries[-1]["hash"] if entries else GENESIS, "event": event}
        entries.append({**body, "hash": digest("probity-history-entry-v0", body)})
    def checkpoint(prefix):
        payload = {"count": len(prefix), "head": prefix[-1]["hash"]}
        return {**payload, "keyid": public(witness), "signature": sign(witness, "probity-checkpoint-v0", payload)}
    receipts = []
    points = {}
    for phase, prefix in (("begin", entries[:1]), ("terminal", entries)):
        if phase == "terminal" and state != "sealed":
            continue
        point = checkpoint(prefix)
        body = {"sequence": len(receipts) + 1, "previous": receipts[-1]["hash"] if receipts else GENESIS,
                "intervalId": authority["intervalId"], "authorityDigest": preimage["authorityDigest"],
                "observerKey": public(observer), "phase": phase, "checkpoint": point}
        receipt = {**body, "hash": digest("probity-witness-receipt-v0", body), "keyid": public(witness),
                   "signature": sign(witness, "probity-witness-receipt-v0", body)}
        receipts.append(receipt)
        points[phase] = {**point, "ledgerReceipt": receipt}
    head_payload = {"format": "probity-witness-ledger-head-v0", "count": len(receipts), "head": receipts[-1]["hash"]}
    head = {**head_payload, "keyid": public(witness), "signature": sign(witness, "probity-witness-ledger-head-v0", head_payload)}
    files = {"history.jsonl": b"".join(encode(entry) + b"\n" for entry in entries),
             "ledger.jsonl": b"".join(encode(receipt) + b"\n" for receipt in receipts),
             "head.json": encode(head), "result.txt": content}
    if state == "sealed":
        packet = {"authority": authority, "commitment": prior, "startCheckpoint": points["begin"],
                  "checkpoint": points["terminal"], "claim": claim, "claimKeyid": public(observer),
                  "claimSignature": sign(observer, "probity-claim-v0", claim)}
        if extension:
            request = {"run_id": "fixture-interval", "request_id": "write-1", "attempt_id": "attempt-1",
                       "tenant_id": "fixture-tenant", "principal_id": "fixture-principal", "tool_id": "file-write",
                       "target_path": "/work/result.txt", "content_sha256": content_sha}
            payload = {"profile": "probity-protected-action-reference-v0", "request": request,
                       "claimDigest": digest("probity-claim-v0", claim), "grantDigest": "b" * 64,
                       "intervalId": "fixture-interval", "authorizedAt": UTC}
            packet["authorizationBinding"] = {"payload": payload, "keyid": public(observer),
                                               "signature": sign(observer, "probity-protected-action-binding-v0", payload)}
        files["packet.json"] = encode(packet)
    return bind(files, state=state, completion=completion, report_content=report_content,
                intended_content=intended_content, target=target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest = {}
    for name, options in (("recorded", {}), ("false-negative", {"completion": False}),
                          ("missing-terminal", {"state": "missing_terminal", "pending": True})):
        files, case, policy = build(**options)
        files.update({"case.json": encode(case) + b"\n", "policy.json": encode(policy) + b"\n"})
        for filename, raw in files.items():
            path = ROOT / name / filename
            if args.check:
                if not path.is_file() or path.read_bytes() != raw:
                    parser.exit(1, f"brokered-file-write: generated bytes differ: {path}\n")
            else:
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(raw)
            manifest[f"{name}/{filename}"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    raw = (json.dumps({"scope": "authored synthetic wire controls; public test-only key seeds", "files": manifest},
                      sort_keys=True, indent=2) + "\n").encode("ascii")
    if args.check:
        if not (ROOT / "MANIFEST.json").is_file() or (ROOT / "MANIFEST.json").read_bytes() != raw:
            parser.exit(1, "brokered-file-write: manifest differs\n")
    else:
        (ROOT / "MANIFEST.json").write_bytes(raw)
    print("brokered-file-write: 3 synthetic cases checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
