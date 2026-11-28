"""The offline record bundle verifier: grades from the verifier's own trust, and every refusal on a broken bundle."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey
from probity_records import witness as w
from probity_records.bundle import (
    BUNDLE_FORMAT,
    COMMITMENT_FORMAT,
    EVALUATOR_PREDICATE,
    PAYLOAD_TYPE,
    STATEMENT_TYPE,
    BundleRefused,
    PublicWitness,
    RecordFacts,
    SourceKey,
    ThirdPartyTrust,
    canonical,
    leaf_entry,
    read_evaluator,
    verify_bundle,
)
from probity_records.core import Signer, pae
from probity_records.receipt_map import ReceiptMap, map_key
from probity_records.refusal_codes import is_registered

ORIGIN = "example.com/decision-log"
NOW = 1_800_000_000
TENANT = "tenant-a"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _record(key: Ed25519PrivateKey, *, permit: str | None = "p-1", stage: str | None = "execute",
            tenant: str = TENANT) -> bytes:
    runtime: dict[str, Any] = {"scope": {"tenant_id": tenant}, "sequence": 0, "previous": None, "tool": "pay"}
    if permit is not None:
        runtime["permitId"] = permit
    if stage is not None:
        runtime["stage"] = stage
    body = {"_type": STATEMENT_TYPE, "subject": [{"name": "call:c-1", "digest": {"sha256": "0" * 64}}],
            "predicateType": EVALUATOR_PREDICATE, "predicate": {"runtime": runtime}}
    payload = json.dumps(body, sort_keys=True).encode()
    sig = key.sign(pae(PAYLOAD_TYPE, payload))
    return json.dumps({"payloadType": PAYLOAD_TYPE, "payload": _b64(payload),
                       "signatures": [{"keyid": "", "sig": _b64(sig)}]}).encode()


class World:
    """A log of one record leaf (and its map commitment), a log key pair and two external witnesses."""

    def __init__(self, *, keyed: bool = True, pq_log: bool = True) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source = SourceKey("evaluator-1", "evaluator", self.source_key.public_key().public_bytes_raw())
        self.raw = _record(self.source_key, permit="p-1" if keyed else None, stage="execute" if keyed else None)
        self.entry = leaf_entry(self.source, read_evaluator(self.raw, self.source), 1_799_999_000_000)
        self.leaves = [canonical(self.entry)]
        self.map_doc: dict[str, Any] | None = None
        if keyed:
            m = ReceiptMap()
            key = map_key(self.source.key_id, "p-1", "execute")
            m.insert(key, 0, w.leaf_hash(self.leaves[0]))
            commitment = {"format": COMMITMENT_FORMAT, "tenant": TENANT, "coversSize": 1, "keys": 1,
                          "root": m.root().hex(), "previousCommitment": None}
            self.leaves.append(canonical(commitment))
            self.proof = m.prove(key)
        hashes = [w.leaf_hash(x) for x in self.leaves]
        self.cp = w.Checkpoint(ORIGIN, len(hashes), w.root(hashes))
        self.log = Signer.generate()
        self.log_pq = MLDSA44PrivateKey.generate() if pq_log else None
        self.wit_a, self.wit_b = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
        if keyed:
            self.map_doc = {"commitment": {"index": 1, "bytes": _b64(self.leaves[1]),
                                           "inclusion": [_b64(h) for h in w.inclusion_proof(1, hashes)]},
                            "proof": self.proof.to_doc()}
        self.hashes = hashes

    def vkeys(self) -> tuple[str, str | None]:
        ed = w.log_vkey(ORIGIN, self.log)
        pq = None if self.log_pq is None else w.vkey(ORIGIN, w.SIG_MLDSA44, self.log_pq.public_key()).encode()
        return ed, pq

    def note(self, *, witnesses: bool = True, at: int = NOW - 10) -> str:
        text = self.cp.text()
        signed = w.parse_note(w.sign_checkpoint(self.cp, self.log))
        sigs = list(signed.sigs)
        if self.log_pq is not None:
            sigs.append(w.cosign_mldsa(text, ORIGIN, self.log_pq, at))
        if witnesses:
            sigs.append(w.cosign(text, "witness-a.example", self.wit_a, at))
            sigs.append(w.cosign_mldsa(text, "witness-b.example", self.wit_b, at + 1))
        return w.Note(text, tuple(sigs)).encode()

    def bundle(self, **note: Any) -> dict[str, Any]:
        ed, pq = self.vkeys()
        return {"format": BUNDLE_FORMAT, "checkpoint": self.note(**note), "log": {"vkey": ed, "pqVkey": pq},
                "leaf": {"index": 0, "bytes": _b64(self.leaves[0]),
                         "inclusion": [_b64(h) for h in w.inclusion_proof(0, self.hashes)]},
                "record": {"bytes": _b64(self.raw), "source": {"id": self.source.source_id, "kind": "evaluator",
                                                               "publicKey": self.source.public_raw.hex()}},
                "map": self.map_doc}

    def trust(self, *, quorum: int = 2, bound: bool = True, pin_pq: bool = True,
              grade: str = "production") -> ThirdPartyTrust:
        witnesses = (
            PublicWitness(w.vkey("witness-a.example", w.SIG_COSIGNATURE_V1, self.wit_a.public_key()).encode(),
                          "operator-a", grade),
            PublicWitness(w.vkey("witness-b.example", w.SIG_MLDSA44, self.wit_b.public_key()).encode(),
                          "operator-b", grade),
        )
        pq = self.vkeys()[1]
        log_pq = {ORIGIN: pq} if pin_pq and pq is not None else {}
        counterparties = {self.source.key_id: "bank.example"} if bound else {}
        return ThirdPartyTrust(witnesses, quorum, counterparties=counterparties, log_pq=log_pq)


def test_a_bound_counterparty_receipt_with_a_map_proof_is_grade_i_and_pq_independent() -> None:
    world = World()
    verdict = verify_bundle(world.bundle(), world.trust(), NOW)
    assert (verdict.grade, verdict.pq, verdict.assurance, verdict.map_status) == (
        "I", "PQ-covered (independence)", "production", "proven")
    assert verdict.externally_witnessed_at == NOW - 9  # the quorum-th cosignature, never the first
    assert verdict.receipt == (world.source.key_id, "p-1", "execute")


def test_without_the_quorum_the_record_is_grade_s_and_pq_pending() -> None:
    world = World()
    verdict = verify_bundle(world.bundle(witnesses=False), world.trust(), NOW)
    assert (verdict.grade, verdict.pq, verdict.externally_witnessed_at) == ("S", "PQ-pending", None)


def test_an_unbound_key_is_grade_w_and_a_claimed_counterparty_is_tenant_declared() -> None:
    world = World()
    assert verify_bundle(world.bundle(), world.trust(bound=False), NOW).grade == "W"
    bundle = world.bundle()
    bundle["record"]["counterparty"] = "other.example"
    verdict = verify_bundle(bundle, world.trust(), NOW)
    assert (verdict.grade, verdict.label) == ("W", "tenant-declared counterparty")


def test_a_log_pq_key_the_verifier_does_not_pin_counts_for_nothing() -> None:
    world = World()
    assert verify_bundle(world.bundle(), world.trust(pin_pq=False), NOW).pq == "PQ-pending"


def test_staging_witnesses_grade_staging_and_stale_cosignatures_do_not_count() -> None:
    world = World()
    assert verify_bundle(world.bundle(), world.trust(grade="staging"), NOW).assurance == "staging-grade"
    assert verify_bundle(world.bundle(at=NOW - 7200), world.trust(), NOW).grade == "S"


def test_an_unkeyed_record_needs_no_map() -> None:
    world = World(keyed=False)
    assert verify_bundle(world.bundle(), world.trust(), NOW).map_status == "unkeyed"


def _tamper(name: str, bundle: dict[str, Any], world: World) -> None:
    other = World()
    if name == "format":
        bundle["format"] = "probity-record-bundle/v0"
    elif name == "extra":
        bundle["extra"] = 1
    elif name == "checkpoint":
        bundle["checkpoint"] = bundle["checkpoint"].replace(f"{ORIGIN}\n2\n", f"{ORIGIN}\n3\n", 1)
    elif name == "log-key":
        ed, pq = other.vkeys()
        bundle["log"] = {"vkey": ed, "pqVkey": pq}
    elif name == "inclusion":
        bundle["leaf"]["inclusion"] = []
    elif name == "record-signature":
        bundle["record"]["source"]["publicKey"] = other.source.public_raw.hex()
    elif name == "record-swapped":
        bundle["record"]["bytes"] = _b64(_record(world.source_key, permit="p-2"))
    elif name == "kind":
        bundle["record"]["source"]["kind"] = "gateway"
    elif name == "map-key":
        bundle["map"]["proof"]["key"] = "00" * 32
    elif name == "claims":
        bundle["claims"] = {"grade": "I", "pq": "PQ-covered (independence)"}


@pytest.mark.parametrize(("name", "code", "trust"), [
    ("format", "bundle_malformed", {}),
    ("extra", "bundle_malformed", {}),
    ("checkpoint", "bundle_checkpoint_refused", {}),
    ("log-key", "bundle_checkpoint_refused", {}),
    ("inclusion", "bundle_leaf_not_included", {}),
    ("record-signature", "bundle_record_invalid", {}),
    ("record-swapped", "bundle_record_mismatch", {}),
    ("kind", "bundle_record_kind_unsupported", {}),
    ("map-key", "bundle_map_invalid", {}),
    ("claims", "bundle_claim_overstated", {"bound": False}),
])
def test_every_broken_bundle_is_refused_with_its_registered_code(name: str, code: str, trust: dict[str, Any]) -> None:
    world = World()
    bundle = world.bundle()
    _tamper(name, bundle, world)
    with pytest.raises(BundleRefused) as raised:
        verify_bundle(bundle, world.trust(**trust), NOW)
    assert raised.value.code == code
    assert is_registered(code)


def _map_holding(world: World, index: int, leaf: bytes) -> dict[str, Any]:
    """A bundle whose committed map holds ``leaf`` at log ``index`` for the record's own permit stage."""
    m = ReceiptMap()
    key = map_key(world.source.key_id, "p-1", "execute")
    m.insert(key, index, leaf)
    commitment = copy.deepcopy(json.loads(world.leaves[1]))
    commitment["root"] = m.root().hex()
    leaves = [world.leaves[0], canonical(commitment)]
    hashes = [w.leaf_hash(x) for x in leaves]
    world.leaves, world.hashes = leaves, hashes
    world.cp = w.Checkpoint(ORIGIN, 2, w.root(hashes))
    bundle = world.bundle()
    bundle["map"] = {"commitment": {"index": 1, "bytes": _b64(leaves[1]),
                                    "inclusion": [_b64(h) for h in w.inclusion_proof(1, hashes)]},
                     "proof": m.prove(key).to_doc()}
    return bundle


def test_a_map_that_holds_another_record_for_the_key_is_a_contradiction() -> None:
    world = World()
    bundle = _map_holding(world, 0, hashlib.sha256(b"another record").digest())
    with pytest.raises(BundleRefused) as raised:
        verify_bundle(bundle, world.trust(), NOW)
    assert raised.value.code == "bundle_map_contradiction"


def test_a_map_that_holds_this_record_at_another_log_index_is_a_contradiction() -> None:
    world = World()
    bundle = _map_holding(world, 1, w.leaf_hash(world.leaves[0]))
    with pytest.raises(BundleRefused) as raised:
        verify_bundle(bundle, world.trust(), NOW)
    assert raised.value.code == "bundle_map_contradiction"


def test_a_caller_reader_grades_a_private_kind_with_the_same_proofs() -> None:
    world = World()
    bundle = world.bundle()
    bundle["record"]["source"]["kind"] = "gateway"
    entry = dict(world.entry, kind="gateway")
    world.leaves[0] = canonical(entry)
    # a reader for the private kind states the same facts the evaluator reader would
    facts = read_evaluator(world.raw, world.source)

    def reader(raw: bytes, key: SourceKey) -> RecordFacts:
        return facts

    hashes = [w.leaf_hash(x) for x in world.leaves]
    world.hashes = hashes
    world.cp = w.Checkpoint(ORIGIN, len(hashes), w.root(hashes))
    m = ReceiptMap()
    key = map_key(world.source.key_id, "p-1", "execute")
    m.insert(key, 0, hashes[0])
    commitment = dict(json.loads(world.leaves[1]), root=m.root().hex())
    world.leaves[1] = canonical(commitment)
    hashes = [w.leaf_hash(x) for x in world.leaves]
    world.hashes, world.cp = hashes, w.Checkpoint(ORIGIN, 2, w.root(hashes))
    world.map_doc = {"commitment": {"index": 1, "bytes": _b64(world.leaves[1]),
                                    "inclusion": [_b64(h) for h in w.inclusion_proof(1, hashes)]},
                     "proof": m.prove(key).to_doc()}
    bundle = world.bundle()
    bundle["record"]["source"]["kind"] = "gateway"
    assert verify_bundle(bundle, world.trust(), NOW, readers={"gateway": reader}).grade == "I"
