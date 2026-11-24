"""Each reader judges an identifier under ``probityai.org`` exactly as under ``probityai.github.io``.

For every reader that compares an identifier taken from a record, an accepted case rewritten to the
new host keeps its verdict and reason, and the ``http://probityai.org/`` spelling keeps the
verdict an unknown identifier gets today. Signed cases are re-signed with the corpus's published
test key; where a case has no test key, the comparison is tested with the rewritten value.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from agent_evidence_verify import actor_marker, bundle
from agent_evidence_verify.adapters import (
    approval_binding,
    audit_principal,
    audit_record,
    evaluation_claim,
    observed_effect,
    restoration,
    uncertain_effect,
)
from agent_evidence_verify.common import CaseError
from agent_evidence_verify.core import REFERENCE_VERIFIER_ID, canonical_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

TESTS = Path(__file__).resolve().parent
EXAMPLES = TESTS.parent / "examples"
OLD, NEW, PLAIN = "https://probityai.github.io/", "https://probityai.org/", "http://probityai.org/"


def rehost(value: Any, host: str) -> Any:
    """``value`` with every identifier under the old host moved to ``host``, recursively."""
    if isinstance(value, str):
        return host + value[len(OLD):] if value.startswith(OLD) else value
    if isinstance(value, list):
        return [rehost(item, host) for item in value]
    if isinstance(value, dict):
        return {key: rehost(item, host) for key, item in value.items()}
    return value


def _accepted(root: Path, accept: str) -> list[dict[str, Any]]:
    manifest = json.loads((root / "MANIFEST.json").read_bytes())
    return [e for e in manifest["vectors"] if e["expected"]["decision"] == accept]


# --- approval-binding/v1 and uncertain-effect/v1: contractId, unsigned -----------------------

APPROVAL = TESTS / "data" / "approval-binding"
EFFECT = TESTS / "data" / "uncertain-effect"


@pytest.mark.parametrize("entry", _accepted(APPROVAL, "allow"), ids=lambda e: e["id"])
def test_approval_binding_reads_the_new_host(entry: dict[str, Any]) -> None:
    directory = APPROVAL / entry["path"]
    record = json.loads((directory / "record.json").read_bytes())
    used = (directory / record["use"]["payloadFile"]).read_bytes()
    assert approval_binding.first_failure(record, used) is None
    assert approval_binding.first_failure(rehost(record, NEW), used) is None
    plain = {**record, "contractId": PLAIN + record["contractId"][len(OLD):]}
    assert approval_binding.first_failure(plain, used) == "contract_id_unknown"


@pytest.mark.parametrize("entry", _accepted(EFFECT, "allow"), ids=lambda e: e["id"])
def test_uncertain_effect_reads_the_new_host(entry: dict[str, Any]) -> None:
    record = json.loads((EFFECT / entry["path"] / "record.json").read_bytes())
    assert uncertain_effect.first_failure(record) is None
    assert uncertain_effect.first_failure(rehost(record, NEW)) is None
    plain = {**record, "contractId": PLAIN + record["contractId"][len(OLD):]}
    assert uncertain_effect.first_failure(plain) == "contract_id_unknown"


# --- actor-marker-survival/v1: contractId of the record and of the trust bundle ---------------

MARKER = TESTS / "data" / "actor-marker-survival"


@pytest.mark.parametrize("entry", _accepted(MARKER, "accept"), ids=lambda e: e["id"])
def test_actor_marker_reads_the_new_host(entry: dict[str, Any]) -> None:
    record = json.loads((MARKER / entry["path"] / "record.json").read_bytes())
    trust = json.loads((MARKER / "TRUST.json").read_bytes())
    expected = (entry["expected"]["decision"], entry["expected"]["reason"])
    for record_host in (OLD, NEW):
        for trust_host in (OLD, NEW):
            held = actor_marker.load_trust(json.dumps(rehost(trust, trust_host)).encode())
            moved = {**record, "contractId": rehost(record["contractId"], record_host)}
            assert actor_marker.judge(json.dumps(moved).encode(), held) == expected
    held = actor_marker.load_trust(json.dumps(trust).encode())
    plain = {**record, "contractId": PLAIN + record["contractId"][len(OLD):]}
    assert actor_marker.judge(json.dumps(plain).encode(), held) == ("reject", "contract_id_unknown")
    with pytest.raises(ValueError, match="contractId"):
        actor_marker.load_trust(json.dumps({**trust, "contractId": plain["contractId"]}).encode())


# --- evaluation-claim/v1: claim_type, and predicateType of a carrying Statement --------------

def test_evaluation_claim_reads_the_new_host() -> None:
    record = json.loads((EXAMPLES / "evaluation-claim" / "record.json").read_bytes())
    assert evaluation_claim.check_envelope(rehost(record, NEW)) == evaluation_claim.check_envelope(record)
    with pytest.raises(evaluation_claim.MalformedInput):
        evaluation_claim.check_envelope({**record, "claim_type": PLAIN + record["claim_type"][len(OLD):]})
    statement = {"_type": evaluation_claim.STATEMENT_TYPE, "predicateType": NEW + record["claim_type"][len(OLD):],
                 "subject": [{"digest": {"sha256": "a" * 64}}], "predicate": record}
    assert evaluation_claim.unwrap(statement) == (record, "sha256:" + "a" * 64)
    with pytest.raises(evaluation_claim.MalformedInput):
        evaluation_claim.unwrap({**statement, "predicateType": PLAIN + record["claim_type"][len(OLD):]})


# --- restoration: predicateType of each record and of each predecessor reference --------------

def test_restoration_record_reads_the_new_host() -> None:
    statement = json.loads((EXAMPLES / "corpus-routes" / "restoration-record" / "statement.json").read_bytes())
    verdict = restoration.check_statement(statement)
    assert verdict[0] == "accept"
    assert restoration.check_statement(rehost(statement, NEW)) == verdict
    plain = {**statement, "predicateType": PLAIN + statement["predicateType"][len(OLD):]}
    assert restoration.check_statement(plain) == ("reject", "statement-malformed")


def test_restoration_bundle_reads_the_new_host_in_the_unreferenced_decision() -> None:
    """r3 is referenced by no record, so its bytes may change: its own type and every
    predecessor reference it carries move to the new host while r1 and r2 keep the old one."""
    root = EXAMPLES / "corpus-routes" / "restoration-bundle"
    files = {name: (root / name).read_bytes() for name in ("r1.json", "r2.json", "r3.json")}
    verdict = restoration.check_bundle_files(files)
    assert verdict[0] == "accept"
    moved = {**files, "r3.json": json.dumps(rehost(json.loads(files["r3.json"]), NEW)).encode()}
    assert restoration.check_bundle_files(moved) == verdict


# --- observed-effect/v1 and agent_audit_record/v1 readers: signed payloads ---------------------

def test_observed_effect_compares_the_predicate_type_under_either_host() -> None:
    for policy_host in (OLD, NEW):
        for statement_host in (OLD, NEW):
            state = SimpleNamespace(
                statement={"predicateType": rehost(observed_effect.PREDICATE_TYPE, statement_host)},
                policy=SimpleNamespace(predicate_type=rehost(observed_effect.PREDICATE_TYPE, policy_host)))
            observed_effect._rule_predicate_type(state)
    state = SimpleNamespace(statement={"predicateType": PLAIN + observed_effect.PREDICATE_TYPE[len(OLD):]},
                            policy=SimpleNamespace(predicate_type=observed_effect.PREDICATE_TYPE))
    with pytest.raises(observed_effect.Malformed, match="predicate-type-unexpected"):
        observed_effect._rule_predicate_type(state)


#: The observer key of the audit-principal corpus is the audit-record corpus's published test key.
AUDIT_SEED = bytes.fromhex("00" * 31 + "33")
PRINCIPAL = TESTS / "data" / "audit-principal"


def _resigned(envelope: dict[str, Any], statement: dict[str, Any]) -> bytes:
    reader = audit_record.reader
    payload = reader.canonical_bytes(statement)
    key = Ed25519PrivateKey.from_private_bytes(AUDIT_SEED)
    sig = key.sign(reader.pae(envelope["payloadType"], payload))
    return json.dumps({**envelope, "payload": base64.b64encode(payload).decode(),
                       "signatures": [{**envelope["signatures"][0],
                                       "sig": base64.b64encode(sig).decode()}]}).encode()


@pytest.mark.parametrize("entry", [e for e in json.loads((PRINCIPAL / "MANIFEST.json").read_bytes())["vectors"]
                                   if e["kind"] == "accept"], ids=lambda e: e["draftId"])
def test_audit_principal_reads_the_new_host(entry: dict[str, Any]) -> None:
    key = json.loads((PRINCIPAL / "MANIFEST.json").read_bytes())["keys"]["observer"]["publicKey"]
    envelope = json.loads((PRINCIPAL / entry["file"]).read_bytes())
    statement = json.loads(base64.b64decode(envelope["payload"]))
    before = audit_principal.verify(_resigned(envelope, statement), key)
    assert before.verdict == entry["expected"]["verdict"]
    moved = {**statement, "predicateType": rehost(statement["predicateType"], NEW)}
    assert audit_principal.verify(_resigned(envelope, moved), key) == before
    plain = {**statement, "predicateType": PLAIN + statement["predicateType"][len(OLD):]}
    assert audit_principal.verify(_resigned(envelope, plain), key).codes == ["predicate-type-unexpected"]


# --- bundles: the verifier id a bundle's producer record names --------------------------------

def _producer(verifier_id: str) -> dict[str, bytes]:
    record = {"schema_version": "probity-bundle/v1", "verifier": {"id": verifier_id, "version": "0.9.0"}}
    return {"bundle.json": canonical_json(record)}


def test_a_bundle_naming_the_verifier_under_either_host_is_ours() -> None:
    for verifier_id in (REFERENCE_VERIFIER_ID, "https://probityai.github.io/probity/verifiers/probity-verify"):
        for host in (OLD, NEW):
            assert bundle._producer_release(_producer(rehost(verifier_id, host))) == "0.9.0"
    with pytest.raises(CaseError, match="written by another verifier"):
        bundle._producer_release(_producer(PLAIN + REFERENCE_VERIFIER_ID[len(OLD):]))
