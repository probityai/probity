"""The receipt verdict codes: a closed set, one corpus vector per code, and unknown codes refused.

``src/agent_evidence_verify/receipt-verdict-codes.json`` is a byte copy of
``docs/reference/receipt-verdict-codes.json`` in probityai/agent-evidence-vectors at commit
6a1ff142087aff1a06129e478f2ef89eaf71350e; the digest below pins it. Each verdict code
names a member of the ``execution-evidence`` corpus copy in ``tests/data``, and the verifier
must reach that code on the member's own bytes, under the corpus's published substrate key
and with no key.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent_evidence_verify import execution_evidence as aee
from agent_evidence_verify import verdict_codes as vc
from agent_evidence_verify.verdict_codes import UnknownCode, VerdictCode

CORPUS = Path(__file__).resolve().parent / "data" / "execution-evidence"
MEMBERS = {m["id"]: m for m in json.loads((CORPUS / "MANIFEST.json").read_text("utf-8"))["vectors"]}
REGISTRY_SHA256 = "47414a9e678efbd3c6685136effad19c57bab27e6d28df7cd6c842f3f4058b2e"
SEVEN = {"NOT_PUBLICLY_VERIFIABLE", "LEAF_HASH_MISMATCH", "PROOF_BROKEN", "CLAIM_NOT_BOUND",
         "SUMMARY_MISMATCH", "MALFORMED", "NOT_RECONSTRUCTIBLE"}


def report_for(vector: str) -> aee.Report:
    return aee.verify((CORPUS / MEMBERS[vector]["file"]).read_bytes())


def test_the_set_is_closed() -> None:
    assert {v.value for v in VerdictCode} == SEVEN
    assert {e["code"] for e in vc.registry()["codes"]} == SEVEN


def test_the_shipped_registry_is_the_pinned_copy() -> None:
    shipped = Path(vc.__file__).with_name("receipt-verdict-codes.json").read_bytes()
    assert hashlib.sha256(shipped).hexdigest() == REGISTRY_SHA256


@pytest.mark.parametrize("entry", vc.registry()["codes"], ids=lambda e: e["code"])
def test_every_code_has_a_vector_that_produces_it(entry: dict) -> None:
    report = report_for(entry["vector"])
    assert report.as_dict()["verdict_code"] == entry["code"]
    expected = MEMBERS[entry["vector"]]["expected"]
    assert report.verdict == expected["verdict"]


def test_an_attested_report_carries_no_code_and_an_unkeyed_one_is_not_publicly_verifiable() -> None:
    seed = hashlib.sha256(b"in-toto-aee-test-key/substrate-observation-test/v1").digest()
    key = aee.load_public_key(Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    member = next(m for m in MEMBERS.values() if m["expected"].get("tierWithPinnedKey") == ["attested"])
    data = (CORPUS / member["file"]).read_bytes()
    assert aee.verify(data, [key]).as_dict()["verdict_code"] is None
    assert aee.verify(data).as_dict()["verdict_code"] == "NOT_PUBLICLY_VERIFIABLE"


def test_every_code_the_corpus_names_is_classified() -> None:
    named = {c for m in MEMBERS.values() for c in m["expected"].get("codes", [])
             + m["expected"].get("alsoCarries", []) + m["expected"].get("alsoEmits", [])}
    assert named
    for code in named:
        assert vc.verdict_for_code(code) in set(VerdictCode)


def test_every_rejected_member_gets_the_code_of_its_primary_code() -> None:
    for member in MEMBERS.values():
        if member["kind"] != "reject":
            continue
        report = report_for(member["id"])
        assert report.as_dict()["verdict_code"] == vc.verdict_for_code(report.codes[0]).value


def test_the_removed_call_case_is_malformed_not_a_proof_failure() -> None:
    assert vc.verdict_for_code("batch-root-orphaned") is VerdictCode.MALFORMED
    assert vc.verdict_for_code("batch-root-mismatch") is VerdictCode.PROOF_BROKEN


def test_policy_codes_outside_the_axis_map_to_none() -> None:
    assert vc.verdict_for_code("scope-unpinned") is None
    assert vc.verdict_for_code("substrate-anchor-mismatch") is VerdictCode.LEAF_HASH_MISMATCH


@pytest.mark.parametrize("code", ["never-heard-of-it", "", "BATCH-ROOT-MISMATCH"])
def test_an_unknown_failure_code_fails_closed(code: str) -> None:
    with pytest.raises(UnknownCode):
        vc.verdict_for_code(code)


def test_an_invalid_report_with_an_unknown_primary_code_fails_closed() -> None:
    with pytest.raises(UnknownCode):
        vc.verdict_for_report("invalid", ["from-a-newer-verifier"], None)
    with pytest.raises(UnknownCode):
        vc.verdict_for_report("invalid", [], None)


@pytest.mark.parametrize("text", ["PASS", "proof_broken", "", "MALFORMED "])
def test_an_unknown_verdict_code_spelling_fails_closed(text: str) -> None:
    with pytest.raises(UnknownCode):
        VerdictCode.parse(text)
    assert VerdictCode.parse("PROOF_BROKEN") is VerdictCode.PROOF_BROKEN
