"""The Adversarial Execution Evidence route agrees with every member of the conformance corpus.

``tests/data/execution-evidence`` is a copy of the ``vectors`` corpus of
probityai/agent-evidence-vectors (suite revision 32, corpus digest
bf3e5befd71640757ff1b3f0af63507364b823b5e3f9059678f72f64a46e11c1, last changed
in commit 8977ca789abfd7cafea214936466be7112daf89e). Every expectation below is
read from that corpus's MANIFEST.json; none comes from the verifier.

Each member is judged through the kernel (``probity_verify.adjudicate``) under
two key policies, the corpus's published substrate test key and no key, and
must reach the corpus's verdict; an accepted member its result and the tier
columns the corpus pins; a rejected member a primary code from the corpus's
set; an indeterminate member a primary code some declared reading predicts,
with one reading explaining the whole family.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_verify import adjudicate
from probity_verify import execution_evidence as aee
from probity_verify.common import CaseError

CORPUS = Path(__file__).resolve().parent / "data" / "execution-evidence"
MANIFEST = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
MEMBERS = MANIFEST["vectors"]
CLAIM = "adversarial_execution_evidence/v1"


def _test_key(role: str) -> str:
    """A key from the corpus's published recipe: seed = SHA-256("in-toto-aee-test-key/<role>/v1")."""
    seed = hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest()
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


SUBSTRATE_KEY = _test_key("substrate-observation-test")


def decide(member: dict, keys: list[str], root: Path = CORPUS) -> dict:
    data = (CORPUS / member["file"]).read_bytes()
    case = {"schema_version": "probity-case/v1", "case_id": member["id"],
            "artifacts": {"statement": {"path": member["file"], "length": len(data),
                                        "sha256": hashlib.sha256(data).hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {member["id"]: {"claim_type": CLAIM, "statement": "statement",
                                             "substrate_observation_keys": keys}}}
    return adjudicate(case, policy, root)


def disagreements(member: dict, decision: dict, pinned: bool) -> list[str]:
    """How a decision departs from what the corpus declares for the member."""
    expected = member["expected"]
    found = decision["checks"][0]
    problems = []
    if found["verdict"] != expected["verdict"]:
        return [f"verdict {found['verdict']} {found['codes']}"]
    if member["kind"] == "accept":
        if found["result"] != expected["result"]:
            problems.append(f"result {found['result']}")
        tiers = expected.get("tierWithPinnedKey" if pinned else "tierWithoutKey")
        if tiers and found["tiers"] != tiers:
            problems.append(f"tiers {found['tiers']}")
    elif member["kind"] == "reject":
        if found["primary_code"] not in expected["codes"]:
            problems.append(f"primary code {found['primary_code']}")
    elif found["primary_code"] not in expected["readings"].values():
        problems.append(f"primary code {found['primary_code']} is no declared reading")
    if found["verdict"] == aee.INVALID and ("result" in found or "tiers" in found):
        problems.append("an invalid verdict carried a result or tiers")
    return problems


@pytest.mark.parametrize("kind", ["accept", "reject", "indeterminate"])
def test_every_member_of_the_family_agrees(kind):
    members = [member for member in MEMBERS if member["kind"] == kind]
    assert len(members) == MANIFEST["counts"][kind] > 0
    failures = []
    for member in members:
        for pinned in (True, False):
            decision = decide(member, [SUBSTRATE_KEY] if pinned else [])
            want = "supported" if member["expected"]["verdict"] == "valid" else "contradicted"
            if decision["decision"] != want:
                failures.append(f"{member['id']}: decision {decision['decision']}")
            failures += [f"{member['id']} pinned={pinned}: {p}"
                         for p in disagreements(member, decision, pinned)]
    assert failures == []


def test_one_reading_explains_each_indeterminate_family():
    families: dict[str, list[dict]] = {}
    for member in MEMBERS:
        if member["kind"] == "indeterminate":
            families.setdefault(member["expected"]["family"], []).append(member)
    assert families
    for family, members in families.items():
        answers = {m["id"]: decide(m, [SUBSTRATE_KEY])["checks"][0]["primary_code"] for m in members}
        readings = [r for r in members[0]["expected"]["readings"]
                    if all(m["expected"]["readings"][r] == answers[m["id"]] for m in members)]
        assert readings, (family, answers)


def test_the_corpus_counts_cover_every_member():
    assert Counter(member["kind"] for member in MEMBERS) == Counter(MANIFEST["counts"])
    assert len(MEMBERS) == 288
    assert MANIFEST["predicateType"] == aee.PREDICATE_TYPE


def test_the_comparison_catches_a_wrong_verdict():
    """The agreement check is not vacuous: a tampered accept member stops agreeing."""
    member = next(m for m in MEMBERS if m["kind"] == "accept")
    statement = json.loads((CORPUS / member["file"]).read_bytes())
    statement["predicate"]["result"] = "pass" if member["expected"]["result"] != "pass" else "fail"
    decision = adjudicate_bytes(json.dumps(statement).encode(), member["id"])
    assert decision["decision"] == "contradicted"
    assert disagreements(member, decision, True)


def adjudicate_bytes(data: bytes, case_id: str, keys: list[str] | None = None) -> dict:
    from probity_verify.common import supplied_artifacts
    digest = hashlib.sha256(data).hexdigest()
    case = {"schema_version": "probity-case/v1", "case_id": case_id,
            "artifacts": {"statement": {"path": "statement.json", "length": len(data), "sha256": digest}}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {case_id: {"claim_type": CLAIM, "statement": "statement",
                                        "substrate_observation_keys": keys or []}}}
    with supplied_artifacts({digest: data}):
        return adjudicate(case, policy, CORPUS)


def test_an_unpinned_signer_never_attests():
    member = next(m for m in MEMBERS if "attested" in m["expected"].get("tierWithPinnedKey", []))
    wrong = decide(member, [_test_key("wrong-signer-test")])["checks"][0]["tiers"]
    assert "attested" not in wrong
    assert "attested" in decide(member, [SUBSTRATE_KEY])["checks"][0]["tiers"]


def test_a_missing_statement_is_not_established(tmp_path):
    member = MEMBERS[0]
    decision = decide(member, [], root=tmp_path)
    assert (decision["decision"], decision["reason"]) == ("not_established", "statement_unavailable")


@pytest.mark.parametrize("keys", [["00"], ["Z" * 64], "abc", [SUBSTRATE_KEY.upper()]])
def test_malformed_key_pins_are_refused(keys):
    with pytest.raises(CaseError):
        decide(MEMBERS[0], keys)


def test_the_decision_names_the_reference_verifier():
    decision = decide(MEMBERS[0], [])
    assert decision["reference"]["verifier"]["id"].endswith("/verifiers/probity-verify")
    assert decision["claim_type"] == CLAIM


@pytest.mark.parametrize("raw,kind", [
    (b'{"a":1,"a":2}', aee.DUPLICATE),
    (b'{"a":"\\ud800"}', aee.NOT_SCALAR),
    (b'{"a":1.5}', aee.NON_INTEGER),
    (b'{"a":9007199254740992}', aee.UNSAFE_INTEGER),
    (b'[' * 129 + b']' * 129, aee.TOO_DEEP),
    (b'{"a":1} x', aee.SYNTAX),
])
def test_the_strict_profile_names_each_fault(raw, kind):
    with pytest.raises(aee.JSONError) as caught:
        aee.parse_strict(raw)
    assert caught.value.kind == kind


def test_canonical_form_sorts_by_utf16_and_writes_integers():
    raw = '{"b":1e2,"a":[true,null],"\u00e9":"\\u0001","\U0001f600":0}'.encode()
    assert aee.canonicalize(raw) == '{"a":[true,null],"b":100,"\u00e9":"\\u0001","\U0001f600":0}'.encode()


@pytest.mark.parametrize("value,ok", [
    ("2026-10-29T12:00:00Z", True), ("2026-10-29T12:00:00.123456789123Z", True),
    ("2026-10-29T12:00:00+00:00", True), ("2026-10-29T12:00:00+01:00", False),
    ("2026-02-30T12:00:00Z", False), ("2026-10-29t12:00:00Z", False), ("2026-10-29T24:00:00Z", False),
])
def test_timestamps_need_a_zero_offset(value, ok):
    if ok:
        aee.parse_timestamp(value)
    else:
        with pytest.raises(ValueError):
            aee.parse_timestamp(value)


def test_carried_base64_must_be_canonical():
    assert aee.decode_carried_base64(base64.b64encode(b"ab").decode()) == b"ab"
    for bad in ("YWI", "YWJ=", "YW\nI=", "é"):
        with pytest.raises(ValueError):
            aee.decode_carried_base64(bad)
