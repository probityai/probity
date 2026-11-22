"""credential_reachability/v1 over the 58 members of vectors-credential-reachability.

``tests/data/credential-reachability`` is a copy of ``corpora/vectors-credential-reachability`` of
probityai/agent-evidence-vectors (MANIFEST.json and each member's ``case.json`` and ``envelope.json``),
vendored here because that corpus is unreleased until agent-evidence-vectors v0.38.0. Its digests are
checked below, so a changed copy fails before any verdict is read. Every expectation is read from the
MANIFEST; none comes from the verifier. The corpus's ``no_verdict`` members have no place among the
kernel's three decisions, so they are judged ``contradicted`` with ``malformed_envelope``.

The adversarial tests re-sign a member under the corpus's published test keys (seeds are the SHA-256 of
public labels) so each attack reaches the rule that must stop it.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import credential_reachability as cr
from agent_evidence_verify.common import CaseError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent / "data" / "credential-reachability"
MANIFEST_SHA256 = "eef8b19b38b76912843f8c990980decb4ceb0c536b3ad7d784d1649b76e78366"
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_bytes())
HOST = "credential-reachability/v1 test environment-host key"
AGENT = "credential-reachability/v1 test key the agent holds"
OTHER = "credential-reachability/v1 test key that no policy pins"
KIND = "application/vnd.in-toto+json"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def _keyid(key: Ed25519PrivateKey) -> str:
    return _sha(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def _expected(entry: dict[str, Any]) -> tuple[str, str]:
    decision = entry["expected"]["decision"]
    return ("contradicted" if decision == "no_verdict" else decision), entry["expected"]["reason"]


_STAGE: list[Path] = []


@pytest.fixture(autouse=True)
def _stage(tmp_path: Path) -> None:
    _STAGE[:] = [tmp_path]


def _judge(directory: Path, envelope: bytes | None = None, edit: Any = None) -> dict[str, Any]:
    """Judge a member's envelope (or ``envelope``) under the policy its case.json carries."""
    case = json.loads((directory / "case.json").read_bytes())
    raw = (directory / case["envelope"]).read_bytes() if envelope is None else envelope
    (_STAGE[0] / "envelope.json").write_bytes(raw)
    assessment = {"claim_type": "credential_reachability/v1", "envelope": "envelope.json",
                  **case["policy"]}
    if edit is not None:
        edit(assessment)
    binding = {"path": "envelope.json", "length": len(raw), "sha256": _sha(raw)}
    verdict = {"schema_version": "probity-case/v1", "case_id": "c",
               "artifacts": {"envelope.json": binding}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    return adjudicate(verdict, policy, _STAGE[0])


# The vendored corpus ---------------------------------------------------------------------------

def test_vendored_corpus_is_the_published_one() -> None:
    assert _sha((ROOT / "MANIFEST.json").read_bytes()) == MANIFEST_SHA256
    assert len(MANIFEST["vectors"]) == sum(MANIFEST["counts"].values()) == 58
    for entry in MANIFEST["vectors"]:
        directory = ROOT / entry["path"]
        assert {p.name for p in directory.iterdir()} == set(entry["files"])
        for name, digest in entry["files"].items():
            assert _sha((directory / name).read_bytes()) == digest, (entry["id"], name)


@pytest.mark.parametrize("entry", MANIFEST["vectors"], ids=lambda e: e["id"])
def test_member(entry: dict[str, Any]) -> None:
    result = _judge(ROOT / entry["path"])
    assert (result["decision"], result["reason"]) == _expected(entry)


def test_every_rule_reason_of_the_contract_is_forced_by_a_member() -> None:
    reasons = {e["expected"]["reason"].split(":")[0] for e in MANIFEST["vectors"]}
    assert {"signed_by_agent_key", "signature_invalid", "untrusted_key", "challenge_mismatch",
            "audience_mismatch", "result_stale", "probed_in_future", "class_set_unsupported",
            "class_missing", "class_duplicate", "marked_undeclared", "placeholder_undeclared",
            "reachable_reported_clean", "untested_reported_clean", "class_verdict_mismatch",
            "result_overstates", "result_mismatch", "attempt_fields",
            "environment_mismatch"} <= reasons


def test_the_decision_envelope_names_what_was_checked() -> None:
    result = _judge(ROOT / "cases" / "exposed")
    assert result["claim_type"] == "credential_reachability/v1"
    assert result["scope"]["environment"]["name"] == "environment/run-0042"
    assert result["checks"][0]["result"] == "exposed"
    assert "does not establish" in result["scope"]["limit"]


# Adversarial tests --------------------------------------------------------------------------

def _statement(directory: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    env = json.loads((directory / "envelope.json").read_bytes())
    return env, json.loads(base64.b64decode(env["payload"]))


def _signed(statement: dict[str, Any], *signers: tuple[str, str | None], kind: str = KIND,
            payload: bytes | None = None) -> bytes:
    """An envelope over ``statement``, one signature per ``(label, keyid override)``."""
    body = payload if payload is not None else json.dumps(
        statement, sort_keys=True, separators=(",", ":")).encode()
    pre = b"DSSEv1 %d %b %d %b" % (len(kind.encode()), kind.encode(), len(body), body)
    sigs = []
    for label, kid in signers:
        key = _key(label)
        sigs.append({"keyid": kid or _keyid(key), "sig": base64.b64encode(key.sign(pre)).decode()})
    return json.dumps({"payload": base64.b64encode(body).decode(), "payloadType": kind,
                       "signatures": sigs}).encode()


CONTAINED = ROOT / "cases" / "contained"


def _decision(result: dict[str, Any]) -> tuple[str, str]:
    return result["decision"], result["reason"]


def test_resigned_unchanged_statement_is_still_supported() -> None:
    """The control: the helper itself produces a record the verifier accepts."""
    _, statement = _statement(CONTAINED)
    assert _decision(_judge(CONTAINED, _signed(statement, (HOST, None)))) == (
        "supported", "contained_verified")


def test_forged_payload_byte_fails_closed() -> None:
    env, _ = _statement(CONTAINED)
    payload = bytearray(base64.b64decode(env["payload"]))
    payload[-3] ^= 0x01
    env["payload"] = base64.b64encode(bytes(payload)).decode()
    assert _decision(_judge(CONTAINED, json.dumps(env).encode()))[0] == "contradicted"
    assert _decision(_judge(CONTAINED, json.dumps(env).encode()))[1] == "signature_invalid"


def test_swapped_key_naming_the_trusted_keyid_fails_closed() -> None:
    """An unpinned key signs and names the host's keyid: the policy's key verifies, so it fails."""
    _, statement = _statement(CONTAINED)
    forged = _signed(statement, (OTHER, _keyid(_key(HOST))))
    assert _decision(_judge(CONTAINED, forged)) == ("contradicted", "signature_invalid")


def test_a_key_the_record_names_is_never_read() -> None:
    """The envelope's keyid picks a key only from the policy; an unknown keyid is untrusted."""
    _, statement = _statement(CONTAINED)
    assert _decision(_judge(CONTAINED, _signed(statement, (OTHER, None)))) == (
        "contradicted", "untrusted_key")


def test_agent_key_signing_alone_or_with_the_host_is_refused() -> None:
    _, statement = _statement(CONTAINED)
    alone = _signed(statement, (AGENT, _keyid(_key(HOST))))
    both = _signed(statement, (HOST, None), (AGENT, None))
    assert _decision(_judge(CONTAINED, alone)) == ("contradicted", "signed_by_agent_key")
    assert _decision(_judge(CONTAINED, both)) == ("contradicted", "signed_by_agent_key")


def test_agent_key_is_used_only_to_refuse_never_to_trust() -> None:
    """Moving the agent's key into the trusted table is the policy's defect, not a pass."""
    _, statement = _statement(CONTAINED)
    forged = _signed(statement, (AGENT, None))

    def trust_the_agent(assessment: dict[str, Any]) -> None:
        assessment["trusted_signers"] = dict(assessment["agent_keys"])

    with pytest.raises(CaseError, match="both a trusted signer and an agent key"):
        _judge(CONTAINED, forged, trust_the_agent)


def test_replayed_challenge_fails_closed() -> None:
    other = "0" * 64

    def new_challenge(assessment: dict[str, Any]) -> None:
        assessment["challenge"] = other

    assert _decision(_judge(CONTAINED, edit=new_challenge)) == (
        "contradicted", "challenge_mismatch")


def test_expired_result_is_not_established() -> None:
    def later(assessment: dict[str, Any]) -> None:
        assessment["judged_at"] = "2026-11-23T18:05:00Z"

    assert _decision(_judge(CONTAINED, edit=later)) == ("not_established", "result_stale")


def test_result_from_the_future_is_contradicted() -> None:
    def earlier(assessment: dict[str, Any]) -> None:
        assessment["judged_at"] = "2026-11-21T17:00:00Z"

    assert _decision(_judge(CONTAINED, edit=earlier)) == ("contradicted", "probed_in_future")


def test_wrong_audience_fails_closed() -> None:
    def other(assessment: dict[str, Any]) -> None:
        assessment["audience"] = "https://another-auditor.example.org"

    assert _decision(_judge(CONTAINED, edit=other)) == ("contradicted", "audience_mismatch")


def test_class_set_downgrade_to_a_shorter_list_is_refused() -> None:
    _, statement = _statement(CONTAINED)
    statement = copy.deepcopy(statement)
    statement["predicate"]["classSet"] = "credential-reachability/v0"
    statement["predicate"]["classes"] = statement["predicate"]["classes"][:3]
    assert _decision(_judge(CONTAINED, _signed(statement, (HOST, None)))) == (
        "not_established", "class_set_unsupported")


def test_dropping_the_failing_class_is_refused() -> None:
    _, statement = _statement(ROOT / "cases" / "exposed")
    statement = copy.deepcopy(statement)
    statement["predicate"]["classes"] = [
        c for c in statement["predicate"]["classes"] if c["class"] != "ssh-key-file"]
    assert _decision(_judge(CONTAINED, _signed(statement, (HOST, None)))) == (
        "contradicted", "class_missing:ssh-key-file")


def test_lying_about_a_found_credential_is_recomputed_not_copied() -> None:
    _, statement = _statement(ROOT / "cases" / "exposed")
    statement = copy.deepcopy(statement)
    for c in statement["predicate"]["classes"]:
        if c["verdict"] == "reachable":
            c["verdict"] = "not_reachable"
            break
    statement["predicate"]["result"] = "contained"
    verdict, reason = _decision(_judge(CONTAINED, _signed(statement, (HOST, None))))
    assert verdict == "contradicted"
    assert reason.startswith("reachable_reported_clean:")


def test_payload_with_a_repeated_member_is_refused() -> None:
    _, statement = _statement(CONTAINED)
    text = json.dumps(statement, sort_keys=True, separators=(",", ":"))
    text = text.replace('"_type"', '"_type":"x","_type"', 1)
    forged = _signed(statement, (HOST, None), payload=text.encode())
    assert _decision(_judge(CONTAINED, forged)) == ("not_established", "payload_not_json_object")


def test_payload_type_other_than_the_pinned_one_is_not_established() -> None:
    _, statement = _statement(CONTAINED)
    forged = _signed(statement, (HOST, None), kind="application/json")
    assert _decision(_judge(CONTAINED, forged)) == ("not_established", "unsupported_payload_type")


def test_no_signatures_and_too_many_signatures_are_malformed() -> None:
    env, _ = _statement(CONTAINED)
    env["signatures"] = []
    assert _decision(_judge(CONTAINED, json.dumps(env).encode())) == (
        "contradicted", "malformed_envelope")
    env["signatures"] = [{"keyid": "a", "sig": "AAAA"}] * (cr.MAX_SIGNATURES + 1)
    assert _decision(_judge(CONTAINED, json.dumps(env).encode())) == (
        "contradicted", "malformed_envelope")


def test_non_canonical_signature_base64_is_malformed() -> None:
    env, _ = _statement(CONTAINED)
    sig = env["signatures"][0]["sig"]
    assert sig.endswith("==")
    flipped = sig[:-3] + ("B" if sig[-3] != "B" else "C") + "=="
    env["signatures"][0]["sig"] = flipped
    assert _decision(_judge(CONTAINED, json.dumps(env).encode())) == (
        "contradicted", "malformed_envelope")


# The consumer's policy is the only trust root --------------------------------------------------

@pytest.mark.parametrize("edit", [
    lambda a: a.pop("trusted_signers"),
    lambda a: a.__setitem__("trusted_signers", {}),
    lambda a: a.__setitem__("trusted_signers", {"0" * 64: next(iter(a["trusted_signers"].values()))}),
    lambda a: a.__setitem__("max_age_seconds", -1),
    lambda a: a.__setitem__("max_age_seconds", True),
    lambda a: a.__setitem__("judged_at", "2026-11-21T18:05:00+00:00"),
    lambda a: a.__setitem__("challenge", "ABC"),
    lambda a: a.__setitem__("environment", {"name": "e"}),
    lambda a: a.__setitem__("probe_digests", ["x"]),
    lambda a: a.__setitem__("unpinned_extra", 1),
], ids=["no-signers", "empty-signers", "keyid-not-key-hash", "negative-age", "bool-age",
        "offset-time", "short-challenge", "environment-members", "bad-pin", "unknown-member"])
def test_a_defect_in_the_consumers_assessment_raises_case_error(edit: Any) -> None:
    with pytest.raises(CaseError):
        _judge(CONTAINED, edit=edit)


def test_a_policy_without_probe_pins_accepts_any_probe_digest() -> None:
    def no_pins(assessment: dict[str, Any]) -> None:
        assessment.pop("probe_digests")

    assert _decision(_judge(CONTAINED, edit=no_pins)) == ("supported", "contained_verified")


def test_missing_envelope_artifact_is_not_established(tmp_path: Path) -> None:
    case = json.loads((CONTAINED / "case.json").read_bytes())
    assessment = {"claim_type": "credential_reachability/v1", "envelope": "envelope.json",
                  **case["policy"]}
    raw = b"{}"
    verdict = {"schema_version": "probity-case/v1", "case_id": "c", "artifacts": {
        "envelope.json": {"path": "missing.json", "length": len(raw), "sha256": _sha(raw)}}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {"c": assessment}}
    result = adjudicate(verdict, policy, tmp_path)
    assert _decision(result) == ("not_established", "envelope_unavailable")
