"""The agent-identity-statement suite: corpus mode and the ``agent_identity_statement/v1`` claim type.

``tests/data/agent-identity-statement`` is a copy of ``corpora/vectors-agent-identity-statement`` of
probityai/agent-evidence-vectors (MANIFEST.json and the member files) at commit 14494ee8b. Every expectation
below is read from that MANIFEST.json; none comes from the verifier. Corpus mode must answer all 46 members as
the corpus declares, and the claim type must reach the same decision and reason for every member it can express
as a consumer case (the instant and key read from the member's decision record).
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import agent_identity_statement as ais
from agent_evidence_verify.adapters import web_bot_auth
from agent_evidence_verify.cli import main
from agent_evidence_verify.common import CaseError

ROOT = Path(__file__).resolve().parent / "data" / "agent-identity-statement"
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
MEMBERS = {entry["id"]: entry for entry in MANIFEST["vectors"]}
ACCEPT_ONE = "accept-single-version"


def _expected(member: str) -> tuple[str, str]:
    expected = MEMBERS[member]["expected"]
    return expected["decision"], expected["reason"]


def test_corpus_mode_answers_every_member_as_declared(capsys: pytest.CaptureFixture[str]) -> None:
    assert MANIFEST["suite"] == ais.SUITE and len(MEMBERS) == 46
    assert main(["corpus", str(ROOT)]) == 0
    printed = [json.loads(text) for text in capsys.readouterr().out.splitlines()]
    assert [line["vector"] for line in printed] == list(MEMBERS)
    wrong = [(line["vector"], line["verdict"], line["reason"]) for line in printed
             if (line["verdict"], line["reason"]) != _expected(line["vector"])]
    assert wrong == []
    assert all(line["corpusDigest"] == MANIFEST["corpusDigest"] for line in printed)


def test_every_check_is_named_by_a_rejected_member() -> None:
    named = {entry["expected"]["reason"] for entry in MANIFEST["vectors"]
             if entry["expected"]["decision"] == "reject"}
    assert set(ais.CHECKS) == named
    assert ais.CHECKS == tuple(dict.fromkeys(ais.CHECKS))


# -- the claim type over the corpus ----------------------------------------------------------------------------


def _bind(root: Path, name: str) -> dict[str, Any]:
    data = (root / name).read_bytes()
    return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _case(root: Path, assessment: dict[str, Any], names: list[str]) -> dict[str, Any]:
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {name: _bind(root, name) for name in names}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {"c": {"claim_type": ais.CLAIM_TYPE, **assessment}}}
    return adjudicate(case, policy, root)


def _member_assessment(member: str, tmp: Path, *, with_decision: bool = True) -> tuple[dict, list[str]]:
    """The consumer case for a member: the context's pins, and the instant and key its decision record names.
    Raises ValueError when the member's decision record carries no instant and key to name."""
    source = ROOT / MEMBERS[member]["path"]
    context = json.loads((source / "context.json").read_text(encoding="utf-8"))
    record = json.loads((source / "decision.json").read_text(encoding="utf-8"))
    if not isinstance(record, dict) or "at" not in record:
        raise ValueError("no decision record")
    assessment = {"history": "history", "issuer_keys": context["issuerKeys"], "agent": context["agent"],
                  "head_sha256": context["head"]["sha256"], "at": record["at"],
                  "key_sha256": record["envelope"]["signatures"][0]["keyid"]}
    names = ["history"]
    (tmp / "history").write_bytes((source / "history.json").read_bytes())
    if with_decision:
        (tmp / "decision").write_text(json.dumps(record["envelope"]), encoding="utf-8")
        assessment["decision"] = "decision"
        names.append("decision")
    return assessment, names


def _verdict(result: dict[str, Any]) -> tuple[str, str]:
    mapped = {"supported": "accept", "contradicted": "reject"}
    return mapped.get(result["decision"], result["decision"]), result["reason"]


#: Members whose decision record holds no instant and key a consumer could name; corpus mode judges them.
NOT_EXPRESSIBLE = {"decision-not-json"}


@pytest.mark.parametrize("member", sorted(set(MEMBERS) - NOT_EXPRESSIBLE))
def test_claim_type_agrees_with_the_corpus(member: str, tmp_path: Path) -> None:
    assessment, names = _member_assessment(member, tmp_path)
    assert _verdict(_case(tmp_path, assessment, names)) == _expected(member)


def test_only_the_unparseable_decision_record_is_left_to_corpus_mode(tmp_path: Path) -> None:
    left = set()
    for member in MEMBERS:
        try:
            _member_assessment(member, tmp_path)
        except (ValueError, KeyError, TypeError, IndexError):
            left.add(member)
    assert left == NOT_EXPRESSIBLE
    assert _expected("decision-not-json") == ("reject", "decision_malformed")


# -- naming the key --------------------------------------------------------------------------------------------


def _accept_key(tmp_path: Path) -> tuple[dict, list[str], bytes]:
    assessment, names = _member_assessment(ACCEPT_ONE, tmp_path)
    history = json.loads((tmp_path / "history").read_text(encoding="utf-8"))
    statement = json.loads(base64.b64decode(history[0]["payload"]))
    raw = bytes.fromhex(statement["predicate"]["keys"][0]["publicKey"])
    assert hashlib.sha256(raw).hexdigest() == assessment["key_sha256"]
    return assessment, names, raw


def test_a_key_named_by_its_jwk_thumbprint_is_the_web_bot_auth_keyid(tmp_path: Path) -> None:
    assessment, names, raw = _accept_key(tmp_path)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": base64.urlsafe_b64encode(raw).decode().rstrip("=")}
    thumbprint = web_bot_auth.jwk_thumbprint(jwk)
    assert ais.jwk_thumbprint(raw) == thumbprint
    del assessment["key_sha256"]
    result = _case(tmp_path, {**assessment, "jwk_thumbprint": thumbprint}, names)
    assert (result["decision"], result["reason"]) == ("supported", "key_in_force")
    assert result["scope"]["key_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["scope"]["version_in_force"]["version"] == 1


def test_an_unlisted_thumbprint_is_key_unknown(tmp_path: Path) -> None:
    assessment, names, _ = _accept_key(tmp_path)
    del assessment["key_sha256"]
    other = ais.jwk_thumbprint(bytes(32))
    result = _case(tmp_path, {**assessment, "jwk_thumbprint": other}, names)
    assert (result["decision"], result["reason"]) == ("contradicted", "key_unknown")


def test_without_a_decision_envelope_the_key_and_instant_are_judged_alone(tmp_path: Path) -> None:
    assessment, names = _member_assessment(ACCEPT_ONE, tmp_path, with_decision=False)
    result = _case(tmp_path, assessment, names)
    assert (result["decision"], result["reason"]) == ("supported", "key_in_force")
    status = {check["id"]: check["status"] for check in result["checks"]}
    assert status["decision_malformed"] == status["decision_signature"] == "not_applicable"
    assert [check["id"] for check in result["checks"]] == list(ais.CHECKS)


def test_a_revoked_agent_is_contradicted_without_a_decision_envelope(tmp_path: Path) -> None:
    assessment, names = _member_assessment("agent-revoked", tmp_path, with_decision=False)
    assert _verdict(_case(tmp_path, assessment, names)) == ("reject", "agent_revoked")


def test_an_absent_history_or_decision_is_not_established(tmp_path: Path) -> None:
    assessment, names = _member_assessment(ACCEPT_ONE, tmp_path)
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {name: _bind(tmp_path, name) for name in names}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {"c": {"claim_type": ais.CLAIM_TYPE, **assessment}}}
    (tmp_path / "decision").unlink()
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["reason"]) == ("not_established", "decision_unavailable")
    (tmp_path / "history").unlink()
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["reason"]) == ("not_established", "history_unavailable")


@pytest.mark.parametrize("edit", [
    lambda a: a.update(jwk_thumbprint=ais.jwk_thumbprint(bytes(32))),
    lambda a: a.pop("key_sha256"),
    lambda a: a.update(issuer_keys=[]),
    lambda a: a.update(issuer_keys=["AB" * 32]),
    lambda a: a.update(head_sha256="00"),
    lambda a: a.update(at="2026-11-05 12:00:00Z"),
    lambda a: a.update(agent={"issuer": "http://idp.example.com", "subject": "travel-agent"}),
    lambda a: a.update(key_sha256="g" * 64),
])
def test_a_malformed_policy_raises(edit: Any, tmp_path: Path) -> None:
    assessment, names = _member_assessment(ACCEPT_ONE, tmp_path)
    edit(assessment)
    with pytest.raises(CaseError):
        _case(tmp_path, assessment, names)


def test_a_time_spelled_with_another_scripts_digits_is_refused(tmp_path: Path) -> None:
    """``\\d`` and ``strptime`` read fullwidth digits; the time rule admits ASCII digits only."""
    member = tmp_path / "m"
    shutil.copytree(ROOT / MEMBERS[ACCEPT_ONE]["path"], member)
    record = json.loads((member / "decision.json").read_text(encoding="utf-8"))
    record["at"] = "２０２６" + record["at"][4:]
    (member / "decision.json").write_text(json.dumps(record), encoding="utf-8")
    assert ais.judge(member) == ("reject", "decision_malformed")


def test_unreadable_pins_refuse_the_member_with_the_first_check(tmp_path: Path) -> None:
    member = tmp_path / "m"
    shutil.copytree(ROOT / MEMBERS[ACCEPT_ONE]["path"], member)
    (member / "context.json").write_text("{}", encoding="utf-8")
    assert ais.judge(member) == ("reject", "history_malformed")
