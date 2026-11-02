"""Every member of three agent-evidence-vectors corpora gets the verdict its corpus declares.

``tests/data/uncertain-effect``, ``tests/data/restart-records`` and ``tests/data/a2a-jcs-v01`` are
copies of ``corpora/vectors-uncertain-effect``, ``corpora/vectors-restart-records`` and
``corpora/vectors-a2a-jcs-v01`` of probityai/agent-evidence-vectors at commit
317df600f9a1503f32bcc2742b9f111036bdee32 (MANIFEST.json and the member files). Every expectation
below is read from a MANIFEST.json or a vector file; none comes from the verifier. Each member is
judged through the kernel (``probity_verify.adjudicate``) as the Action's reference stage judges it:
an accepted member must be ``supported`` with the corpus's reason, a rejected one ``contradicted``
with the corpus's reason. docs/corpus-routes.md states the mapping.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from probity_verify import adjudicate
from probity_verify.adapters import jcs_canonical, uncertain_effect
from probity_verify.common import CaseError

DATA = Path(__file__).resolve().parent / "data"


def _manifest(name: str) -> dict[str, Any]:
    return json.loads((DATA / name / "MANIFEST.json").read_text(encoding="utf-8"))


def _artifact(root: Path, name: str) -> dict[str, Any]:
    data = (root / name).read_bytes()
    return {"path": name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _judge(case_id: str, root: Path, artifacts: list[str], assessment: dict[str, Any]) -> dict:
    case = {"schema_version": "probity-case/v1", "case_id": case_id,
            "artifacts": {name: _artifact(root, name) for name in artifacts}}
    policy = {"schema_version": "probity-policy/v1", "assessments": {case_id: assessment}}
    return adjudicate(case, policy, root)


def _expected(verdict: str) -> str:
    return "supported" if verdict in ("allow", "accept") else "contradicted"


# vectors-uncertain-effect ---------------------------------------------------------------------

UNCERTAIN = _manifest("uncertain-effect")


def test_uncertain_effect_manifest_is_complete() -> None:
    assert len(UNCERTAIN["vectors"]) == UNCERTAIN["counts"]["allow"] + UNCERTAIN["counts"]["deny"]


@pytest.mark.parametrize("entry", UNCERTAIN["vectors"], ids=lambda e: e["id"])
def test_uncertain_effect_member(entry: dict[str, Any]) -> None:
    root = DATA / "uncertain-effect" / entry["path"]
    result = _judge(entry["id"], root, ["record.json"],
                    {"claim_type": "uncertain_effect/v1", "record": "record.json"})
    expected = entry["expected"]
    assert (result["decision"], result["reason"]) == (
        _expected(expected["decision"]), expected["reason"])


# vectors-restart-records ----------------------------------------------------------------------

RESTART = _manifest("restart-records")


def test_restart_records_manifest_is_complete() -> None:
    assert len(RESTART["vectors"]) == RESTART["counts"]["accept"] + RESTART["counts"]["reject"]


@pytest.mark.parametrize("entry", RESTART["vectors"], ids=lambda e: e["id"])
def test_restart_records_member(entry: dict[str, Any]) -> None:
    root = DATA / "restart-records" / entry["path"]
    files = sorted(entry["files"])
    if entry["shape"] == "record":
        assessment = {"claim_type": "restoration_record/v1", "record": files[0]}
    else:
        assessment = {"claim_type": "restoration_bundle/v1", "records": files}
    result = _judge(entry["id"], root, files, assessment)
    expected = entry["expected"]
    assert (result["decision"], result["reason"]) == (
        _expected(expected["verdict"]), expected["reason"])


# vectors-a2a-jcs-v01 --------------------------------------------------------------------------

JCS = _manifest("a2a-jcs-v01")


class _Token(str):
    """A JSON number exactly as the vector file spells it."""


def input_text(vector: dict[str, Any]) -> str:
    """The vector's input as JSON text, every number token as the file spells it."""
    if "input_raw" in vector:
        return str(vector["input_raw"])
    tokens: list[str] = []
    nonce = os.urandom(8).hex()

    def swap(value: Any) -> Any:
        if isinstance(value, _Token):
            tokens.append(str(value))
            return f"{nonce}-{len(tokens) - 1}"
        if isinstance(value, dict):
            return {key: swap(item) for key, item in value.items()}
        if isinstance(value, list):
            return [swap(item) for item in value]
        return value

    text = json.dumps(swap(vector["input"]), ensure_ascii=True, allow_nan=False)
    for index, token in enumerate(tokens):
        text = text.replace(json.dumps(f"{nonce}-{index}"), token)
    return text


def _jcs(tmp_path: Path, vector: dict[str, Any], target: str) -> dict:
    text = input_text(vector)
    claimed = (bytes.fromhex(vector["expected"]["canonical_utf8_hex"])
               if vector["disposition"] == "MUST-ACCEPT" else text.encode("utf-8"))
    (tmp_path / "input.json").write_bytes(text.encode("utf-8"))
    (tmp_path / "claimed.bin").write_bytes(claimed)
    return _judge(vector["id"], tmp_path, ["input.json", "claimed.bin"],
                  {"claim_type": "jcs_canonical/v1", "target": target,
                   "input": "input.json", "claimed": "claimed.bin"})


def _vector(entry: dict[str, Any]) -> dict[str, Any]:
    body = (DATA / "a2a-jcs-v01" / entry["path"]).read_bytes()
    assert hashlib.sha256(body).hexdigest() == entry["sha256"]
    vector: dict[str, Any] = json.loads(body, parse_int=_Token, parse_float=_Token)
    return vector


def _jcs_expected(vector: dict[str, Any]) -> tuple[str, str]:
    if vector["disposition"] == "MUST-ACCEPT":
        return "supported", "canonical_bytes_match"
    if vector["clause"] == "a2a-spec-8.4.1-rule-3":
        return "contradicted", "canonical_bytes_differ"
    return "contradicted", "no_canonical_form"


def test_a2a_jcs_manifest_is_complete() -> None:
    assert len(JCS["vectors"]) == JCS["counts"]["total"]
    assert JCS["counts"]["accept"] + JCS["counts"]["reject"] == JCS["counts"]["total"]


@pytest.mark.parametrize("entry", JCS["vectors"], ids=lambda e: Path(e["path"]).stem)
def test_a2a_jcs_card_signing_input(tmp_path: Path, entry: dict[str, Any]) -> None:
    vector = _vector(entry)
    result = _jcs(tmp_path, vector, "card-signing-input")
    assert (result["decision"], result["reason"]) == _jcs_expected(vector)


@pytest.mark.parametrize("entry", [e for e in JCS["vectors"] if not e["path"].startswith("a2-")],
                         ids=lambda e: Path(e["path"]).stem)
def test_a2a_jcs_rfc8785(tmp_path: Path, entry: dict[str, Any]) -> None:
    vector = _vector(entry)
    result = _jcs(tmp_path, vector, "rfc8785")
    assert (result["decision"], result["reason"]) == _jcs_expected(vector)


def test_rfc8785_target_count_matches_manifest() -> None:
    owned = [e for e in JCS["vectors"] if not e["path"].startswith("a2-")]
    assert len(owned) == JCS["targets"]["rfc8785"]["vectors"]


# Mutation controls: each rule changes some member's verdict -----------------------------------

@pytest.mark.parametrize("check", uncertain_effect.CHECKS)
def test_every_uncertain_effect_check_is_forced(monkeypatch: pytest.MonkeyPatch, check: str) -> None:
    monkeypatch.setattr(uncertain_effect, "CHECKS",
                        tuple(name for name in uncertain_effect.CHECKS if name != check))
    changed = 0
    for entry in UNCERTAIN["vectors"]:
        root = DATA / "uncertain-effect" / entry["path"]
        result = _judge(entry["id"], root, ["record.json"],
                        {"claim_type": "uncertain_effect/v1", "record": "record.json"})
        changed += result["reason"] != entry["expected"]["reason"]
    assert changed > 0


def _jcs_failures(tmp_path: Path) -> int:
    failures = 0
    for entry in JCS["vectors"]:
        vector = _vector(entry)
        result = _jcs(tmp_path, vector, "card-signing-input")
        failures += (result["decision"], result["reason"]) != _jcs_expected(vector)
    return failures


def test_code_point_key_order_fails_the_corpus(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real = jcs_canonical._value

    def by_code_point(value: Any) -> str:
        if isinstance(value, dict):
            return "{" + ",".join(jcs_canonical._string_form(key) + ":" + by_code_point(value[key])
                                  for key in sorted(value)) + "}"
        if isinstance(value, list):
            return "[" + ",".join(by_code_point(item) for item in value) + "]"
        return real(value)

    monkeypatch.setattr(jcs_canonical, "_value", by_code_point)
    assert _jcs_failures(tmp_path) > 0


def test_python_number_spelling_fails_the_corpus(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(jcs_canonical, "_number", repr)
    assert _jcs_failures(tmp_path) > 0


def test_keeping_signatures_fails_the_corpus(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real = jcs_canonical.canonical
    monkeypatch.setattr(jcs_canonical, "canonical", lambda _target, text: real("rfc8785", text))
    assert _jcs_failures(tmp_path) > 0


# Controls: the routes refuse what is not a verdict ---------------------------------------------

def test_missing_record_is_not_established(tmp_path: Path) -> None:
    case = {"schema_version": "probity-case/v1", "case_id": "c",
            "artifacts": {"record.json": {"path": "record.json", "length": 2,
                                          "sha256": hashlib.sha256(b"{}").hexdigest()}}}
    policy = {"schema_version": "probity-policy/v1",
              "assessments": {"c": {"claim_type": "uncertain_effect/v1", "record": "record.json"}}}
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["reason"]) == ("not_established", "record_unavailable")


def test_record_that_is_not_an_object_is_a_case_error(tmp_path: Path) -> None:
    (tmp_path / "record.json").write_bytes(b"[]")
    with pytest.raises(CaseError):
        _judge("c", tmp_path, ["record.json"],
               {"claim_type": "uncertain_effect/v1", "record": "record.json"})


def test_unknown_jcs_target_is_a_case_error(tmp_path: Path) -> None:
    (tmp_path / "input.json").write_bytes(b"{}")
    (tmp_path / "claimed.bin").write_bytes(b"{}")
    with pytest.raises(CaseError):
        _judge("c", tmp_path, ["input.json", "claimed.bin"],
               {"claim_type": "jcs_canonical/v1", "target": "json", "input": "input.json",
                "claimed": "claimed.bin"})


def test_bundle_with_two_decisions_is_a_case_error(tmp_path: Path) -> None:
    source = DATA / "restart-records"
    entry = next(e for e in RESTART["vectors"] if e["id"] == "bundle-consistent")
    r3 = (source / entry["path"] / "r3.json").read_bytes()
    (tmp_path / "a.json").write_bytes(r3)
    (tmp_path / "b.json").write_bytes(r3.replace(b"\n", b"\n "))
    with pytest.raises(CaseError):
        _judge("c", tmp_path, ["a.json", "b.json"],
               {"claim_type": "restoration_bundle/v1", "records": ["a.json", "b.json"]})
