"""Every member of three agent-evidence-vectors corpora gets the verdict its corpus declares.

``tests/data/uncertain-effect``, ``tests/data/restart-records`` and ``tests/data/a2a-jcs-v01`` are
copies of ``corpora/vectors-uncertain-effect``, ``corpora/vectors-restart-records`` and
``corpora/vectors-a2a-jcs-v01`` of probityai/agent-evidence-vectors at commit
317df600f9a1503f32bcc2742b9f111036bdee32 (MANIFEST.json and the member files). Every expectation
below is read from a MANIFEST.json or a vector file; none comes from the verifier. Each member is
judged through the kernel (``agent_evidence_verify.adjudicate``) as the Action's reference stage judges it:
an accepted member must be ``supported`` with the corpus's reason, a rejected one ``contradicted``
with the corpus's reason. docs/corpus-routes.md states the mapping.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import (
    jcs_canonical,
    observed_effect,
    uncertain_effect,
)
from agent_evidence_verify.common import CaseError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DATA = Path(__file__).resolve().parent / "data"
# No member of the corpus carries codeDigest or invocationBinding, and none pins either on the
# consumer side, so the corpus cannot force these four. The join-key tests below force them with a
# member re-signed under a test key.
UNFORCED_OBSERVED_RULES = frozenset({"code-digest-shape", "code-digest-policy",
                                     "invocation-binding-shape", "invocation-binding-policy"})


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


def _uncertain_record(reason: str) -> dict[str, Any]:
    """A member's record, parsed; the reason names the member."""
    entry = next(e for e in UNCERTAIN["vectors"] if e["expected"]["reason"] == reason)
    return json.loads((DATA / "uncertain-effect" / entry["path"] / "record.json").read_bytes())


def _judge_uncertain(tmp_path: Path, text: str) -> dict:
    (tmp_path / "record.json").write_text(text, encoding="utf-8")
    return _judge("c", tmp_path, ["record.json"],
                  {"claim_type": "uncertain_effect/v1", "record": "record.json"})


@pytest.mark.parametrize("spelling", ['NaN', 'true', '-1', '1.5', '"2"', '[2]'])
def test_uncertain_effect_owner_count_must_be_a_count(tmp_path: Path, spelling: str) -> None:
    """Each spelling of a two-effect ledger once read as at most one effect, or crashed a check."""
    text = json.dumps(_uncertain_record("duplicate_effect"))
    assert '"ownerEffects": 2' in text
    with pytest.raises(CaseError):
        _judge_uncertain(tmp_path, text.replace('"ownerEffects": 2', '"ownerEffects": ' + spelling))


def test_uncertain_effect_refuses_a_repeated_member(tmp_path: Path) -> None:
    """A parser that keeps the last member reads this record as one effect; others read two."""
    text = json.dumps(_uncertain_record("duplicate_effect"))
    with pytest.raises(CaseError, match="duplicate"):
        _judge_uncertain(tmp_path, text.replace('"ownerEffects": 2',
                                                '"ownerEffects": 2, "ownerEffects": 1'))


def _set(record: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    for step in path[:-1]:
        record = record[step]
    record[path[-1]] = value


@pytest.mark.parametrize(("reason", "path", "value"), [
    ("retry_after_unknown", ("attempts", 0, "reply"), "timed_out"),
    ("retry_after_unknown", ("effectOwner", "deduplicatesByKey"), "false"),
    ("retry_after_unknown", ("effectOwner", "keyRetentionSeconds"), True),
    ("unknown_released", ("reservation", "charged"), "false"),
    ("outcome_disagrees_with_authority", ("reported", "outcome"), "done"),
    ("outcome_settled_without_authority", ("reported", "outcome"), "done"),
    ("effect_after_stop_reported_quiescent", ("stop", "reported"), "idle"),
    ("authority_used_after_revocation", ("stop", "authorityChecks", 0, "result"), "ACCEPTED"),
    ("dispatch_beyond_lease", ("leases",), False),
    ("effect_after_stop_reported_quiescent", ("stop",), "stopped"),
], ids=lambda part: "-".join(map(str, part)) if isinstance(part, tuple) else str(part))
def test_uncertain_effect_refuses_a_value_outside_the_contract(
        tmp_path: Path, reason: str, path: tuple[Any, ...], value: Any) -> None:
    record = _uncertain_record(reason)
    _set(record, path, value)
    with pytest.raises(CaseError):
        _judge_uncertain(tmp_path, json.dumps(record))


def test_uncertain_effect_refuses_a_final_flag_that_is_not_a_flag(tmp_path: Path) -> None:
    """A truthy word must not read as the final answer that protects a resend."""
    record = _uncertain_record("retry_after_unknown")
    record["reconciliations"].append({"at": record["attempts"][-1]["dispatchedAt"],
                                      "idempotencyKey": "k", "result": "absent", "final": "no"})
    with pytest.raises(CaseError):
        _judge_uncertain(tmp_path, json.dumps(record))


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


# vectors-observed-effect ----------------------------------------------------------------------

OBSERVED = _manifest("observed-effect")
OBSERVER_KEY = OBSERVED["keys"]["observer"]["publicKey"]


def _observed(tmp_path: Path, entry: dict[str, Any]) -> dict:
    """Judge one member under the consumer inputs the corpus publishes: the key and the blob."""
    source = DATA / "observed-effect" / entry["file"]
    (tmp_path / "envelope.json").write_bytes(source.read_bytes())
    blob = next(iter(OBSERVED["blobs"].values()))
    (tmp_path / "blob.bin").write_bytes(blob.encode("utf-8"))
    return _judge(entry["id"], tmp_path, ["envelope.json", "blob.bin"],
                  {"claim_type": "observed_effect/v1", "envelope": "envelope.json",
                   "observer_public_key": OBSERVER_KEY, "blobs": ["blob.bin"]})


def test_observed_effect_manifest_is_complete() -> None:
    assert len(OBSERVED["vectors"]) == 80
    assert {entry["kind"] for entry in OBSERVED["vectors"]} == {"accept", "reject", "indeterminate"}


@pytest.mark.parametrize("entry", OBSERVED["vectors"], ids=lambda e: e["slug"])
def test_observed_effect_member(tmp_path: Path, entry: dict[str, Any]) -> None:
    result = _observed(tmp_path, entry)
    check = result["checks"][0]
    if entry["kind"] == "indeterminate":
        assert check["verdict"] in {reading["verdict"] for reading in entry["readings"]}
        return
    expected = entry["expected"]
    assert check["verdict"] == expected["verdict"]
    if expected["verdict"] == "valid":
        assert (result["decision"], result["reason"]) == ("supported", "record_conforms")
        assert check["derived_tier"] == expected["derivedTier"]
        assert check["effects_independently_observed"] == expected["effectsIndependentlyObserved"]
        assert check["absence_established"] == expected["absenceEstablished"]
    else:
        assert result["decision"] == "contradicted"
        assert check["codes"] == expected["codes"]
        assert result["reason"] == expected["codes"][0]


def test_observed_effect_refuses_under_another_observer_key(tmp_path: Path) -> None:
    entry = next(e for e in OBSERVED["vectors"] if e["kind"] == "accept")
    source = DATA / "observed-effect" / entry["file"]
    (tmp_path / "envelope.json").write_bytes(source.read_bytes())
    result = _judge(entry["id"], tmp_path, ["envelope.json"],
                    {"claim_type": "observed_effect/v1", "envelope": "envelope.json",
                     "observer_public_key": OBSERVED["keys"]["observedParty"]["publicKey"]})
    assert result["decision"] == "contradicted"
    assert result["checks"][0]["verdict"] == "invalid"


def test_observed_effect_huge_exponent_is_not_parseable_not_a_crash() -> None:
    payload = base64.b64encode(b'{"n": 1e99999999999999999999}').decode()
    report = observed_effect.verify(json.dumps({"payload": payload}).encode(),
                                    observed_effect.Policy(observed_effect.PREDICATE_TYPE, "00"))
    assert report.verdict == "malformed"


@pytest.mark.parametrize(("rule", "member"), [
    (observed_effect._rule_code_digest_shape, "codeDigest"),
    (observed_effect._rule_invocation_binding_shape, "invocationBinding"),
])
def test_observed_effect_join_keys_refuse_a_wrong_shape(rule: Any, member: str) -> None:
    policy = observed_effect.Policy(observed_effect.PREDICATE_TYPE, "00")
    rule(observed_effect._State({}, {}, policy))  # the member is optional
    with pytest.raises(observed_effect.Malformed):
        rule(observed_effect._State({}, {member: "not-an-object"}, policy))


def _joined(tmp_path: Path, join_keys: dict[str, Any], **pins: str) -> dict:
    """Judge an accepted member re-signed with these join keys, under the consumer's pins."""
    # A self-vantage member carries no prior commitment, so the test key signs the whole record.
    entry = next(e for e in OBSERVED["vectors"] if e["slug"] == "voluntary-self-vantage")
    envelope = json.loads((DATA / "observed-effect" / entry["file"]).read_bytes())
    statement = json.loads(base64.b64decode(envelope["payload"]))
    statement["predicate"].update(join_keys)
    payload = json.dumps(statement).encode()
    key = Ed25519PrivateKey.generate()
    signature = key.sign(observed_effect._pae(envelope["payloadType"], payload))
    envelope["payload"] = base64.b64encode(payload).decode()
    envelope["signatures"] = [{"keyid": envelope["signatures"][0]["keyid"],
                               "sig": base64.b64encode(signature).decode()}]
    (tmp_path / "envelope.json").write_text(json.dumps(envelope), encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(next(iter(OBSERVED["blobs"].values())).encode("utf-8"))
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return _judge(entry["id"], tmp_path, ["envelope.json", "blob.bin"],
                  {"claim_type": "observed_effect/v1", "envelope": "envelope.json",
                   "observer_public_key": public, "blobs": ["blob.bin"], **pins})


JOIN_KEYS = [("codeDigest", "expected_code_digest", "code-digest"),
             ("invocationBinding", "expected_invocation_binding", "invocation-binding")]


@pytest.mark.parametrize(("member", "pin", "_code"), JOIN_KEYS)
def test_observed_effect_join_key_equal_to_the_pin_conforms(
        tmp_path: Path, member: str, pin: str, _code: str) -> None:
    result = _joined(tmp_path, {member: {"sha256": "a" * 64}}, **{pin: "a" * 64})
    assert (result["decision"], result["reason"]) == ("supported", "record_conforms")


@pytest.mark.parametrize(("member", "pin", "code"), JOIN_KEYS)
def test_observed_effect_refuses_another_join_key_than_the_pin(
        tmp_path: Path, member: str, pin: str, code: str) -> None:
    result = _joined(tmp_path, {member: {"sha256": "b" * 64}}, **{pin: "a" * 64})
    assert (result["decision"], result["reason"]) == ("contradicted", code + "-mismatch")
    assert result["checks"][0]["verdict"] == "invalid"


@pytest.mark.parametrize(("_member", "pin", "code"), JOIN_KEYS)
def test_observed_effect_refuses_a_record_without_the_pinned_join_key(
        tmp_path: Path, _member: str, pin: str, code: str) -> None:
    result = _joined(tmp_path, {}, **{pin: "a" * 64})
    assert (result["decision"], result["reason"]) == ("contradicted", code + "-required")


@pytest.mark.parametrize(("_member", "pin", "_code"), JOIN_KEYS)
@pytest.mark.parametrize("value", ["", "A" * 64, "a" * 63])
def test_observed_effect_a_malformed_pin_blames_the_policy_not_the_record(
        tmp_path: Path, _member: str, pin: str, _code: str, value: str) -> None:
    """The consumer's pin is the policy's defect: no verdict, never a refusal of a good record."""
    with pytest.raises(CaseError, match=pin):
        _joined(tmp_path, {}, **{pin: value})


@pytest.mark.parametrize("name", [name for name, _ in observed_effect.RULES])
def test_observed_effect_rule_mutations(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str) -> None:
    """Every rule changes some member's verdict or code, except the two no member can reach."""
    monkeypatch.setattr(observed_effect, "RULES",
                        tuple(rule for rule in observed_effect.RULES if rule[0] != name))
    changed = 0
    for entry in OBSERVED["vectors"]:
        if entry["kind"] == "indeterminate":
            continue
        check = _observed(tmp_path, entry)["checks"][0]
        expected = entry["expected"]
        changed += (check["verdict"], check["codes"]) != (expected["verdict"],
                                                          expected.get("codes", []))
    assert (changed > 0) == (name not in UNFORCED_OBSERVED_RULES)


# Input too deep to walk: no verdict on any claim type ------------------------------------------

@pytest.mark.parametrize("depth", [2000, 50_000])
@pytest.mark.parametrize("claim", ["uncertain", "restoration", "observed", "jcs"])
def test_input_nested_past_the_walkers_gets_no_verdict(
        tmp_path: Path, claim: str, depth: int) -> None:
    nested = "[" * depth + "]" * depth
    assessment: dict[str, Any] = {"claim_type": "jcs_canonical/v1", "target": "rfc8785",
                                  "input": "input.json", "claimed": "claimed.bin"}
    names = ["input.json", "claimed.bin"]
    (tmp_path / "claimed.bin").write_bytes(b"[]")
    if claim == "uncertain":
        text = '{"contractId":' + nested + "}"
        assessment = {"claim_type": "uncertain_effect/v1", "record": "input.json"}
        names = ["input.json"]
    elif claim == "restoration":
        text = '{"_type":"x","predicateType":"y","predicate":' + nested + "}"
        assessment = {"claim_type": "restoration_record/v1", "record": "input.json"}
        names = ["input.json"]
    elif claim == "observed":
        statement = ('{"_type":"https://in-toto.io/Statement/v1","predicate":{"n":' + nested
                     + "}}")
        text = json.dumps({"payload": base64.b64encode(statement.encode()).decode()})
        assessment = {"claim_type": "observed_effect/v1", "envelope": "input.json",
                      "observer_public_key": "00" * 32}
        names = ["input.json"]
    else:
        text = nested
    (tmp_path / "input.json").write_text(text, encoding="utf-8")
    with pytest.raises(CaseError):
        _judge("c", tmp_path, names, assessment)


def test_a_canonicalizer_out_of_stack_never_says_no_canonical_form(tmp_path: Path) -> None:
    """Depth 500 has a canonical form, and the canonicalizer's frames run out first."""
    (tmp_path / "input.json").write_text("[" * 500 + "]" * 500, encoding="utf-8")
    (tmp_path / "claimed.bin").write_bytes(b"[]")
    with pytest.raises(CaseError, match="too deeply"):
        _judge("c", tmp_path, ["input.json", "claimed.bin"],
               {"claim_type": "jcs_canonical/v1", "target": "rfc8785", "input": "input.json",
                "claimed": "claimed.bin"})


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
