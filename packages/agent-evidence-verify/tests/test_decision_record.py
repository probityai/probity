"""The decision-record reader against the format's published cases, and the strict profile's refusals."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest
from agent_evidence_verify import decision_record as dr

DATA = Path(__file__).parent / "data" / "decision-record"
SOURCE = json.loads((DATA / "SOURCE.json").read_text(encoding="utf-8"))


def _published(name: str) -> dict:
    raw = (DATA / name).read_bytes()
    pin = SOURCE["files"][name]
    assert (hashlib.sha256(raw).hexdigest(), len(raw)) == (pin["sha256"], pin["length"])
    return json.loads(raw)


CASES = _published("cases.json")
VECTORS = _published("vectors.json")
POLICY = VECTORS["trust_policy"]


def _attachment(name: str, patch: list | None = None) -> dict:
    return dr.apply_patch(copy.deepcopy(VECTORS["attachments"][name]), patch or [])


def _record(name: str | None) -> bytes | None:
    return CASES["records"][name].encode("utf-8") if name else None


def _unsigned(name: str, patch: list | None = None) -> bytes:
    doc = _attachment(name, patch)
    doc.pop("issuer_signature", None)
    return dr.compact(doc)


@pytest.mark.parametrize("case", CASES["binding_cases"], ids=[c["id"] for c in CASES["binding_cases"]])
def test_every_published_binding_case_reads_as_expected(case):
    report = dr.read(dr.compact(_attachment(case["attachment"], case["patch"])), record=_record(case["record"]))
    assert report["structural_validity"]["status"] == dr.VERIFIED
    assert dr.expected_differences(case, report) == []


def test_the_published_base_report_dimensions_agree():
    base = {r["decision_id"]: r for r in VECTORS["base_report"]["results"]}
    for name, record in (("A0", "R0"), ("A1", "R1")):
        data = dr.compact(VECTORS["attachments"][name])
        report = dr.read(data, record=_record(record), trust_policy=POLICY)
        want = base[report["decision_id"]]
        assert report["attachment_digest"] == want["attachment_digest"]
        for dim in ("record_statements", "action_binding", "stage_order", "authorisation_recheck",
                    "observed_results", "rationale_provenance", "identity_assurance", "authority_assurance"):
            assert report[dim]["status"] == want[dim]["status"], dim


def test_a_signed_attachment_verifies_on_its_stated_time_and_a_changed_byte_fails():
    data = dr.compact(VECTORS["attachments"]["A0"])
    signature = dr.read(data, trust_policy=POLICY)["issuer_signature"]
    assert signature["status"] == dr.VERIFIED
    assert signature["holder"] == "Example issuer (test only)"
    assert signature["key_state"]["time_basis"] == "stated_time"
    assert signature["attests"] == "issuer_recorded_claims_only"
    changed = data.replace(b'"observed":"succeeded"', b'"observed":"indeterminate"')
    assert changed != data
    report = dr.read(changed, trust_policy=POLICY)
    assert report["issuer_signature"]["status"] == dr.FAILED
    assert dr.verdict(report, "baseline") == ("reject", "issuer_signature:failed")


def test_a_signature_needs_a_policy_and_never_reads_a_key_from_the_attachment():
    data = dr.compact(VECTORS["attachments"]["A0"])
    assert dr.read(data)["issuer_signature"]["status"] == dr.NOT_CHECKED
    other = copy.deepcopy(POLICY)
    other["keys"] = [k for k in other["keys"] if k["key_ref"] != "org-seal-1"]
    assert dr.read(data, trust_policy=other)["issuer_signature"]["status"] == dr.FAILED


def test_a_policy_listing_one_key_twice_is_refused_and_nothing_rests_on_it():
    data = dr.compact(VECTORS["attachments"]["A0"])
    twice = copy.deepcopy(POLICY)
    seal = next(k for k in twice["keys"] if k["key_ref"] == "org-seal-1")
    twice["keys"].append({**seal, "key_ref": "org-seal-1-again"})
    report = dr.read(data, trust_policy=twice)
    assert report["trust_policy"]["status"] == dr.FAILED
    assert report["issuer_signature"]["status"] == dr.FAILED


def test_a_member_named_twice_is_not_read():
    text = VECTORS["texts"]["dup_decision_id"]["attachment_text"].encode("utf-8")
    report = dr.read(text, trust_policy=POLICY)
    assert report["structural_validity"]["status"] == dr.FAILED
    assert all(report[name]["status"] == dr.NOT_CHECKED for name in dr.BINDING_DIMENSIONS)
    assert dr.verdict(report) == ("reject", "structural_validity:failed")


def test_timestamps_beside_are_not_supported_rather_than_verified():
    report = dr.read(dr.compact(VECTORS["attachments"]["A0"]), trust_policy=POLICY, timestamps_beside=True)
    assert report["time_assurance"]["status"] == dr.NOT_SUPPORTED


# --- the strict profile --------------------------------------------------------------------------

SELF_APPROVAL = [{"set": "/stages/1/reviewer_ref", "value": "urn:example:role:payables-drafting"},
                 {"set": "/stages/2/actor_ref", "value": "urn:example:role:payables-drafting"}]
SECOND_SUCCESS = [
    {"insert": "/stages/7", "value": {"stage_id": "c2", "kind": "recheck", "at": "2026-10-01T09:20:00Z",
                                      "request_ref": "q1", "result": "authorised",
                                      "authority_source_ref": "urn:example:permission-service:2"}},
    {"insert": "/stages/8", "value": {"stage_id": "x2", "kind": "attempt", "at": "2026-10-01T09:20:05Z",
                                      "request_ref": "q1", "recheck_ref": "c2",
                                      "spec_digest": VECTORS["attachments"]["A0"]["stages"][0]["spec_digest"],
                                      "executor_ref": "urn:example:service:payment-executor"}},
    {"insert": "/stages/9", "value": {"stage_id": "r2", "kind": "result", "at": "2026-10-01T09:20:09Z",
                                      "attempt_ref": "x2", "observed": "succeeded",
                                      "basis": "target_response"}}]


def test_an_approval_by_the_drafting_role_passes_the_baseline_and_fails_the_strict_profile():
    report = dr.read(_unsigned("A0", SELF_APPROVAL))
    assert dr.verdict(report, "baseline") == ("accept", None)
    assert report["strict"]["approver_independence"]["status"] == dr.FAILED
    assert dr.verdict(report, "strict")[0] == "reject"


def test_one_request_observed_to_succeed_twice_fails_the_strict_profile():
    report = dr.read(_unsigned("A0", SECOND_SUCCESS))
    assert dr.verdict(report, "baseline") == ("accept", None)
    assert report["strict"]["single_effect_per_request"]["status"] == dr.FAILED


def test_a_retry_after_an_indeterminate_attempt_needs_the_target_to_say():
    patch = [{"set": "/stages/6/observed", "value": "indeterminate"}] + SECOND_SUCCESS
    data = _unsigned("A0", patch)
    assert dr.read(data)["strict"]["single_effect_per_request"]["status"] == dr.NOT_CHECKED
    rid = VECTORS["attachments"]["A0"]["stages"][3]["request_id"]
    once = dr.read(data, relying_party={"target_effects": {rid: 1}})
    assert once["strict"]["single_effect_per_request"]["status"] == dr.VERIFIED
    twice = dr.read(data, relying_party={"target_effects": {rid: 2}})
    assert twice["strict"]["single_effect_per_request"]["status"] == dr.FAILED


def _relying_party(doc: dict, digest: str, **changes) -> dict:
    stages = doc["stages"]
    actors = {s.get(k) for s in stages for k in ("reviewer_ref", "actor_ref")
              if s.get(k) and s.get("kind") != "proposal"}
    grants = [{"actor_ref": s["actor_ref"], "authority_ref": s["authority"]["authority_ref"]}
              for s in stages if s.get("kind") in ("outcome", "standing_approval", "change_authorisation")
              and "authority" in s]
    observed = {s["stage_id"]: s["at"] for s in stages
                if s.get("kind") in ("outcome", "standing_approval", "change_authorisation", "attempt")}
    party = {"identities": {a: {"status": "verified", "source": "urn:example:directory"} for a in actors},
             "authority_grants": grants,
             "independent_times": {"tolerance_seconds": 60, "observed": observed},
             "latest": {doc["decision_id"]: digest}}
    party.update(changes)
    return party


def test_the_strict_profile_accepts_a_signed_attachment_every_independent_source_confirms():
    doc = VECTORS["attachments"]["A0"]
    data = dr.compact(doc)
    report = dr.read(data, record=_record("R0"), trust_policy=POLICY,
                     relying_party=_relying_party(doc, dr.sha256_hex(data)))
    assert {k: v["status"] for k, v in report["strict"].items()} == dict.fromkeys(dr.STRICT_DIMENSIONS,
                                                                                    dr.VERIFIED)
    assert dr.verdict(report, "strict") == ("accept", None)


@pytest.mark.parametrize("limit,dimension", [
    ("unverified person", "identity_independent"),
    ("change by an unnamed service", "authority_independent"),
    ("every stage backdated", "time_independent"),
    ("an older attachment", "latest_attachment"),
    ("signature removed", "signature_required"),
])
def test_each_declared_limit_is_a_strict_refusal(limit, dimension):
    doc = copy.deepcopy(VECTORS["attachments"]["A0"])
    data = dr.compact(doc)
    party = _relying_party(doc, dr.sha256_hex(data))
    if limit == "unverified person":
        party["identities"]["owner-example-1"] = {"status": "not_verified"}
    elif limit == "change by an unnamed service":
        party["authority_grants"] = []
    elif limit == "every stage backdated":
        party["independent_times"]["observed"]["x1"] = "2026-10-01T11:00:00Z"
    elif limit == "an older attachment":
        party["latest"] = {doc["decision_id"]: "0" * 64}
    else:
        doc.pop("issuer_signature")
        data = dr.compact(doc)
        party["latest"] = {doc["decision_id"]: dr.sha256_hex(data)}
    report = dr.read(data, record=_record("R0"), trust_policy=POLICY, relying_party=party)
    assert dr.verdict(report, "baseline") == ("accept", None)
    assert report["strict"][dimension]["status"] == dr.FAILED
    assert dr.verdict(report, "strict") == ("reject", f"{dimension}:failed")


def test_an_unknown_profile_is_an_error():
    with pytest.raises(ValueError):
        dr.verdict(dr.read(_unsigned("A0")), "lenient")


@pytest.mark.parametrize("text,ok,why", [
    ("2026-10-01T09:12:00Z", True, ""),
    ("2026-10-01T11:12:00+02:00", True, ""),
    ("2026-10-01T23:59:60Z", False, "no such time"),
    ("2026-02-30T09:00:00Z", False, "no such date"),
    ("2026-10-01T09:12:00", False, "no offset"),
    ("9999-12-31T23:00:00-05:00", True, ""),
])
def test_times_are_read_as_instants_or_named_as_none(text, ok, why):
    read = dr.instant(text)
    assert read.ok is ok and read.why == why


def test_offsets_name_one_instant():
    assert dr.instant("2026-10-01T09:12:00Z").seconds == dr.instant("2026-10-01T11:12:00+02:00").seconds


def test_the_command_line_prints_the_report_and_the_profile_verdict(tmp_path, capsys):
    attachment = tmp_path / "a0.json"
    attachment.write_bytes(dr.compact(VECTORS["attachments"]["A0"]))
    policy = tmp_path / "policy.json"
    policy.write_bytes(dr.compact(POLICY))
    assert dr.main([str(attachment), "--trust-policy", str(policy)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert (out["verdict"], out["report"]["issuer_signature"]["status"]) == ("accept", dr.VERIFIED)
    assert dr.main([str(attachment), "--profile", "strict"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "reject"
    attachment.write_bytes(VECTORS["texts"]["dup_decision_id"]["attachment_text"].encode("utf-8"))
    assert dr.main([str(attachment)]) == 2
    assert "verdict" not in json.loads(capsys.readouterr().out)


def test_corpus_mode_answers_each_member_under_its_profile(tmp_path):
    from agent_evidence_verify import corpus

    members = {"baseline-self-approval": {"profile": "baseline"}, "strict-self-approval": {"profile": "strict"}}
    entries = []
    (tmp_path / "members").mkdir()
    for name, extra in members.items():
        member = {"attachment": _unsigned("A0", SELF_APPROVAL).decode("utf-8"), **extra}
        (tmp_path / "members" / f"{name}.json").write_bytes(dr.compact(member))
        entries.append({"id": name, "path": f"members/{name}.json"})
    manifest = {"suite": dr.SUITE, "corpusDigest": "0" * 64, "vectors": entries}
    (tmp_path / "MANIFEST.json").write_bytes(dr.compact(manifest))
    got = {line["vector"]: (line["verdict"], line["reason"]) for line in corpus.lines(tmp_path)}
    assert got == {"baseline-self-approval": ("accept", None),
                   "strict-self-approval": ("reject", "approver_independence:failed")}


# --- the four checks 0.7.0 adds -------------------------------------------------------------------


def _respell(text: str) -> list[str]:
    """Every other base64 text whose decoded bytes are ``text``'s: the unused low bits set."""
    pad = len(text) - len(text.rstrip("="))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = len(text) - pad - 1
    unused = {2: 4, 1: 2}.get(pad, 0)  # "==" leaves four bits unused, "=" two
    base = alphabet.index(text[last])
    out = [text[:last] + alphabet[base | low] + text[last + 1:] for low in range(1, 2 ** unused)]
    assert all(base64.b64decode(t) == base64.b64decode(text) for t in out)
    return out


def test_a_signature_in_any_spelling_but_its_canonical_one_is_not_read():
    doc = copy.deepcopy(VECTORS["attachments"]["A0"])
    canonical = doc["issuer_signature"]["value_b64"]
    spellings = _respell(canonical)
    assert len(spellings) == 15  # sixteen texts of one signature, one of them canonical
    for spelling in spellings:
        doc["issuer_signature"]["value_b64"] = spelling
        report = dr.read(dr.compact(doc), trust_policy=POLICY)
        assert report["structural_validity"]["status"] == dr.FAILED, spelling
        assert dr.verdict(report, "baseline") == ("reject", "structural_validity:failed")
    doc["issuer_signature"]["value_b64"] = canonical
    assert dr.read(dr.compact(doc), trust_policy=POLICY)["issuer_signature"]["status"] == dr.VERIFIED


def test_carried_bytes_in_a_second_spelling_are_not_read():
    doc = _attachment("A0")
    doc.pop("issuer_signature")
    content = doc["action_specifications"][0]["content"]
    raw = base64.b64decode(content["bytes_b64"]) + b" "  # one byte more: the last group carries padding
    content["bytes_b64"] = base64.b64encode(raw).decode("ascii")
    assert dr.read(dr.compact(doc))["structural_validity"]["status"] == dr.VERIFIED
    content["bytes_b64"] = _respell(content["bytes_b64"])[0]
    assert dr.read(dr.compact(doc))["structural_validity"]["status"] == dr.FAILED
