"""Authority capture boundaries through the public adjudication kernel."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from probity_verify import CaseError, adjudicate


def encoded(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


@pytest.fixture
def probe(tmp_path: Path) -> tuple[Path, dict, dict, dict]:
    capture = {"schema_version": "probity-http-capture/v1",
               "request_url": "https://registry.example.test/owners/probity",
               "captured_at": "2026-09-28T12:00:00Z", "status": 200,
               "body": {"owner": {"login": "probityai"}}}
    data = encoded(capture)
    (tmp_path / "capture.json").write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    case = {"schema_version": "probity-case/v1", "case_id": "anchor-1",
            "artifacts": {"capture": {"path": "capture.json", "length": len(data),
                                      "sha256": digest}}}
    policy = {"schema_version": "probity-policy/v1",
              "witnesses": {"registry": {"artifact": "capture", "sha256": digest,
                                         "authority": "consumer-reviewed registry capture"}},
              "assessments": {"anchor-1": {
                  "claim_type": "authority_anchor/v1", "capture_witness": "registry",
                  "request_url": capture["request_url"], "json_pointer": "/owner/login",
                  "expected_value": "probityai", "capture_window": {
                      "start": "2026-09-28T00:00:00Z", "end": "2026-09-28T23:59:59Z"}}}}
    return tmp_path, case, policy, capture


def decide(probe: tuple[Path, dict, dict, dict], *, capture: dict | None = None,
           policy: dict | None = None) -> dict:
    root, case, original_policy, original_capture = probe
    case = copy.deepcopy(case)
    policy = copy.deepcopy(policy or original_policy)
    data = encoded(capture or original_capture)
    (root / "capture.json").write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    case["artifacts"]["capture"].update(length=len(data), sha256=digest)
    policy["witnesses"]["registry"]["sha256"] = digest
    return adjudicate(case, policy, root)


def test_bound_matching_capture_is_supported(probe):
    result = decide(probe)
    assert (result["decision"], result["reason"]) == ("supported", "anchor_matches")
    assert result["checks"][0]["observed"] == "probityai"
    assert len(result["policy_sha256"]) == 64


def test_different_bound_identity_is_contradicted(probe):
    capture = copy.deepcopy(probe[3])
    capture["body"]["owner"]["login"] = "other"
    result = decide(probe, capture=capture)
    assert (result["decision"], result["reason"]) == ("contradicted", "anchor_mismatch")


@pytest.mark.parametrize("change,reason", [
    ({"request_url": "https://other.example.test/owners/probity"}, "capture_target_mismatch"),
    ({"captured_at": "2026-09-29T12:00:00Z"}, "capture_outside_window"),
    ({"status": 404}, "authority_response_unavailable"),
    ({"body": {"owner": {}}}, "field_unavailable"),
])
def test_wrong_target_time_status_or_missing_field_is_not_established(probe, change, reason):
    capture = copy.deepcopy(probe[3])
    capture.update(change)
    result = decide(probe, capture=capture)
    assert (result["decision"], result["reason"]) == ("not_established", reason)


def test_case_digest_cannot_replace_consumer_pin(probe):
    root, case, policy, _ = probe
    data = encoded({**probe[3], "body": {"owner": {"login": "other"}}})
    (root / "capture.json").write_bytes(data)
    case = copy.deepcopy(case)
    case["artifacts"]["capture"].update(length=len(data), sha256=hashlib.sha256(data).hexdigest())
    result = adjudicate(case, policy, root)
    assert (result["decision"], result["reason"]) == (
        "not_established", "witness_unavailable_or_unbound")


def test_absent_capture_and_ambiguous_json_are_not_established(probe):
    root, case, policy, _ = probe
    (root / "capture.json").unlink()
    result = adjudicate(case, policy, root)
    assert result["reason"] == "witness_unavailable_or_unbound"
    data = (b'{"schema_version":"probity-http-capture/v1",'
            b'"request_url":"https://registry.example.test/owners/probity",'
            b'"captured_at":"2026-09-28T12:00:00Z","status":200,'
            b'"body":{"owner":{"login":"probityai","login":"other"}}}')
    (root / "capture.json").write_bytes(data)
    case = copy.deepcopy(case)
    policy = copy.deepcopy(policy)
    digest = hashlib.sha256(data).hexdigest()
    case["artifacts"]["capture"].update(length=len(data), sha256=digest)
    policy["witnesses"]["registry"]["sha256"] = digest
    assert adjudicate(case, policy, root)["reason"] == "capture_unreadable"


def test_policy_pointer_refuses_non_rfc6901_escape(probe):
    policy = copy.deepcopy(probe[2])
    policy["assessments"]["anchor-1"]["json_pointer"] = "/owner/~2login"
    with pytest.raises(CaseError, match="json_pointer"):
        decide(probe, policy=policy)


def test_capture_claim_requires_https_and_a_bounded_pointer(probe):
    policy = copy.deepcopy(probe[2])
    policy["assessments"]["anchor-1"]["request_url"] = "file:///etc/passwd"
    with pytest.raises(CaseError, match="HTTPS URL"):
        decide(probe, policy=policy)
    policy["assessments"]["anchor-1"]["request_url"] = probe[3]["request_url"]
    capture = copy.deepcopy(probe[3])
    capture["body"]["owner"] = [{"login": "probityai"}]
    policy["assessments"]["anchor-1"]["json_pointer"] = "/owner/" + "1" * 5000
    assert decide(probe, capture=capture, policy=policy)["reason"] == "field_unavailable"
