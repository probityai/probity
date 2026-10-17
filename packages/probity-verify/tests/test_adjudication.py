import copy
import hashlib
from pathlib import Path

import pytest

from probity_verify import CaseError, adjudicate
from probity_verify.cli import _load


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def bundle(tmp_path):
    source = (b"<article><p>The initial incident.</p>"
              b"<script>Irrelevant hidden words</script>"
              b"<p>Several channels were removed.</p></article>")
    report = b"The initial incident.\nSeveral channels were rem\n"
    (tmp_path / "source.html").write_bytes(source)
    (tmp_path / "report.txt").write_bytes(report)
    case = {
        "schema_version": "probity-case/v1", "case_id": "case-1",
        "artifacts": {
            "source": {"path": "source.html", "length": len(source), "sha256": sha(source)},
            "report": {"path": "report.txt", "length": len(report), "sha256": sha(report)},
        },
    }
    policy = {
        "schema_version": "probity-policy/v1",
        "witnesses": {"archive": {
            "artifact": "source", "sha256": sha(source),
            "captured_at": "2019-06-26T07:25:02Z", "source_url": "https://example.org/capture",
            "authority": "Consumer-reviewed fixture", "source_format": "html_article_text/v1",
        }},
        "assessments": {"case-1": {
            "claim_type": "source_text_coverage/v1", "source_witness": "archive",
            "record_artifact": "report", "record_sha256": sha(report),
            "record_version": "synthetic-v1",
            "source_window": {"start": "2019-06-26T00:00:00Z", "end": "2019-06-26T23:59:59Z"},
            "required_spans": [{"id": "response", "text": "Several channels were removed."}],
        }},
    }
    return tmp_path, source, case, policy


def check(bundle, case=None, policy=None):
    root, _, default_case, default_policy = bundle
    return adjudicate(case if case is not None else default_case,
                      policy if policy is not None else default_policy, root)


def test_visible_omission_is_contradicted_only_at_witness_time(bundle):
    result = check(bundle)
    assert (result["decision"], result["reason"]) == (
        "contradicted", "selected_span_missing_from_record")
    assert result["checks"] == [{"id": "response", "status": "failed",
                                  "observations": {"in_source": True, "in_record": False}}]
    policy = copy.deepcopy(bundle[3])
    policy["assessments"]["case-1"]["source_window"] = {
        "start": "2019-04-13T00:00:00Z", "end": "2019-04-13T23:59:59Z"}
    result = check(bundle, policy=policy)
    assert (result["decision"], result["reason"]) == (
        "not_established", "witness_outside_source_window")


def test_neutral_source_coverage_schema_and_mixed_pair(bundle):
    case = copy.deepcopy(bundle[2])
    policy = copy.deepcopy(bundle[3])
    case["schema_version"] = "source-coverage-case/v1"
    policy["schema_version"] = "source-coverage-policy/v1"
    result = check(bundle, case=case, policy=policy)
    assert (result["decision"], result["reason"]) == (
        "contradicted", "selected_span_missing_from_record")
    policy["schema_version"] = "probity-policy/v1"
    with pytest.raises(CaseError, match="unsupported schema_version"):
        check(bundle, case=case, policy=policy)


def test_supported_when_all_consumer_selected_passages_are_present(bundle):
    root, _, case, policy = bundle
    report = b"The initial incident. Several channels were removed."
    (root / "report.txt").write_bytes(report)
    case["artifacts"]["report"].update(length=len(report), sha256=sha(report))
    policy["assessments"]["case-1"]["record_sha256"] = sha(report)
    assert check(bundle)["decision"] == "supported"


def test_producer_swapping_record_and_case_digest_cannot_create_support(bundle):
    root, _, case, _ = bundle
    report = b"The initial incident. Several channels were removed."
    (root / "report.txt").write_bytes(report)
    changed = copy.deepcopy(case)
    changed["artifacts"]["report"].update(length=len(report), sha256=sha(report))
    result = check(bundle, case=changed)
    assert (result["decision"], result["reason"]) == (
        "not_established", "record_pin_mismatch")


def test_producer_cannot_self_pin_witness_or_withdraw_required_span(bundle):
    case = copy.deepcopy(bundle[2])
    case["required_spans"] = []
    with pytest.raises(CaseError):
        check(bundle, case=case)
    policy = copy.deepcopy(bundle[3])
    policy["witnesses"]["archive"]["sha256"] = "0" * 64
    assert check(bundle, policy=policy)["reason"] == "witness_pin_mismatch"


def test_broken_binding_and_unanchored_span_do_not_count_as_contradiction(bundle):
    root, source, _, policy = bundle
    (root / "source.html").write_bytes(b"changed")
    with pytest.raises(CaseError, match="binding_mismatch"):
        check(bundle)
    (root / "source.html").write_bytes(source)
    changed = copy.deepcopy(policy)
    changed["assessments"]["case-1"]["required_spans"][0]["text"] = "No such passage."
    assert check(bundle, policy=changed)["reason"] == "selected_span_not_in_witness"


def test_hidden_html_text_cannot_satisfy_source_requirement(bundle):
    policy = copy.deepcopy(bundle[3])
    policy["assessments"]["case-1"]["required_spans"][0]["text"] = "Irrelevant hidden words"
    result = check(bundle, policy=policy)
    assert (result["decision"], result["reason"]) == (
        "not_established", "selected_span_not_in_witness")
    assert result["checks"][0]["status"] == "unavailable"


def test_bound_non_utf8_capture_cannot_establish_text_claim(bundle):
    root, _, case, policy = bundle
    source = b"\xff\xfe"
    (root / "source.html").write_bytes(source)
    case["artifacts"]["source"].update(length=len(source), sha256=sha(source))
    policy["witnesses"]["archive"]["sha256"] = sha(source)
    result = check(bundle)
    assert (result["decision"], result["reason"]) == (
        "not_established", "artifact_not_utf8")


def test_page_without_article_cannot_supply_article_evidence(bundle):
    root, _, case, policy = bundle
    source = b"<p>Several channels were removed.</p>"
    (root / "source.html").write_bytes(source)
    case["artifacts"]["source"].update(length=len(source), sha256=sha(source))
    policy["witnesses"]["archive"]["sha256"] = sha(source)
    assert check(bundle)["reason"] == "source_selection_unavailable"


def test_policy_digest_changes_when_consumer_changes_required_passage(bundle):
    first = check(bundle)
    policy = copy.deepcopy(bundle[3])
    policy["assessments"]["case-1"]["required_spans"][0]["text"] = "The initial incident."
    second = check(bundle, policy=policy)
    assert first["policy_sha256"] != second["policy_sha256"]
    assert second["decision"] == "supported"


def test_refuses_traversal_and_symlink(bundle):
    root, _, case, _ = bundle
    changed = copy.deepcopy(case)
    changed["artifacts"]["source"]["path"] = "../source.html"
    with pytest.raises(CaseError):
        check(bundle, case=changed)
    (root / "alias.txt").symlink_to(root / "source.html")
    changed["artifacts"]["source"]["path"] = "alias.txt"
    with pytest.raises(CaseError):
        check(bundle, case=changed)


def test_rejects_ambiguous_json_policy(tmp_path):
    path = tmp_path / "ambiguous.json"
    path.write_text('{"witnesses":{},"witnesses":{"archive":{}}}')
    with pytest.raises(CaseError, match="duplicate JSON key"):
        _load(path)


@pytest.mark.parametrize("case_name,policy_name,expected", [
    ("case.json", "policy-june.json", "contradicted"),
    ("case.json", "policy-april.json", "not_established"),
    ("case-complete.json", "policy-complete.json", "supported"),
])
def test_shipped_cases_cover_all_three_decisions(case_name, policy_name, expected):
    root = Path(__file__).resolve().parents[1] / "examples" / "source-coverage"
    assert adjudicate(_load(root / case_name), _load(root / policy_name), root)["decision"] == expected
