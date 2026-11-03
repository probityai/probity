"""The release environment check refuses a publish job with no allowed tag, and an unread policy."""

import importlib.util
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_release_environment", ROOT / "scripts" / "check_release_environment.py")
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


def test_it_reads_every_publish_job_in_release_yml():
    jobs = check.publish_distributions((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    assert "probity-effects" in jobs and "probity-ratchet-cases" in jobs
    assert "resolve" not in jobs and "build" not in jobs


def test_a_job_with_no_pattern_is_uncovered():
    assert check.uncovered(["probity-effects", "probity-verify"], ["probity-verify-v*"]) == ["probity-effects"]


def test_the_bare_version_pattern_covers_no_distribution_tag():
    assert check.uncovered(["probity-effects"], ["v*"]) == ["probity-effects"]


def test_one_distribution_pattern_does_not_cover_a_longer_name():
    assert check.uncovered(["probity-ratchet-cases"], ["probity-ratchet-v*"]) == ["probity-ratchet-cases"]


def test_a_branch_policy_with_the_same_name_allows_no_tag():
    reply = {"branch_policies": [{"name": "probity-effects-v*", "type": "branch"}, {"name": "probityai-v*", "type": "tag"}]}
    assert check.allowed_tags(reply) == ["probityai-v*"]


def test_a_reply_with_no_policies_is_unread_not_empty():
    with pytest.raises(check.PolicyUnread):
        check.allowed_tags({"message": "Not Found"})


def test_a_failed_read_exits_2_and_never_passes(monkeypatch):
    def refuse(*args, **kwargs):
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(check.urllib.request, "urlopen", refuse)
    assert check.main() == 2


def test_an_uncovered_job_exits_1(monkeypatch):
    monkeypatch.setattr(check, "read_policy", lambda **kwargs: {"branch_policies": [{"name": "v*", "type": "tag"}]})
    assert check.main() == 1


def test_a_covered_workflow_exits_0(monkeypatch):
    jobs = check.publish_distributions((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    policies = [{"name": f"{name}-v*", "type": "tag"} for name in jobs]
    monkeypatch.setattr(check, "read_policy", lambda **kwargs: {"branch_policies": policies})
    assert check.main() == 0
