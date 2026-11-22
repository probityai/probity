"""The reference webhook SSRF judge shipped with agent-evidence-a2a, scored on the 42-URL corpus."""

from __future__ import annotations

import pytest
from agent_evidence_a2a import judge_url, load_ssrf, recorded_judge, score_ssrf_judge
from agent_evidence_a2a.cli import main
from agent_evidence_a2a.ssrf import recorded_resolver


def test_the_reference_judge_catches_all_30_unsafe_urls_and_flags_none_of_the_6_safe() -> None:
    report = score_ssrf_judge(recorded_judge())
    assert len(report.caught) == 30
    assert report.missed == ()
    assert report.false_flags == ()
    assert len(report.unscored) == 6


def test_the_cli_scores_the_reference_judge_clean_without_a_judge_argument() -> None:
    assert main(["ssrf"]) == 0


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_PING",
        " http://127.0.0.1/hook",
        "http:///hook",
        "http://[::1/hook",
    ],
)
def test_unfetchable_or_unparseable_urls_are_refused(url: str) -> None:
    assert judge_url(url, recorded_resolver()) is True


def test_a_name_that_does_not_resolve_is_refused() -> None:
    assert judge_url("http://nowhere.invalid/hook", recorded_resolver()) is True


def test_a_resolver_returning_one_private_address_among_public_ones_refuses() -> None:
    assert judge_url("http://rebind.example/hook", lambda _h: ["1.1.1.1", "10.0.0.1"]) is True
    assert judge_url("http://ok.example/hook", lambda _h: ["1.1.1.1"]) is False


def test_the_unscored_unfetchable_urls_are_all_refused() -> None:
    resolve = recorded_resolver()
    for case in load_ssrf():
        if case.truth == "UNFETCHABLE":
            assert judge_url(case.url, resolve) is True, case.url
