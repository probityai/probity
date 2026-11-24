"""The identifier host rule: one host written, two hosts read as ours, nothing else recognised."""

import pytest
from agent_evidence_verify.identifiers import (
    IDENTIFIER_HOST,
    RECOGNISED_HOSTS,
    canonical_identifier,
    identifier,
    same_identifier,
)

PATH = "agent-evidence-vectors/predicate/v1/observed-effect"
OLD = "https://probityai.github.io/" + PATH
NEW = "https://probityai.org/" + PATH

#: Every spelling the rule must refuse to recognise, each beside the recognised one it imitates.
REFUSED = [
    "http://probityai.org/" + PATH,
    "http://probityai.github.io/" + PATH,
    "https://www.probityai.org/" + PATH,
    "https://probityai.org:443/" + PATH,
    "https://probityai.org./" + PATH,
    "https://PROBITYAI.ORG/" + PATH,
    "https://Probityai.org/" + PATH,
    "HTTPS://probityai.org/" + PATH,
    "https://user@probityai.org/" + PATH,
    "https://probityai.org.example/" + PATH,
    "https://probityai.organisation/" + PATH,
    "https://probityai.org",
    "https://probityai.github.io",
    "https://evil.example/https://probityai.org/" + PATH,
    " https://probityai.org/" + PATH,
    "https:/probityai.org/" + PATH,
    "https://probityai.orgx/" + PATH,
    "https://xprobityai.org/" + PATH,
]


def test_hosts():
    assert IDENTIFIER_HOST == "probityai.github.io"
    assert RECOGNISED_HOSTS == ("probityai.github.io", "probityai.org")
    assert IDENTIFIER_HOST in RECOGNISED_HOSTS


def test_identifier_writes_the_identifier_host():
    assert identifier(PATH) == "https://" + IDENTIFIER_HOST + "/" + PATH
    assert identifier(PATH) == OLD
    assert identifier("") == "https://probityai.github.io/"


@pytest.mark.parametrize("value", [OLD, NEW])
def test_both_hosts_canonicalise_to_the_written_host(value):
    assert canonical_identifier(value) == OLD


def test_only_the_prefix_is_rewritten():
    tail = "a/b?c=https://probityai.org/#frag"
    assert canonical_identifier("https://probityai.org/" + tail) == "https://probityai.github.io/" + tail
    assert canonical_identifier("https://probityai.org/") == "https://probityai.github.io/"


@pytest.mark.parametrize("value", REFUSED)
def test_refused_spellings_are_unchanged(value):
    assert canonical_identifier(value) == value
    assert not same_identifier(value, OLD)
    assert not same_identifier(value, NEW)


@pytest.mark.parametrize("value", [None, 1, 1.5, True, [], {}, [NEW], {"id": NEW}, b"https://probityai.org/x"])
def test_non_strings_are_returned_as_they_are(value):
    assert canonical_identifier(value) is value


def test_other_identifiers_are_unchanged():
    for value in ("https://w3id.org/agent-evidence/predicate/v1/done-receipt",
                  "https://in-toto.io/Statement/v1", "uncertain_effect/v1", ""):
        assert canonical_identifier(value) == value


def test_same_identifier():
    assert same_identifier(OLD, NEW)
    assert same_identifier(NEW, OLD)
    assert same_identifier(NEW, NEW)
    assert not same_identifier(NEW, "https://probityai.org/agent-evidence-vectors/predicate/v1/other")
    assert not same_identifier(None, OLD)
    assert same_identifier(None, None)
