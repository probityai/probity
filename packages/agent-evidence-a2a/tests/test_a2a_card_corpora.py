"""The card corpus, the a2a-jcs-v01 canonicaliser mode and the webhook SSRF corpus of agent-evidence-a2a."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_a2a import (
    check_canonicaliser,
    load_cards,
    load_ssrf,
    score_card_verifier,
    score_ssrf_judge,
)
from agent_evidence_a2a.cli import main
from agent_evidence_a2a.corpus import default_verifier, ground_truth
from agent_evidence_a2a.vectors import broken_ascii_escaping, broken_code_point_order, reference_canonicalize

DATA = Path(str(files("agent_evidence_a2a"))) / "data"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "agent_card_schema.py"


def test_card_corpus_is_judged_correctly_by_the_served_bytes_verifier() -> None:
    report = score_card_verifier(default_verifier())
    assert len(report.detected) == 28
    assert report.missed == ()
    assert report.false_rejects == ()
    assert report.accepted_controls == 11
    assert len(load_cards()) == 43


def test_unsettled_probes_are_pending_on_the_spec_issue_and_never_scored() -> None:
    pending = [c for c in load_cards() if c.expected == "PENDING"]
    assert sorted(c.id for c in pending) == ["k25f09676", "k350f8306", "k404dc3ea", "ke353257a"]
    assert {c.pending_on for c in pending} == {"a2aproject/A2A#2122"}
    assert score_card_verifier(lambda _served: True).pending == tuple(c.id for c in pending)


def test_a_verifier_that_accepts_everything_misses_all_28_attacks() -> None:
    report = score_card_verifier(lambda _served: True)
    assert len(report.missed) == 28
    assert report.false_rejects == ()


def test_a_verifier_that_rejects_everything_falsely_rejects_all_11_controls() -> None:
    report = score_card_verifier(lambda _served: False)
    assert len(report.false_rejects) == 11
    assert report.missed == ()


INTENT_WORDS = ("evil", "attacker", "forged", "malicious", "exploit", "spoof", "hijack", "phish", "bypass", "poison")


def test_the_forged_second_name_no_longer_spells_out_the_attack_on_the_wire() -> None:
    """No served card names its own attack; ``kcd76c262`` once pointed its injected member at ``attacker.example``."""
    served = {c.id: c.served.decode("utf-8") for c in load_cards()}
    leaks = {cid: word for cid, text in served.items() for word in INTENT_WORDS if word in text.lower()}
    assert leaks == {}
    top_level_names = [
        v for k, v in json.loads(served["kb48e1fb1"], object_pairs_hook=lambda pairs: pairs) if k == "name"
    ]
    assert top_level_names == ["Atlas", "Atlas Mirror"]


def test_shipped_files_match_their_digests() -> None:
    manifest = json.loads((DATA / "MANIFEST.json").read_text(encoding="utf-8"))
    assert len(manifest) >= 49
    for name, digest in manifest.items():
        assert hashlib.sha256((DATA / name).read_bytes()).hexdigest() == digest, name


def test_reference_canonicaliser_passes_all_57_vectors() -> None:
    report = check_canonicaliser(reference_canonicalize)
    assert (report.total, report.passed) == (57, 57)


def test_canonicaliser_under_test_reproduces_the_published_failure_counts() -> None:
    m1 = check_canonicaliser(broken_code_point_order)
    m2 = check_canonicaliser(broken_ascii_escaping)
    assert (m1.total, len(m1.failed_ids)) == (57, 10)
    assert (m2.total, len(m2.failed_ids)) == (57, 24)


def test_cli_canonicaliser_exits_non_zero_for_a_broken_implementation() -> None:
    assert main(["canonicaliser"]) == 0
    assert main(["canonicaliser", "--impl", "agent_evidence_a2a.vectors:broken_ascii_escaping"]) == 1


def test_cli_corpus_is_clean_for_the_packaged_verifier() -> None:
    assert main(["corpus"]) == 0


def test_ssrf_corpus_has_42_urls_with_resolved_ground_truth() -> None:
    cases = load_ssrf()
    assert len(cases) == 42
    scored = [c for c in cases if c.scored]
    assert len(scored) == 41
    counts = {t: sum(c.truth == t for c in scored) for t in ("UNSAFE", "SAFE", "UNFETCHABLE")}
    assert counts == {"UNSAFE": 30, "SAFE": 6, "UNFETCHABLE": 5}
    for case in scored:
        assert ground_truth(case.addrs) == case.truth, case.url


def test_ssrf_judge_scores_follow_the_ground_truth() -> None:
    by_url = {c.url: c.truth for c in load_ssrf()}
    oracle = score_ssrf_judge(lambda url: by_url[url] == "UNSAFE")
    assert (len(oracle.caught), oracle.missed, oracle.false_flags) == (30, (), ())
    nothing = score_ssrf_judge(lambda _url: False)
    assert len(nothing.missed) == 30
    everything = score_ssrf_judge(lambda _url: True)
    assert len(everything.false_flags) == 6
    shared_space = {"http://100.100.100.200/latest/meta-data/", "http://100.64.0.1/hook"}
    assert shared_space <= {c.url for c in load_ssrf() if c.truth == "UNSAFE"}


def _fresh_schema() -> Any:
    spec = importlib.util.spec_from_file_location("agent_card_schema", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.schema()


def test_shipped_schema_table_matches_the_installed_a2a_protobuf() -> None:
    shipped = json.loads((DATA / "agent_card_schema.json").read_text(encoding="utf-8"))
    assert shipped == json.loads(json.dumps(_fresh_schema()))


@pytest.mark.parametrize("card_id", ["kcd76c262", "k2151ce69", "kb48e1fb1", "kb768e7c3"])
def test_the_attacks_the_tck_and_sdk_verifiers_miss_are_rejected(card_id: str) -> None:
    case = next(c for c in load_cards() if c.id == card_id)
    assert default_verifier()(case.served) is False
