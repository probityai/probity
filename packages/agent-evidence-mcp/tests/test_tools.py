"""Every tool runs against the real packages and the real shipped corpus. Nothing is mocked."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
from importlib import metadata, resources
from pathlib import Path

import pytest
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

from agent_evidence_mcp.server import TOOLS, build_server
from conftest import call

SAMPLES = Path(str(resources.files("probity_verify") / "samples"))
JUNE_POLICY_SHA = "dfda1551714f92702169d1411af6b0bfeee54732f934ce71265534af775fa388"


def _sample_inputs(case: str, policy: str) -> dict:
    artifacts = {
        p.name: p.read_text(encoding="utf-8") for p in SAMPLES.iterdir() if p.suffix in {".txt", ".html"}
    }
    return {
        "case": json.loads((SAMPLES / case).read_text(encoding="utf-8")),
        "policy": json.loads((SAMPLES / policy).read_text(encoding="utf-8")),
        "artifacts": artifacts,
    }


# --- listing and annotations ---------------------------------------------------------

def test_every_tool_is_annotated_read_only_titled_and_short() -> None:
    async def listing():
        async with Client(build_server()) as client:
            return (await client.list_tools()).tools

    tools = asyncio.run(listing())
    assert {t.name for t in tools} == {f.__name__ for f, _ in TOOLS}
    for tool in tools:
        assert len(tool.name) < 64
        assert tool.title and tool.annotations is not None
        assert tool.annotations.title == tool.title
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.open_world_hint is False


def test_serves_over_stdio() -> None:
    async def run():
        params = StdioServerParameters(command=sys.executable, args=["-m", "agent_evidence_mcp.server"])
        async with Client(params) as client:
            return await client.call_tool("verify_sample", {"scenario": "contradicted"})

    result = asyncio.run(run())
    assert result.structured_content["decision"] == "contradicted"


# --- verify_claim / verify_sample ----------------------------------------------------

@pytest.mark.parametrize(
    ("scenario", "decision", "reason"),
    [
        ("contradicted", "contradicted", "selected_span_missing_from_record"),
        ("not_established", "not_established", "witness_outside_source_window"),
        ("supported", "supported", "all_selected_spans_present"),
    ],
)
def test_verify_sample_decisions(scenario: str, decision: str, reason: str) -> None:
    out = call("verify_sample", {"scenario": scenario})
    assert (out["decision"], out["reason"]) == (decision, reason)
    assert out["packet"].startswith("Probity decision packet v1")
    assert f"Decision: {decision}" in out["packet"]


def test_verify_sample_reports_its_checks() -> None:
    assert len(call("verify_sample", {"scenario": "contradicted"})["checks"]) == 1
    assert call("verify_sample", {"scenario": "not_established"})["checks"] == []


def test_verify_sample_binds_the_policy_bytes() -> None:
    assert call("verify_sample", {"scenario": "contradicted"})["policy_sha256"] == JUNE_POLICY_SHA


def test_verify_sample_rejects_unknown_scenario() -> None:
    out = call("verify_sample", {"scenario": "nope"})
    assert out["ok"] is False and "scenario" in out["error"]


def test_verify_claim_matches_the_sample_run() -> None:
    sample = call("verify_sample", {"scenario": "contradicted"})
    direct = call("verify_claim", _sample_inputs("case.json", "policy-june.json"))
    assert direct["decision"] == sample["decision"] == "contradicted"
    assert direct["policy_sha256"] == JUNE_POLICY_SHA
    assert direct["checks"] == sample["checks"]


def test_verify_claim_changes_its_decision_when_the_evidence_changes() -> None:
    inputs = _sample_inputs("case-complete.json", "policy-complete.json")
    assert call("verify_claim", inputs)["decision"] == "supported"
    inputs["artifacts"]["report-complete.txt"] = "nothing the source said"
    changed = call("verify_claim", inputs)
    assert changed["ok"] is False and "binding_mismatch" in changed["error"]


@pytest.mark.parametrize("name", ["../escape.txt", "/etc/passwd", "a/../../b"])
def test_verify_claim_refuses_artifact_paths_outside_the_case(name: str) -> None:
    inputs = _sample_inputs("case.json", "policy-june.json")
    inputs["artifacts"][name] = "x"
    out = call("verify_claim", inputs)
    assert out["ok"] is False and "relative" in out["error"]


def test_verify_claim_reports_invalid_input_without_a_verdict() -> None:
    out = call("verify_claim", {"case": {}, "policy": {}})
    assert out["ok"] is False and "decision" not in out


# --- vectors -------------------------------------------------------------------------

def test_corpora_listing_has_the_main_corpus_with_its_count() -> None:
    out = call("list_vector_corpora")
    rows = {r["corpus"]: r for r in out["corpora"]}
    assert out["total"] == len(rows) >= 30
    assert rows["vectors"]["vectors"] == 288


def test_run_vectors_replays_the_main_corpus_clean() -> None:
    out = call("run_vectors", {"corpus": "vectors", "limit": 5})
    assert out["exit_code"] == 0
    assert out["release"] == metadata.version("agent-evidence-vectors")
    assert out["totals"]["vectors"] == 288 and out["totals"]["pass"] == 288 and out["totals"]["fail"] == 0
    assert len(out["page"]) == 5 and out["next_offset"] == 5
    assert all(row["status"] == "PASS" for row in out["page"])


def test_run_vectors_pages_to_the_end() -> None:
    out = call("run_vectors", {"corpus": "vectors", "offset": 280, "limit": 50})
    assert len(out["page"]) == 8 and out["next_offset"] is None


def test_run_vectors_final_page_that_ends_exactly_at_the_corpus_end_has_no_next() -> None:
    out = call("run_vectors", {"corpus": "vectors", "offset": 238, "limit": 50})
    assert len(out["page"]) == 50 and out["next_offset"] is None


def test_run_vectors_replays_a_second_corpus_with_a_report() -> None:
    out = call("run_vectors", {"corpus": "vectors-agent-change-admission", "limit": 3})
    assert out["ok"] and out["totals"]["fail"] == 0 and out["totals"]["vectors"] == 35


def test_run_vectors_returns_the_text_verdict_for_a_corpus_without_a_report() -> None:
    out = call("run_vectors", {"corpus": "vectors-admission"})
    assert out["ok"] is True and out["report"] is None and out["exit_code"] == 0
    assert "every member behaves as MANIFEST.json declares" in out["output"]


def test_run_vectors_surfaces_a_corpus_that_needs_an_external_verifier() -> None:
    out = call("run_vectors", {"corpus": "vectors-source-coverage"})
    assert out["ok"] is False and out["exit_code"] == 2 and "external verifier" in out["error"]


def test_run_vectors_refuses_an_unknown_corpus() -> None:
    assert call("run_vectors", {"corpus": "../etc"})["ok"] is False


def test_explain_vector_returns_entry_and_input_bytes() -> None:
    out = call("explain_vector", {"vector_id": "vcf20eae7df4f1f1b"})
    assert out["entry"]["conditions"] == ["aee-c-1", "aee-c-3", "aee-c-12", "aee-c-28", "aee-c-50"]
    assert out["entry"]["expected"] == {"verdict": "valid", "result": "fail"}
    assert json.loads(out["input"]) and out["input_bytes"] > 0


def test_explain_vector_unknown_id_and_path_like_id() -> None:
    assert call("explain_vector", {"vector_id": "nope"})["ok"] is False
    assert call("explain_vector", {"vector_id": "../MANIFEST"})["ok"] is False


# --- vocabulary ----------------------------------------------------------------------

def test_lookup_term_finds_a_term() -> None:
    out = call("lookup_term", {"term": "observation_vantage"})
    match = out["matches"][0]
    assert match["values"] == ["substrate", "artifact"] and match["status"] == "proposed"
    assert out["vocabulary_version"] == metadata.version("agent-evidence-vocabulary")
    assert "substrate" in match["definition"]


def test_lookup_term_suggests_close_terms_and_never_invents() -> None:
    out = call("lookup_term", {"term": "vantage"})
    assert out["ok"] is False and "observation_vantage" in out["close_terms"]
    assert call("lookup_term", {"term": "zzzz"})["close_terms"] == []


# --- digest check --------------------------------------------------------------------

ARTIFACT = "the artifact bytes"
DIGEST = hashlib.sha256(ARTIFACT.encode()).hexdigest()
STATEMENT = json.dumps({"subject": [{"name": "a", "digest": {"sha256": DIGEST}}]})


def test_digest_match_admits() -> None:
    out = call("check_artifact_digest", {"document": STATEMENT, "artifact_text": ARTIFACT})
    assert out["admitted"] is True and out["matched"] == {"algorithm": "sha256", "digest": DIGEST}


def test_digest_mismatch_refuses_with_the_declared_digest() -> None:
    out = call("check_artifact_digest", {"document": STATEMENT, "artifact_text": ARTIFACT + "!"})
    assert out["admitted"] is False and out["reason"] == "digest-mismatch"
    assert out["declared"] == [{"algorithm": "sha256", "digest": DIGEST}]


def test_document_naming_no_digest_refuses() -> None:
    out = call("check_artifact_digest", {"document": "{}", "artifact_text": ARTIFACT})
    assert out["admitted"] is False and out["reason"] == "no-digest-named"


def test_base64_artifact_and_argument_errors() -> None:
    b64 = base64.b64encode(ARTIFACT.encode()).decode()
    assert call("check_artifact_digest", {"document": STATEMENT, "artifact_base64": b64})["admitted"] is True
    assert call("check_artifact_digest", {"document": STATEMENT})["ok"] is False
    assert call("check_artifact_digest", {"document": STATEMENT, "artifact_base64": "!!"})["ok"] is False
    assert call("check_artifact_digest", {"document": "not json", "artifact_text": "x"})["ok"] is False


# --- pins ----------------------------------------------------------------------------

def test_every_package_is_pinned_exactly_and_installed_at_that_pin() -> None:
    requires = [r for r in metadata.requires("agent-evidence-mcp") or [] if "extra ==" not in r]
    pins = dict(r.split("==") for r in requires)
    assert set(pins) == {
        "mcp", "pyyaml", "probity-verify", "agent-evidence-vectors",
        "agent-evidence-vocabulary", "agent-evidence-admission",
    }
    for name, version in pins.items():
        assert metadata.version(name) == version
