"""Corpus mode prints one verdict line per member, in the shared verdict-line format.

The lines are held to the manifests of this package's copies of the AEE corpus
and the uncertain-effect corpus: one line per member, the manifest's digest, and
the verdict, result token and (for the decision corpus) reason the manifest
expects. A suite this package does not implement is answered not-applicable for
every member, and an unreadable corpus is refused rather than printed empty.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agent_evidence_verify import corpus
from agent_evidence_verify.cli import main

DATA = Path(__file__).resolve().parent / "data"
KEYS = {"schema", "suite", "corpusDigest", "vector", "verdict", "reason", "result", "verifier"}
TOKENS = {"valid": "accept", "invalid": "reject", "allow": "accept", "deny": "reject"}


def _printed(capsys) -> list[dict]:
    return [json.loads(text) for text in capsys.readouterr().out.splitlines()]


@pytest.mark.parametrize("name", ["execution-evidence", "uncertain-effect"])
def test_every_member_answered_as_the_manifest_expects(name: str, capsys) -> None:
    root = DATA / name
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    assert main(["corpus", str(root)]) == 0
    printed = _printed(capsys)
    assert [line["vector"] for line in printed] == [e["id"] for e in manifest["vectors"]]
    for line, entry in zip(printed, manifest["vectors"], strict=True):
        expected = entry["expected"]
        assert set(line) <= KEYS and KEYS - {"result"} <= set(line)
        assert line["schema"] == corpus.SCHEMA_ID
        assert line["suite"] == manifest["suite"]
        assert line["corpusDigest"] == manifest["corpusDigest"]
        assert line["verifier"]["name"] == "agent-evidence-verify"
        token = expected.get("verdict", expected.get("decision"))
        assert line["verdict"] == TOKENS[token], (entry["id"], line)
        if "result" in expected and line["verdict"] == "accept":
            assert line["result"] == expected["result"]
        if "decision" in expected:
            assert line["reason"] == expected["reason"]
        if line["verdict"] != "accept":
            assert line["reason"] and "result" not in line


def test_unimplemented_suite_is_not_applicable_member_by_member(tmp_path: Path, capsys) -> None:
    manifest = {"suite": "approval-binding/v1", "corpusDigest": "a" * 64,
                "vectors": [{"id": "one"}, {"id": "two"}]}
    (tmp_path / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["corpus", str(tmp_path)]) == 0
    assert [(ln["vector"], ln["verdict"], ln["reason"]) for ln in _printed(capsys)] == [
        ("one", "not-applicable", "suite-not-implemented"),
        ("two", "not-applicable", "suite-not-implemented")]


def test_unreadable_member_is_an_error_line(tmp_path: Path, capsys) -> None:
    manifest = {"suite": corpus.AEE_SUITE, "corpusDigest": "b" * 64,
                "vectors": [{"id": "gone", "file": "statements/gone.json"}]}
    (tmp_path / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["corpus", str(tmp_path)]) == 0
    (line,) = _printed(capsys)
    assert line["verdict"] == "error" and line["reason"].startswith("FileNotFoundError")


def test_unreadable_corpus_is_refused(tmp_path: Path, capsys) -> None:
    assert main(["corpus", str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "NOT RUN" in captured.err
