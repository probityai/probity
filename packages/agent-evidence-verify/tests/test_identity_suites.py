"""The payment-mandate and status-receipt-binding suites in corpus mode.

Every member is answered with the decision and the reason the corpus declares, so the Action's
reference stage reads 36 of 36 and 24 of 24 for the two suites.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agent_evidence_verify import corpus
from agent_evidence_verify.cli import main

DATA = Path(__file__).resolve().parent / "data"
VERDICT = {"accepted": "accept", "rejected": "reject", "accept": "accept", "reject": "reject"}
SUITES = {"payment-mandate": ("agent-payment-mandate/v1", 36),
          "status-receipt-binding": ("status-receipt-binding/v1", 24)}


def _printed(capsys) -> list[dict]:
    return [json.loads(text) for text in capsys.readouterr().out.splitlines()]


@pytest.mark.parametrize("name", sorted(SUITES))
def test_every_member_answered_as_the_corpus_declares(name: str, capsys) -> None:
    suite, count = SUITES[name]
    root = DATA / name
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["suite"] == suite and len(manifest["vectors"]) == count
    assert main(["corpus", str(root)]) == 0
    printed = _printed(capsys)
    assert [line["vector"] for line in printed] == [e["id"] for e in manifest["vectors"]]
    wrong = [(e["id"], line["verdict"], line["reason"], e["expected"])
             for line, e in zip(printed, manifest["vectors"], strict=True)
             if (line["verdict"], line["reason"])
             != (VERDICT[e["expected"]["decision"]], e["expected"]["reason"])]
    assert wrong == []
    assert all(line["corpusDigest"] == manifest["corpusDigest"] for line in printed)
    assert all(line["schema"] == corpus.SCHEMA_ID for line in printed)
