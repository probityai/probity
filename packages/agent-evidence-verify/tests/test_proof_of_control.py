"""proof_of_control/v1 against every case of the pinned poc-evidence-vectors corpus.

The corpus is read from the installed poc-evidence-vectors package,
which the test extra pins; the stdin bridge is checked through a subprocess.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

import pytest

from agent_evidence_verify import adjudicate
from agent_evidence_verify.adapters import proof_of_control




def _cases() -> list[dict]:
    root = files("poc_evidence_vectors") / "corpus"
    return [json.loads(f.read_text(encoding="utf-8"))
            for d in sorted(root.iterdir(), key=lambda p: p.name) if d.is_dir()
            for f in sorted(d.iterdir(), key=lambda p: p.name) if f.name.endswith(".json")]


CASES = _cases()


def _passes(case: dict, code: str | None) -> bool:
    want = case["expect"]
    if want["result"] == "accept":
        return code is None
    return code is not None and code in want["code"]


def test_corpus_size() -> None:
    assert len(CASES) == 171


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_every_case(case: dict) -> None:
    assert _passes(case, proof_of_control.judge(case))


def test_claim_type_decisions(tmp_path: Path) -> None:
    good = next(c for c in CASES if c["expect"]["result"] == "accept")
    bad = next(c for c in CASES if c["expect"]["result"] == "reject")
    for name, case, want in (("good.json", good, "supported"), ("bad.json", bad, "contradicted")):
        data = json.dumps(case).encode()
        (tmp_path / name).write_bytes(data)
        record = {"case_id": name, "artifacts": {"input": {"path": name, "sha256":
                  hashlib.sha256(data).hexdigest()}},
                  "assessment": {"claim_type": "proof_of_control/v1", "input": "input"}}
        result = adjudicate(record, {"claim_requirements": {}}, tmp_path)
        assert result["decision"] == want


def test_stdin_bridge() -> None:
    case = CASES[0]
    out = subprocess.run([sys.executable, "-c",
                          "from agent_evidence_verify.adapters.proof_of_control import main;"
                          "raise SystemExit(main())"],
                         input=json.dumps(case), text=True, capture_output=True, check=True)
    got = json.loads(out.stdout)
    assert got["result"] in {"accept", "reject"}
