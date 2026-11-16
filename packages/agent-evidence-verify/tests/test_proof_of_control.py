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
        record = {"schema_version": "probity-case/v1", "case_id": name,
                  "artifacts": {"input": {"path": name, "length": len(data),
                                          "sha256": hashlib.sha256(data).hexdigest()}}}
        assessment = {"claim_type": "proof_of_control/v1", "input": "input"}
        if case.get("public_key"):  # a signed artifact agrees only under the consumer's own pin
            assessment["key_authority"] = {"kind": "pin", "keys": [{"public_key_sha256": hashlib.sha256(
                bytes.fromhex(case["public_key"])).hexdigest()}]}
        policy = {"schema_version": "probity-policy/v1", "assessments": {name: assessment}}
        result = adjudicate(record, policy, tmp_path)
        assert result["decision"] == want


def test_stdin_bridge() -> None:
    case = CASES[0]
    code = ("from agent_evidence_verify.adapters.proof_of_control import main;"
            "raise SystemExit(main())")
    out = subprocess.run([sys.executable, "-c", code],
                         input=json.dumps(case), text=True, capture_output=True, check=True)
    got = json.loads(out.stdout)
    assert got["result"] in {"accept", "reject"}


def _anchored_chain() -> dict:
    return next(c for c in CASES if c["id"] == "CHN-P-six-steps-anchored")


def test_an_anchor_counts_heads_from_genesis() -> None:
    """Break-it counter-example: the twin reads ``records[index - 1]``.

    An anchor at index 0 therefore compared against the last head, so ``{"index": 0, "root":
    <last head>}`` passed and the true head after zero steps, the genesis head, failed.
    """
    case = dict(_anchored_chain())
    genesis = hashlib.sha256(b"poc-genesis").hexdigest()
    last = case["records"][-1]["poc_claims"]["chain_head"].split(":", 1)[1]
    assert proof_of_control.judge(dict(case, anchor={"index": 0, "root": genesis})) is None
    assert proof_of_control.judge(dict(case, anchor={"index": 0, "root": last})) == "history-rewritten"
    first = case["records"][0]["poc_claims"]["chain_head"].split(":", 1)[1]
    assert proof_of_control.judge(dict(case, anchor={"index": 1, "root": first})) is None


@pytest.mark.parametrize("index", [-1, True, 1.0, "1"])
def test_an_anchor_index_that_is_not_a_count_of_steps_is_malformed(index) -> None:
    """``-1`` named the second-to-last head and ``true`` the first; neither is a step count."""
    case = _anchored_chain()
    with pytest.raises(ValueError):
        proof_of_control.judge(dict(case, anchor={"index": index, "root": "0" * 64}))
