"""The done-check corpus: byte-identical regeneration, commitments, and the verifier."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _module("done_checks_corpus", "check_vectors.py")
MEMBERS = 20


def test_regeneration_is_byte_identical() -> None:
    done = subprocess.run([sys.executable, str(ROOT / "gen_vectors.py"), "--check"],
                          capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout


def test_verifier_executes_all_vectors() -> None:
    executed, errors = corpus.check("probity-verify")
    assert executed == MEMBERS
    assert errors == []


def test_changed_fixture_is_rejected_before_execution(tmp_path: Path) -> None:
    copied = tmp_path / "corpus"
    shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    (copied / "cases" / "protected-ancestor-swap" / "observation.json").write_bytes(b"x")
    executed, errors = corpus.check("/bin/false", root=copied)
    assert executed == MEMBERS - 1
    assert "protected-ancestor-swap: fixture digest mismatch" in errors


def test_always_support_verifier_is_rejected(tmp_path: Path) -> None:
    stub = tmp_path / "always.py"
    stub.write_text('import json\nprint(json.dumps({"decision": "supported", '
                    '"reason": "tool_claims_matched"}))\n', encoding="ascii")
    executed, errors = corpus.check(f"{sys.executable} {stub}")
    assert executed == MEMBERS
    assert len(errors) == MEMBERS - 2
