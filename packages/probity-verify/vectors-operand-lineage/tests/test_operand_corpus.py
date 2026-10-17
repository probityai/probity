"""Check reproducibility, byte commitments, and external verifier behavior."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _module("operand_corpus", "check_vectors.py")
generator = _module("operand_generator", "gen_vectors.py")


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in (ROOT / "cases").rglob("*") if p.is_file()}
    committed[Path("MANIFEST.json")] = (ROOT / "MANIFEST.json").read_bytes()
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_verifier_executes_all_vectors() -> None:
    executed, errors = corpus.check("probity-verify")
    assert executed == 10
    assert errors == []


def test_changed_fixture_is_rejected_before_execution(tmp_path: Path) -> None:
    copied = tmp_path / "corpus"
    shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
    (copied / "cases" / "complete" / "execution.json").write_bytes(b"different")
    executed, errors = corpus.check("/bin/false", root=copied)
    assert executed == 9
    assert "complete: fixture digest mismatch" in errors


def test_always_support_verifier_is_rejected(tmp_path: Path) -> None:
    stub = tmp_path / "always.py"
    stub.write_text(
        'import json\nprint(json.dumps({"decision": "supported", '
        '"reason": "lineage_recomputed"}))\n', encoding="ascii",
    )
    executed, errors = corpus.check(f"{sys.executable} {stub}")
    assert executed == 10
    assert len(errors) == 9


def test_missing_verifier_does_not_count_as_execution(tmp_path: Path) -> None:
    executed, errors = corpus.check(str(tmp_path / "missing"))
    assert executed == 0
    assert len(errors) == 10
