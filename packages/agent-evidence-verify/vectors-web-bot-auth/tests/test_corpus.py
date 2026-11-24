"""The browser profile corpus refuses byte drift, and the published verifier decides every case as the manifest says."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, file: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _module("web_bot_auth_corpus", "check_vectors.py")
generator = _module("web_bot_auth_generator", "gen_vectors.py")
TOTAL = len(generator.CASES)


class TestPassingCases:
    def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
        generator.generate(tmp_path)
        committed_files = [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
        committed = {p.relative_to(ROOT): p.read_bytes() for p in committed_files if p.is_file()}
        regenerated = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        assert regenerated == committed
        assert generator.stale() == []

    def test_published_verifier_executes_all_cases(self) -> None:
        executed, errors = corpus.check("agent-evidence-verify")
        assert (executed, errors) == (TOTAL, [])

    def test_every_case_is_signed_in_the_profile(self) -> None:
        for entry in json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]:
            request = json.loads((ROOT / entry["path"] / "request.json").read_text())
            inputs = [v for n, v in request["headers"] if n == "Signature-Input"]
            assert len(inputs) == 1 and inputs[0].startswith("agent=(") and 'tag="web-bot-auth"' in inputs[0]
            assert '"probity-stamp-digest"' in inputs[0] or entry["id"] == "digest-not-covered"


class TestFailingCases:
    def test_missing_verifier_does_not_count_as_executed(self, tmp_path: Path) -> None:
        executed, errors = corpus.check(str(tmp_path / "no-such-verifier"))
        assert executed == 0
        assert len(errors) == TOTAL and all("verifier did not run" in e for e in errors)

    def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
        copied = tmp_path / "corpus"
        shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
        (copied / "cases" / "supported" / "body.bin").write_bytes(b"different")
        executed, errors = corpus.check("/bin/false", root=copied)
        assert executed == TOTAL - 1
        assert "supported: fixture digest mismatch" in errors
        assert "stale: cases/supported/body.bin" in [f"stale: {p}" for p in generator.stale(copied)]

    def test_always_support_verifier_is_refused(self, tmp_path: Path) -> None:
        stub = tmp_path / "always.py"
        stub.write_text('import json\nprint(json.dumps({"decision": "supported", '
                        '"reason": "request_signed_by_pinned_agent"}))\n', encoding="ascii")
        executed, errors = corpus.check(f"{sys.executable} {stub}")
        supported = sum(1 for c in generator.CASES if c.decision == "supported")
        assert executed == TOTAL and len(errors) == TOTAL - supported
