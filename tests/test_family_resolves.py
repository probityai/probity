"""The in-family exact-pin lint refuses what it names and passes ranges and third-party pins."""

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("family_resolves", Path(__file__).resolve().parents[1] / "scripts" / "family_resolves.py")
fr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fr)


def project(tmp_path: Path, deps: str) -> Path:
    d = tmp_path / "packages" / "x"
    d.mkdir(parents=True)
    (d / "pyproject.toml").write_text(f'[project]\nname="x"\nversion="1"\ndependencies={deps}\n', encoding="utf-8")
    return tmp_path


def test_exact_in_family_pin_is_refused(tmp_path: Path) -> None:
    assert fr.lint(project(tmp_path, '["probity-verify==0.1.1"]'))


def test_underscore_spelling_and_extras_are_refused(tmp_path: Path) -> None:
    assert fr.lint(project(tmp_path, '["agent_evidence_observer[done]==0.1.0"]'))


def test_ranges_and_third_party_pins_pass(tmp_path: Path) -> None:
    assert fr.lint(project(tmp_path, '["probity-verify~=0.2.1", "mcp==2.3.0", "jcs-admit>=0.1"]')) == []


def test_frozen_interop_experiments_may_pin(tmp_path: Path) -> None:
    d = tmp_path / "packages" / "observer" / "interop" / "run-2026-10-03"
    d.mkdir(parents=True)
    (d / "pyproject.toml").write_text('[project]\nname="y"\nversion="1"\ndependencies=["agent-evidence-observer==0.1.0"]\n', encoding="utf-8")
    assert fr.lint(tmp_path) == []


def test_resolve_pins_every_member_to_its_latest_release() -> None:
    latest = {name: f"9.{i}.0" for i, name in enumerate(fr.FAMILY)}
    specs = fr.pinned_specs(latest)
    assert len(specs) == len(fr.FAMILY)
    assert all(spec.endswith(f"=={latest[name]}") for spec, name in zip(specs, fr.FAMILY, strict=True))
    assert "agent-evidence-observer[done,witness]==9.3.0" in specs
