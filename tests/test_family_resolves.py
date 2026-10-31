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
    assert fr.lint(project(tmp_path, '["probity-verify>=0.2.1,<0.4", "mcp==2.3.0", "jcs-admit>=0.1"]')) == []


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


def members(tmp_path: Path, verify: str, deps: str) -> Path:
    """A tree holding probity-verify at `verify` and one dependent with `deps`."""
    for name, version, dependencies in (("probity-verify", verify, "[]"), ("probityai", "0.1.0", deps)):
        d = tmp_path / "packages" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="{version}"\ndependencies={dependencies}\n', encoding="utf-8"
        )
    return tmp_path


def test_window_ceiling_is_the_end_of_the_next_series() -> None:
    assert fr.window_ceiling((0, 3, 0)) == (0, 5)
    assert fr.window_ceiling((0, 3, 7)) == (0, 5)
    assert fr.window_ceiling((1, 4, 2)) == (2, 0)


def test_window_over_the_current_and_next_series_passes(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["probity-verify>=0.3.0,<0.5"]')) == []


def test_a_compatible_release_range_on_a_member_is_refused(tmp_path: Path) -> None:
    """The failure this policy exists for: ~=0.3.0 excluded 0.4 the day verify released it."""
    problems = fr.lint(members(tmp_path, "0.3.0", '["probity-verify~=0.3.0"]'))
    assert problems and "window" in problems[0]


def test_a_window_that_does_not_move_with_the_member_is_refused(tmp_path: Path) -> None:
    """Verify at 0.4.0 makes <0.5 stale: the bump must move every dependent in the same change."""
    problems = fr.lint(members(tmp_path, "0.4.0", '["probity-verify>=0.3.0,<0.5"]'))
    assert problems and "<0.6" in problems[0]


def test_a_window_wider_than_the_next_series_is_refused(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["probity-verify>=0.3.0,<1"]'))
    assert fr.lint(members(tmp_path, "0.3.0", '["probity-verify>=0.3.0"]'))


def test_a_floor_above_the_tree_is_refused(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["probity-verify>=0.4.0,<0.5"]'))


def test_a_member_from_one_point_zero_spans_one_major(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "1.2.0", '["probity-verify>=1.0.0,<2"]')) == []
    assert fr.lint(members(tmp_path, "1.2.0", '["probity-verify>=1.0.0,<3"]'))


def test_a_family_member_outside_the_tree_keeps_the_compatible_release(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["agent-evidence-vectors~=0.30.0"]')) == []


def test_the_real_tree_passes() -> None:
    assert fr.lint() == []
