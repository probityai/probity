"""Tests for the workspace change map and the release-tag resolver."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("workspace", Path(__file__).parents[1] / "scripts/workspace.py")
workspace = importlib.util.module_from_spec(_spec)
sys.modules["workspace"] = workspace
_spec.loader.exec_module(workspace)


def _member(root: Path, directory: str, name: str, version: str, deps: list[str]) -> None:
    path = root / "packages" / directory
    path.mkdir(parents=True)
    quoted = ", ".join(f'"{d}"' for d in deps)
    (path / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\ndependencies = [{quoted}]\n')


@pytest.fixture
def root(tmp_path):
    _member(tmp_path, "lib", "base-lib", "1.2.3", [])
    _member(tmp_path, "cli", "front", "0.1.0", ["base_lib>=1.2", "cryptography>=50"])
    _member(tmp_path, "other", "other-tool", "0.0.1", [])
    return tmp_path


def test_a_member_change_selects_it_and_its_dependents(root):
    assert workspace.changed(["packages/lib/src/x.py"], root) == {
        "base-lib": True, "front": True, "other-tool": False}


def test_a_dependent_change_does_not_select_its_dependency(root):
    assert workspace.changed(["packages/cli/README.md"], root) == {
        "base-lib": False, "front": True, "other-tool": False}


def test_a_shared_file_selects_every_member(root):
    assert set(workspace.changed(["uv.lock"], root).values()) == {True}
    assert set(workspace.changed([".github/workflows/ci.yml"], root).values()) == {True}


def test_root_documentation_selects_no_member(root):
    assert set(workspace.changed(["README.md", "docs/architecture/MONOREPO.md"], root).values()) == {False}


def test_a_directory_prefix_is_not_a_member_match(root):
    assert workspace.changed(["packages/library/x.py"], root)["base-lib"] is False


def test_release_tag_resolves_the_member(root):
    assert workspace.release_target("base-lib-v1.2.3", root) == {
        "distribution": "base-lib", "directory": "packages/lib", "version": "1.2.3"}


@pytest.mark.parametrize("tag, message", [
    ("v1.2.3", "is not <distribution>-v"),
    ("base-lib-1.2.3", "is not <distribution>-v"),
    ("base-lib-v1.2", "is not <distribution>-v"),
    ("nobody-v1.0.0", "names no workspace member"),
    ("base-lib-v1.2.4", "does not match packages/lib version 1.2.3"),
])
def test_release_tag_refusals(root, tag, message):
    with pytest.raises(SystemExit, match=message):
        workspace.release_target(tag, root)


def test_duplicate_distribution_names_are_refused(root):
    _member(root, "dup", "front", "9.9.9", [])
    with pytest.raises(SystemExit, match="two members declare"):
        workspace.members(root)


def test_the_real_workspace_resolves():
    table = workspace.members()
    assert {"probity-verify", "probityai"} <= set(table)
    assert "probity-verify" in table["probityai"].requires


def test_requires_lists_workspace_dependencies_before_the_member(root):
    assert workspace.requires("front", root) == ["packages/lib", "packages/cli"]
    assert workspace.requires("base-lib", root) == ["packages/lib"]
    with pytest.raises(SystemExit, match="not a workspace member"):
        workspace.requires("nope", root)


def test_every_member_has_its_own_publish_job_in_environment_pypi():
    release = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    for name in workspace.members():
        job = release.split(f"  publish-{name}:\n", 1)
        assert len(job) == 2, f"release.yml has no publish-{name} job"
        body = job[1].split("\n  publish-", 1)[0]
        assert f"needs.resolve.outputs.distribution == '{name}'" in body
        assert "name: pypi\n" in body and f"name: python-distributions-{name}\n" in body


def test_a_package_that_is_its_own_workspace_brings_its_members(tmp_path):
    _member(tmp_path, "ratchet", "probity-ratchet", "0.2.0", ["probity-ratchet-cases==0.3.0"])
    manifest = tmp_path / "packages/ratchet/pyproject.toml"
    manifest.write_text(manifest.read_text() + '\n[tool.uv.workspace]\nmembers = ["cases"]\n')
    cases = tmp_path / "packages/ratchet/cases"
    cases.mkdir()
    (cases / "pyproject.toml").write_text('[project]\nname = "probity-ratchet-cases"\nversion = "0.3.0"\n')
    table = workspace.members(tmp_path)
    assert table["probity-ratchet-cases"].directory == "packages/ratchet/cases"
    assert workspace.changed(["packages/ratchet/cases/x.py"], tmp_path) == {
        "probity-ratchet": True, "probity-ratchet-cases": True}
    assert workspace.requires("probity-ratchet", tmp_path) == ["packages/ratchet/cases", "packages/ratchet"]


def test_a_hatch_dynamic_version_is_read_from_its_file(tmp_path):
    pkg = tmp_path / "packages/cases"
    (pkg / "src/cases").mkdir(parents=True)
    (pkg / "src/cases/__init__.py").write_text('__version__ = "0.4.1"\n')
    (pkg / "pyproject.toml").write_text(
        '[project]\nname = "cases"\ndynamic = ["version"]\n\n'
        '[tool.hatch.version]\npath = "src/cases/__init__.py"\n')
    assert workspace.members(tmp_path)["cases"].version == "0.4.1"


def test_a_distribution_whose_name_extends_another_resolves_to_itself(tmp_path):
    _member(tmp_path, "ratchet", "probity-ratchet", "0.2.0", [])
    _member(tmp_path, "ratchet-cases", "probity-ratchet-cases", "0.3.0", [])
    assert workspace.release_target("probity-ratchet-v0.2.0", tmp_path)["directory"] == "packages/ratchet"
    assert workspace.release_target("probity-ratchet-cases-v0.3.0", tmp_path)["directory"] == "packages/ratchet-cases"


def test_a_tag_must_sit_on_main_or_on_the_maintenance_branch_of_its_own_series():
    release = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    assert "git merge-base --is-ancestor HEAD origin/main" in release
    assert 'branch="origin/maint/${name}-${version%.*}"' in release
    assert 'git merge-base --is-ancestor HEAD "$branch"' in release
