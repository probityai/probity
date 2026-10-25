"""The distribution check refuses private files and names, and the build runs from a clean export."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dist_clean = _load("check_dist_clean", "check-dist-clean.py")
build_from_tag = _load("build_from_tag", "build-from-tag.py")
workspace = _load("workspace_for_dist_clean", "workspace.py")

ALLOW = {"sdist": ["PKG-INFO", "pyproject.toml", "src/*"], "wheel": ["pkg/*", "pkg-*.dist-info/*"]}
BASE = {"PKG-INFO": b"Name: pkg\n", "pyproject.toml": b"[project]\n", "src/pkg/__init__.py": b"x = 1\n"}


def _sdist(tmp_path: Path, files: dict[str, bytes], name: str = "pkg-1.0.tar.gz") -> Path:
    target = tmp_path / name
    with tarfile.open(target, "w:gz") as tar:
        for rel, data in files.items():
            info = tarfile.TarInfo(f"pkg-1.0/{rel}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return target


def _wheel(tmp_path: Path, files: dict[str, bytes]) -> Path:
    target = tmp_path / "pkg-1.0-py3-none-any.whl"
    with zipfile.ZipFile(target, "w") as z:
        for rel, data in files.items():
            z.writestr(rel, data)
    return target


def test_clean_sdist_passes(tmp_path):
    assert dist_clean.scan(_sdist(tmp_path, BASE), ALLOW) == []


def test_planted_todo_fails(tmp_path):
    found = dist_clean.scan(_sdist(tmp_path, {**BASE, "TODO.md": b"- [ ] anything\n"}), ALLOW)
    assert any("private file TODO.md" in line for line in found)


@pytest.mark.parametrize("path", ["research/1/a.txt", ".handoff/entries/a.md", ".claude/state.lock", "CLAUDE.md",
                                  "docs/TODO-2026.md", "private/x.txt", ".env"])
def test_private_paths_fail(tmp_path, path):
    assert dist_clean.scan(_sdist(tmp_path, {**BASE, path: b"x\n"}), ALLOW)


def test_docs_research_directory_is_not_private(tmp_path):
    assert dist_clean.scan(_sdist(tmp_path, {**BASE, "docs/research/a.md": b"x\n"}), None) == []


@pytest.mark.parametrize("name", ["private-name-a", "private-name-b", "private-name-c", "private-name-d",
                                  "private-name-e", "private-name-f", "private-name-g", "private-name-b"])
def test_private_names_in_content_fail(tmp_path, name):
    found = dist_clean.scan(_sdist(tmp_path, {**BASE, "src/pkg/a.py": f"# see {name}\n".encode()}), ALLOW)
    assert len(found) == 1 and ":2:" not in found[0] and "a.py:1:" in found[0]


def test_unlisted_file_fails(tmp_path):
    found = dist_clean.scan(_sdist(tmp_path, {**BASE, "extra/notes.txt": b"x\n"}), ALLOW)
    assert any("not on the sdist allowlist" in line for line in found)


def test_wheel_is_checked_by_its_own_allowlist(tmp_path):
    clean = {"pkg/__init__.py": b"x = 1\n", "pkg-1.0.dist-info/METADATA": b"Name: pkg\n"}
    assert dist_clean.scan(_wheel(tmp_path, clean), ALLOW) == []
    assert dist_clean.scan(_wheel(tmp_path, {**clean, "stray.py": b"x\n"}), ALLOW)


def test_command_exits_one_on_a_planted_file_and_zero_when_clean(tmp_path):
    allow = tmp_path / "allow.toml"
    allow.write_text('[distribution.pkg]\nsdist = ["PKG-INFO", "pyproject.toml", "src/*"]\n')

    def run(path: Path) -> int:
        return subprocess.run([sys.executable, "-I", str(SCRIPTS / "check-dist-clean.py"), "--allowlist", str(allow),
                               "--distribution", "pkg", str(path)], check=False, capture_output=True).returncode

    assert run(_sdist(tmp_path, BASE, "a-1.0.tar.gz")) == 0
    assert run(_sdist(tmp_path, {**BASE, "TODO.md": b"x\n"}, "b-1.0.tar.gz")) == 1
    assert run(tmp_path / "missing.tar.gz") == 2


def test_every_workspace_member_has_an_allowlist():
    names = set(workspace.members())
    import tomllib
    listed = set(tomllib.loads((SCRIPTS / "dist-allowlist.toml").read_text())["distribution"])
    assert names <= listed, f"add [distribution.*] tables for {sorted(names - listed)}"


def test_export_of_a_tag_carries_tracked_files_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "tag.gpgSign=false",
                        "-c", "commit.gpgSign=false", *args], cwd=repo, check=True,
                       capture_output=True)

    git("init", "-q")
    (repo / "pyproject.toml").write_text("[project]\n")
    git("add", "pyproject.toml")
    git("commit", "-q", "-m", "init")
    git("tag", "pkg-v0.1.0")
    (repo / ".git" / "info" / "exclude").write_text("TODO.md\n")
    (repo / "TODO.md").write_text("private\n")
    (repo / "scratch.txt").write_text("untracked\n")
    dest = tmp_path / "export"
    build_from_tag.export_tag("pkg-v0.1.0", dest, repo)
    assert sorted(p.name for p in dest.iterdir()) == ["pyproject.toml"]
