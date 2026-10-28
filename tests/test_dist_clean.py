"""The distribution check refuses private files and names, and the build runs from a clean export."""

from __future__ import annotations

import importlib.util
import io
import os
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

# Made-up names with the shapes the real list has (an owner/repo path, a dotted host, a hyphenated
# package name). The real list is a CI secret and never appears in this repository.
FAKE_NAMES = "example-owner/private-repo\nprivate-pkg-name\nexample-private.invalid\n"
FAKE_SHA256 = dist_clean.names_digest(dist_clean.canonical_names(FAKE_NAMES))
NEEDLES = dist_clean.load_names(FAKE_NAMES, FAKE_SHA256)


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
    assert dist_clean.scan(_sdist(tmp_path, BASE), NEEDLES, ALLOW) == []


def test_planted_todo_fails(tmp_path):
    found = dist_clean.scan(_sdist(tmp_path, {**BASE, "TODO.md": b"- [ ] anything\n"}), NEEDLES, ALLOW)
    assert any("private file TODO.md" in line for line in found)


@pytest.mark.parametrize("path", ["research/1/a.txt", ".handoff/entries/a.md", ".claude/state.lock", "CLAUDE.md",
                                  "docs/TODO-2026.md", "private/x.txt", ".env"])
def test_private_paths_fail(tmp_path, path):
    assert dist_clean.scan(_sdist(tmp_path, {**BASE, path: b"x\n"}), NEEDLES, ALLOW)


def test_docs_research_directory_is_not_private(tmp_path):
    assert dist_clean.scan(_sdist(tmp_path, {**BASE, "docs/research/a.md": b"x\n"}), NEEDLES, None) == []


@pytest.mark.parametrize("text", [
    "# see example-owner/private-repo PR 43",
    "# git clone https://github.com/example-owner/private-repo.git",
    "# PRIVATE-PKG-NAME",
    "# https://example-private.invalid/x?y=1",
    "url = 'https://docs.example-private.invalid'",
])
def test_private_names_in_content_fail(tmp_path, text):
    found = dist_clean.scan(_sdist(tmp_path, {**BASE, "src/pkg/a.py": f"{text}\n".encode()}), NEEDLES, ALLOW)
    assert len(found) == 1 and ":2:" not in found[0] and "a.py:1:" in found[0]


def test_a_finding_names_the_entry_by_number_not_by_text(tmp_path):
    found = dist_clean.scan(_sdist(tmp_path, {**BASE, "src/pkg/a.py": b"x = 'private-pkg-name'\n"}), NEEDLES, ALLOW)
    assert found and all("private-pkg-name" not in line for line in found)
    assert "private name #" in found[0]


@pytest.mark.parametrize("text", [None, "", " \n\n", "example-owner/private-repo\n"])
def test_a_missing_empty_or_altered_list_fails_closed(text):
    with pytest.raises(dist_clean.NameListError):
        dist_clean.load_names(text, FAKE_SHA256)


def test_the_list_is_read_without_regard_to_case_order_or_blank_lines():
    shuffled = "\n  PRIVATE-PKG-NAME \n\nexample-private.invalid\nexample-owner/private-repo\n"
    assert dist_clean.load_names(shuffled, FAKE_SHA256) == NEEDLES


def test_the_pinned_digest_is_not_the_digest_of_the_test_names():
    assert dist_clean.PRIVATE_NAMES_SHA256 != FAKE_SHA256
    assert len(dist_clean.PRIVATE_NAMES_SHA256) == 64


def test_unlisted_file_fails(tmp_path):
    found = dist_clean.scan(_sdist(tmp_path, {**BASE, "extra/notes.txt": b"x\n"}), NEEDLES, ALLOW)
    assert any("not on the sdist allowlist" in line for line in found)


def test_wheel_is_checked_by_its_own_allowlist(tmp_path):
    clean = {"pkg/__init__.py": b"x = 1\n", "pkg-1.0.dist-info/METADATA": b"Name: pkg\n"}
    assert dist_clean.scan(_wheel(tmp_path, clean), NEEDLES, ALLOW) == []
    assert dist_clean.scan(_wheel(tmp_path, {**clean, "stray.py": b"x\n"}), NEEDLES, ALLOW)


def test_command_exits_one_on_a_planted_file_and_zero_when_clean(tmp_path):
    allow = tmp_path / "allow.toml"
    allow.write_text('[distribution.pkg]\nsdist = ["PKG-INFO", "pyproject.toml", "src/*"]\n')

    def run(path: Path, names: str | None = FAKE_NAMES, digest: str = FAKE_SHA256) -> int:
        env = {"PATH": os.environ.get("PATH", "")}
        if names is not None:
            env["DIST_CLEAN_PRIVATE_NAMES"] = names
        return subprocess.run([sys.executable, "-I", str(SCRIPTS / "check-dist-clean.py"), "--allowlist", str(allow),
                               "--distribution", "pkg", "--names-sha256", digest, str(path)], check=False,
                              capture_output=True, env=env).returncode

    clean = _sdist(tmp_path, BASE, "a-1.0.tar.gz")
    assert run(clean) == 0
    assert run(_sdist(tmp_path, {**BASE, "TODO.md": b"x\n"}, "b-1.0.tar.gz")) == 1
    assert run(_sdist(tmp_path, {**BASE, "src/x.py": b"# private-pkg-name\n"}, "c-1.0.tar.gz")) == 1
    assert run(tmp_path / "missing.tar.gz") == 2
    assert run(clean, names=None) == 2
    assert run(clean, names="") == 2
    assert run(clean, digest=dist_clean.PRIVATE_NAMES_SHA256) == 2


def test_self_test_passes():
    assert dist_clean._self_test() == 0


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
