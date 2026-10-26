"""The verifier is our public package, not a copy: assert the ranges, the lock and that they run.

Each in-family dependency is a compatible-release range (`~=X.Y.Z`), so the family installs together at
its latest releases. The lock names one version per package, from the index with a hash per file. The
tests hold the lock to the range and the installed package to the lock: a bump that moves only one of
them fails.
"""

from __future__ import annotations

import re
import sys
import tomllib
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_vectors.run_vectors import main as vectors_main  # type: ignore[import-untyped]
from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[2]
PYPI = {"registry": "https://pypi.org/simple"}


def requirement(name: str) -> Requirement:
    """The one `[project].dependencies` entry for `name`, which must be a compatible-release range."""
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    named = [dep for dep in deps if re.match(rf"{re.escape(name)}\s*[=<>!~ ;\[]", dep)]
    assert len(named) == 1, f"{name} must appear once in [project].dependencies, found {named}"
    req = Requirement(named[0])
    assert re.fullmatch(r"~=[0-9]+\.[0-9]+\.[0-9]+", str(req.specifier)), (
        f"{name} must take a compatible release (~=X.Y.Z), found {named[0]!r}"
    )
    return req


def locked(name: str) -> dict[str, Any]:
    """The single `uv.lock` entry for `name`, whose version the manifest range must admit."""
    packages = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]
    entries = [pkg for pkg in packages if pkg["name"] == name]
    assert len(entries) == 1, f"uv.lock must hold one {name}, found {len(entries)}"
    (entry,) = entries
    assert requirement(name).specifier.contains(Version(entry["version"])), (
        f"uv.lock holds {name} {entry['version']}, outside {requirement(name).specifier}"
    )
    return entry


def assert_hash_pinned_from_pypi(entry: dict[str, Any]) -> None:
    assert entry["source"] == PYPI
    files = [entry["sdist"], *entry.get("wheels", [])]
    assert all(f["hash"].startswith("sha256:") for f in files)
    assert entry.get("wheels"), "the lock must name a wheel, so the image builds none"


def test_probity_verify_is_the_hash_pinned_release_from_pypi() -> None:
    dist = metadata.distribution("probity-verify")
    assert dist.version == locked("probity-verify")["version"]
    assert dist.read_text("direct_url.json") is None  # from the index, not a git checkout or a path
    assert_hash_pinned_from_pypi(locked("probity-verify"))


def test_the_demo_image_build_installs_no_system_package() -> None:
    dockerfile = (ROOT / "docker/demo.Dockerfile").read_text(encoding="utf-8")
    assert "dnf " not in dockerfile and "apt-get" not in dockerfile and "microdnf" not in dockerfile


def test_agent_evidence_vectors_is_pinned_from_pypi() -> None:
    dist = metadata.distribution("agent-evidence-vectors")
    assert dist.version == locked("agent-evidence-vectors")["version"]
    assert dist.read_text("direct_url.json") is None
    assert_hash_pinned_from_pypi(locked("agent-evidence-vectors"))


def test_pinned_vector_harness_self_test_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["agent-evidence-vectors", "--self-test"])
    assert vectors_main() == 0


def test_jcs_admit_is_the_hash_pinned_release_from_pypi() -> None:
    """The lock takes jcs-admit from the index, with a hash per file, and the image builds no wheel."""
    assert_hash_pinned_from_pypi(locked("jcs-admit"))
    dockerfile = (ROOT / "docker/demo.Dockerfile").read_text(encoding="utf-8")
    assert "JCS_ADMIT_COMMIT" not in dockerfile and "rustup" not in dockerfile


FAMILY = ["probity-verify", "agent-evidence-vectors", "jcs-admit"]


@pytest.mark.parametrize("name", FAMILY)
def test_a_range_the_lock_falls_outside_fails(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A manifest range that moved without the lock (or the reverse) is refused, not read past."""
    manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    old = f'"{name}{requirement(name).specifier}"'
    (tmp_path / "pyproject.toml").write_text(manifest.replace(old, f'"{name}~=999.0.0"'), encoding="utf-8")
    (tmp_path / "uv.lock").write_bytes((ROOT / "uv.lock").read_bytes())
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    with pytest.raises(AssertionError):
        locked(name)


@pytest.mark.parametrize("name", [*FAMILY, "probity-ratchet-cases"])
def test_an_exact_in_family_pin_is_refused(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The family installs together only while no member pins another exactly."""
    manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    old = f'"{name}{requirement(name).specifier}"'
    version = str(requirement(name).specifier)[2:]
    (tmp_path / "pyproject.toml").write_text(manifest.replace(old, f'"{name}=={version}"'), encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    with pytest.raises(AssertionError):
        requirement(name)
