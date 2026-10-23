"""The verifier is our pinned public package, not a copy: assert the exact pins and that they run.

Every expected version is read from the manifest this package ships, so a bump that moves the pin
and the lock together passes, and a bump that moves only one of them fails.
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

ROOT = Path(__file__).resolve().parents[2]
PYPI = {"registry": "https://pypi.org/simple"}


def pinned(name: str) -> str:
    """The exact version `pyproject.toml` pins `name` to; anything but one `==` pin fails."""
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    named = [dep for dep in deps if re.match(rf"{re.escape(name)}\s*[=<>!~ ;\[]", dep)]
    assert len(named) == 1, f"{name} must appear once in [project].dependencies, found {named}"
    match = re.fullmatch(rf"{re.escape(name)}==([0-9][0-9A-Za-z.+-]*)", named[0])
    assert match, f"{name} must be pinned exactly, found {named[0]!r}"
    return match.group(1)


def locked(name: str) -> dict[str, Any]:
    """The single `uv.lock` entry for `name`, which must be the version the manifest pins."""
    packages = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]
    entries = [pkg for pkg in packages if pkg["name"] == name]
    assert len(entries) == 1, f"uv.lock must hold one {name}, found {len(entries)}"
    (entry,) = entries
    assert entry["version"] == pinned(name)
    return entry


def assert_hash_pinned_from_pypi(entry: dict[str, Any]) -> None:
    assert entry["source"] == PYPI
    files = [entry["sdist"], *entry.get("wheels", [])]
    assert all(f["hash"].startswith("sha256:") for f in files)
    assert entry.get("wheels"), "the lock must name a wheel, so the image builds none"


def test_probity_verify_is_the_hash_pinned_release_from_pypi() -> None:
    dist = metadata.distribution("probity-verify")
    assert dist.version == pinned("probity-verify")
    assert dist.read_text("direct_url.json") is None  # from the index, not a git checkout or a path
    assert_hash_pinned_from_pypi(locked("probity-verify"))


def test_the_demo_image_build_installs_no_system_package() -> None:
    dockerfile = (ROOT / "docker/demo.Dockerfile").read_text(encoding="utf-8")
    assert "dnf " not in dockerfile and "apt-get" not in dockerfile and "microdnf" not in dockerfile


def test_agent_evidence_vectors_is_pinned_from_pypi() -> None:
    dist = metadata.distribution("agent-evidence-vectors")
    assert dist.version == pinned("agent-evidence-vectors")
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


@pytest.mark.parametrize("name", ["probity-verify", "agent-evidence-vectors", "jcs-admit"])
def test_a_pin_the_lock_lacks_fails(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A manifest pin that moved without the lock (or the reverse) is refused, not read past."""
    manifest = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    old = f'"{name}=={pinned(name)}"'
    (tmp_path / "pyproject.toml").write_text(manifest.replace(old, f'"{name}==999.0.0"'), encoding="utf-8")
    (tmp_path / "uv.lock").write_bytes((ROOT / "uv.lock").read_bytes())
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    with pytest.raises(AssertionError):
        locked(name)
