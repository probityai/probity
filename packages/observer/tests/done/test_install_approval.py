"""Real-filesystem tests for pinned installation approval."""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from probity_observer.done.install_approval import (
    IDENTITY, INSTALL, OPTIONS, Approval, Installation, Mount, Observation,
    Runtime, Source, Startup, approve,
)

PYTHON = "/opt/bin/python"
SITE = "/opt/site"
OVERRIDE = "/opt/bin/python._pth"


def _put(root: Path, path: str, data: bytes) -> None:
    node = root / path.lstrip("/")
    node.parent.mkdir(parents=True, exist_ok=True)
    node.write_bytes(data)


def _pins(root: Path) -> dict[str, Source]:
    found = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for node in (Path(directory), *(Path(directory) / name for name in dirs + files)):
            name = "/" + node.relative_to(root).as_posix()
            if node.is_symlink():
                found[name] = Source("link", target=os.readlink(node))
            elif node.is_dir():
                found[name] = Source("dir")
            else:
                found[name] = Source("file", hashlib.sha256(node.read_bytes()).hexdigest())
    return found


def _case(root: Path, argv: tuple[str, ...] = (PYTHON, "-I", "-c", "pass"),
          *, submitted: str | None = None
          ) -> tuple[Installation, Observation, Runtime]:
    digest = hashlib.sha256((root / PYTHON.lstrip("/")).read_bytes()).hexdigest()
    worker = 65534 if os.getuid() != 65534 else 65533
    mounts = (Mount("/", "sealed-image", "overlay", True),)
    startup = Startup("cpython", PYTHON, digest, ("/opt/bin", "/opt/lib", SITE),
                      dependencies=("/opt/ld.so", "/opt/lib/libc.so"),
                      site_dirs=(SITE,), override_candidates=(OVERRIDE,))
    installation = Installation("externally-pinned", "3.12", {digest: startup},
                                _pins(root), mounts)
    observation = Observation(PYTHON, digest, tuple(arg.encode() for arg in argv),
                              {"PYTHONNOUSERSITE": "1"}, submitted)
    runtime = Runtime(root, mounts, worker, (), ("/workspace", "/tmp"))
    return installation, observation, runtime


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """Make a small, real startup tree with pinned loader and library files."""
    _put(tmp_path, PYTHON, b"pinned executable")
    _put(tmp_path, "/opt/ld.so", b"loader")
    _put(tmp_path, "/opt/lib/libc.so", b"library")
    _put(tmp_path, "/opt/lib/os.py", b"stdlib")
    (tmp_path / SITE.lstrip("/")).mkdir()
    return tmp_path


@pytest.mark.parametrize(("argv", "reason"), [
    ((PYTHON, "-P", "-c", "pass"), None),
    ((PYTHON, "-PE", "-c", "pass"), OPTIONS),
    ((PYTHON, "-PEs", "-c", "pass"), None),
    ((PYTHON, "-PES", "-c", "pass"), None),
    ((PYTHON, "-c", "print('-I')"), OPTIONS),
    ((PYTHON, "-W", "ignore:-I", "-c", "pass"), OPTIONS),
    ((PYTHON, "-X", "dev=-I", "-c", "pass"), OPTIONS),
    ((PYTHON, "script.py", "-I"), OPTIONS),
    ((PYTHON, "-Z", "-I", "-c", "pass"), OPTIONS),
])
def test_effective_cpython_options(tree: Path, argv: tuple[str, ...],
                                   reason: str | None) -> None:
    installation, observation, runtime = _case(tree, argv)
    assert approve(installation, observation, runtime) == Approval("cpython", reason)


@pytest.mark.parametrize("line", [b"import attack\n", b"import\tattack\n",
                                  b"../../workspace/late.zip\n", b"/tmp/late.zip\n"])
def test_processed_pth_refuses_code_and_writable_destinations(
        tree: Path, line: bytes) -> None:
    _put(tree, SITE + "/extra.pth", line)
    installation, observation, runtime = _case(tree)
    assert approve(installation, observation, runtime).reason == INSTALL


def test_immutable_archive_in_pth(tree: Path) -> None:
    _put(tree, SITE + "/extra.pth", b"packages.zip\n")
    _put(tree, SITE + "/packages.zip", b"pinned archive")
    installation, observation, runtime = _case(tree)
    assert approve(installation, observation, runtime).reason is None


def test_symlink_to_writable_startup_path(tree: Path) -> None:
    _put(tree, SITE + "/extra.pth", b"linked.zip\n")
    (tree / (SITE + "/linked.zip").lstrip("/")).symlink_to("/workspace/new.zip")
    installation, observation, runtime = _case(tree)
    assert approve(installation, observation, runtime).reason == INSTALL


def test_poisoned_read_only_image_and_changed_mount(tree: Path) -> None:
    installation, observation, runtime = _case(tree)
    _put(tree, "/opt/lib/os.py", b"poisoned")
    assert approve(installation, observation, runtime).reason == INSTALL
    clean, observation, runtime = _case(tree)
    changed = replace(runtime, mounts=(Mount("/", "other-image", "overlay", True),))
    assert approve(clean, observation, changed).reason == INSTALL


def test_writable_venv_even_with_I(tree: Path) -> None:
    (tree / "workspace/.venv").mkdir(parents=True)
    installation, observation, runtime = _case(tree)
    image = installation.images[observation.sha256]
    image = replace(image, venv_prefixes=("/workspace/.venv",))
    installation = replace(installation, images={observation.sha256: image})
    assert approve(installation, observation, runtime).reason == INSTALL


def test_direct_shebang_uses_effective_argv(tree: Path) -> None:
    script = "/opt/bin/check"
    _put(tree, script, b"#!/opt/bin/python -I\npass\n")
    installation, observation, runtime = _case(tree, (PYTHON, "-I", script),
                                                submitted=script)
    assert approve(installation, observation, runtime).reason is None
    changed = replace(observation, argv=(PYTHON.encode(), script.encode()))
    assert approve(installation, changed, runtime).reason == IDENTITY


def test_override_and_unapproved_hook(tree: Path) -> None:
    _put(tree, OVERRIDE, b"../lib\n")
    installation, observation, runtime = _case(tree)
    image = replace(installation.images[observation.sha256], override=OVERRIDE)
    installation = replace(installation, images={observation.sha256: image})
