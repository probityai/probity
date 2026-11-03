"""The replay parent's image: the verifier's own code and its own pytest, nothing of the task's.

A pytest replay runs the task's sealed tests and conftests under pytest in the parent
(:mod:`.pytest_replay`). The parent runs in a container of its own, so that code never runs in
the verifier's process or on the verifier's host. The image cannot be the task's: the task
author controls that image's pytest. It is built here from the files the verifier itself runs:
the ``probity_observer`` package as imported, and the installed files of every distribution the
observer and pytest need, copied onto a pinned Python base of the verifier's own minor version.
The image is tagged by the digest of that build context, so one verifier build gives one image,
and a changed verifier gives a new one.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .formats import DoneError

# The base each supported minor version builds on, pinned by digest (the same base as the
# test agent image).
BASES = {
    (3, 12): "python:3.12-slim-trixie@sha256:"
             "a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1",
}
# The distributions the parent imports: the observer's own (``python -m
# probity_observer.done.replay`` imports the package) and pytest, with what each requires.
ROOTS = ("agent-evidence-observer", "pytest")
PACKAGE = "probity_observer"
TAG = "probity-replay-parent"
SKIP = ("__pycache__",)


def base() -> str:
    found = BASES.get(sys.version_info[:2])
    if found is None:
        raise DoneError("no pinned replay parent base for Python "
                        f"{sys.version_info[0]}.{sys.version_info[1]}")
    return found


def closure(roots: tuple[str, ...] = ROOTS) -> list[metadata.Distribution]:
    """Every installed distribution ``roots`` need, with no extras, sorted by name."""
    from packaging.requirements import Requirement

    found: dict[str, metadata.Distribution] = {}
    todo = list(roots)
    while todo:
        name = todo.pop()
        key = name.lower().replace("_", "-")
        if key in found:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError as error:
            raise DoneError(f"the replay parent needs {name}, which is not installed") from error
        found[key] = dist
        for line in dist.requires or ():
            requirement = Requirement(line)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                todo.append(requirement.name)
    return [found[key] for key in sorted(found)]


def _copy_tree(source: Path, target: Path) -> None:
    shutil.copytree(source, target, symlinks=False, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(*SKIP, "*.pyc"))


def context(dest: Path) -> str:
    """Write the build context under ``dest`` and return its digest."""
    site = dest / "site"
    site.mkdir(parents=True)
    import probity_observer

    _copy_tree(Path(probity_observer.__file__).resolve().parent, site / PACKAGE)
    for dist in closure():
        if dist.metadata["Name"].lower() == ROOTS[0]:
            continue  # its code is the package copied above, however it was installed
        root = Path(dist.locate_file("")).resolve()
        for item in dist.files or ():
            path = Path(dist.locate_file(item)).resolve()
            if (root not in path.parents or not path.is_file() or path.suffix == ".pyc"
                    or any(part in SKIP for part in path.parts)):
                continue
            target = site / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    version = f"{sys.version_info[0]}.{sys.version_info[1]}"
    (dest / "Dockerfile").write_text(
        f"FROM {base()}\n"
        f"COPY site/ /usr/local/lib/python{version}/site-packages/\n"
        "USER 65534:65534\n")
    digest = hashlib.sha256()
    for path in sorted(dest.rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(dest)).encode() + b"\0")
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def ensure(docker: str = "docker") -> str:
    """The image id of the replay parent image for this verifier, built when missing."""
    with tempfile.TemporaryDirectory(prefix="probity-parent-image-") as work:
        digest = context(Path(work))
        tag = f"{TAG}:{digest[:20]}"
        found = subprocess.run([docker, "image", "inspect", "--format", "{{.Id}}", tag],
                               capture_output=True, text=True, check=False)
        if found.returncode != 0:
            built = subprocess.run([docker, "build", "-q", "-t", tag, work],
                                   capture_output=True, text=True, check=False)
            if built.returncode != 0:
                raise DoneError(f"cannot build the replay parent image: {built.stderr[-2000:]}")
            found = subprocess.run([docker, "image", "inspect", "--format", "{{.Id}}", tag],
                                   capture_output=True, text=True, check=False)
    if found.returncode != 0 or not found.stdout.strip().startswith("sha256:"):
        raise DoneError(f"cannot read the replay parent image id: {found.stderr.strip()}")
    return found.stdout.strip()
