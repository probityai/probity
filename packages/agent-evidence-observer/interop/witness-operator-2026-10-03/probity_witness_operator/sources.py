"""Retain the selected installed core/profile source population only."""

from __future__ import annotations

import importlib.metadata as metadata
import json
from pathlib import Path

from .protocol import require, sha

PACKAGES = ("agent-evidence-observer", "probity-witness-operator-reference")


def installed_sources() -> dict[str, Path]:
    """Return every installed Python source file owned by the two selected wheels.

    Returns
    -------
    dict
        Relative installed module names and resolved source paths. Dependency
        and interpreter source are outside this selected population.
    """
    sources: dict[str, Path] = {}
    for name in PACKAGES:
        distribution = metadata.distribution(name)
        require(distribution.files is not None, "installed source population is missing")
        selected = {str(item): Path(distribution.locate_file(item)).resolve()
                    for item in distribution.files if str(item).endswith(".py")}
        require(bool(selected), "selected wheel has no installed Python source")
        sources.update(selected)
    return sources


def installed_map() -> dict[str, str]:
    """Hash exact source bytes for the selected installed wheel population."""
    return {name: sha(path.read_bytes()) for name, path in installed_sources().items()}


def retain_sources(directory: Path) -> dict[str, str]:
    """Copy selected installed source bytes before launching the producer."""
    sources = installed_sources()
    directory.mkdir()
    for name, path in sources.items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    return {name: sha(path.read_bytes()) for name, path in sources.items()}


def load_withheld(path: Path, directory: Path) -> dict[str, str]:
    """Read a retained copy's withheld-source record as names under one source directory.

    Parameters
    ----------
    path : Path
        JSON object mapping paths, relative to the record's own directory, to SHA-256.
    directory : Path
        Source directory of the retained packet that the names are made relative to.
    """
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict) and list(value) == sorted(value), "withheld source record is not a sorted object")
    base = directory.resolve().relative_to(path.resolve().parent).as_posix() + "/"
    return {name.removeprefix(base): digest for name, digest in value.items() if name.startswith(base)}


def _found(directory: Path) -> set[str]:
    """Name every regular file under a retained source directory."""
    return {str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()}


def _check_present(directory: Path, name: str, digest: str) -> None:
    """Require one present retained source to be a plain file with the selected bytes."""
    path = directory / name
    require(not path.is_symlink(), "retained source is a symlink")
    require(path.resolve().is_relative_to(directory.resolve()), "retained source escapes directory")
    require(sha(path.read_bytes()) == digest, "retained source bytes differ")


def verify_sources(directory: Path, expected: dict[str, str], withheld: dict[str, str] | None = None) -> None:
    """Refuse changes or additions to the retained physical source population.

    A selected name may be absent only when ``withheld`` lists it with exactly
    the selected digest; every present file must still match byte for byte.
    """
    withheld = withheld or {}
    found = _found(directory)
    require(found <= set(expected), "retained source population differs")
    for name in set(expected) - found:
        require(withheld.get(name) == expected[name], "retained source is absent without a matching withheld digest")
    for name in found:
        _check_present(directory, name, expected[name])
