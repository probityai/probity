"""Check current-source runtime locks against mandatory Observer metadata.

Run from the repository root with the owning test environment. These locks
serve the current source, not separately pinned historical Observer builds.
Installed environments must also pass their own pip check before a reader runs.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

EXEMPT = "runtime-locks.toml"
PATTERNS = ("*.lock", "requirements*.txt")


def runtime_locks(root: Path) -> list[Path]:
    """Every requirements file under interop/ outside retained runs, less declared exemptions.

    Discovery, not a list: a new profile lock is checked the day it lands, and a lock that never
    installs the observer must say so in runtime-locks.toml.
    """
    exempt = {item["path"] for item in tomllib.loads((root / "scripts" / EXEMPT).read_text())["exempt"]}
    interop = root / "interop"
    found = {p for pattern in PATTERNS for p in interop.rglob(pattern) if "retained" not in p.relative_to(interop).parts}
    missing = exempt - {p.relative_to(interop).as_posix() for p in found}
    if missing:
        raise SystemExit("exemption names no requirements file: " + ", ".join(sorted(missing)))
    return sorted(p for p in found if p.relative_to(interop).as_posix() not in exempt)


def main() -> None:
    """Refuse a missing or incompatible core pin before native qualification."""
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    requirements = [Requirement(value) for value in project["dependencies"]]
    locks = runtime_locks(root)
    for path in locks:
        selected = dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s;]+)", path.read_text(), re.MULTILINE))
        selected = {canonicalize_name(name): Version(version) for name, version in selected.items()}
        for requirement in requirements:
            if requirement.url is not None:
                raise SystemExit("core URL needs an explicit source decision: " + str(requirement))
            if requirement.marker is not None:
                raise SystemExit("core marker needs an explicit profile decision: " + str(requirement))
            version = selected.get(canonicalize_name(requirement.name))
            if version is None or version not in requirement.specifier:
                raise SystemExit(f"{path.relative_to(root)} omits core requirement {requirement}")
    print(f"{len(locks)} current-source runtime locks contain every mandatory Observer requirement")


if __name__ == "__main__":
    main()
