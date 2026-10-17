"""Read the workspace members, and map changes and release tags onto them.

    python3 scripts/workspace.py changes <base> <head>   # JSON {member: true|false}
    python3 scripts/workspace.py release-target <tag>    # JSON {distribution, directory, version, environment}
    python3 scripts/workspace.py requires <distribution> # member directories it needs, itself last

Members are the directories under packages/ that hold a pyproject.toml. A member
is changed when a file under its directory changed, when a workspace member it
depends on changed, or when a shared file changed (anything outside packages/,
except documentation). The rules live here and nowhere else, so CI and tests
read the same answer. Standard library only: CI runs it before any install.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
_SHARED_IGNORED = re.compile(r"(docs/.*|[^/]+\.md|LICENSE)\Z")
_TAG = re.compile(r"(?P<dist>[a-z0-9][a-z0-9-]*?)-v(?P<version>\d+\.\d+\.\d+)\Z")


@dataclass(frozen=True)
class Member:
    distribution: str
    directory: str
    version: str
    requires: frozenset[str]


def _name(requirement: str) -> str:
    return re.split(r"[\s<>=!~;\[(]", requirement, maxsplit=1)[0].lower().replace("_", "-")


def members(root: Path = ROOT) -> dict[str, Member]:
    """Return every member by distribution name."""
    found = {}
    for manifest in sorted((root / "packages").glob("*/pyproject.toml")):
        project = tomllib.loads(manifest.read_text())["project"]
        name = project["name"]
        if name in found:
            raise SystemExit(f"two members declare the distribution {name!r}")
        found[name] = Member(name, manifest.parent.relative_to(root).as_posix(), project["version"],
                             frozenset(_name(r) for r in project.get("dependencies", [])))
    return found


def changed(paths: list[str], root: Path = ROOT) -> dict[str, bool]:
    """Return, for each member, whether these changed paths require its checks."""
    table = members(root)
    shared = any(not p.startswith("packages/") and not _SHARED_IGNORED.match(p) for p in paths)
    result = {name: shared or any(PurePosixPath(p).is_relative_to(m.directory) for p in paths)
              for name, m in table.items()}
    grew = True
    while grew:
        grew = False
        for name, member in table.items():
            if not result[name] and any(result.get(dep) for dep in member.requires):
                result[name] = grew = True
    return result


def release_target(tag: str, root: Path = ROOT) -> dict[str, str]:
    """Resolve a release tag ``<distribution>-v<version>`` to the member it releases."""
    match = _TAG.match(tag)
    if not match:
        raise SystemExit(f"release tag {tag!r} is not <distribution>-v<major>.<minor>.<patch>")
    table = members(root)
    member = table.get(match["dist"])
    if member is None:
        raise SystemExit(f"release tag {tag!r} names no workspace member (members: {', '.join(table)})")
    if member.version != match["version"]:
        raise SystemExit(f"release tag {tag!r} does not match {member.directory} version {member.version}")
    return {"distribution": member.distribution, "directory": member.directory,
            "version": member.version, "environment": f"pypi-{member.distribution}"}


def requires(distribution: str, root: Path = ROOT) -> list[str]:
    """Return the directories of every workspace member ``distribution`` needs, itself last."""
    table = members(root)
    if distribution not in table:
        raise SystemExit(f"{distribution!r} is not a workspace member")
    order: list[str] = []

    def visit(name: str) -> None:
        for dep in sorted(table[name].requires & table.keys()):
            visit(dep)
        if table[name].directory not in order:
            order.append(table[name].directory)

    visit(distribution)
    return order


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "changes":
        diff = subprocess.run(["git", "diff", "--name-only", f"{argv[1]}...{argv[2]}"], cwd=ROOT,
                              check=True, capture_output=True, text=True).stdout.split()
        print(json.dumps(changed(diff), sort_keys=True))
        return 0
    if len(argv) == 2 and argv[0] == "release-target":
        print(json.dumps(release_target(argv[1]), sort_keys=True))
        return 0
    if len(argv) == 2 and argv[0] == "requires":
        print("\n".join(requires(argv[1])))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
