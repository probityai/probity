#!/usr/bin/env python3
"""Fail a README that carries a package whose source is not in this repository.

Each package's version and download badge appears in exactly one place: the
repository that holds its source. A README package-table row, or a downloads
badge (assets/badges/dl-pypi-<name>.svg, pepy.tech/projects/<name>), for a
package with no packages/<name> directory here is a duplicate and fails.

Exit 0 when clean, 1 on a duplicate, 2 when the README cannot be read.
Standard library only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROW = re.compile(r"^\|\s*\[([A-Za-z0-9._-]+)\]\(.*\*\*\d")
BADGE = re.compile(r"dl-pypi-([A-Za-z0-9._-]+?)\.svg|pepy\.tech/projects/([A-Za-z0-9._-]+)")


def foreign(readme: Path, root: Path) -> list[str]:
    owned = {p.name for p in (root / "packages").iterdir() if p.is_dir()}
    found: list[str] = []
    for number, line in enumerate(readme.read_text(encoding="utf-8").splitlines(), start=1):
        names = []
        row = ROW.match(line)
        if row:
            names.append(row.group(1))
        names += [a or b for a, b in BADGE.findall(line)]
        for name in dict.fromkeys(names):
            if name not in owned:
                found.append(
                    f"{readme}:{number}: {name} has no packages/{name} here; "
                    "its version and downloads belong in the repository that holds its source"
                )
    return found


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    readme = Path(args[0] if args else "README.md")
    root = Path(args[1]) if len(args) > 1 else readme.resolve().parent
    try:
        failures = foreign(readme, root)
    except OSError as exc:
        print(f"readme-package-owner-lint: could not read {readme}: {exc}", file=sys.stderr)
        return 2
    if failures:
        print("\n".join(failures))
        return 1
    print(f"readme-package-owner-lint: {readme} passes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
