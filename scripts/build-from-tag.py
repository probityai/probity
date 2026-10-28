#!/usr/bin/env python3
"""Build a member's release files from a clean export of its release tag.

    python3 scripts/build-from-tag.py <distribution>-v<version> [--out DIR]

A release is built from the tag's committed tree and from nothing else. The tree is exported
with `git archive`, which carries tracked files only: no untracked file, no ignored file, no
`.git/info/exclude` entry and no tool state from the working tree it was run in. The member
and every workspace member it needs are then built from that export the way
.github/workflows/python-build.yml builds them, and the result is refused unless
scripts/check-dist-clean.py passes it, which needs DIST_CLEAN_PRIVATE_NAMES set in the
environment exactly as CI sets it from its secret. Use this for any build that does not run in CI; the
published files come from CI (release.yml), which builds from a fresh checkout and runs the same check.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def export_tag(tag: str, dest: Path, repo: Path = ROOT) -> str:
    """Write the tracked files of ``tag`` into ``dest`` and return the commit they came from."""
    commit = subprocess.run(["git", "rev-parse", "--verify", f"{tag}^{{commit}}"], cwd=repo, check=True,
                            capture_output=True, text=True).stdout.strip()
    archive = subprocess.run(["git", "archive", "--format=tar", commit], cwd=repo, check=True,
                             capture_output=True).stdout
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    return commit


def _run(cmd: list[str], cwd: Path, env: dict[str, str]) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True, env=env).stdout


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tag")
    ap.add_argument("--out", type=Path, default=Path("dist"))
    args = ap.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="release-export-") as tmp:
        tree = Path(tmp)
        commit = export_tag(args.tag, tree)
        env = {**os.environ, "PYTHONHASHSEED": "0",
               "SOURCE_DATE_EPOCH": _run(["git", "show", "-s", "--format=%ct", commit], ROOT, os.environ).strip()}
        target = json.loads(_run([sys.executable, "scripts/workspace.py", "release-target", args.tag],
                                               tree, env))
        dirs = _run([sys.executable, "scripts/workspace.py", "requires", target["distribution"]], tree, env).split()
        out = args.out.resolve()
        out.mkdir(parents=True, exist_ok=True)
        for directory in dirs:
            built = out if directory == dirs[-1] else tree / "dependencies"
            _run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(built), directory], tree, env)
        files = sorted(str(p) for p in out.iterdir() if p.suffix == ".whl" or p.name.endswith(".tar.gz"))
        check = subprocess.run([sys.executable, "scripts/check-dist-clean.py", "--allowlist",
                                "scripts/dist-allowlist.toml", "--distribution", target["distribution"], *files],
                               cwd=tree, check=False)
        if check.returncode:
            print(f"REFUSED: {args.tag} built from {commit} fails the distribution check", file=sys.stderr)
            return check.returncode
        print(f"built {target['distribution']} {target['version']} from {commit} into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
