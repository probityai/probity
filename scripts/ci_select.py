"""Decide which CI jobs a change needs, for the `changes` job of .github/workflows/ci.yml.

    python3 scripts/ci_select.py <event> <base> <head>

Prints `members=`, `rust=`, `runner=`, `plugins=` and `jobs=` lines for $GITHUB_OUTPUT.
`jobs` is a JSON object with one boolean per entry of scripts/ci_jobs.toml.

The events:
  pull_request   the fast tier: jobs whose paths changed between <base> and <head>
  merge_group    the full tier for one batch: the same selection over the batch's diff, plus
                 the jobs marked tier = "full"
  push           the merge-queue answer again for a direct push; every job when <base> is
                 unknown (a new branch or a rewritten history)
  workflow_dispatch  every job
  schedule       only the jobs marked schedule = true

A change to ci.yml, this script or ci_jobs.toml selects every job, and so does a change the
workspace map treats as shared (see scripts/workspace.py). Standard library only: CI runs it
before any install.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVERYTHING = frozenset({".github/workflows/ci.yml", "scripts/ci_select.py", "scripts/ci_jobs.toml"})
_RUST = re.compile(r"(crates/|Cargo\.(toml|lock)\Z|\.github/)")
_RUNNER = re.compile(r"(examples/checkout-runner/|\.github/workflows/ci\.yml\Z)")
# The plugins are a harness, not a workspace member: their files decide alone.
_PLUGINS = re.compile(r"(harnesses/agent-evidence-plugins/|\.claude-plugin/|\.github/workflows/ci\.yml\Z)")


def _workspace():
    spec = importlib.util.spec_from_file_location("workspace", ROOT / "scripts/workspace.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("workspace", module)
    spec.loader.exec_module(module)
    return module


@lru_cache(maxsize=None)
def glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a GitHub path-filter glob: `**` crosses slashes, `*` and `?` do not."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def table(root: Path = ROOT) -> dict[str, dict]:
    return tomllib.loads((root / "scripts/ci_jobs.toml").read_text())["jobs"]


def select_jobs(event: str, paths: list[str] | None, jobs: dict[str, dict]) -> dict[str, bool]:
    """Return, per job, whether it runs. `paths` is None when the change is unknown."""
    if event == "schedule":
        return {name: bool(job.get("schedule")) for name, job in jobs.items()}
    everything = event == "workflow_dispatch" or paths is None or any(p in EVERYTHING for p in paths)
    chosen = {}
    for name, job in jobs.items():
        hit = everything or any(glob_regex(g).match(p) for g in job["paths"] for p in paths)
        chosen[name] = hit and (event != "pull_request" or job["tier"] == "fast")
    return chosen


def changed_paths(base: str, head: str) -> list[str] | None:
    """The paths changed between base and head, or None when base is not a known commit."""
    if not base or set(base) == {"0"}:
        return None
    known = subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=ROOT, capture_output=True)
    if known.returncode:
        return None
    return subprocess.run(["git", "diff", "--name-only", f"{base}...{head}"], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.split()


def select(event: str, base: str, head: str) -> dict[str, object]:
    workspace = _workspace()
    jobs = table()
    paths = None if event in ("workflow_dispatch", "schedule") else changed_paths(base, head)
    if event == "schedule":
        members = {name: False for name in workspace.members()}
    elif paths is None:
        members = {name: True for name in workspace.members()}
    else:
        members = workspace.changed(paths)
    everything = paths is None and event != "schedule"
    flags = {
        "rust": everything or any(_RUST.match(p) for p in paths or []),
        "runner": everything or any(_RUNNER.match(p) for p in paths or []),
        "plugins": everything or any(_PLUGINS.match(p) for p in paths or []),
    }
    return {"members": members, **flags, "jobs": select_jobs(event, paths, jobs)}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    result = select(*argv)
    for key, value in result.items():
        print(f"{key}={json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
