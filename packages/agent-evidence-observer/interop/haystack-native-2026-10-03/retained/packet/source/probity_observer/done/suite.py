"""The repository's own test suite: the node ids that pass every run on both states.

A contract for a repository task can seal the repository's existing tests as one trusted pass
command, ``guard-repo``. :func:`stable_nodes` measures which node ids qualify: each file's
tests are collected on the reference (or the start state when there is none), then run
:data:`STABILITY_RUNS` times on each state with the ``probity_outcome`` plugin, and a node id
is kept only when it passes every run.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any, Sequence

from . import pytest_plugins
from .runner import Runner

STABILITY_RUNS = 3
GUARD_ID = "guard-repo"


def clean_copy(state: Path, scratch: Path, name: str) -> Path:
    """A copy of ``state`` under ``scratch/name`` without ``__pycache__``."""
    target = scratch / name
    shutil.copytree(state, target, symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def outcome_argv(prefix: Sequence[str], args: Sequence[str]) -> tuple[str, ...]:
    """``prefix`` with the ``probity_outcome`` plugin and ``args``."""
    return tuple(prefix) + ("-p", "probity_outcome", *args)


def _collect(runner: Runner, state: Path, heldout: Path | None, prefix: Sequence[str],
             name: str, timeout: float) -> list[str]:
    printed: list[str] = []
    runner.run(state, tuple(prefix) + ("--collect-only", "--verbosity=-1", name), heldout, timeout,
               output=printed)
    return sorted({line.strip() for text in printed for line in text.splitlines()
                   if line.strip().startswith(name + "::")})


def stable_nodes(runner: Runner, start: Path, reference: Path, heldout: Path | None,
                 prefix: Sequence[str], files: Sequence[str], timeout: float
                 ) -> tuple[dict[str, list[str]], dict[str, float], list[dict[str, Any]]]:
    """Per file, the node ids that pass every run on both states; each node's seconds."""
    kept: dict[str, list[str]] = {}
    seconds: dict[str, float] = {}
    log: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="probity-suite-") as scratch:
        states = {"start": clean_copy(start, Path(scratch), "start"),
                  "reference": clean_copy(reference, Path(scratch), "reference")}
        for name in files:
            nodes = _collect(runner, states["reference"], heldout, prefix, name, timeout)
            passing = set(nodes)
            for label, state in states.items():
                for _ in range(STABILITY_RUNS):
                    printed: list[str] = []
                    runner.run(state, outcome_argv(prefix, [name]), heldout, timeout,
                               output=printed)
                    result = pytest_plugins.outcomes(printed)
                    passing &= {node for node, entry in result.items() if entry["passed"]}
                    if label == "reference":
                        for node, entry in result.items():
                            seconds[node] = max(seconds.get(node, 0.0), entry["seconds"])
            log.append({"file": name, "collected": len(nodes), "stable": len(passing)})
            if passing:
                kept[name] = sorted(passing)
    return kept, seconds, log
