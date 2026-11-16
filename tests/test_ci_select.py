"""Tests for the CI job selector and its agreement with .github/workflows/ci.yml."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
_spec = importlib.util.spec_from_file_location("ci_select", ROOT / "scripts/ci_select.py")
ci_select = importlib.util.module_from_spec(_spec)
sys.modules["ci_select"] = ci_select
_spec.loader.exec_module(ci_select)

JOBS = {
    "fast": {"paths": ["pkg/a/**", "pkg/b/x.toml"], "tier": "fast"},
    "slow": {"paths": ["pkg/a/**"], "tier": "full"},
    "weekly": {"paths": ["pkg/w/**"], "tier": "fast", "schedule": True},
}


@pytest.mark.parametrize("pattern,path,expected", [
    ("pkg/a/**", "pkg/a/deep/file.py", True),
    ("pkg/a/**", "pkg/ab/file.py", False),
    ("pkg/*/x.toml", "pkg/b/x.toml", True),
    ("pkg/*/x.toml", "pkg/b/c/x.toml", False),
    ("**/pyproject.toml", "pyproject.toml", True),
    ("packages/**/pyproject.toml", "packages/x/pyproject.toml", True),
    ("packages/**/pyproject.toml", "packages/x/y/pyproject.toml", True),
    ("packages/*/pyproject.toml", "packages/x/y/pyproject.toml", False),
])
def test_glob_follows_github_path_filters(pattern, path, expected):
    assert bool(ci_select.glob_regex(pattern).match(path)) is expected


def test_pull_request_runs_only_fast_jobs_for_the_paths_changed():
    assert ci_select.select_jobs("pull_request", ["pkg/a/f.py"], JOBS) == {"fast": True, "slow": False, "weekly": False}
    assert ci_select.select_jobs("pull_request", ["docs/x.md"], JOBS) == {"fast": False, "slow": False, "weekly": False}


def test_merge_group_and_push_add_the_full_tier():
    for event in ("merge_group", "push"):
        assert ci_select.select_jobs(event, ["pkg/a/f.py"], JOBS) == {"fast": True, "slow": True, "weekly": False}


@pytest.mark.parametrize("path", sorted(ci_select.EVERYTHING))
def test_a_changed_workflow_or_selector_selects_every_job(path):
    assert ci_select.select_jobs("pull_request", [path], JOBS) == {"fast": True, "slow": False, "weekly": True}
    assert ci_select.select_jobs("merge_group", [path], JOBS) == {"fast": True, "slow": True, "weekly": True}


def test_an_unknown_change_and_a_manual_run_select_everything_in_the_tier():
    assert ci_select.select_jobs("merge_group", None, JOBS) == {"fast": True, "slow": True, "weekly": True}
    assert ci_select.select_jobs("workflow_dispatch", [], JOBS) == {"fast": True, "slow": True, "weekly": True}


def test_schedule_runs_only_the_scheduled_jobs():
    assert ci_select.select_jobs("schedule", ["pkg/a/f.py"], JOBS) == {"fast": False, "slow": False, "weekly": True}


def test_an_unknown_base_means_everything():
    assert ci_select.changed_paths("", "HEAD") is None
    assert ci_select.changed_paths("0" * 40, "HEAD") is None
    assert ci_select.changed_paths("1" * 40, "HEAD") is None


def test_the_workflow_and_the_table_name_the_same_jobs():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    used = set(re.findall(r"fromJSON\(needs\.changes\.outputs\.jobs\)\['([a-z0-9-]+)'\]", workflow))
    assert used == set(ci_select.table()), "ci.yml and scripts/ci_jobs.toml disagree"


def test_every_job_is_a_need_of_the_aggregator():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    ids = re.findall(r"^  ([a-z0-9-]+):\s*$", workflow.split("\njobs:\n", 1)[1], re.MULTILINE)
    needs = re.search(r"^  ci-ok:\n    if: \$\{\{ \(.*\) && \(always\(\)\) \}\}\n    needs: \[(.*?)\]\n",
                      workflow, re.MULTILINE | re.DOTALL)
    assert needs, "ci-ok must run with the batch gate and always() and list its needs"
    assert set(ids) - {"ci-ok"} == {n.strip() for n in needs.group(1).split(",")}


def test_every_package_and_node_directory_selects_a_job():
    """A changed path must select the jobs that test it, so no package may be left unmapped."""
    import tomllib

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    used = set(re.findall(r"outputs\.members\)\['([a-z0-9-]+)'\]", workflow))
    members = {tomllib.loads(p.read_text(encoding="utf-8"))["project"]["name"]: p.parent.name
               for p in (ROOT / "packages").glob("*/pyproject.toml")}
    unmapped = sorted(name for name in members if name not in used)
    assert not unmapped, f"no job in ci.yml is selected by a change to these packages: {unmapped}"
    globs = [g for job in ci_select.table().values() for g in job["paths"]]
    bare = sorted(d.name for d in (ROOT / "node").iterdir()
                  if d.is_dir() and not any(ci_select.glob_regex(g).match(f"node/{d.name}/package.json") for g in globs))
    assert not bare, f"no entry of scripts/ci_jobs.toml selects a change to these node packages: {bare}"
