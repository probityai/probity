#!/usr/bin/env python3
"""Every publish job in release.yml has a tag the pypi environment lets it deploy from.

A release's publish job runs in the `pypi` environment, whose deployment policy lists the tags
allowed to reach it. A member added to release.yml without its tag pattern on that list passes
every other check, then fails at its first release in about two seconds with no steps run. The
policy lives in the repository's settings, so this reads it from the API.

Exit 0 when every job is covered, 1 when one is not, 2 when the policy could not be read: an
unread policy is not a covered one.

To cover a job, add its tag pattern:
    gh api repos/<owner>/<repo>/environments/pypi/deployment-branch-policies \\
        -X POST -f name='<distribution>-v*' -f type=tag
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "probityai/probity"
PUBLISH_JOB = re.compile(r"^  publish-([a-z0-9-]+):\s*$", re.MULTILINE)


class PolicyUnread(RuntimeError):
    """The environment's deployment policy could not be read."""


def publish_distributions(workflow: str) -> list[str]:
    """The distributions release.yml has a publish job for."""
    return PUBLISH_JOB.findall(workflow)


def allowed_tags(reply: dict[str, object]) -> list[str]:
    """The tag patterns in one reply of the deployment-branch-policies endpoint."""
    policies = reply.get("branch_policies")
    if not isinstance(policies, list):
        raise PolicyUnread(f"the reply carries no branch_policies: {sorted(reply)}")
    return [item["name"] for item in policies if item.get("type") == "tag"]


def uncovered(distributions: list[str], patterns: list[str]) -> list[str]:
    """The distributions whose release tag, ``<distribution>-v<version>``, matches no pattern."""
    return [name for name in distributions
            if not any(fnmatch.fnmatchcase(f"{name}-v0.0.0", pattern) for pattern in patterns)]


def read_policy(repository: str = REPOSITORY, token: str | None = None) -> dict[str, object]:
    url = f"https://api.github.com/repos/{repository}/environments/pypi/deployment-branch-policies?per_page=100"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as reply:
            answer: dict[str, object] = json.loads(reply.read())
            return answer
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise PolicyUnread(f"{url}: {error}") from error


def main() -> int:
    distributions = publish_distributions((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    if not distributions:
        print("no publish job found in release.yml", file=sys.stderr)
        return 2
    try:
        patterns = allowed_tags(read_policy(token=os.environ.get("GH_TOKEN")))
    except PolicyUnread as error:
        print(f"the pypi environment's policy was not read: {error}", file=sys.stderr)
        return 2
    missing = uncovered(distributions, patterns)
    for name in missing:
        print(f"publish-{name} cannot deploy: no pypi environment tag pattern matches {name}-v<version>",
              file=sys.stderr)
    if not missing:
        print(f"{len(distributions)} publish jobs, each with a tag the pypi environment allows")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
