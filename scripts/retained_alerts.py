#!/usr/bin/env python3
"""Dismiss Dependabot alerts that sit under retained-evidence paths, and list the rest.

Exit codes: 0 nothing open under a retained prefix (or all dismissed by `apply`),
1 an alert is open under a retained prefix, 2 the alert list could not be read.
A read that failed is never reported as a clean result.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

CONFIG = Path(__file__).resolve().parent.parent / ".github" / "retained-evidence.toml"
REPO = "probityai/probity"
DISMISS_REASON = "not_used"


def load_rules(path: Path = CONFIG) -> list[dict[str, str]]:
    rules = tomllib.loads(path.read_text(encoding="utf-8")).get("retained", [])
    for rule in rules:
        if not rule.get("prefix") or not rule.get("reason"):
            raise ValueError(f"every [[retained]] entry needs a prefix and a reason: {rule}")
    return rules


def match(manifest: str, rules: list[dict[str, str]]) -> dict[str, str] | None:
    path = manifest.removeprefix("./")
    return next((rule for rule in rules if path.startswith(rule["prefix"])), None)


def partition(alerts: list[dict], rules: list[dict[str, str]]) -> tuple[list[tuple[dict, dict]], list[dict]]:
    retained, live = [], []
    for alert in alerts:
        rule = match(alert["dependency"]["manifest_path"], rules)
        (retained.append((alert, rule)) if rule else live.append(alert))
    return retained, live


def fetch_open(repo: str = REPO) -> list[dict]:
    out = subprocess.run(
        ["gh", "api", "--paginate", "--jq", ".[]", f"repos/{repo}/dependabot/alerts?state=open&per_page=100"],
        capture_output=True, text=True, check=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def dismiss(alert: dict, rule: dict[str, str], repo: str = REPO) -> None:
    comment = f"Retained evidence ({rule['prefix']}). {rule['reason']}"[:280]
    subprocess.run(
        ["gh", "api", "-X", "PATCH", f"repos/{repo}/dependabot/alerts/{alert['number']}",
         "-f", "state=dismissed", "-f", f"dismissed_reason={DISMISS_REASON}", "-f", f"dismissed_comment={comment}"],
        capture_output=True, text=True, check=True,
    )


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "check"
    if mode not in ("check", "apply"):
        print("usage: retained_alerts.py check|apply", file=sys.stderr)
        return 2
    try:
        alerts = fetch_open()
        rules = load_rules()
    except (subprocess.CalledProcessError, OSError, ValueError, json.JSONDecodeError) as err:
        print(f"READ FAILED, nothing was checked: {err}", file=sys.stderr)
        return 2
    retained, live = partition(alerts, rules)
    print(f"open alerts: {len(alerts)}; under a retained prefix: {len(retained)}; live: {len(live)}")
    if mode == "apply":
        for alert, rule in retained:
            dismiss(alert, rule)
        print(f"dismissed {len(retained)} as {DISMISS_REASON}")
        return 0
    for alert, _ in retained:
        print(f"  retained  #{alert['number']} {alert['dependency']['manifest_path']}")
    return 1 if retained else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
