"""Alerts under a retained-evidence prefix are split from live ones; a bad config is refused."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("retained_alerts", ROOT / "scripts" / "retained_alerts.py")
ra = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ra)

RULES = [{"prefix": "packages/agent-evidence-observer/interop/", "reason": "frozen"}]


def alert(number: int, manifest: str) -> dict:
    return {"number": number, "dependency": {"manifest_path": manifest}}


def test_retained_and_live_are_split() -> None:
    alerts = [
        alert(1, "packages/agent-evidence-observer/interop/x/retained/uv.lock"),
        alert(2, "./uv.lock"),
        alert(3, "integrations/keycloak-evidence-hook/pom.xml"),
    ]
    retained, live = ra.partition(alerts, RULES)
    assert [a["number"] for a, _ in retained] == [1]
    assert [a["number"] for a in live] == [2, 3]


def test_a_sibling_directory_is_not_retained() -> None:
    assert ra.match("packages/agent-evidence-observer/pyproject.toml", RULES) is None


def test_the_shipped_config_loads_and_covers_the_crewai_lock() -> None:
    rules = ra.load_rules()
    assert ra.match("packages/agent-evidence-observer/interop/crewai-job-fences-2026-10-04/retained/actual-run/native-source/uv.lock", rules)


def test_an_entry_without_a_reason_is_refused(tmp_path: Path) -> None:
    bad = tmp_path / "r.toml"
    bad.write_text('[[retained]]\nprefix = "a/"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        ra.load_rules(bad)
