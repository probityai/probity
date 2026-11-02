"""pytest plugin: a test that takes ``lost_reply_scenario`` runs once per shipped scenario.

It does nothing for a test that does not ask for the fixture, and needs
``probity-effects[testing]`` only when one does.
"""

from __future__ import annotations

from typing import Any

import pytest


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "lost_reply_scenario" not in metafunc.fixturenames:
        return
    try:
        from probity_effects.testing import lost_reply_scenarios

        scenarios: list[dict[str, Any]] = lost_reply_scenarios()
    except ImportError as error:
        raise pytest.UsageError(
            f"lost_reply_scenario needs agent-evidence-vectors: install probity-effects[testing] ({error})"
        ) from error
    metafunc.parametrize("lost_reply_scenario", scenarios, ids=[item["id"] for item in scenarios])
