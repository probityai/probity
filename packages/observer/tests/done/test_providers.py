"""The plug-in points: at most one plug-in per group, never two."""

import types

import pytest

from probity_observer.done import providers
from probity_observer.done.formats import DoneError


class Point:
    def __init__(self, name, value):
        self.name, self.value = name, value

    def load(self):
        return self.value


def test_an_installed_plugin_is_loaded(monkeypatch):
    plugin = types.SimpleNamespace(applies=None, detect=None)
    monkeypatch.setattr(providers, "entry_points",
                        lambda group: [Point("one", plugin)] if group == providers.VISIBLE_DETECTORS else [])
    assert providers.visible_detector() is plugin


def test_two_plugins_in_one_group_are_refused(monkeypatch):
    monkeypatch.setattr(providers, "entry_points", lambda group: [Point("b", 1), Point("a", 2)])
    with pytest.raises(DoneError, match="2 plug-ins installed \\(a, b\\)"):
        providers.guard_selector()


def test_with_no_plugin_there_is_none(monkeypatch):
    monkeypatch.setattr(providers, "entry_points", lambda group: [])
    assert providers.contract_provider() is None
    assert providers.guard_selector() is None
    assert providers.visible_detector() is None
