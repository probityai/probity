from __future__ import annotations

from collections.abc import Iterator
from importlib.metadata import EntryPoint
from typing import Any

import pytest

from ratchet.improve import failures
from ratchet.improve.admit import check_overfit
from ratchet.improve.failures import (
    FailureCluster,
    FailurePoint,
    Literals,
    OpenOverfitScreen,
    installed_diagnoser,
    installed_overfit_screen,
    open_diagnose,
)
from ratchet.types import Guard, Harness

from .fakes import FakeSimulator, bad_timeout, good_plain, lazy, make_trace

PARENT = Harness.build(parent=None, system_prompt="Base.", procedures=[], guards=[], tool_allowlist=[],
                       created_by="seed")  # fmt: skip


@pytest.fixture(autouse=True)
def _fresh_selection() -> Iterator[None]:
    installed_diagnoser.cache_clear()
    installed_overfit_screen.cache_clear()
    yield
    installed_diagnoser.cache_clear()
    installed_overfit_screen.cache_clear()


def test_the_open_diagnoser_groups_failures_by_the_graders_reason() -> None:
    traces = [bad_timeout(1), bad_timeout(2), lazy(3), good_plain(4)]
    clusters = open_diagnose(traces, FakeSimulator())
    assert [len(c.members) for c in clusters] == [2, 1]
    dup, omit = clusters
    assert dup.key["mode"] == "commission" and omit.key["mode"] == "omission"
    assert {m.case_id for m in dup.members} == {"timeout-1", "timeout-2"}
    assert all(m.tool == "payments_refund" for m in dup.members)
    assert set(dup.traces) == {"bad-1", "bad-2"}
    assert all(
        isinstance(c, FailureCluster) and isinstance(m, FailurePoint) for c in clusters for m in c.members
    )


def test_the_open_diagnoser_ids_are_stable_and_the_payload_shape_is_unchanged() -> None:
    first = open_diagnose([bad_timeout(1), lazy(3)], FakeSimulator())
    again = open_diagnose([lazy(3), bad_timeout(1)], FakeSimulator())
    assert [c.id for c in first] == [c.id for c in again]
    payload = first[0].to_payload()
    assert set(payload) == {"id", "key", "summary", "members"}
    assert set(payload["members"][0]) == {"run_id", "case_id", "seq", "reason", "mode", "tool", "id"}


def test_the_open_diagnoser_skips_passing_runs_and_survives_an_unwalkable_trace() -> None:
    errors: list[str] = []

    class Broken:
        def walk(self, trace: Any) -> Any:
            raise RuntimeError("no world")

    clusters = open_diagnose(
        [good_plain(1), bad_timeout(2)], Broken(), on_walk_error=lambda t, exc: errors.append(t.run_id)
    )
    assert errors == ["bad-2"] and [len(c.members) for c in clusters] == [1]
    assert clusters[0].members[0].mode == "commission"  # located by the id the reason names, no walk needed
    assert open_diagnose([good_plain(1)]) == []


def test_a_summarizer_writes_the_summary_and_never_decides_membership() -> None:
    plain = open_diagnose([bad_timeout(1), lazy(3)], FakeSimulator())
    said = open_diagnose([bad_timeout(1), lazy(3)], FakeSimulator(), summarize=lambda k, m, t: "mechanism")
    assert [c.summary for c in said] == ["mechanism"] * 2
    assert [(c.id, c.members) for c in said] == [(c.id, c.members) for c in plain]

    def boom(*_: Any) -> str:
        raise ValueError

    failed = open_diagnose([bad_timeout(1)], FakeSimulator(), summarize=boom)
    assert failed[0].summary.endswith("(model summary unavailable: ValueError)")


def _calls(n: int = 1) -> list[tuple[str, dict[str, Any]]]:
    return [
        ("payments_refund", {"charge_id": f"ch_{n}", "note": "duplicate", "email": "maya@fastmail.example"})
    ]


def test_the_open_screen_takes_specific_tool_argument_strings_only() -> None:
    lit = OpenOverfitScreen().training_literals([make_trace("timeout-1", _calls(), "run-a")])
    assert lit.ids == {"ch_1", "maya@fastmail.example"}
    assert lit.amounts == set() and lit.names == set()


def test_the_open_screen_flags_copied_literals_in_new_text_only() -> None:
    screen = OpenOverfitScreen()
    lit = screen.training_literals([make_trace("timeout-1", _calls(), "run-a")])
    general = Guard("g1", "no duplicate refunds", "def check(call, view, history):\n    return None\n")
    copied = Guard("g2", "for ch_1", "def check(call, view, history):\n    return 'x' if False else None\n")
    cand = PARENT.child(
        guards=[general, copied], system_prompt="Base.\n\nMail maya@fastmail.example.", created_by="improver"
    )
    got = {(h["where"], h["category"], h["literal"]) for h in screen.lint(PARENT, cand, lit)}
    assert got == {("guard g2", "id", "ch_1"), ("system prompt", "id", "maya@fastmail.example")}
    assert screen.lint(cand, cand, lit) == []


def test_ids_inside_longer_tokens_do_not_match() -> None:
    screen = OpenOverfitScreen()
    lit = screen.training_literals([make_trace("timeout-1", _calls(1), "run-a")])
    g = Guard("g", "d", "def check(call, view, history):\n    return 'ch_10' if False else None\n")
    assert screen.lint(PARENT, PARENT.child(guards=[g], created_by="improver"), lit) == []


def test_admission_names_the_screen_that_ran() -> None:
    check = check_overfit(PARENT, PARENT, Literals(ids={"ch_1"}))
    assert check.passed and check.evidence["screen"] == "open-literals"
    assert check.evidence["screened"] == {"ids": 1, "amounts": 0, "names": 0}


class _Screen:
    name = "stub"

    def training_literals(self, traces: Any) -> Literals:
        return Literals(ids={"x"})

    def lint(self, parent: Harness, candidate: Harness, literals: Literals) -> list[dict[str, str]]:
        return [{"where": "w", "category": "id", "literal": "x"}]


def test_an_explicit_screen_decides_admission() -> None:
    check = check_overfit(PARENT, PARENT, Literals(), _Screen())
    assert not check.passed and check.evidence["screen"] == "stub"


def _register(monkeypatch: pytest.MonkeyPatch, *entries: EntryPoint) -> None:
    monkeypatch.setattr(failures, "entry_points", lambda group: [e for e in entries if e.group == group])


def test_the_open_defaults_run_when_nothing_is_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    _register(monkeypatch)
    assert installed_diagnoser() is open_diagnose
    assert isinstance(installed_overfit_screen(), OpenOverfitScreen)


def test_an_installed_entry_replaces_the_open_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _register(
        monkeypatch,
        EntryPoint("diagnoser", f"{__name__}:make_diagnoser", failures.GROUP),
        EntryPoint("overfit", f"{__name__}:_Screen", failures.GROUP),
    )
    assert installed_diagnoser()([]) == []
    assert installed_diagnoser() is not open_diagnose
    assert installed_overfit_screen().name == "stub"


def make_diagnoser() -> Any:
    return lambda traces, simulator=None, summarize=None, on_walk_error=None: []


def test_two_distributions_registering_one_name_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _register(
        monkeypatch,
        EntryPoint("overfit", "a.b:c", failures.GROUP),
        EntryPoint("overfit", "d.e:f", failures.GROUP),
    )
    with pytest.raises(LookupError, match="register 'overfit'"):
        installed_overfit_screen()
