"""The open referee factory keeps a signed file store only and selects held-out cases from the suite."""

from __future__ import annotations

from contextlib import ExitStack

import pytest

from ratchet.improve.referee import RefereeError, factory_name
from ratchet.improve.referee_open import held_out, parts


def test_a_database_store_is_refused_by_the_open_referee() -> None:
    with pytest.raises(RefereeError, match="signed file store only"):
        parts({"cases": "heldout", "store": {"kind": "atlas", "db": "x"}}, None, ExitStack())


def test_held_out_cases_come_from_the_installed_suite() -> None:
    every = held_out("heldout")
    assert every and all(c.split == "heldout" for c in every)
    assert [c.id for c in held_out([every[0].id])] == [every[0].id]
    with pytest.raises(RefereeError, match="unknown held-out case ids"):
        held_out(["no-such-case"])


def test_the_factory_is_the_configured_module_then_the_environment_then_the_open_one() -> None:
    env = {"RATCHET_REFEREE_FACTORY": "hosted.referee"}
    assert factory_name("case_suite_parts", {}, {}) == "ratchet.improve.referee_open:case_suite_parts"
    assert factory_name("policy_parts", {}, env) == "hosted.referee:policy_parts"
    assert factory_name("policy_parts", {"factory": "own.referee"}, env) == "own.referee:policy_parts"
