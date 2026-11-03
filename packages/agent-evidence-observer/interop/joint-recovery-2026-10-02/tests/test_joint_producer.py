"""Producer-side controls for the live native population and current-authority gate."""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st
from probity_observer.crypto import VerificationError
import tempfile

from joint_common import CASES, load
from joint_run import current
from joint_worker import current_gate
from lg_common import PacketError


class TestNativeLaunch:
    """A live run freezes absolute launch roots."""

    class TestPassingCases:
        def test_relative_native_output_freezes_absolute_launch_roots(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]]) -> None:
            root = fresh[0]
            plan = load(root, "plan-before-run.json")
            assert plan["captureRoot"] == str(root.resolve())
            assert Path(plan["hostPrivateRoot"]).is_absolute()
            for name in CASES:
                value = load(root, "attempts/" + name + ".json")
                assert all(Path(target["command"][2]).is_absolute() for target in value["targets"])
                assert all(Path(worker["process"]["command"][2]).is_absolute() and Path(worker["process"]["command"][6]).is_absolute() for worker in value["workers"])


class TestCurrentGate:
    """Merged clock gate remains durable across new host selection refusals."""

    class TestPassingCases:
        @settings(max_examples=20, deadline=None)
        @given(clock=st.integers(min_value=101, max_value=199))
        def test_strictly_later_selection_clears_denial(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], clock: int) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            first = current(case, "first", True)
            denied = {**first, "authority": {**first["authority"], "revoked": True}}
            with tempfile.TemporaryDirectory() as folder, sqlite3.connect(Path(folder) / "clock.sqlite") as connection:
                assert current_gate(connection, case, first, "first")["status"] == "authorized"
                assert current_gate(connection, case, denied, "second")["status"] == "refused-revoked"
                assert current_gate(connection, case, first, "second")["status"] == "refused-stale-authority"
                later = {**first, "authority": {**first["authority"], "clock": clock}}
                assert current_gate(connection, case, later, "second")["status"] == "authorized"

        @pytest.mark.parametrize("field,value", [("grantSha256", "0" * 64), ("serviceKey", "0" * 64), ("storeIdentity", "0" * 32)])
        def test_selection_denial_is_sticky_at_same_clock(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, field: str, value: str) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            first = current(case, "first", True)
            denied = {**first, "selection": {**first["selection"], field: value}}
            with sqlite3.connect(tmp_path / "clock.sqlite") as connection:
                current_gate(connection, case, first, "first")
                assert current_gate(connection, case, denied, "second")["status"] == "refused-current-selection"
                assert current_gate(connection, case, first, "second")["status"] == "refused-stale-authority"

    class TestFailingCases:
        @pytest.mark.parametrize("field,value,reason", [("clock", True, "authority-types"), ("expires", False, "authority-types"), ("revoked", 0, "authority-types"), ("actionSha256", "0" * 64, "authority-action")])
        def test_malformed_authority_refuses_without_anchor(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture, field: str, value: Any, reason: str) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            selected = current(case, "first", True)
            selected["authority"][field] = value
            with sqlite3.connect(tmp_path / "clock.sqlite") as connection, caplog.at_level(logging.WARNING), pytest.raises(PacketError, match="^" + reason + "$"):
                current_gate(connection, case, selected, "first")
            assert "LangGraph packet refused: " + reason in caplog.messages

        def test_boolean_target_readiness_refuses(self, fresh: tuple[Path, dict[str, Any], dict[str, Any]], tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            case = load(fresh[0], "cases/valid-before.json")
            selected = {**current(case, "first", True), "targetReady": 1}
            with sqlite3.connect(tmp_path / "clock.sqlite") as connection, caplog.at_level(logging.WARNING), pytest.raises(VerificationError, match="^current-target-readiness-type$"):
                current_gate(connection, case, selected, "first")
            assert "Joint recovery refused: current-target-readiness-type" in caplog.messages
