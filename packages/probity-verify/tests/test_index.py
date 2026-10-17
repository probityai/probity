"""Decision index tests using the shipped replayable examples."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from probity_verify.bundle import create_bundle
from probity_verify.common import CaseError
from probity_verify.core import canonical_json
from probity_verify.index import (
    add_challenge,
    add_decision,
    add_supersession,
    main,
    verify_index,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _bundle(tmp_path: Path, name: str) -> Path:
    examples = {
        "june": ("source-coverage", "case.json", "policy-june.json"),
        "april": ("source-coverage", "case.json", "policy-april.json"),
        "complete": ("source-coverage", "case-complete.json", "policy-complete.json"),
        "operand": ("operand-lineage", "case.json", "policy.json"),
    }
    folder, case, policy = examples[name]
    root = EXAMPLES / folder
    path = tmp_path / f"{name}.zip"
    create_bundle(root / case, root / policy, path)
    return path


class TestDecisionIndex:
    @staticmethod
    def two_decisions(tmp_path: Path) -> tuple[Path, str, str]:
        index = tmp_path / "decisions.db"
        june = add_decision(index, _bundle(tmp_path, "june"))
        april = add_decision(index, _bundle(tmp_path, "april"))
        return index, june, april


class TestPassingCases(TestDecisionIndex):
    def test_decision_challenge_and_supersession_replay(
        self, tmp_path: Path
    ) -> None:
        index, june, april = self.two_decisions(tmp_path)
        challenge = add_challenge(
            index, june, april, "The June capture cannot establish the April intake."
        )
        supersession = add_supersession(
            index, june, april, "The April intake is not established by a June capture."
        )
        entries = verify_index(index)
        assert [entry["id"] for entry in entries] == [
            june, april, challenge, supersession
        ]
        assert [entry["kind"] for entry in entries] == [
            "decision", "decision", "challenge", "supersession"
        ]
        assert [entry["decision"] for entry in entries[:2]] == [
            "contradicted", "not_established"
        ]
        assert entries[2]["target"] == june
        assert entries[2]["counter"] == april
        assert entries[3]["replacement"] == april
        assert [entry["sequence"] for entry in entries] == [1, 2, 3, 4]

    def test_ids_do_not_depend_on_index_location(self, tmp_path: Path) -> None:
        bundle = _bundle(tmp_path, "june")
        first = add_decision(tmp_path / "first.db", bundle)
        second = add_decision(tmp_path / "other" / "second.db", bundle)
        assert first == second
        assert first.startswith("sha256:")

    def test_cli_add_and_verify(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        index = tmp_path / "decisions.db"
        assert main(["add", str(index), str(_bundle(tmp_path, "operand"))]) == 0
        event_id = capsys.readouterr().out.strip()
        assert main(["verify", str(index)]) == 0
        output = json.loads(capsys.readouterr().out)
        assert output["entries"][0]["id"] == event_id
        assert output["entries"][0]["claim_type"] == "operand_lineage/v1"

    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz 0123456789", min_size=1, max_size=80))
    @settings(max_examples=15, deadline=None)
    def test_challenge_basis_survives_replay(self, basis: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            index, june, april = self.two_decisions(Path(directory))
            add_challenge(index, june, april, basis)
            assert verify_index(index)[-1]["basis"] == basis


class TestFailingCases(TestDecisionIndex):
    def test_missing_index_and_invalid_zip(self, tmp_path: Path) -> None:
        with pytest.raises(CaseError, match="index does not exist"):
            verify_index(tmp_path / "missing.db")
        invalid = tmp_path / "invalid.zip"
        invalid.write_bytes(b"not a ZIP")
        assert main(["add", str(tmp_path / "index.db"), str(invalid)]) == 2

    def test_duplicate_event_does_not_append(self, tmp_path: Path) -> None:
        index = tmp_path / "index.db"
        bundle = _bundle(tmp_path, "june")
        add_decision(index, bundle)
        with pytest.raises(CaseError, match="index event already exists"):
            add_decision(index, bundle)
        assert len(verify_index(index)) == 1

    @pytest.mark.parametrize("counter,basis,error", [
        ("missing", "Reason", "challenge must cite earlier decisions"),
        ("self", "Reason", "challenge cannot cite itself"),
        ("second", "", "invalid challenge event"),
    ])
    def test_invalid_challenge(
        self, tmp_path: Path, counter: str, basis: str, error: str
    ) -> None:
        index, june, april = self.two_decisions(tmp_path)
        chosen = {"missing": "sha256:missing", "self": june, "second": april}[counter]
        with pytest.raises(CaseError, match=error):
            add_challenge(index, june, chosen, basis)
        assert len(verify_index(index)) == 2

    def test_supersession_requires_same_case_and_claim(self, tmp_path: Path) -> None:
        index, june, april = self.two_decisions(tmp_path)
        other = add_decision(index, _bundle(tmp_path, "complete"))
        with pytest.raises(CaseError, match="same case and claim type"):
            add_supersession(index, june, other, "Different case.")
        with pytest.raises(CaseError, match="requires a different decision"):
            add_supersession(index, june, june, "Same decision.")
        with pytest.raises(CaseError, match="replacement must be a later decision"):
            add_supersession(index, april, june, "Older decision.")
        assert len(verify_index(index)) == 3

    def test_changed_bundle_is_detected(self, tmp_path: Path) -> None:
        index, _, _ = self.two_decisions(tmp_path)
        with sqlite3.connect(index) as connection:
            connection.execute("UPDATE bundles SET content = ?", (b"changed",))
        with pytest.raises(CaseError, match="indexed bundle is missing or changed"):
            verify_index(index)

    def test_nonbinary_bundle_is_detected(self, tmp_path: Path) -> None:
        index, _, _ = self.two_decisions(tmp_path)
        with sqlite3.connect(index) as connection:
            connection.execute("UPDATE bundles SET content = ?", ("changed",))
        with pytest.raises(CaseError, match="indexed bundle is missing or changed"):
            verify_index(index)

    def test_changed_event_is_detected(self, tmp_path: Path) -> None:
        index, _, _ = self.two_decisions(tmp_path)
        with sqlite3.connect(index) as connection:
            row = connection.execute(
                "SELECT sequence, payload FROM events ORDER BY sequence LIMIT 1"
            ).fetchone()
            event = json.loads(row[1])
            event["decision"] = "supported"
            connection.execute(
                "UPDATE events SET payload = ? WHERE sequence = ?",
                (canonical_json(event), row[0]),
            )
        with pytest.raises(CaseError, match="indexed event ID or canonical bytes changed"):
            verify_index(index)

    def test_broken_reference_is_detected(self, tmp_path: Path) -> None:
        index, june, april = self.two_decisions(tmp_path)
        add_challenge(index, june, april, "Later evidence.")
        with sqlite3.connect(index) as connection:
            connection.execute("DELETE FROM events WHERE id = ?", (june,))
        with pytest.raises(CaseError, match="challenge must cite earlier decisions"):
            verify_index(index)
