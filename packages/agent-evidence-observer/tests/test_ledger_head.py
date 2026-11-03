"""Retained witness heads expose registered omissions and valid-prefix rollback, over committed records."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fixture_records import load, materialize, signing_keys

from probity_observer import LedgerWitness, SigningKey, VerificationError, verify_ledger_head, verify_packet
from probity_observer.crypto import digest, verify_signature
from probity_observer.history import GENESIS
from probity_observer.ledger import HEAD_DOMAIN, read_ledger


@dataclass(frozen=True)
class LedgerRun:
    """Keep one local protocol fixture's keys and receipt log together."""

    root: Path
    observer: SigningKey
    witness: LedgerWitness

    def head(self, **changes: Any) -> dict[str, Any]:
        """Create a correctly signed candidate head, including hostile fields."""
        payload = {"format": HEAD_DOMAIN, "count": 0, "head": GENESIS, **changes}
        signer = self.witness.signing_key
        return {**payload, "keyid": signer.public_hex, "signature": signer.sign(HEAD_DOMAIN, payload)}


@pytest.fixture
def ledger_run(tmp_path: Path) -> LedgerRun:
    """Create a fresh same-operator fixture for each regression."""
    observer = SigningKey.generate()
    witness = LedgerWitness(tmp_path / "ledger.jsonl", SigningKey.generate(), observer.public_hex)
    return LedgerRun(tmp_path, observer, witness)



def recorded(name: str, tmp_path: Path) -> tuple[LedgerRun, dict[str, Any]]:
    """Copy a committed ledger record and return it with its retained head."""
    record = materialize(name, tmp_path)
    observer, witness_key = signing_keys(record)
    return LedgerRun(record, observer, LedgerWitness(record / "ledger.jsonl", witness_key, observer.public_hex)), load(record / "retained-head.json")


def assert_rejected(
    run: LedgerRun,
    retained_head: dict[str, Any],
    expected: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Compare the exact exception and the bounded warning for a rejection."""
    caplog.clear()
    with pytest.raises(VerificationError) as caught:
        verify_ledger_head(run.witness.state_path, retained_head, run.witness.signing_key.public_hex)
    assert str(caught.value) == expected
    assert caplog.messages == [f"witness ledger verification failed: {expected}"]
    assert run.observer.public_hex not in caplog.text
    assert run.witness.signing_key.public_hex not in caplog.text


class TestLedgerHead:
    class TestPassingCases:
        def test_empty_log_is_bound_to_genesis(self, ledger_run: LedgerRun) -> None:
            witness = ledger_run.witness
            head = witness.signed_head()
            payload = {key: head[key] for key in ("format", "count", "head")}
            verify_signature(witness.signing_key.public_hex, HEAD_DOMAIN, payload, head["signature"])
            assert payload == {"format": HEAD_DOMAIN, "count": 0, "head": GENESIS}
            assert head == witness.signed_head()
            assert verify_ledger_head(witness.state_path, head, witness.signing_key.public_hex) == {
                "count": 0, "head": GENESIS, "registeredIntervals": 0, "missingTerminals": [],
            }

        def test_missing_terminal_is_visible_after_signed_extension(self, tmp_path: Path) -> None:
            run, retained = recorded("ledger-head-sealed-missing", tmp_path)
            receipts = read_ledger(run.witness.state_path, run.witness.signing_key.public_hex)
            result = verify_ledger_head(run.witness.state_path, retained, run.witness.signing_key.public_hex)
            missing = {"intervalId": "missing", "scope": "/work", "operation": "write-file"}
            assert result == {
                "count": 3, "head": receipts[-1]["hash"], "registeredIntervals": 2,
                "missingTerminals": [{
                    "intervalId": "missing",
                    "authorityDigest": digest("probity-authority-v0", missing),
                    "observerKey": run.observer.public_hex,
                }],
            }
            claim = verify_packet(load(run.root / "sealed/packet.json"), run.root / "sealed/history.jsonl",
                                  run.observer.public_hex, run.witness.signing_key.public_hex)
            assert claim["witnessScope"] == "PEER"
            assert claim["coverage"]["unmediatedEffects"] == "not-established"

        def test_interval_summary_matches_registered_population(self, tmp_path: Path) -> None:
            run, retained = recorded("ledger-head-population", tmp_path)
            terminals = [True, False, True, True, False, False, True, False]
            summary = verify_ledger_head(run.witness.state_path, retained, run.witness.signing_key.public_hex)
            assert summary["count"] == len(terminals) + sum(terminals)
            assert summary["registeredIntervals"] == len(terminals)
            assert [item["intervalId"] for item in summary["missingTerminals"]] == [
                f"interval-{index}" for index, terminal in enumerate(terminals) if not terminal
            ]


    class TestFailingCases:
        def test_whole_interval_omission_leaves_valid_prefix_but_fails_retained_head(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            run, retained = recorded("ledger-head-two-sealed", tmp_path)
            path = run.witness.state_path
            lines = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[:2]))
            assert len(read_ledger(path, run.witness.signing_key.public_hex)) == 2
            assert_rejected(run, retained, "ledger is shorter than the retained witness head", caplog)

        def test_operator_restoration_and_resigning_still_fails_old_consumer_head(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            run, retained = recorded("ledger-head-fork", tmp_path)
            fork_head = load(run.root / "fork-head.json")
            assert fork_head["count"] == retained["count"] == 4
            assert fork_head["head"] != retained["head"]
            # Trusting only the newly supplied head accepts the operator's fork.
            assert verify_ledger_head(run.witness.state_path, fork_head, fork_head["keyid"])["count"] == 4
            assert_rejected(run, retained, "ledger does not extend the retained witness head", caplog)

        @pytest.mark.parametrize("field,value", [("count", 1), ("head", "a" * 64)])
        def test_altered_signed_head_is_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture, field: str, value: Any,
        ) -> None:
            head = ledger_run.witness.signed_head()
            head[field] = value
            assert_rejected(ledger_run, head, "signature does not verify under the pinned key", caplog)

        def test_correct_signature_from_unpinned_witness_is_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            attacker = SigningKey.generate()
            payload = {"format": HEAD_DOMAIN, "count": 0, "head": GENESIS}
            head = {**payload, "keyid": attacker.public_hex, "signature": attacker.sign(HEAD_DOMAIN, payload)}
            assert_rejected(ledger_run, head, "witness ledger head key differs from the pinned key", caplog)

        def test_checkpoint_signature_cannot_be_replayed_as_ledger_head(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture,
        ) -> None:
            head = ledger_run.witness.signed_head()
            head["signature"] = ledger_run.witness.signing_key.sign("probity-checkpoint-v0", {"count": 0, "head": GENESIS})
            assert_rejected(ledger_run, head, "signature does not verify under the pinned key", caplog)

        @pytest.mark.parametrize("changes,expected", [
            ({"count": True}, "witness ledger head has an invalid count"),
            ({"count": -1}, "witness ledger head has an invalid count"),
            ({"count": "0"}, "witness ledger head has an invalid count"),
            ({"head": None}, "witness ledger head has an invalid hash"),
            ({"head": "A" * 64}, "witness ledger head has an invalid hash"),
            ({"head": "0" * 63}, "witness ledger head has an invalid hash"),
            ({"head": "0" * 64 + "\n"}, "witness ledger head has an invalid hash"),
            ({"format": "other-v0"}, "witness ledger head has an unsupported format"),
            ({"signature": None}, "witness ledger head has an invalid signature"),
            ({"extra": "value"}, "witness ledger head has invalid fields"),
        ])
        def test_malformed_head_fields_are_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture, changes: dict[str, Any], expected: str,
        ) -> None:
            head = {**ledger_run.witness.signed_head(), **changes}
            assert_rejected(ledger_run, head, expected, caplog)

        @pytest.mark.parametrize("count,head,expected", [
            (1, GENESIS, "ledger is shorter than the retained witness head"),
            (0, "a" * 64, "ledger does not extend the retained witness head"),
        ])
        def test_correctly_signed_false_position_is_refused(
            self, ledger_run: LedgerRun, caplog: pytest.LogCaptureFixture, count: int, head: str, expected: str,
        ) -> None:
            assert_rejected(ledger_run, ledger_run.head(count=count, head=head), expected, caplog)

        def test_missing_middle_receipt_is_refused_before_head_binding(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            run, retained = recorded("ledger-head-two-sealed", tmp_path)
            path = run.witness.state_path
            lines = path.read_bytes().splitlines(keepends=True)
            path.write_bytes(b"".join(lines[:1] + lines[2:]))
            assert_rejected(run, retained, "witness ledger sequence or predecessor differs", caplog)

        def test_partial_receipt_line_is_refused(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
        ) -> None:
            run, retained = recorded("ledger-head-two-sealed", tmp_path)
            path = run.witness.state_path
            path.write_bytes(path.read_bytes()[:-1])
            assert_rejected(run, retained, "witness ledger ends with an incomplete line", caplog)
