"""Ledger terminals distinguish boundary aborts from unresolved write outcomes, over committed records."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from fixture_records import load, materialize, pinned_keys, signing_keys
from hypothesis import HealthCheck, given, settings, strategies as st

from probity_observer import LedgerWitness, SigningKey, VerificationError, Witness, verify_incomplete, verify_ledger_head, verify_ledger_receipts
from probity_observer.history import append_history, read_history
from probity_observer.ledger import read_ledger


@dataclass(frozen=True)
class AbortRun:
    """Hold a begun interval's record, its signers and its witnessed begin checkpoint."""

    observer: SigningKey
    witness: LedgerWitness
    history: Path
    start: dict[str, Any]


def make_run(root: Path) -> AbortRun:
    """Copy the committed begun interval with a ledger witness."""
    record = materialize("ledger-begin", root)
    observer, witness_key = signing_keys(record)
    witness = LedgerWitness(record / "ledger.jsonl", witness_key, observer.public_hex)
    return AbortRun(observer, witness, record / "history.jsonl", load(record / "start-checkpoint.json"))


@pytest.fixture
def abort_run(tmp_path: Path) -> AbortRun:
    """Provide a fresh witnessed begin for each terminal regression."""
    return make_run(tmp_path)


def add_pending_write(run: AbortRun) -> None:
    """Retain an intent whose write outcome remains unknown."""
    before_root = read_history(run.history)[0]["event"]["commitment"]["preimage"]["beforeRoot"]
    append_history(run.history, {
        "kind": "write-intent", "requestId": "pending", "path": "/work/x",
        "contentDigest": hashlib.sha256(b"unresolved").hexdigest(), "beforeRoot": before_root,
    })


def add_incomplete(run: AbortRun, reason: str, request_ids: Any) -> None:
    """Append a candidate terminal without asking the witness to accept it."""
    append_history(run.history, {"kind": "incomplete", "reason": reason, "requestIds": request_ids})


def attempt_terminal(run: AbortRun, consumer: str) -> None:
    """Exercise the ledger signer or a pinned offline reader independently."""
    if consumer == "ledger":
        run.witness.checkpoint(run.history)
        return
    # A simple checkpoint signer can sign malformed terminal semantics.
    signer = Witness(run.history.parent / "candidate-checkpoint.json", run.witness.signing_key)
    checkpoint = signer.checkpoint(run.history)
    verify_incomplete(run.history, run.start, checkpoint, run.observer.public_hex, run.witness.signing_key.public_hex)


def assert_terminal_refused(
    run: AbortRun,
    consumer: str,
    expected: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Require an exact refusal and no new signed ledger receipt."""
    before = run.witness.state_path.read_bytes()
    caplog.clear()
    with pytest.raises(VerificationError) as caught:
        attempt_terminal(run, consumer)
    assert str(caught.value) == expected
    assert caplog.messages == [f"incomplete terminal refused: {expected}"]
    assert run.witness.state_path.read_bytes() == before
    assert len(read_ledger(run.witness.state_path, run.witness.signing_key.public_hex)) == 1
    assert run.observer.public_hex not in caplog.text
    assert run.witness.signing_key.public_hex not in caplog.text


class TestLedgerAbort:
    class TestPassingCases:
        @pytest.mark.parametrize("name,reason", [("abort-isolation", "isolation setup failed"), ("abort-probes", "boundary probes failed")])
        def test_no_write_abort_after_begin_is_witnessed(self, tmp_path: Path, name: str, reason: str) -> None:
            record = materialize(name, tmp_path)
            observer, witness = pinned_keys(record)
            result = load(record / "incomplete.json")
            terminal = verify_incomplete(record / "history.jsonl", result["startCheckpoint"], result["checkpoint"], observer, witness)
            assert result["status"] == "incomplete"
            assert terminal == {"kind": "incomplete", "reason": reason, "requestIds": []}
            assert [entry["event"]["kind"] for entry in read_history(record / "history.jsonl")] == ["begin", "incomplete"]
            assert verify_ledger_receipts(record / "ledger.jsonl", result["startCheckpoint"], result["checkpoint"], witness)["count"] == 2

        def test_abort_after_completed_write_keeps_the_effect_and_incomplete_outcome(self, tmp_path: Path) -> None:
            record = materialize("abort-after-write", tmp_path)
            observer, witness = pinned_keys(record)
            result = load(record / "incomplete.json")
            terminal = verify_incomplete(record / "history.jsonl", result["startCheckpoint"], result["checkpoint"], observer, witness)
            assert result["status"] == "incomplete"
            assert terminal["requestIds"] == []
            assert (record / "workspace/x").read_bytes() == b"retained effect"
            assert [entry["event"]["kind"] for entry in read_history(record / "history.jsonl")] == [
                "begin", "write-intent", "write", "incomplete",
            ]
            summary = verify_ledger_head(record / "ledger.jsonl", load(record / "retained-head.json"), witness)
            assert summary["missingTerminals"] == []
            assert summary["registeredIntervals"] == 1
            # Receipt inclusion does not promote an incomplete outcome to success.
            assert terminal["reason"] == "boundary probes failed"

        def test_recovered_write_names_the_exact_pending_request(self, tmp_path: Path) -> None:
            record = materialize("ledger-recovered", tmp_path)
            observer, witness = pinned_keys(record)
            result = load(record / "incomplete.json")
            terminal = verify_incomplete(record / "history.jsonl", result["startCheckpoint"], result["checkpoint"], observer, witness)
            assert result["status"] == "incomplete"
            assert terminal["requestIds"] == ["pending"]
            assert terminal["reason"] == "write outcome unresolved after interruption"
            assert verify_ledger_receipts(record / "ledger.jsonl", result["startCheckpoint"], result["checkpoint"], witness)["count"] == 2

    class TestFailingCases:
        @settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture])
        @given(request_ids=st.lists(st.text(alphabet="pendingother-0123456789", max_size=12), max_size=4).filter(lambda ids: ids != ["pending"]))
        def test_mismatched_interrupted_request_ids_are_refused_by_both_readers(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture, request_ids: list[str],
        ) -> None:
            with TemporaryDirectory(dir=tmp_path) as directory:
                run = make_run(Path(directory))
                add_pending_write(run)
                add_incomplete(run, "write outcome unresolved after interruption", request_ids)
                for consumer in ("ledger", "offline"):
                    assert_terminal_refused(run, consumer, "incomplete event does not name the unresolved write", caplog)

        @pytest.mark.parametrize("consumer", ["ledger", "offline"])
        @pytest.mark.parametrize("request_ids", [["pending", "pending"], "pending"])
        def test_duplicate_or_nonlist_request_ids_are_refused(
            self, abort_run: AbortRun, caplog: pytest.LogCaptureFixture, consumer: str, request_ids: Any,
        ) -> None:
            add_pending_write(abort_run)
            add_incomplete(abort_run, "write outcome unresolved after interruption", request_ids)
            assert_terminal_refused(abort_run, consumer, "incomplete event does not name the unresolved write", caplog)

        @pytest.mark.parametrize("consumer", ["ledger", "offline"])
        @pytest.mark.parametrize("reason", ["isolation setup failed", "boundary probes failed"])
        def test_abort_cannot_hide_an_unresolved_write(
            self, abort_run: AbortRun, caplog: pytest.LogCaptureFixture, consumer: str, reason: str,
        ) -> None:
            add_pending_write(abort_run)
            add_incomplete(abort_run, reason, [])
            assert_terminal_refused(abort_run, consumer, "aborted interval has unresolved writes", caplog)

        @pytest.mark.parametrize("consumer", ["ledger", "offline"])
        @pytest.mark.parametrize("request_ids", [[], ["pending"]])
        def test_interruption_without_pending_intent_is_refused(
            self, abort_run: AbortRun, caplog: pytest.LogCaptureFixture, consumer: str, request_ids: list[str],
        ) -> None:
            add_incomplete(abort_run, "write outcome unresolved after interruption", request_ids)
            assert_terminal_refused(abort_run, consumer, "incomplete event does not name the unresolved write", caplog)

        @pytest.mark.parametrize("consumer", ["ledger", "offline"])
        def test_abort_with_invented_request_id_is_refused(
            self, abort_run: AbortRun, caplog: pytest.LogCaptureFixture, consumer: str,
        ) -> None:
            add_incomplete(abort_run, "boundary probes failed", ["invented"])
            assert_terminal_refused(abort_run, consumer, "aborted interval has unresolved writes", caplog)

        @pytest.mark.parametrize("consumer", ["ledger", "offline"])
        def test_unknown_abort_reason_is_refused(
            self, abort_run: AbortRun, caplog: pytest.LogCaptureFixture, consumer: str,
        ) -> None:
            add_incomplete(abort_run, "unknown failure", [])
            assert_terminal_refused(abort_run, consumer, "incomplete event has an unknown reason", caplog)

        def test_seal_with_pending_intent_is_still_refused(self, abort_run: AbortRun, caplog: pytest.LogCaptureFixture) -> None:
            add_pending_write(abort_run)
            append_history(abort_run.history, {"kind": "seal", "claimDigest": "0" * 64})
            before = abort_run.witness.state_path.read_bytes()
            expected = "witness terminal disagrees with write intents"
            with pytest.raises(VerificationError) as caught:
                abort_run.witness.checkpoint(abort_run.history)
            assert str(caught.value) == expected
            assert caplog.messages == [f"witness terminal refused: {expected}"]
            assert abort_run.witness.state_path.read_bytes() == before
