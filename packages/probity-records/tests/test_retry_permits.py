"""verify_journal accepts a re-issued permit only when the journal itself shows the earlier call did not take effect."""

from __future__ import annotations

from test_records import ARGS, _effect, _write_run

from probity_records import (
    NOT_RUN_RETRY, RECONCILED_RETRY, TOOL_CALL_RECORD, Journal, Signer, args_sha256, permit_id, tool_call_predicate,
    verify_journal,
)


def _common(pid: str) -> dict:
    return {"run_id": "run", "tool_call_id": "call-1", "tool": "refund_payment",
            "args_sha256_hex": args_sha256(ARGS), "permit_id": pid}


def _reissue(journal: Journal, pid: str, reason: str, **extra) -> None:
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason=reason, **extra, **_common(pid)))


def _retry_failures(tmp_path, gate: Signer, journal: Journal) -> list[str]:
    report = verify_journal(tmp_path, [gate.public_pem()], journal.checkpoint())
    return [f for f in report["failures"] if "retry" in f or "settled_outcome" in f]


def test_not_run_retry_after_a_committed_effect_is_refused(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    pid = _write_run(journal, Signer.generate(), "committed", "confirmed")
    _reissue(journal, pid, NOT_RUN_RETRY)
    assert any("not_run_retry_but_an_effect_may_have_happened" in f for f in _retry_failures(tmp_path, gate, journal))


def test_not_run_retry_with_no_intent_since_the_last_permit_is_accepted(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    pid = permit_id("pause", "call-1", args_sha256(ARGS))
    _reissue(journal, pid, NOT_RUN_RETRY)
    assert any("retry_without_earlier_permit" in f for f in _retry_failures(tmp_path, gate, journal))
    (tmp_path / "two").mkdir()
    other = Journal(tmp_path / "two", gate)
    _reissue(other, pid, "no_approval_required")
    _reissue(other, pid, NOT_RUN_RETRY)
    assert _retry_failures(tmp_path / "two", gate, other) == []


def test_reconciled_retry_needs_a_final_absent_answer(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    pid = _write_run(journal, Signer.generate(), "unknown", "timeout")
    _reissue(journal, pid, RECONCILED_RETRY)
    assert any("reconciled_retry_without_final_absent_answer" in f for f in _retry_failures(tmp_path, gate, journal))


def test_an_effect_record_after_a_settled_outcome_is_refused(tmp_path) -> None:
    gate = Signer.generate()
    journal = Journal(tmp_path, gate)
    pid = _write_run(journal, Signer.generate(), "committed", "confirmed")
    journal.append(TOOL_CALL_RECORD, "tool-call:call-1", args_sha256(ARGS), tool_call_predicate(
        phase="effect", outcome="committed", uncertain_effect=_effect("committed", "confirmed", 2), **_common(pid)))
    assert any("effect_record_after_settled_outcome" in f for f in _retry_failures(tmp_path, gate, journal))
