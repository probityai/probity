"""Loss in the journal is a signed line, never a silence: gap lines, the torn-tail line a writer appends after a crash
mid-write, and the run a checkpoint names."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from probity_records import Journal, Signer, verify_journal
from probity_records.clock import FixedClock
from probity_records.journal import GAP_TYPE, JOURNAL_FILE, TORN_TAIL_TYPE

STEP = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/test-step"


def _journal(tmp_path: Path, signer: Signer, run: str | None = "run-7") -> Journal:
    return Journal(tmp_path, signer, clock=FixedClock(1_790_000_000_000_000_000), run=run)


def _step(journal: Journal, n: int) -> None:
    journal.append(STEP, "step", "ab" * 32, {"n": n})


def test_gap_lines_are_chained_and_the_verifier_reports_what_was_dropped(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = _journal(tmp_path, signer)
    _step(journal, 1)
    journal.gap(dropped=5, after_seq=1, reason="ring_overflow")
    _step(journal, 2)
    out = verify_journal(tmp_path, [signer.public_pem()], journal.checkpoint(), run="run-7")
    assert out["verdict"] == "PASS", out["failures"]
    assert out["dropped"] == 5
    assert out["gaps"] == [{"afterSeq": 1, "dropped": 5, "line": 2, "reason": "ring_overflow"}]


def test_a_stripped_gap_line_breaks_the_chain(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = _journal(tmp_path, signer)
    _step(journal, 1)
    journal.gap(dropped=5, after_seq=1, reason="ring_overflow")
    _step(journal, 2)
    checkpoint = journal.checkpoint()
    path = tmp_path / JOURNAL_FILE
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(lines[0] + lines[2])
    out = verify_journal(tmp_path, [signer.public_pem()], checkpoint, run="run-7")
    assert out["verdict"] == "FAIL"
    assert out["dropped"] == 0


@pytest.mark.parametrize(("dropped", "after_seq"), [(0, 1), (-1, 1), (1, 5), (True, 1)])
def test_a_gap_the_journal_cannot_hold_is_refused_before_it_is_written(tmp_path: Path, dropped: int,
                                                                       after_seq: int) -> None:
    journal = _journal(tmp_path, Signer.generate())
    _step(journal, 1)
    with pytest.raises(ValueError, match="journal_gap_invalid"):
        journal.gap(dropped=dropped, after_seq=after_seq, reason="ring_overflow")
    assert len((tmp_path / JOURNAL_FILE).read_bytes().splitlines()) == 1


def test_a_truncated_tail_is_reported_and_never_read_as_a_record(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = _journal(tmp_path, signer)
    _step(journal, 1)
    _step(journal, 2)
    checkpoint = journal.checkpoint()
    path = tmp_path / JOURNAL_FILE
    whole = path.read_bytes()
    torn = b'{"payload":"eyJ'  # a writer died mid-line
    path.write_bytes(whole + torn)
    out = verify_journal(tmp_path, [signer.public_pem()], checkpoint, run="run-7")
    assert out["records"] == 2
    assert out["tornTail"] == {"afterSeq": 2, "bytes": len(torn)}
    assert out["verdict"] == "NOT_ESTABLISHED"
    assert not out["failures"]


def test_the_next_writer_removes_a_torn_tail_only_with_a_signed_line_that_says_so(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = _journal(tmp_path, signer)
    _step(journal, 1)
    path = tmp_path / JOURNAL_FILE
    torn = b'{"payload":"eyJ'
    path.write_bytes(path.read_bytes() + torn)
    reopened = _journal(tmp_path, signer)
    _step(reopened, 2)
    statements = reopened.statements()
    assert [s["predicateType"] for s in statements] == [STEP, TORN_TAIL_TYPE, STEP]
    assert statements[1]["predicate"]["bytes"] == len(torn)
    assert statements[1]["predicate"]["tornSha256"] == hashlib.sha256(torn).hexdigest()
    assert statements[1]["predicate"]["afterSeq"] == 1
    out = verify_journal(tmp_path, [signer.public_pem()], reopened.checkpoint(), run="run-7")
    assert out["verdict"] == "PASS", out["failures"]
    assert out["tornTails"] == [{"afterSeq": 1, "bytes": len(torn), "line": 2}]


def test_a_checkpoint_of_another_run_under_the_same_key_is_refused(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = _journal(tmp_path, signer, run="run-8")
    _step(journal, 1)
    out = verify_journal(tmp_path, [signer.public_pem()], journal.checkpoint(), run="run-7")
    assert out["verdict"] == "FAIL"
    assert "checkpoint_run_mismatch:run-8:run-7" in out["failures"]


def test_a_pinned_run_refuses_a_checkpoint_that_names_none(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = _journal(tmp_path, signer, run=None)
    _step(journal, 1)
    out = verify_journal(tmp_path, [signer.public_pem()], journal.checkpoint(), run="run-7")
    assert "checkpoint_run_mismatch:None:run-7" in out["failures"]


def test_a_forged_gap_line_shape_is_a_failure(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = _journal(tmp_path, signer)
    _step(journal, 1)
    journal.append(GAP_TYPE, "tool-call-journal", "00" * 32, {"dropped": "five", "afterSeq": 1, "reason": "x"})
    out = verify_journal(tmp_path, [signer.public_pem()], journal.checkpoint(), run="run-7")
    assert out["verdict"] == "FAIL"
    assert any(f.startswith("line_2:journal_gap_invalid") for f in out["failures"]), out["failures"]
