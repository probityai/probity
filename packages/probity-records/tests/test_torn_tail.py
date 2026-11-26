"""A writer killed mid-append leaves a torn last line: every reader skips it, the next append cuts it first.

An append is durable on return, so a torn tail is the bytes of an append that never returned: nothing acted on
it. Each append-only file the package writes (journal.jsonl, keys.jsonl, checkpoints.log) is cut back to its last
whole entry, under the lock and fsynced, before the next entry is written; each reader stops at the last whole line.
"""

from __future__ import annotations

import fcntl
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_records import Journal, Signer, verify_journal
from probity_records import journal as journal_mod
from probity_records import witness as w
from probity_records.clock import FixedClock, from_datetime
from probity_records.journal import JOURNAL_FILE, KEYS_FILE
from probity_records.otel import AuditStream, export_journal
from probity_records.signing import DelegationScope, delegate

CLOCK = FixedClock(from_datetime(datetime(2026, 11, 26, 12, 0, tzinfo=UTC)))
TYPE = "https://example.test/t"


def _append(journal: Journal, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        journal.append(TYPE, f"s{i}", "0" * 64, {"phase": "note", "i": i})


def _tear(path: Path, keep: int) -> bytes:
    """Cut the last line of ``path`` to its first ``keep`` bytes (no newline): the bytes of a killed write."""
    data = path.read_bytes()
    lines = data.splitlines(keepends=True)
    torn = lines[-1][:keep]
    assert not torn.endswith(b"\n")
    path.write_bytes(b"".join(lines[:-1]) + torn)
    return torn


def _cuts(path: Path) -> list[int]:
    """Every cut of the last line that leaves a torn tail: one byte, half, and all but the newline."""
    last = path.read_bytes().splitlines(keepends=True)[-1]
    return [1, len(last) // 2, len(last) - 1]


def _seqs(path: Path) -> list[int]:
    return [journal_mod._payload(json.loads(line))["predicate"]["seq"] for line in path.read_bytes().splitlines()]


@pytest.mark.parametrize("cut", range(3))
def test_statements_skip_a_torn_tail(tmp_path: Path, cut: int) -> None:
    signer = Signer.generate()
    _append(Journal(tmp_path, signer, clock=CLOCK), 4)
    _tear(tmp_path / JOURNAL_FILE, _cuts(tmp_path / JOURNAL_FILE)[cut])
    assert [s["predicate"]["seq"] for s in Journal(tmp_path, signer, clock=CLOCK).statements()] == [1, 2, 3]


@pytest.mark.parametrize("cut", range(3))
def test_the_next_append_cuts_the_torn_tail_and_the_journal_verifies(tmp_path: Path, cut: int) -> None:
    signer = Signer.generate()
    _append(Journal(tmp_path, signer, clock=CLOCK), 4)
    _tear(tmp_path / JOURNAL_FILE, _cuts(tmp_path / JOURNAL_FILE)[cut])
    restarted = Journal(tmp_path, signer, clock=CLOCK)
    _append(restarted, 1, start=99)
    assert _seqs(tmp_path / JOURNAL_FILE) == [1, 2, 3, 4]
    assert [s["predicate"]["i"] for s in restarted.statements()] == [0, 1, 2, 99]
    out = verify_journal(tmp_path, [signer.public_pem()], restarted.checkpoint())
    assert (out["verdict"], out["records"], out["verified"], out["tornTailBytes"]) == ("PASS", 4, 4, 0), out["failures"]


def test_an_instance_that_saw_the_torn_tail_before_its_first_append_also_cuts_it(tmp_path: Path) -> None:
    signer = Signer.generate()
    _append(Journal(tmp_path, signer, clock=CLOCK), 3)
    _tear(tmp_path / JOURNAL_FILE, 40)
    restarted = Journal(tmp_path, signer, clock=CLOCK)
    assert [s["predicate"]["seq"] for s in restarted.statements()] == [1, 2]
    restarted.checkpoint()  # a read that refreshes the cached head past the whole lines only
    _append(restarted, 2, start=10)
    assert _seqs(tmp_path / JOURNAL_FILE) == [1, 2, 3, 4]


def test_the_torn_tail_is_cut_under_the_lock_and_fsynced_before_the_line_is_written(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    signer = Signer.generate()
    _append(Journal(tmp_path, signer, clock=CLOCK), 2)
    path = tmp_path / JOURNAL_FILE
    _tear(path, 25)
    whole = sum(len(line) for line in path.read_bytes().splitlines(keepends=True)[:-1])
    restarted = Journal(tmp_path, signer, clock=CLOCK)
    events: list[tuple] = []
    real_flock, real_truncate, real_fsync, real_write = fcntl.flock, os.ftruncate, os.fsync, os.write

    def flock(fd, op):
        events.append(("flock", op))
        return real_flock(fd, op)

    def ftruncate(fd, size):
        events.append(("ftruncate", size))
        return real_truncate(fd, size)

    def fsync(fd):
        events.append(("fsync",))
        return real_fsync(fd)

    def write(fd, data):
        events.append(("write", len(data)))
        return real_write(fd, data)

    monkeypatch.setattr(journal_mod.fcntl, "flock", flock)
    monkeypatch.setattr(journal_mod.os, "ftruncate", ftruncate)
    monkeypatch.setattr(journal_mod.os, "fsync", fsync)
    monkeypatch.setattr(journal_mod.os, "write", write)
    _append(restarted, 1)
    names = [e[0] for e in events]
    locked, cut, synced, wrote = (names.index("flock"), names.index("ftruncate"), names.index("fsync"),
                                  names.index("write"))
    assert events[locked] == ("flock", fcntl.LOCK_EX)
    assert events[cut] == ("ftruncate", whole)
    assert locked < cut < synced < wrote
    assert ("flock", fcntl.LOCK_UN) in events[wrote:]
    monkeypatch.undo()
    assert _seqs(path) == [1, 2]


def test_a_whole_journal_is_never_cut(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    signer = Signer.generate()
    _append(Journal(tmp_path, signer, clock=CLOCK), 2)
    cuts: list[int] = []
    monkeypatch.setattr(journal_mod.os, "ftruncate", lambda fd, size: cuts.append(size))
    _append(Journal(tmp_path, signer, clock=CLOCK), 2, start=2)
    assert cuts == []
    assert _seqs(tmp_path / JOURNAL_FILE) == [1, 2, 3, 4]


def test_verify_journal_does_not_count_a_torn_tail_and_reports_it(tmp_path: Path) -> None:
    signer = Signer.generate()
    journal = Journal(tmp_path, signer, clock=CLOCK)
    _append(journal, 3)
    checkpoint = journal.checkpoint()
    _append(journal, 1, start=3)
    torn = _tear(tmp_path / JOURNAL_FILE, 30)
    out = verify_journal(tmp_path, [signer.public_pem()], checkpoint)
    assert (out["verdict"], out["records"], out["verified"]) == ("PASS", 3, 3), out["failures"]
    assert out["tornTailBytes"] == len(torn)
    # the writer's own checkpoint over the same file agrees with the verifier's count
    after_crash = Journal(tmp_path, signer, clock=CLOCK).checkpoint()
    assert verify_journal(tmp_path, [signer.public_pem()], after_crash)["checkpoint"] == "matches"


def _delegated(root: Signer):
    return delegate(root, DelegationScope("record", "ours", "tenant-a", 600),
                    now=datetime(2026, 11, 26, 11, 59, tzinfo=UTC))


def test_a_torn_certificate_is_not_read_and_the_next_certificate_cuts_it(tmp_path: Path) -> None:
    root = Signer.generate()
    journal = Journal(tmp_path, _delegated(root), clock=CLOCK)
    _append(journal, 1)
    keys = tmp_path / KEYS_FILE
    second = _delegated(root)
    line = json.dumps(second.certificate, sort_keys=True, separators=(",", ":")).encode()
    keys.write_bytes(keys.read_bytes() + line[: len(line) // 2])  # the certificate write was killed
    out = verify_journal(tmp_path, [root.public_pem()], journal.checkpoint())
    assert out["verdict"] == "PASS", out["failures"]
    journal.rotate(second)  # the restarted writer certifies the key again before it signs
    _append(journal, 1, start=1)
    rows = [json.loads(row) for row in keys.read_bytes().splitlines()]
    assert len(rows) == 2 and rows[1] == second.certificate and keys.read_bytes().endswith(b"\n")
    out = verify_journal(tmp_path, [root.public_pem()], journal.checkpoint())
    assert (out["verdict"], out["verified"]) == ("PASS", 2), out["failures"]


def test_export_journal_skips_a_torn_tail(tmp_path: Path) -> None:
    signer = Signer.generate()
    _append(Journal(tmp_path, signer, clock=CLOCK), 3)
    _tear(tmp_path / JOURNAL_FILE, 50)
    stream = AuditStream(Signer.generate(), clock=CLOCK)
    export_journal(stream, tmp_path / JOURNAL_FILE, actor_id="agent:orders")
    assert len(stream.records) == 2


ORIGIN = "authority.example/journal"


def _feed(tmp_path: Path):
    signer = Signer.generate()
    journal = Journal(tmp_path / "authority", signer, clock=CLOCK)
    key = Ed25519PrivateKey.generate()
    feed_vkey = w.log_vkey(ORIGIN, signer)
    wit = w.Witness("customer.example/witness-0", key, {ORIGIN: [w.parse_vkey(feed_vkey)]},
                    state_dir=tmp_path / "witness-0", clock=CLOCK)
    srv = w.serve_witness(wit)
    pairs = [(f"http://127.0.0.1:{srv.server_address[1]}", wit.vkey.encode())]
    return journal, w.Feed(journal, ORIGIN, pairs), srv


def test_a_torn_entry_in_the_checkpoint_log_is_cut_before_the_next(tmp_path: Path) -> None:
    journal, feed, srv = _feed(tmp_path)
    try:
        _append(journal, 2)
        first = feed.publish()
        _append(journal, 1, start=2)
        second = feed.publish()
        log = Path(feed.directory) / "checkpoints.log"
        assert log.read_text() == first + "\n" + second + "\n"
        for keep in (len(second) // 3, second.index("\n\n") + 2, len(second)):  # cut in the text, at the blank, at the end
            data = (first + "\n" + second[:keep]).encode()
            log.write_bytes(data)
            _append(journal, 1, start=10 + keep)
            third = feed.publish()
            assert log.read_text() == first + "\n" + third + "\n", keep
            assert [w.parse_note(n).text for n in (first, third)]
    finally:
        srv.shutdown()


def test_the_feed_writes_a_witness_size_whole_or_not_at_all(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal, feed, srv = _feed(tmp_path)
    try:
        _append(journal, 2)
        feed.publish()
        state = next(Path(feed.directory).glob("witness-*.size"))
        assert state.read_text() == "2\n"
        _append(journal, 1, start=2)

        real = Path.write_text

        def killed(self: Path, data: str, *args: object, **kwargs: object) -> int:
            if not self.name.startswith("witness-"):  # the feed's size file and any temporary beside it
                return real(self, data, *args, **kwargs)
            self.write_bytes(b"")  # opened for writing, then killed before a byte landed
            raise OSError("killed mid-write")

        monkeypatch.setattr(Path, "write_text", killed)
        feed.publish()  # without a policy the feed publishes past a witness error; the kill is one such error
        monkeypatch.undo()
        assert state.read_text() == "2\n"  # the old size, never an empty or half-written file
        _append(journal, 1, start=3)
        assert w.parse_checkpoint(w.parse_note(feed.publish()).text).size == 4
        assert state.read_text() == "4\n"
    finally:
        srv.shutdown()
