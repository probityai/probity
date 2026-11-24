"""Each producer in the package takes its time from the clock it was given, and only from it.

The clocks here stand in 2001, far from the host's time, so a site that read the host clock would show it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from probity_records import Journal, Signer
from probity_records import witness as w
from probity_records.clock import NS_PER_S, FixedClock, from_datetime
from probity_records.journal import timestamp
from probity_records.otel import AuditStream
from probity_records.signing import DelegationScope, delegate

T2001 = from_datetime(datetime(2001, 9, 9, 1, 46, 40, tzinfo=UTC))


def _ats(journal: Journal) -> list[str]:
    return [s["predicate"]["at"] for s in journal.statements()]


def test_journal_lines_and_checkpoint_carry_the_injected_time(tmp_path: Path) -> None:
    clock = FixedClock(T2001)
    journal = Journal(tmp_path, Signer.generate(), clock=clock)
    journal.append("urn:t", "s", "0" * 64, {})
    clock.advance(3 * NS_PER_S)
    journal.append("urn:t", "s", "0" * 64, {})
    assert _ats(journal) == ["2001-09-09T01:46:40.000000Z", "2001-09-09T01:46:43.000000Z"]
    body = json.loads(__import__("base64").b64decode(journal.checkpoint()["payload"]))
    assert body["predicate"]["at"] == "2001-09-09T01:46:43.000000Z"


def test_journal_time_never_goes_back_when_the_wall_clock_steps_back(tmp_path: Path) -> None:
    clock = FixedClock(T2001)
    journal = Journal(tmp_path, Signer.generate(), clock=clock)
    journal.append("urn:t", "s", "0" * 64, {})
    clock.step_wall(-3600 * NS_PER_S)
    journal.append("urn:t", "s", "0" * 64, {})
    assert _ats(journal) == [timestamp(T2001), timestamp(T2001)]


def test_a_second_writer_with_a_slow_clock_cannot_reverse_the_chain(tmp_path: Path) -> None:
    ahead = Journal(tmp_path, Signer.generate(), clock=FixedClock(T2001 + 60 * NS_PER_S))
    behind = Journal(tmp_path, ahead.signer, clock=FixedClock(T2001))
    ahead.append("urn:t", "s", "0" * 64, {})
    behind.append("urn:t", "s", "0" * 64, {})
    first, second = _ats(ahead)
    assert second == first == timestamp(T2001 + 60 * NS_PER_S)


def test_audit_stream_records_the_injected_time() -> None:
    clock = FixedClock(T2001)
    stream = AuditStream(Signer.generate(), clock=clock)
    record, _ = stream.emit("e", {})
    assert record["timestamp"] == record["observed_timestamp"] == T2001
    record, _ = stream.emit("e", {}, timestamp=0)  # an explicit zero is a time, never "use the clock"
    assert record["timestamp"] == 0


def test_witness_cosigns_at_the_injected_time() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    log = Signer.generate()
    origin = "authority.example/t"
    wit = w.Witness("w.example/w", Ed25519PrivateKey.generate(), {origin: [w.parse_vkey(w.log_vkey(origin, log))]},
                    clock=FixedClock(T2001))
    note = w.sign_checkpoint(w.Checkpoint(origin, 0, w.EMPTY_ROOT), log)
    line = w.parse_note(w.attach(note, wit.add_checkpoint(w.encode_add_checkpoint(0, [], note)))).sigs[-1]
    assert int.from_bytes(line.sig[:8], "big") == T2001 // NS_PER_S


def test_delegate_is_valid_from_the_time_it_is_given() -> None:
    start = datetime(2001, 9, 9, tzinfo=UTC)
    session = delegate(Signer.generate(), DelegationScope("record", "ours", "t1", 300), now=start)
    body = session.certificate["body"]
    assert body["notBefore"].startswith("2001-09-09T00:00:00") and body["notAfter"].startswith("2001-09-09T00:05:00")
