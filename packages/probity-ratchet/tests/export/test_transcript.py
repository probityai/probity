"""The emit hook's history reference: rebuilt from the transcript prefix, refused once it changes."""

from __future__ import annotations

from pathlib import Path

import pytest

from ratchet.export import hook_emit
from ratchet.export.transcript import RecordError, parse_transcript, reads_history, recorded_history

from .synth import Session, hook_event

CONFIG = hook_emit.EmitConfig("g", "0" * 64)


def test_recorded_history_is_the_prefix_the_hook_saw(tmp_path: Path) -> None:
    session = Session().prompt("go").bash("c1", "ls").result("c1", "a").bash("c2", "rm a")
    path = session.write(tmp_path / "s.jsonl")
    record = hook_emit.make_record(CONFIG, hook_event(path, "c2", "rm a"))
    assert recorded_history(record) == parse_transcript(session.text().splitlines()).events[:3]
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"type": "user"}\n')
    assert recorded_history(record) == parse_transcript(session.text().splitlines()).events[:3]
    path.write_text(session.text().replace("rm a", "rm b"), encoding="utf-8")
    with pytest.raises(RecordError, match="no longer holds"):
        recorded_history(record)


def test_recorded_history_refuses_a_broken_reference(tmp_path: Path) -> None:
    assert recorded_history({"transcript": None}) == []
    with pytest.raises(RecordError, match="not an object"):
        recorded_history({"transcript": "x"})
    with pytest.raises(RecordError, match="needs path"):
        recorded_history({"transcript": {"path": "x"}})
    with pytest.raises(RecordError, match="cannot be read"):
        recorded_history({"transcript": {"path": str(tmp_path / "gone"), "bytes": 1, "sha256": "0"}})


def test_records_go_beside_the_hook_unless_redirected(tmp_path: Path) -> None:
    hook = hook_emit.EmitConfig("g", "0" * 64, hook_file=str(tmp_path / "h.py"))
    assert hook_emit.records_dir(hook, {}) == tmp_path / "ratchet-records"
    assert hook_emit.records_dir(hook, {hook_emit.RECORDS_ENV: "/r"}) == Path("/r")
    with pytest.raises(ValueError, match=hook_emit.RECORDS_ENV):
        hook_emit.records_dir(CONFIG, {})
    assert hook_emit.session_file(tmp_path, "../a b").name == "_a_b.jsonl"
    record = hook_emit.make_record(CONFIG, {"hook_event_name": "Stop"})
    assert record["call"] is None and "expected PreToolUse" in record["error"]
    assert reads_history("def check(call, view, history):\n    return None\n") is False
