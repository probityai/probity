"""Replay a real record (from agent-evidence-vectors) and edits of it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agent_evidence_vectors.auditrecord import canonical_bytes

from evaluator_replay_kit import Pin, make_pin, replay_bytes
from evaluator_replay_kit.cli import main
from evaluator_replay_kit.replay import PinError, digest

FIXTURE = Path(__file__).parent / "fixtures" / "accept-3" / "record.jsonl"
DATA = FIXTURE.read_bytes()
LINES = DATA.split(b"\n")[:-1]
PIN = Pin.from_json(make_pin(DATA))


def join(lines: list[bytes]) -> bytes:
    return b"\n".join(lines) + b"\n"


def edit(line: bytes, **changes: object) -> bytes:
    """Change members of a step and write it back in canonical form."""
    node = json.loads(line)
    node.update(changes)
    return canonical_bytes(node)


def codes(report) -> set[str]:
    return {f.code for f in report.findings}


def test_fixture_is_a_three_step_chain():
    assert len(LINES) == 3


def test_intact_record_without_pin_has_an_unproven_end():
    report = replay_bytes(DATA)
    assert (report.verdict, report.end, report.findings) == ("intact", "unproven", [])


def test_intact_record_with_pin_proves_its_end():
    report = replay_bytes(DATA, PIN)
    assert (report.verdict, report.end) == ("intact", "proven")


def test_require_end_turns_a_prefix_into_a_gap():
    report = replay_bytes(DATA, require_end=True)
    assert report.verdict == "gap" and codes(report) == {"end_unproven"}


def test_edited_step_is_tamper_with_the_pin():
    changed = join([LINES[0], edit(LINES[1], toolName="other_tool"), LINES[2]])
    report = replay_bytes(changed, PIN)
    assert report.verdict == "tampered"
    assert {"digest_mismatch", "link_broken"} <= codes(report)
    link = next(f for f in report.findings if f.code == "link_broken")
    assert link.cls == "tamper" and link.index == 2


def test_edited_step_without_pin_is_broken_not_classified():
    changed = join([LINES[0], edit(LINES[1], toolName="other_tool"), LINES[2]])
    report = replay_bytes(changed)
    assert report.verdict == "broken" and codes(report) == {"link_broken"}


def test_removed_middle_step_is_a_gap_with_the_pin():
    report = replay_bytes(join([LINES[0], LINES[2]]), PIN)
    assert report.verdict == "gap"
    assert codes(report) == {"step_missing", "link_broken"}
    assert next(f for f in report.findings if f.code == "step_missing").id == json.loads(LINES[1])["id"]


def test_removed_middle_step_with_only_a_count_is_a_gap():
    report = replay_bytes(join([LINES[0], LINES[2]]), Pin(count=3))
    assert report.verdict == "gap" and "steps_missing" in codes(report)


def test_truncated_tail_is_a_gap():
    report = replay_bytes(join(LINES[:2]), PIN)
    assert report.verdict == "gap" and "step_missing" in codes(report)
    assert report.end == "unproven"


def test_truncated_tail_is_a_gap_with_only_the_head():
    report = replay_bytes(join(LINES[:2]), Pin(head=PIN.head, count=3))
    assert report.verdict == "gap"


def test_head_of_an_earlier_step_names_the_cut():
    report = replay_bytes(join(LINES[:2]), Pin(head=digest(LINES[1])))
    assert report.verdict == "intact" and report.end == "proven"
    full = replay_bytes(DATA, Pin(head=digest(LINES[1])))
    assert full.verdict == "gap" and codes(full) == {"tail_truncated"}


def test_altered_last_step_is_tamper_with_count_and_head():
    changed = join([LINES[0], LINES[1], edit(LINES[2], toolName="x")])
    report = replay_bytes(changed, Pin(head=PIN.head, count=3))
    assert report.verdict == "tampered" and codes(report) == {"head_mismatch"}


def test_altered_last_step_with_only_a_head_is_unresolved():
    changed = join([LINES[0], LINES[1], edit(LINES[2], toolName="x")])
    report = replay_bytes(changed, Pin(head=PIN.head))
    assert report.verdict == "broken"


def test_appended_step_is_tamper():
    extra = canonical_bytes({"id": "extra", "previousHash": digest(LINES[2]), "type": "tool_call"})
    report = replay_bytes(join([*LINES, extra]), PIN)
    assert report.verdict == "tampered"
    assert {"step_unpinned", "count_mismatch"} <= codes(report)


def test_reformatted_line_is_not_canonical():
    pretty = json.dumps(json.loads(LINES[1]), indent=1).replace("\n", " ").encode()
    report = replay_bytes(join([LINES[0], pretty, LINES[2]]), PIN)
    assert report.verdict == "tampered" and "line_not_canonical" in codes(report)


def test_reordered_steps_break_the_chain():
    report = replay_bytes(join([LINES[0], LINES[2], LINES[1]]), PIN)
    assert report.verdict == "tampered" and "link_broken" in codes(report)


def test_duplicate_id_is_a_fork():
    twin = edit(LINES[1], id=json.loads(LINES[0])["id"])
    report = replay_bytes(join([LINES[0], twin, LINES[2]]))
    assert "id_duplicate" in codes(report) and report.verdict == "tampered"


def test_missing_genesis_is_flagged():
    report = replay_bytes(join(LINES[1:]))
    assert "genesis_missing" in codes(report)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json\n",
        b"[]\n",
        b'{"id": "a"}\n',
        b'{"id": "a", "previousHash": "genesis", "id": "b"}\n',
        b'{"id": "a", "previousHash": "genesis", "n": 1.5}\n',
        b'{"id": "a", "previousHash": "genesis", "n": 9007199254740993}\n',
        b'{"id": "a", "previousHash": "genesis"}\n\n',
        b"\xff\n",
    ],
)
def test_unreadable_record_is_invalid(data):
    report = replay_bytes(data)
    assert report.verdict == "invalid" and report.findings[0].code == "record_unreadable"


@pytest.mark.parametrize(
    "node",
    [[], {"schema": "other"}, {"schema": "evaluator-replay-pin/v1", "head": "ABC"},
     {"schema": "evaluator-replay-pin/v1", "count": -1},
     {"schema": "evaluator-replay-pin/v1", "records": {"a": "short"}}],
)
def test_bad_pin_is_refused(node):
    with pytest.raises(PinError):
        Pin.from_json(node)


def bundle(tmp_path: Path, data: bytes, pin: dict | None = None) -> Path:
    (tmp_path / "record.jsonl").write_bytes(data)
    if pin is not None:
        (tmp_path / "pin.json").write_text(json.dumps(pin))
    return tmp_path


def test_cli_exit_codes(tmp_path, capsys):
    good = tmp_path / "good"
    good.mkdir()
    bundle(good, DATA)
    assert main(["verify", str(good)]) == 0
    cut = tmp_path / "cut"
    cut.mkdir()
    bundle(cut, join(LINES[:2]), make_pin(DATA))
    assert main(["verify", str(cut)]) == 1
    assert "step_missing [gap]" in capsys.readouterr().out
    junk = tmp_path / "junk"
    junk.mkdir()
    bundle(junk, b"nope\n")
    assert main(["verify", str(junk)]) == 2
    assert main(["verify", str(tmp_path / "absent")]) == 2


def test_cli_json_and_flags(tmp_path, capsys):
    folder = tmp_path / "b"
    folder.mkdir()
    bundle(folder, DATA)
    assert main(["verify", str(folder), "--json", "--head", PIN.head]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "intact" and out["end"] == "proven" and out["steps"] == 3
    assert main(["verify", str(folder), "--require-end"]) == 1
    assert main(["verify", str(folder / "record.jsonl"), "--count", "5"]) == 1


def test_cli_pin_round_trip(tmp_path, capsys):
    folder = tmp_path / "p"
    folder.mkdir()
    bundle(folder, DATA)
    assert main(["pin", str(folder)]) == 0
    pin_file = tmp_path / "held.json"
    pin_file.write_text(capsys.readouterr().out)
    assert main(["verify", str(folder), "--pin", str(pin_file), "--require-end"]) == 0
