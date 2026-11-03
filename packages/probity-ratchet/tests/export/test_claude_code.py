from __future__ import annotations

import ast
import json
import os
import stat
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest
from ratchet_cases.types import sha256_hex

from ratchet.agent.guard_api import GuardLimits
from ratchet.export import claude_code, hook_emit
from ratchet.export.claude_code import (
    EMIT_HEADER_KEYS,
    EMIT_RUNTIME_PATH,
    ExportError,
    admitted_guard,
    export_hook,
    harness_from_json,
    hook_body,
    main,
    public_key,
    py_literal,
    read_header,
    render_hook,
    settings_entry,
    text_sha256,
    verify_hook,
)
from ratchet.export.transcript import parse_transcript, recorded_history
from ratchet.improve.admit import Check, Decision
from ratchet.improve.receipt import Signer, receipt
from ratchet.types import Guard, Harness
from ratchet.verify.dsse import raw_public

from .synth import Session, hook_event

NO_RM = """
def check(call, view, history):
    if call.name == "Bash" and call.args.get("command", "").startswith("rm "):
        return "rm is not allowed (" + str(len(history)) + " earlier events)"
    return None
"""


def harness(source: str = NO_RM) -> Harness:
    return Harness.build(
        parent=None,
        system_prompt="",
        procedures=[],
        guards=[Guard("no-rm", "never rm", source)],
        tool_allowlist=["Bash"],
        created_by="human",
    )


def decision(h: Harness, admitted: bool = True) -> Decision:
    return Decision(
        parent="root",
        candidate=h.version,
        candidate_digest=h.digest,
        admitted=admitted,
        checks=[Check("replay", admitted, {"fires": 1})],
        decided_at="2026-10-11T12:00:00+00:00",
    )


@pytest.fixture(scope="module")
def signer() -> Signer:
    return Signer.generate()


def keys(signer: Signer) -> dict[str, Any]:
    return {signer.keyid: signer.public_key}


def test_admitted_guard_carries_provenance(signer: Signer) -> None:
    h = harness()
    envelope = receipt(decision(h), signer)
    guard, prov = admitted_guard(h, "no-rm", envelope, keys(signer))
    assert guard.source == NO_RM
    assert prov.guard_id == "no-rm" and prov.guard_sha256 == text_sha256(NO_RM)
    assert (prov.harness_version, prov.harness_digest) == (h.version, h.digest)
    assert prov.decision_receipt_sha256 == sha256_hex(envelope)
    assert prov.decision_signers == signer.keyid
    assert prov.decided_at == "2026-10-11T12:00:00+00:00"
    other = Signer.generate()
    both = {**keys(signer), other.keyid: other.public_key}
    assert admitted_guard(h, "no-rm", envelope, both)[1].decision_signers == signer.keyid


def test_admitted_guard_refuses_what_the_receipt_does_not_admit(signer: Signer) -> None:
    h = harness()
    good = receipt(decision(h), signer)
    with pytest.raises(ExportError, match="does not verify"):
        admitted_guard(h, "no-rm", good, keys(Signer.generate()))
    with pytest.raises(ExportError, match="does not match its digest"):
        admitted_guard(replace(h, system_prompt="changed"), "no-rm", good, keys(signer))
    with pytest.raises(ExportError, match="did not admit"):
        admitted_guard(h, "no-rm", receipt(decision(h, admitted=False), signer), keys(signer))
    with pytest.raises(ExportError, match="not harness"):
        admitted_guard(harness(NO_RM + "\n"), "no-rm", good, keys(signer))
    with pytest.raises(ExportError, match="has no guard"):
        admitted_guard(h, "other", good, keys(signer))


@pytest.mark.parametrize(
    "text",
    [
        "plain",
        "a\nb",
        'two\n"""quotes"""',
        "both\n\"\"\"\n'''",
        "ends in a backslash\n\\",
        'ends in a quote\n"',
        'tab\there "q"',
    ],
)
def test_py_literal_is_exact(text: str) -> None:
    assert ast.literal_eval(py_literal(text)) == text
    assert py_literal("a\nb") == 'r"""a\nb"""'
    assert py_literal('x\n"""') == "r'''x\n\"\"\"'''"
    assert py_literal("one line") == '"one line"'


def render(signer: Signer, source: str = NO_RM, limits: GuardLimits | None = None) -> str:
    h = harness(source)
    guard, prov = admitted_guard(h, "no-rm", receipt(decision(h), signer), keys(signer))
    return render_hook(guard, prov, limits or GuardLimits(require=()))


def test_rendered_hook_carries_and_matches_its_header(signer: Signer) -> None:
    text = render(signer)
    header = verify_hook(text)
    assert set(header) == set(EMIT_HEADER_KEYS)
    assert header["hook_kind"] == "emit"
    assert header["hook_runtime_sha256"] == text_sha256(EMIT_RUNTIME_PATH.read_text(encoding="utf-8"))
    assert text.startswith("#!/usr/bin/env python3\n")


def test_emit_hook_refuses_required_isolation(signer: Signer) -> None:
    with pytest.raises(ExportError, match="enforces nothing"):
        render(signer, limits=GuardLimits(require=("seccomp",)))


def test_verify_hook_catches_every_kind_of_edit(signer: Signer) -> None:
    text = render(signer)
    with pytest.raises(ExportError, match="guard_sha256"):
        verify_hook(text.replace('startswith("rm ")', 'startswith("rmdir ")'))
    with pytest.raises(ExportError, match="hook_runtime_sha256"):
        verify_hook(text.replace('RECORDS_DIR = "ratchet-records"', 'RECORDS_DIR = "elsewhere"'))
    head = read_header(text, EMIT_HEADER_KEYS)
    with pytest.raises(ExportError, match="GUARD_SHA256"):
        verify_hook(text.replace(f'GUARD_SHA256 = "{head["guard_sha256"]}"', f'GUARD_SHA256 = "{"0" * 64}"'))
    with pytest.raises(ExportError, match="RUNTIME_SHA256"):
        verify_hook(
            text.replace(
                f'RUNTIME_SHA256 = "{head["hook_runtime_sha256"]}"', f'RUNTIME_SHA256 = "{"0" * 64}"'
            )
        )
    with pytest.raises(ExportError, match="missing"):
        verify_hook(text.replace("# decided_at:", "# decided:"))
    with pytest.raises(ExportError, match="markers"):
        verify_hook(text.replace(hook_emit.RUNTIME_END, ""))
    with pytest.raises(ExportError, match="no hook_kind"):
        verify_hook(text.replace("# hook_kind:", "# kind:"))
    with pytest.raises(ExportError, match="no hook body 'enforce'"):
        verify_hook(text.replace("# hook_kind: emit", "# hook_kind: enforce"))


def run_hook_file(path: Path, event: dict[str, Any], records: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, hook_emit.RECORDS_ENV: str(records)}
    return subprocess.run(
        [sys.executable, str(path)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def test_installed_hook_records_and_allows(signer: Signer, tmp_path: Path) -> None:
    h = harness()
    out = tmp_path / "hooks" / "ratchet_no_rm.py"
    export_hook(h, "no-rm", receipt(decision(h), signer), keys(signer), out, GuardLimits(require=()))
    assert out.stat().st_mode & stat.S_IXUSR
    transcript = Session().prompt("tidy up").bash("c1", "ls").result("c1", "a b").bash("c2", "rm -rf a")
    path = transcript.write(tmp_path / "s.jsonl")
    records = tmp_path / "records"

    done = run_hook_file(out, hook_event(path, "c2", "rm -rf a"), records)
    assert (done.returncode, done.stdout, done.stderr) == (0, "", "")
    [line] = (records / "00000000-0000-4000-8000-000000000001.jsonl").read_text().splitlines()
    record = json.loads(line)
    assert record["call"] == {
        "name": "Bash",
        "args": {"command": "rm -rf a", "description": "run"},
        "call_id": "c2",
    }
    assert record["integrity_error"] is None and record["error"] is None
    assert record["guard_sha256"] == text_sha256(NO_RM)
    expected = parse_transcript(transcript.text().splitlines()).events[:3]
    assert recorded_history(record) == expected


def test_tampered_or_broken_hook_still_allows(signer: Signer, tmp_path: Path) -> None:
    path = tmp_path / "hook.py"
    path.write_text(render(signer).replace('RECORDS_DIR = "ratchet-records"', 'RECORDS_DIR = "x"'), "utf-8")
    records = tmp_path / "records"
    done = run_hook_file(path, hook_event(None, "c", "ls"), records)
    assert (done.returncode, done.stdout) == (0, "")
    record = json.loads((records / "00000000-0000-4000-8000-000000000001.jsonl").read_text())
    assert record["integrity_error"] == "hook runtime does not match its recorded digest"
    (tmp_path / "blocker").write_text("a file, not a directory")
    done = run_hook_file(path, hook_event(None, "c", "ls"), tmp_path / "blocker")
    assert done.returncode == 0 and "not recorded" in done.stderr
    bad = subprocess.run([sys.executable, str(path)], input="[]", capture_output=True, text=True, timeout=60)
    assert bad.returncode == 0 and "not a JSON object" in bad.stderr


def test_generated_hook_is_lint_and_format_clean(signer: Signer, tmp_path: Path) -> None:
    path = tmp_path / "hook.py"
    path.write_text(render(signer), encoding="utf-8")
    for args in (["check", "--no-cache", str(path)], ["format", "--no-cache", "--check", str(path)]):
        done = subprocess.run(
            [sys.executable, "-m", "ruff", *args], capture_output=True, text=True, check=False
        )
        assert done.returncode == 0, done.stdout + done.stderr


class _Body:
    kind = "test-body"

    def render(self, guard: Guard, provenance: Any, limits: GuardLimits) -> str:
        return f"# hook_kind: {self.kind}\n# guard: {guard.id} {','.join(limits.require)}\n"

    def verify(self, text: str) -> dict[str, str]:
        return {"hook_kind": self.kind, "verified": "yes"}


class _EntryPoint:
    name = "test-body"

    def load(self) -> Any:
        return _Body


def test_hook_bodies_come_from_the_entry_point_group(signer: Signer, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(group: str) -> list[_EntryPoint]:
        assert group == "ratchet.hooks"
        return [_EntryPoint()]

    monkeypatch.setattr(claude_code, "entry_points", fake)
    h = harness()
    guard, prov = admitted_guard(h, "no-rm", receipt(decision(h), signer), keys(signer))
    text = render_hook(guard, prov, GuardLimits(require=("seccomp",)), "test-body")
    assert text == "# hook_kind: test-body\n# guard: no-rm seccomp\n"
    assert verify_hook(text) == {"hook_kind": "test-body", "verified": "yes"}
    assert hook_body().kind == "emit"
    with pytest.raises(ExportError, match="installed: emit, test-body"):
        hook_body("missing")


def test_settings_entry_blocks_when_the_hook_cannot_start() -> None:
    entry = settings_entry("python3", "${CLAUDE_PROJECT_DIR}/.claude/hooks/h.py", "Bash")
    handler = entry["hooks"]["PreToolUse"][0]["hooks"][0]
    assert entry["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
    assert handler == {
        "type": "command",
        "command": "python3",
        "args": ["${CLAUDE_PROJECT_DIR}/.claude/hooks/h.py"],
        "onFailure": "block",
    }


def write_inputs(tmp_path: Path, signer: Signer, admitted: bool = True) -> list[str]:
    h = harness()
    (tmp_path / "harness.json").write_text(json.dumps(asdict(h)), encoding="utf-8")
    (tmp_path / "receipt.json").write_bytes(receipt(decision(h, admitted), signer))
    key = raw_public(signer.public_key).hex()
    return [
        "--harness",
        "harness.json",
        "--guard-id",
        "no-rm",
        "--receipt",
        "receipt.json",
        "--trusted-key",
        key,
    ]


def test_command_line_exports_and_verifies(
    signer: Signer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    args = write_inputs(tmp_path, signer)
    assert main([*args, "--out", ".claude/hooks/no_rm.py", "--require", ""]) == 0
    printed = capsys.readouterr().out
    assert '"${CLAUDE_PROJECT_DIR}/.claude/hooks/no_rm.py"' in printed
    assert main(["--verify", ".claude/hooks/no_rm.py"]) == 0
    assert json.loads(capsys.readouterr().out)["guard_id"] == "no-rm"
    absolute = tmp_path / "abs.py"
    assert main([*args, "--out", str(absolute), "--require", ""]) == 0
    assert f'"{absolute}"' in capsys.readouterr().out


def test_command_line_refuses(signer: Signer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    args = write_inputs(tmp_path, signer, admitted=False)
    assert main(args) == 1
    assert main([*args, "--out", "h.py"]) == 1
    assert main([*args[:-1], "abcd", "--out", "h.py"]) == 1
    good = write_inputs(tmp_path, signer)
    assert main([*good, "--out", "h.py", "--require", "netns"]) == 1
    assert main([*good, "--out", "h.py", "--require", "", "--hook", "nope"]) == 1
    assert not (tmp_path / "h.py").exists()
    with pytest.raises(ExportError):
        public_key("zz")


def test_harness_round_trips_through_json() -> None:
    h = harness()
    assert harness_from_json(json.loads(json.dumps(asdict(h)))) == h
