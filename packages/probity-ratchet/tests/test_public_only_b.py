"""With the enforcing guard runtime and hook modules unimportable, the engine still runs guards through the
open runtime, replays transcripts, exports and verifies an emit-only hook, and refuses an isolation demand."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "claude-code"

PROGRAM = textwrap.dedent(
    """
    import contextlib, importlib, importlib.abc, io, json, os, pkgutil, subprocess, sys, tempfile
    from pathlib import Path

    BLOCKED = ("ratchet.agent.guards", "ratchet.agent._guard_child", "ratchet.export.mcp_gateway",
               "ratchet.export.hookrt")

    class Refuse(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name in BLOCKED:
                raise ImportError(f"{name} is blocked in this test")
            return None

    sys.meta_path.insert(0, Refuse())
    import ratchet.verify, ratchet.view
    names = ["ratchet.cli", "ratchet.improve.loop", "ratchet.improve.referee", "ratchet.improve.run",
             "ratchet.improve.sandbox", "ratchet.demo.scenario", "ratchet.agent.worker",
             "ratchet.export.claude_code", "ratchet.export.replay_transcripts", "ratchet.export.hook_emit",
             "ratchet.export.transcript"]
    for package in (ratchet.verify, ratchet.view):
        names += [m.name for m in pkgutil.walk_packages(package.__path__, package.__name__ + ".")
                  if not m.name.endswith("__main__")]
    for name in names:
        importlib.import_module(name)

    from ratchet.agent.guard_api import GuardLimits, SandboxUnavailableError, guard_runtime
    from ratchet.export import claude_code
    from ratchet.export.replay_transcripts import discover, replay_transcripts
    from ratchet.export.transcript import recorded_history
    from ratchet.improve.replay import GuardInput
    from ratchet.improve.sandbox import SandboxRunner
    from ratchet.types import Guard
    from ratchet_cases.types import ToolCall

    example = Path(sys.argv[1])
    guard = Guard("no-force-push-main", "", (example / "no_force_push_main.py").read_text())
    expected = (example / "expected_fires.txt").read_text().split()
    with guard_runtime(workers=2) as runtime:
        print(type(runtime).__name__)
        report = replay_transcripts(guard, discover([example / "transcripts"]), runtime, expect=expected)
        assert report.passed is True and len(report.fires) == 3, report.summary()
        verdicts = SandboxRunner(runtime).check_batch(
            guard, [GuardInput(ToolCall("Bash", {"command": "git push -f origin main"}, "c"), {}, [])]
        )
        assert verdicts[0].block is not None and verdicts[0].error is None, verdicts

    claude_code.verify_hook((example / "hooks" / "ratchet_no_force_push_main.py").read_text())
    out = Path(tempfile.mkdtemp()) / "hook.py"
    args = ["--harness", str(example / "harness.json"), "--guard-id", guard.id,
            "--receipt", str(example / "receipt.json"), "--trusted-key",
            (example / "public_key.txt").read_text().strip(), "--out", str(out)]
    with contextlib.redirect_stdout(io.StringIO()):
        assert claude_code.main([*args, "--require", ""]) == 0
        assert claude_code.main(["--verify", str(out)]) == 0
    transcript = example / "transcripts" / "force-push-on-main.jsonl"
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s",
             "tool_input": {"command": "git push --force"}, "transcript_path": str(transcript), "cwd": "/"}
    env = {**os.environ, "RATCHET_HOOK_RECORDS": str(out.parent / "records")}
    done = subprocess.run([sys.executable, str(out)], input=json.dumps(event), text=True,
                          capture_output=True, env=env, timeout=60)
    assert (done.returncode, done.stdout) == (0, ""), done.stderr
    record = json.loads((out.parent / "records" / "s.jsonl").read_text())
    assert recorded_history(record), record

    try:
        guard_runtime(GuardLimits(require=("seccomp",)))
    except SandboxUnavailableError as exc:
        assert "not an isolation boundary" in str(exc)
    else:
        raise AssertionError("the open runtime accepted an isolation demand")
    with contextlib.redirect_stderr(io.StringIO()):
        assert claude_code.main([*args, "--require", "seccomp"]) == 1
    print("ok")
    """
)


def test_public_engine_runs_guards_and_hooks_without_the_enforcing_modules() -> None:
    env = {k: v for k, v in os.environ.items() if k != "RATCHET_GUARD_REQUIRE"}
    out = subprocess.run([sys.executable, "-c", PROGRAM, str(EXAMPLE)], capture_output=True, text=True,
                         check=False, timeout=300, env=env)  # fmt: skip
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["OpenGuardRuntime", "ok"]
