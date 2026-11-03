"""Emit-only Claude Code PreToolUse hook runtime. Standard library only; it never blocks a call.

`ratchet.export.claude_code` pastes this module verbatim into a generated hook by default. At each tool call
the hook appends one JSON line to `<records>/<session_id>.jsonl` and exits 0 with no output, which leaves the
call to Claude Code's normal permission flow. Every failure (unreadable input, an unwritable directory, a
hook file whose digests no longer match) is reported on stderr or in the record and still allows the call:
this hook observes, and enforcement is the job of an enforcing hook body (`--hook` in `claude_code`).

A record holds the guard it was generated for, the call, the guard's view and a reference to the history:
  {"guard_id", "guard_sha256", "session_id", "hook_event_name", "call": {"name", "args", "call_id"},
   "view": {"cwd", "git_branch"}, "transcript": {"path", "bytes", "sha256"} | null,
   "integrity_error": str | null, "error": str | null, "recorded_at"}
The history is the transcript prefix the hook saw (the file's bytes at the time of the call, by size and
SHA-256), not a copy: Claude Code appends to the transcript, so the prefix is fixed, and copying it into
every record would make the records quadratic in the session's length. `ratchet.export.transcript.
recorded_history` rebuilds the events before the call from it, the same events an enforcing hook reads, and
refuses when the prefix changed. Keep the transcript with the records when the history must outlive
Claude Code's own transcript cleanup.

Records go to RATCHET_HOOK_RECORDS when it is set, else to `ratchet-records/` beside the hook file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

RUNTIME_BEGIN = "# >>> ratchet emit hook runtime (verbatim ratchet/export/hook_emit.py) >>>"
RUNTIME_END = "# <<< ratchet emit hook runtime <<<"
RECORDS_ENV = "RATCHET_HOOK_RECORDS"
RECORDS_DIR = "ratchet-records"


def coding_view(cwd: str, git_branch: str) -> dict[str, Any]:
    return {"cwd": cwd, "git_branch": git_branch}


def _head_file(directory: Path) -> Path | None:
    dot = directory / ".git"
    if dot.is_dir():
        return dot / "HEAD"
    if dot.is_file():
        text = dot.read_text(encoding="utf-8").strip()
        if text.startswith("gitdir:"):
            gitdir = Path(text[len("gitdir:") :].strip())
            return (gitdir if gitdir.is_absolute() else directory / gitdir) / "HEAD"
    return None


def git_branch(cwd: str) -> str:
    """The checked-out branch for `cwd`, as Claude Code records it: a name, "HEAD" when detached, else ""."""
    start = Path(cwd)
    for directory in (start, *start.parents):
        head = _head_file(directory)
        if head is None:
            continue
        try:
            value = head.read_text(encoding="utf-8").strip()
        except OSError:
            return ""
        if not value.startswith("ref:"):
            return "HEAD"
        return value[len("ref:") :].strip().removeprefix("refs/heads/")
    return ""


def transcript_path(event: Mapping[str, Any]) -> Path | None:
    """The transcript a call belongs to: the subagent's own file when the call came from a subagent
    (`<session>/subagents/agent-<agent_id>.jsonl`)."""
    path = event.get("transcript_path")
    if not isinstance(path, str) or not path:
        return None
    agent = event.get("agent_id")
    if isinstance(agent, str) and agent:
        own = Path(path).with_suffix("") / "subagents" / f"agent-{agent}.jsonl"
        if own.is_file():
            return own
    return Path(path)


def call_and_view(event: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | str:
    """The guard's call and view for a PreToolUse event, or why the event cannot be judged."""
    if event.get("hook_event_name") != "PreToolUse":
        return f"installed on {event.get('hook_event_name')!r}, expected PreToolUse"
    name, args = event.get("tool_name"), event.get("tool_input")
    if not isinstance(name, str) or not isinstance(args, dict):
        return "hook input has no tool_name and tool_input"
    call = {"name": name, "args": args, "call_id": str(event.get("tool_use_id") or "")}
    cwd = str(event.get("cwd") or "")
    return call, coding_view(cwd, git_branch(cwd) if cwd else "")


def transcript_ref(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """The transcript prefix this call's history is read from: path, size and SHA-256 of its bytes now."""
    path = transcript_path(event)
    if path is None:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


@dataclass(frozen=True)
class EmitConfig:
    """`hook_file` and `runtime_sha256` are set in a generated hook, which re-hashes its own embedded runtime
    at every call; they are None when this module is imported rather than embedded."""

    guard_id: str
    guard_sha256: str
    runtime_sha256: str | None = None
    hook_file: str | None = None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def embedded_runtime(text: str) -> str | None:
    """The runtime source pasted between the markers of a generated hook, or None without markers."""
    begin, end = text.find(RUNTIME_BEGIN + "\n"), text.find("\n" + RUNTIME_END)
    if begin < 0 or end < begin:
        return None
    return text[begin + len(RUNTIME_BEGIN) + 1 : end].rstrip("\n") + "\n"


def integrity_error(config: EmitConfig) -> str | None:
    if config.hook_file is None:
        return None
    runtime = embedded_runtime(Path(config.hook_file).read_text(encoding="utf-8"))
    if runtime is None or _sha256(runtime) != config.runtime_sha256:
        return "hook runtime does not match its recorded digest"
    return None


def records_dir(config: EmitConfig, env: Mapping[str, str]) -> Path:
    if env.get(RECORDS_ENV):
        return Path(env[RECORDS_ENV])
    if config.hook_file is None:
        raise ValueError(f"set {RECORDS_ENV}: an imported emit hook has no hook file to write beside")
    return Path(config.hook_file).resolve().parent / RECORDS_DIR


def session_file(directory: Path, session_id: Any) -> Path:
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(session_id or "")).strip(".") or "unknown-session"
    return directory / f"{name[:120]}.jsonl"


def make_record(config: EmitConfig, event: Mapping[str, Any], now: datetime | None = None) -> dict[str, Any]:
    prepared = call_and_view(event)
    call, view = prepared if not isinstance(prepared, str) else (None, None)
    return {
        "guard_id": config.guard_id,
        "guard_sha256": config.guard_sha256,
        "session_id": str(event.get("session_id") or ""),
        "hook_event_name": event.get("hook_event_name"),
        "call": call,
        "view": view,
        "transcript": transcript_ref(event) if call is not None else None,
        "integrity_error": integrity_error(config),
        "error": prepared if isinstance(prepared, str) else None,
        "recorded_at": (now or datetime.now(UTC)).isoformat(timespec="microseconds"),
    }


def append_record(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def run_hook(config: EmitConfig, stdin: IO[str], stderr: IO[str], env: Mapping[str, str]) -> int:
    """Record the call and allow it: always exit 0 with no output on stdout."""
    try:
        event = json.loads(stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook input is not a JSON object")
        record = make_record(config, event)
        append_record(session_file(records_dir(config, env), event.get("session_id")), record)
    except Exception as exc:  # observing must never block the call
        stderr.write(f"ratchet emit hook {config.guard_id}: not recorded: {type(exc).__name__}: {exc}\n")
    return 0


def main(config: EmitConfig, argv: Sequence[str]) -> int:
    del argv
    return run_hook(config, sys.stdin, sys.stderr, os.environ)
