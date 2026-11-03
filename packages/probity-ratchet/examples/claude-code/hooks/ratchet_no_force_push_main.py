#!/usr/bin/env python3
# Ratchet emit-only guard hook for Claude Code (PreToolUse), from ratchet.export.claude_code.
# guard_id: no-force-push-main
# guard_sha256: 93ff0217a5d985a7c5d6bde1a28598ecc5562e535cfc2efcb0ec7129567ee341
# harness_version: c864f7158ed1
# harness_digest: c864f7158ed193dff641f55b4b52cc8c7f97226cace282a438c6a0f34a907fe0
# decision_receipt_sha256: 0a8411039051a0a65f3e05bfc51febe1d8ea27f357b0701c8cf244f69bdc032c
# decision_signers: e5f69435774f7baa472271261bea675f174b6f8bb2e3c22d2c1943cb8234d63e
# decided_at: 2026-10-12T00:10:59+00:00
# hook_kind: emit
# hook_runtime_sha256: fff6b8ce4b1bdb059f26497011f38622137cc692dd8cb6ffddbb21ed75adbfa4
# It records every call for replay against the guard and allows it; it never blocks.
# `python -m ratchet.export.claude_code --verify <this file>` checks every digest above.
# >>> ratchet emit hook runtime (verbatim ratchet/export/hook_emit.py) >>>
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


# <<< ratchet emit hook runtime <<<

GUARD_ID = "no-force-push-main"
GUARD_SHA256 = "93ff0217a5d985a7c5d6bde1a28598ecc5562e535cfc2efcb0ec7129567ee341"
RUNTIME_SHA256 = "fff6b8ce4b1bdb059f26497011f38622137cc692dd8cb6ffddbb21ed75adbfa4"
GUARD_SOURCE = r'''"""Ratchet guard: never force-push to, or delete, main or master.

Runs in the Ratchet guard sandbox: `check(call, view, history)` sees one tool call. A string blocks the call
and is shown to the agent; None leaves the call to the normal permission flow. Only modules the sandbox
preloads can be imported (`re`, `string`, ...); `shlex` is not one, so the shell words are split here.

A push targets main when a refspec names it (`main`, `HEAD:main`, `+x:refs/heads/main`), when it
pushes everything (`--all`, `--mirror`), or when it names no refspec and the checked-out branch,
`view["git_branch"]`, is main. It is forced by `-f`, `--force`, `--force-with-lease`, a `+` refspec, or
`--mirror`, which force-updates every remote branch. Pushes inside `$(...)`, backticks, `sh -c`/`bash -c`
scripts, `eval`, and heredocs or here-strings fed to a shell are found too. Text that merely mentions a
push, in a commit message, an echo, a grep, single quotes or a heredoc fed to any other program (a
`python -` script writing a document, `cat > file`), is not a push.
"""

import re
from typing import Any

PROTECTED = ("main", "master")
FORCE_FLAGS = ("--force", "--force-with-lease")  # and `-f`, alone or in a group of short flags
DELETE_FLAGS = ("--delete",)  # and `-d`, alone or in a group of short flags
DRY_RUN_FLAGS = ("--dry-run",)  # and `-n`; a dry run reports what would be pushed and changes nothing
EVERYTHING_FLAGS = ("--all", "--mirror", "--branches")
FORCING_FLAGS = ("--mirror",)  # git: "locally updated refs will be force updated on the remote end"
GIT_VALUE_OPTIONS = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path")
PUSH_VALUE_OPTIONS = ("-o", "--push-option", "--repo", "--receive-pack", "--exec")
WRAPPERS = ("sudo", "command", "env", "nohup", "time", "exec", "nice")
SHELLS = ("sh", "bash", "zsh", "dash", "ksh")
SEPARATORS = ";|&\n()"
MAX_DEPTH = 8
REDIRECT = re.compile(r"^(?:\d*|&)(?:>>?|<|>&|<&)(.*)$")


def closing(text: str, start: int) -> int:
    """Index of the parenthesis that closes a `$(` whose body starts at `start`, or len(text)."""
    depth = 1
    for i in range(start, len(text)):
        depth += {"(": 1, ")": -1}.get(text[i], 0)
        if depth == 0:
            return i
    return len(text)


def substitutions_in(text: str) -> list[str]:
    """Bodies of `$(...)` and backticks in text where quotes mean nothing, such as an unquoted heredoc."""
    out: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("$(", i):
            end = closing(text, i + 2)
            out.append(text[i + 2 : end])
        elif text[i] == "`":
            end = text.find("`", i + 1)
            end = len(text) if end < 0 else end
            out.append(text[i + 1 : end])
        else:
            end = i + (2 if text[i] == "\\" else 1) - 1
        i = end + 1
    return out


class Scanner:
    """Shell words per simple command, plus the bodies of command substitutions. Quotes and backslashes
    are honoured: nothing inside single quotes runs; `$(...)` and backticks run inside double quotes. A
    heredoc body is data: with a quoted delimiter nothing in it runs, otherwise only its substitutions."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.commands: list[list[str]] = []
        self.substitutions: list[str] = []
        self.scripts: list[str] = []
        self.words: list[str] = []
        self.word: list[str] = []
        self.started = False
        self.heredocs: list[tuple[str, bool, bool, list[str]]] = []
        i = 0
        quote = ""
        while i < len(text):
            i, quote = self.step(i, quote)
        self.end_word()
        self.end_command()

    def end_word(self) -> None:
        if self.started:
            self.words.append("".join(self.word))
        self.word, self.started = [], False

    def end_command(self) -> None:
        if self.words:
            self.commands.append(self.words)
        self.words = []

    def take(self, c: str) -> None:
        self.word.append(c)
        self.started = True

    def heredoc(self, i: int) -> int:
        """Record the heredoc whose `<<` is at `i`; return the index after its delimiter word."""
        j = i + 2
        strip_tabs = self.text.startswith("-", j)
        j += strip_tabs
        while j < len(self.text) and self.text[j] in " \t":
            j += 1
        start = j
        while j < len(self.text) and not self.text[j].isspace() and self.text[j] not in SEPARATORS:
            j += 1
        raw = self.text[start:j]
        delimiter = raw.replace("'", "").replace('"', "").replace("\\", "")
        self.heredocs.append((delimiter, raw != delimiter, strip_tabs, self.words))
        return j

    def bodies(self, i: int) -> int:
        """Consume the heredoc bodies that start at `i`; return the index after the last delimiter line. A
        body fed to a shell reading its script from stdin is a script; any other body is data."""
        for delimiter, quoted, strip_tabs, words in self.heredocs:
            body: list[str] = []
            while i < len(self.text):
                end = self.text.find("\n", i)
                end = len(self.text) if end < 0 else end
                line = self.text[i:end]
                i = end + 1
                if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                    break
                body.append(line)
            if shell_reads_stdin(words):
                self.scripts.append("\n".join(body))
            elif not quoted:
                self.substitutions.extend(substitutions_in("\n".join(body)))
        self.heredocs = []
        return i

    def step(self, i: int, quote: str) -> tuple[int, str]:
        text, c = self.text, self.text[i]
        if not quote and text.startswith("<<<", i):
            self.word.append("<<<")
            self.started = True
            return i + 3, quote
        if not quote and text.startswith("<<", i):
            self.end_word()
            return self.heredoc(i), quote
        if not quote and c == "\n" and self.heredocs:
            self.end_word()
            self.end_command()
            return self.bodies(i + 1), quote
        if quote == "'":
            if c == "'":
                return i + 1, ""
            self.take(c)
            return i + 1, quote
        if text.startswith("$(", i):
            end = closing(text, i + 2)
            self.substitutions.append(text[i + 2 : end])
            self.started = True
            return end + 1, quote
        if c == "`":
            end = text.find("`", i + 1)
            end = len(text) if end < 0 else end
            self.substitutions.append(text[i + 1 : end])
            self.started = True
            return end + 1, quote
        if c == "\\" and i + 1 < len(text):
            self.take(text[i + 1])
            return i + 2, quote
        if quote == '"':
            if c == '"':
                return i + 1, ""
            self.take(c)
            return i + 1, quote
        if c in "'\"":
            self.started = True
            return i + 1, c
        if c.isspace() or c in SEPARATORS:
            self.end_word()
            if c in SEPARATORS:
                self.end_command()
            return i + 1, quote
        self.take(c)
        return i + 1, quote


def command_start(words: list[str]) -> int:
    """Index of the command word, after `VAR=value` assignments and wrappers such as `sudo`."""
    i = 0
    while i < len(words) and (("=" in words[i] and not words[i].startswith("-")) or words[i] in WRAPPERS):
        i += 1
    return i


def shell_reads_stdin(words: list[str]) -> bool:
    """True when the command is a shell that takes its script from stdin: no `-c`, no script file."""
    i = command_start(words)
    if i >= len(words) or words[i].rsplit("/", 1)[-1] not in SHELLS:
        return False
    j = i + 1
    while j < len(words):
        w = words[j]
        if w.startswith("<<<"):
            j += 2 if w == "<<<" else 1
            continue
        redirect = REDIRECT.match(w)
        if redirect is not None:
            j += 1 if redirect.group(1) else 2
            continue
        if w == "--" or not w.startswith(("-", "+")):
            return False  # what follows is a script file; stdin is that script's data
        if not w.startswith("--") and "c" in w[1:]:
            return False
        if not w.startswith("--") and "s" in w[1:]:
            return True  # `-s`: the script is stdin and the remaining words are its arguments
        j += 1
    return True


def push_args(words: list[str]) -> list[str] | None:
    """The arguments after `git ... push`, or None when the command is not a git push."""
    i = command_start(words)
    if i >= len(words) or words[i].rsplit("/", 1)[-1] != "git":
        return None
    i += 1
    while i < len(words) and words[i].startswith("-"):
        i += 2 if words[i] in GIT_VALUE_OPTIONS else 1
    if i >= len(words) or words[i] != "push":
        return None
    return words[i + 1 :]


def nested_scripts(words: list[str]) -> list[str]:
    """Scripts a command runs as shell code: `sh -c <script>` (and `-lc` and the like), and `eval`."""
    i = command_start(words)
    if i >= len(words):
        return []
    name = words[i].rsplit("/", 1)[-1]
    if name == "eval":
        return [" ".join(words[i + 1 :])]
    if name not in SHELLS:
        return []
    for j in range(i + 1, len(words) - 1):
        flag = words[j]
        if flag.startswith("-") and not flag.startswith("--") and "c" in flag:
            return [words[j + 1]]
    if not shell_reads_stdin(words):
        return []
    for j in range(i + 1, len(words)):  # a here-string fed to the shell is its script
        if words[j] == "<<<" and j + 1 < len(words):
            return [words[j + 1]]
        if words[j].startswith("<<<") and words[j] != "<<<":
            return [words[j][3:]]
    return []


def destination(refspec: str, branch: str) -> str:
    dst = refspec.lstrip("+")
    if ":" in dst:
        dst = dst.split(":", 1)[1]
    if dst in ("HEAD", "@"):
        dst = branch
    return dst.removeprefix("refs/heads/")


def verdict(args: list[str], branch: str) -> str | None:
    forced = deleting = everything = dry_run = False
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        redirect = REDIRECT.match(a)
        if a in PUSH_VALUE_OPTIONS or (redirect is not None and not redirect.group(1)):
            i += 2  # an option's value, or a redirection's target, is not a refspec
            continue
        if redirect is not None:
            i += 1
            continue
        short = a[1:] if a.startswith("-") and not a.startswith("--") else ""  # `-nf` is `-n -f`
        forced = forced or a.split("=", 1)[0] in FORCE_FLAGS or a in FORCING_FLAGS or "f" in short
        deleting = deleting or a in DELETE_FLAGS or "d" in short
        dry_run = dry_run or a in DRY_RUN_FLAGS or "n" in short
        everything = everything or a in EVERYTHING_FLAGS
        if not a.startswith("-"):
            positional.append(a)
        i += 1
    if dry_run:
        return None
    refspecs = positional[1:]
    if not refspecs and not everything:
        refspecs = [branch or "?"]
    hits = sorted({destination(r, branch) for r in refspecs} & set(PROTECTED)) or (
        list(PROTECTED) if everything else []
    )
    plus = any(r.startswith("+") and destination(r, branch) in PROTECTED for r in refspecs)
    empty_src = any(r.startswith(":") and destination(r, branch) in PROTECTED for r in refspecs)
    if hits and (forced or plus):
        return (
            f"force push to {hits[0]} rewrites shared history; push a branch and open a pull request instead"
        )
    if hits and (deleting or empty_src):
        return f"deleting {hits[0]} is not allowed"
    if forced and not branch and not positional[1:] and not everything:
        return "force push with no refspec and an unknown current branch; name the branch you mean to push"
    return None


def reason_for(text: str, branch: str, depth: int = 0) -> str | None:
    if depth > MAX_DEPTH:
        return "shell nesting too deep to check; run the push directly"
    scan = Scanner(text)
    for words in scan.commands:
        args = push_args(words)
        reason = verdict(args, branch) if args is not None else None
        for script in [] if reason else nested_scripts(words):
            reason = reason or reason_for(script, branch, depth + 1)
        if reason is not None:
            return reason
    for body in scan.substitutions + scan.scripts:
        reason = reason_for(body, branch, depth + 1)
        if reason is not None:
            return reason
    return None


def check(call: Any, view: Any, history: Any) -> str | None:
    if call.name != "Bash":
        return None
    command = call.args.get("command")
    if not isinstance(command, str):
        return None
    return reason_for(command, str(view.get("git_branch") or ""))
'''
CONFIG = EmitConfig(
    guard_id=GUARD_ID,
    guard_sha256=GUARD_SHA256,
    runtime_sha256=RUNTIME_SHA256,
    hook_file=__file__,
)

if __name__ == "__main__":
    sys.exit(main(CONFIG, sys.argv[1:]))
