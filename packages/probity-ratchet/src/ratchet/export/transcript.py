"""Claude Code session transcripts as guard inputs. Standard library only.

Transcript mapping (one JSONL line per content block, as Claude Code writes them):
  assistant text or tool_use  ->  Event "model"      {"model", "content", "tool_calls"}
  each tool_use               ->  Event "tool_call"  {"call": {"name", "args", "call_id"}, "view"}
  user tool_result            ->  Event "tool_result" {"result": {"call_id", "ok", "data", "error"},
                                                       "decisions": []}
User prompts, thinking blocks, attachments and system lines carry no event: the contract's event kinds
have none for them, and the shapes above are the ones the Ratchet worker records. Tool results are kept
whole.

The guard's `view` for a coding session is {"cwd", "git_branch"} (`ratchet.export.hook_emit.coding_view`,
the function the live hook uses). The history for a call is every event before the transcript line that
holds the call. A guard whose source provably never reads its history (see `reads_history`) gets an empty
history.

`recorded_history` rebuilds the history of a call the emit-only hook recorded, from the transcript prefix the
record names, and refuses when that prefix no longer has the recorded digest.
"""

from __future__ import annotations

import ast
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ratchet.export.hook_emit import coding_view


# --- transcript parsing -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class CallSite:
    """One tool call in a transcript, with what the guard saw at that point."""

    call: dict[str, Any]
    view: dict[str, Any]
    history_len: int
    line: int


@dataclass
class Transcript:
    events: list[dict[str, Any]] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    lines: int = 0
    malformed: int = 0

    def add(self, kind: str, payload: dict[str, Any], ts: float) -> None:
        self.events.append({"seq": len(self.events), "kind": kind, "payload": payload, "ts": ts})

    def feed(self, lines: Iterable[str | bytes]) -> Transcript:
        """Parse more JSONL lines. Lines that are not JSON objects are counted, not fatal."""
        for raw in lines:
            self.lines += 1
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except ValueError:
                self.malformed += 1
                continue
            if not isinstance(entry, dict):
                self.malformed += 1
                continue
            message = entry.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), list):
                continue
            ts = _timestamp(entry.get("timestamp"))
            if entry.get("type") == "assistant":
                _assistant(self, entry, message, self.lines, ts)
            elif entry.get("type") == "user":
                _user(self, message, ts)
        return self

    def site_of(self, call: Mapping[str, Any]) -> CallSite | None:
        """The call's own site: by tool use id, else the last call with the same name and arguments."""
        call_id = call.get("call_id")
        if call_id:
            for site in reversed(self.calls):
                if site.call["call_id"] == call_id:
                    return site
        for site in reversed(self.calls):
            if site.call["name"] == call.get("name") and site.call["args"] == call.get("args"):
                return site
        return None

    def history_before(self, call: Mapping[str, Any]) -> list[dict[str, Any]]:
        site = self.site_of(call)
        return self.events[: site.history_len] if site is not None else list(self.events)


def parse_transcript(lines: Iterable[str | bytes]) -> Transcript:
    return Transcript().feed(lines)


def _timestamp(value: Any) -> float:
    if not isinstance(value, str):
        return 0.0
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return 0.0


def _blocks(content: list[Any], kind: str) -> list[dict[str, Any]]:
    return [b for b in content if isinstance(b, dict) and b.get("type") == kind]


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            str(b.get("text", "")) if b.get("type") == "text" else f"[{b.get('type')}]"
            for b in content
            if isinstance(b, dict)
        ]
        return "\n".join(parts)
    return ""


def _assistant(t: Transcript, entry: dict[str, Any], message: dict[str, Any], line: int, ts: float) -> None:
    content = message["content"]
    texts = [str(b.get("text", "")) for b in _blocks(content, "text")]
    calls = [
        {
            "name": str(b.get("name", "")),
            "args": b["input"] if isinstance(b.get("input"), dict) else {},
            "call_id": str(b.get("id", "")),
        }
        for b in _blocks(content, "tool_use")
    ]
    if not texts and not calls:
        return
    before = len(t.events)
    view = coding_view(str(entry.get("cwd") or ""), str(entry.get("gitBranch") or ""))
    model = {"model": str(message.get("model") or ""), "content": "\n".join(texts), "tool_calls": calls}
    t.add("model", model, ts)
    for call in calls:
        t.calls.append(CallSite(call, view, before, line))
        t.add("tool_call", {"call": call, "view": view}, ts)


def _user(t: Transcript, message: dict[str, Any], ts: float) -> None:
    for block in _blocks(message["content"], "tool_result"):
        text = _result_text(block.get("content"))
        failed = bool(block.get("is_error"))
        result = {
            "call_id": str(block.get("tool_use_id", "")),
            "ok": not failed,
            "data": None if failed else {"content": text},
            "error": text if failed else None,
        }
        t.add("tool_result", {"result": result, "decisions": []}, ts)


# --- does the guard read its history? ---------------------------------------------------------------------

# Names through which code can reach a frame, a code object or another function's arguments.
INTROSPECTION = frozenset(
    {
        "locals", "vars", "globals", "eval", "exec", "compile", "__import__", "getattr", "setattr",
        "delattr", "sys", "inspect", "gc", "builtins", "__builtins__", "importlib", "_getframe",
        "f_locals", "f_back", "f_globals", "tb_frame", "gi_frame", "cr_frame", "ag_frame", "__code__",
        "__closure__", "__globals__", "__dict__", "__self__", "__func__", "__traceback__",
        "__getattribute__", "attrgetter", "methodcaller",
    }
)  # fmt: skip


# Attribute names that lead from an object to a frame, a code object or a function's namespace.
FRAME_WORDS = tuple(
    sorted(w for w in INTROSPECTION if w.startswith(("f_", "tb_", "gi_", "cr_", "ag_", "_", "__")))
)
# Attributes that are a way in wherever they appear (`re.compile` is harmless; a bare `compile` is not).
ATTRIBUTE_WORDS = frozenset(
    {
        *FRAME_WORDS,
        "attrgetter",
        "methodcaller",
        "currentframe",
        "__subclasses__",
        "__mro__",
        "__bases__",
        "__base__",
    }
)


def _check_def(tree: ast.Module) -> ast.FunctionDef | None:
    """The module's one plain `def check(call, view, history)`, or None when it has no such single def."""
    defs = [
        n for n in tree.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef) and n.name == "check"
    ]
    if len(defs) != 1 or not isinstance(defs[0], ast.FunctionDef) or defs[0].decorator_list:
        return None
    args = defs[0].args
    plain = [*args.posonlyargs, *args.args]
    if args.vararg or args.kwarg or args.kwonlyargs or len(plain) != 3:
        return None
    return defs[0]


def _could_reach(node: ast.AST, hidden: str, check: ast.FunctionDef) -> bool:
    """Whether this node names the hidden parameter, rebinds `check`, or names a way into frames."""
    if isinstance(node, ast.Name):
        rebinds = node.id == "check" and not isinstance(node.ctx, ast.Load)
        return rebinds or node.id == hidden or node.id in INTROSPECTION
    if isinstance(node, ast.Attribute):
        return node.attr in ATTRIBUTE_WORDS
    if isinstance(node, ast.Constant):  # a format field such as "{0.gi_frame}" reads an attribute by name
        return isinstance(node.value, str) and any(word in node.value for word in FRAME_WORDS)
    if isinstance(node, ast.Import | ast.ImportFrom):
        modules = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
        named = [m.split(".")[0] for m in modules] + [a.name for a in node.names]
        return any(n in INTROSPECTION for n in named)
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return node is not check and node.name == "check"
    return False


def reads_history(source: str) -> bool:
    """False only when the guard provably never sees its history: the module defines `check` once, at top
    level, undecorated, with exactly three plain parameters; the third is never named anywhere; `check` is
    never rebound; and nothing names a way into frames or code objects, not even inside a string. Anything
    else counts as reading."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True
    check = _check_def(tree)
    if check is None:
        return True
    hidden = [*check.args.posonlyargs, *check.args.args][2].arg
    return any(_could_reach(node, hidden, check) for node in ast.walk(tree))


class RecordError(ValueError):
    """A hook record's transcript prefix is missing or no longer matches its recorded digest."""


def recorded_history(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The events before the recorded call, read from the transcript prefix the hook record names."""
    ref = record.get("transcript")
    if ref is None:
        return []
    if not isinstance(ref, Mapping):
        raise RecordError("the record's transcript reference is not an object")
    path, size, digest = ref.get("path"), ref.get("bytes"), ref.get("sha256")
    if not isinstance(path, str) or not isinstance(size, int) or not isinstance(digest, str):
        raise RecordError("the record's transcript reference needs path, bytes and sha256")
    try:
        with Path(path).open("rb") as handle:
            prefix = handle.read(size)
    except OSError as exc:
        raise RecordError(f"transcript {path} cannot be read: {exc}") from exc
    if len(prefix) != size or hashlib.sha256(prefix).hexdigest() != digest:
        raise RecordError(f"transcript {path} no longer holds the recorded prefix")
    return parse_transcript(prefix.splitlines()).history_before(record["call"])
