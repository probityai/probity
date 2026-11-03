# Ratchet guard as a Claude Code hook

One guard, proven against session transcripts, then installed into Claude Code as a PreToolUse hook. The
guard here blocks force pushes to, and deletion of, `main` or `master`. The hook this package exports by
default records every call for replay against the guard and allows it; a hook that denies the call before it
runs needs an enforcing hook body (see "Enforcing hook bodies" below).

| File | What it is |
| --- | --- |
| `no_force_push_main.py` | The guard: `check(call, view, history) -> str | None` |
| `transcripts/` | Six synthetic Claude Code sessions (one in a subagent file), written for this example |
| `expected_fires.txt` | The three tool calls the guard must block, by tool use id |
| `replay.json` | The replay over `transcripts/`: 15 calls, 3 fires, all expected, 0 unexpected, 0 errors |
| `harness.json`, `receipt.json`, `public_key.txt` | The harness holding the guard, the signed decision that admitted it, and the signer's public key |
| `hooks/ratchet_no_force_push_main.py` | The generated emit-only hook: one self-contained file, Python 3.12+, standard library only |
| `settings.json` | The `.claude/settings.json` fragment that installs it |
| `build.py` | Rebuilds every file above: `uv run python examples/claude-code/build.py` |

## Prove it on your own sessions first

```bash
uv run python -m ratchet.export.replay_transcripts --guard examples/claude-code/no_force_push_main.py \
    ~/.claude/projects --out private/replay.json
```

The command prints counts only (sessions, calls, fires, guard errors, per tool); the fire sites and the
guard's reasons go to the `--out` file. Each call is judged with the inputs the live hook builds: the call,
the view `{"cwd", "git_branch"}` and the events before it. Pass `--expect ids.txt` to require that the
guard fires on exactly those calls.

On one developer machine (13,739 sessions, 632,126 tool calls) this guard fired on 6 calls in 3 sessions,
with no guard error and no false alarm; all 6 were force pushes onto `main`. An earlier version also fired
on text inside a quoted heredoc that a Python script was writing to a document, which this one reads as data.

## Install

```bash
mkdir -p .claude/hooks
cp examples/claude-code/hooks/ratchet_no_force_push_main.py .claude/hooks/
```

Then merge `settings.json` into `.claude/settings.json`. The hook never blocks: it appends one JSON line
per call to `.claude/hooks/ratchet-records/<session>.jsonl` (or to `$RATCHET_HOOK_RECORDS`) and exits 0, even
when it cannot write or its own digests no longer match, which the record then says.

Try it without Claude Code:

```bash
echo '{"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": ".", "session_id": "try",
       "tool_input": {"command": "git push --force origin main"}}' \
  | python3 .claude/hooks/ratchet_no_force_push_main.py; echo "exit $?"
cat .claude/hooks/ratchet-records/try.jsonl
```

It exits 0 and the record holds the call, the view `{"cwd", "git_branch"}` and a reference to the transcript
prefix the history is read from (path, size and SHA-256). `ratchet.export.transcript.recorded_history`
rebuilds the events before the call from it, and refuses once that prefix has changed.

## Enforcing hook bodies

`--hook NAME` takes the hook body from the `ratchet.hooks` entry-point group: a package registers a factory
that returns a `HookBody` (`ratchet.export.claude_code`), which renders the hook file and verifies it, and
`--verify` picks the body from the header's `hook_kind`. This package registers none, because it ships no
isolation boundary to run an untrusted guard in at every tool call; `--require` with the emit body is
refused rather than ignored.

## Provenance

The hook's header names the guard, the harness version and digest, the SHA-256 of `receipt.json`, and the
key that signed it. The exporter refuses a guard unless that receipt verifies under a trusted key and
admits exactly this harness.

```bash
uv run python -m ratchet.export.claude_code --verify .claude/hooks/ratchet_no_force_push_main.py
sha256sum examples/claude-code/receipt.json     # equals decision_receipt_sha256 in the header
```

This example's decision records one check, the transcript replay above, admitted by a human. Ratchet's
held-out, no-regression and authority gates run on its simulated-company cases and do not apply to this
coding-agent guard.

To export your own admitted guard:

```bash
uv run python -m ratchet.export.claude_code --harness harness.json --guard-id <id> \
    --receipt receipt.json --trusted-key <public key hex> --out .claude/hooks/ratchet_<id>.py
```

The MCP gateway that applies the same guards to `tools/call` requests is part of the enforcing runtime and
is not covered here.
