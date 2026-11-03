# Measurements: a plain LangGraph tool against the guarded one

Measured on Mon 2 Nov 2026 with langgraph 1.2.19 and the eight runtime scenarios of
agent-evidence-vectors 0.31.2 (`vectors-uncertain-effect`), on Python 3.12. The plain tool posts
the write with httpx and raises on failure, as an ordinary `@tool` does; the guarded tool is
`effect_tool` from this package. Each cell is the number of effects the counting owner holds
afterwards. A scenario passes when the effect count and the reported outcome are ones the scenario
accepts; for the guarded tool it also needs the reference reader to allow the exported record and
the journal to match the owner's counts.

| scenario | plain, no retry | plain, RetryPolicy | plain, model calls again | guarded, every path |
| --- | --- | --- | --- | --- |
| confirmed | 1 | 2 | 1 | 1 |
| commit-then-lost-reply | 1 | 2 | 2 | 1 |
| commit-then-lost-reply-deduplicating | 1 | 1 | 1 | 1 |
| owner-unreachable-after-lost-reply | 1 | 2 | 2 | 1 |
| lost-before-commit | 0 | 1 | 1 | 1 |
| late-commit-after-missed-lookup | 0 | 2 | 2 | 1 |
| definite-no-effect | 0 | 0 | 1 | 0 or 1 |
| lease-lost-after-lost-reply | 1 | 2 | 2 | 1 |
| scenarios passed | 3 of 8 | 3 of 8 | 4 of 8 | 8 of 8 on each of four paths |

The RetryPolicy column is the documented `RetryPolicy(max_attempts=3)` with its default `retry_on`,
on a `ToolNode` whose step also calls a second tool that loses its connection once. LangGraph retries
the node, and the node runs every tool call of the step again: a write whose reply arrived
(`confirmed`) is sent a second time. The "model calls again" column uses
`ToolNode(handle_tool_errors=True)`, so the model sees the error and calls the tool again.

The guarded tool passes all eight on four paths: no retry, the RetryPolicy path above, a process
that stops right after the first send and a new process that resumes the checkpointed thread from
the journal file, and a model calling again. `definite-no-effect` leaves one effect on the paths
that call the tool a second time: the owner had answered that the first call did nothing, so the
second send is the first effect, which the scenario accepts.

Reproduce with `uv run python -m pytest tests/test_scenarios.py` in `packages/probity-effects`;
the two control tests there assert the plain-tool counts above for the RetryPolicy and the
model-calls-again paths.
