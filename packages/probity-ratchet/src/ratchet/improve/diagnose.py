"""Group failed traces by failure mechanism and name the step in each trace that caused the failure.

Grouping is deterministic: the cluster key is built from the grader reason (with ids and numbers
normalised away), whether the failure is something the agent did or something it never did, the tool
called at the failing step, the error the world returned just before it, and whether the call repeats an
earlier one. A caller may supply `summarize`, which writes the one-line mechanism summary for each cluster;
it never decides membership, and without it the summary is built from the key.

The failing step comes from grading intermediate states: the earliest tool call after which the reason
holds and keeps holding. A reason that holds before the agent acts and is never cleared is an omission,
located at the trace's last event.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ratchet_cases.types import Trace, sha256_hex

from ratchet.canonical import canonical_json
from ratchet.improve.evaluate import is_infra_failure
from ratchet.improve.failures import (
    FailureCluster,
    FailurePoint,
    Summarizer,
    locate,
    normalize,
)
from ratchet.improve.sim import Simulator, Walk, call_of


def _features(trace: Trace, seq: int) -> dict[str, str]:
    before = [e for e in trace.events if e.seq < seq]
    at = next((e for e in trace.events if e.seq == seq), None)
    tool = call_of(at)["name"] if at is not None and at.kind == "tool_call" else "<end>"
    prior_error = ""
    for e in reversed(before):
        if e.kind == "tool_result":
            p = e.payload.get("result", e.payload)
            if p.get("ok") is False:
                prior_error = normalize(str(p.get("error") or "error"))
            break
    repeat = ""
    if at is not None and at.kind == "tool_call":
        c = call_of(at)
        earlier = [call_of(e) for e in before if e.kind == "tool_call"]
        if any(x["name"] == c["name"] and x["args"] == c["args"] for x in earlier):
            repeat = "same_args"
        elif any(x["name"] == c["name"] for x in earlier):
            repeat = "same_tool"
    return {"tool": tool, "prior_error": prior_error, "repeat": repeat}


def failure_points(trace: Trace, walk: Walk | None) -> list[FailurePoint]:
    points: list[FailurePoint] = []
    for reason in trace.outcome.reasons or ["failed without a reason"]:
        seq, mode = locate(trace, walk, reason)
        tool = _features(trace, seq)["tool"]
        points.append(FailurePoint(trace.run_id, trace.case_id, seq, reason, mode, tool))
    return points


def _key(trace: Trace, point: FailurePoint) -> dict[str, str]:
    return {"reason": normalize(point.reason), "mode": point.mode, **_features(trace, point.seq)}


def _default_summary(key: dict[str, str], n: int) -> str:
    what = "did" if key["mode"] == "commission" else "never did"
    bits = [f"{n} failure(s): the agent {what} something that led to '{key['reason']}'"]
    if key["tool"] != "<end>":
        bits.append(f"at a {key['tool']} call")
    if key["prior_error"]:
        bits.append(f"right after the world returned '{key['prior_error']}'")
    if key["repeat"]:
        bits.append(f"repeating an earlier call ({key['repeat']})")
    return ", ".join(bits) + "."


def diagnose(
    traces: Sequence[Trace],
    simulator: Simulator | None = None,
    summarize: Summarizer | None = None,
    on_walk_error: Callable[[Trace, Exception], None] | None = None,
) -> list[FailureCluster]:
    """Cluster the failed traces in `traces` (passing ones are ignored), largest cluster first."""
    groups: dict[str, tuple[dict[str, str], list[FailurePoint]]] = {}
    by_run: dict[str, Trace] = {}
    for t in traces:
        if t.outcome.passed or is_infra_failure(t):  # an endpoint failure says nothing about the harness
            continue
        by_run[t.run_id] = t
        walk: Walk | None = None
        if simulator is not None:
            try:
                walk = simulator.walk(t)
            except Exception as exc:  # one unreplayable trace must not sink the diagnosis
                if on_walk_error is not None:
                    on_walk_error(t, exc)
        for p in failure_points(t, walk):
            key = _key(t, p)
            cid = sha256_hex(canonical_json(key))[:10]
            groups.setdefault(cid, (key, []))[1].append(p)
    clusters: list[FailureCluster] = []
    for cid, (key, members) in sorted(groups.items(), key=lambda kv: (-len(kv[1][1]), kv[0])):
        summary = _default_summary(key, len(members))
        traces_of = {m.run_id: by_run[m.run_id] for m in members}
        if summarize is not None:
            try:
                summary = summarize(key, members, traces_of) or summary
            except Exception as exc:  # the deterministic summary stands, and says why
                summary += f" (model summary unavailable: {type(exc).__name__})"
        clusters.append(FailureCluster(cid, key, members, summary, traces_of))
    return clusters
