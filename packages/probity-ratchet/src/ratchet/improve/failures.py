"""Failure finding: the records it produces, the two protocols behind it, and the open baseline of each.

A diagnoser groups failed traces into clusters and names the step in each trace that caused the failure.
An overfit screen collects the literals the training traces contain and reports each one a candidate's new
text copies. The loop, admission, the demo and the evidence view take both by argument. Without one, the
`ratchet.failures` entry-point group names the installed implementation (entries `diagnoser` and `overfit`,
each a zero-argument factory), and without an installed entry the open baselines in this module run.

The open baselines are deliberately small. `open_diagnose` makes one cluster per distinct grader reason, with the
step located by grading intermediate states when a simulator is supplied. `OpenOverfitScreen` flags a candidate
that repeats, word for word, a string the training traces passed to a tool. They are enough to run, replay
and verify every published record; a richer implementation plugs in through the entry points.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from functools import cache
from importlib.metadata import entry_points
from typing import Any, Literal, Protocol

from ratchet_cases.types import Event, Trace, sha256_hex

from ratchet.canonical import canonical_json
from ratchet.improve.evaluate import is_infra_failure
from ratchet.improve.sim import Simulator, Walk, call_of, last_seq
from ratchet.types import Harness

GROUP = "ratchet.failures"
DIAGNOSER_ENTRY = "diagnoser"
OVERFIT_ENTRY = "overfit"

Mode = Literal["commission", "omission", "unlocated"]

_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_IDLIKE = re.compile(r"\b[\w.-]*\d[\w.-]*\b")
# Record ids, emails and slugs: any token joining word characters with "@", ".", "-" or "_".
_COMPOUND = re.compile(r"[\w]+(?:[@.\-_][\w]+)+")
_SPACE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """A reason with its specifics removed, so the same mechanism on different records matches."""
    out = _QUOTED.sub("<s>", text.lower())
    out = _COMPOUND.sub("<id>", out)
    out = _IDLIKE.sub("<id>", out)
    return _SPACE.sub(" ", out).strip()


@dataclass(frozen=True)
class FailurePoint:
    run_id: str
    case_id: str
    seq: int
    reason: str
    mode: Mode
    tool: str

    @property
    def id(self) -> str:
        return f"{self.run_id}@{self.seq}"


@dataclass(frozen=True)
class FailureCluster:
    id: str
    key: dict[str, str]
    members: list[FailurePoint]
    summary: str = ""
    traces: dict[str, Trace] = field(default_factory=dict, compare=False, repr=False)

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "summary": self.summary,
            "members": [asdict(m) | {"id": m.id} for m in self.members],
        }


@dataclass
class Literals:
    ids: set[str] = field(default_factory=set)
    amounts: set[int] = field(default_factory=set)
    names: set[str] = field(default_factory=set)


# A cluster's key, its members and their traces in; a one-sentence mechanism, or None for the default, out.
Summarizer = Callable[[Mapping[str, str], Sequence[FailurePoint], Mapping[str, Trace]], str | None]
WalkErrorHandler = Callable[[Trace, Exception], None]


class Diagnoser(Protocol):
    """Cluster the failed traces among `traces` (passing ones are ignored), largest cluster first.

    A caller may supply `summarize`, which writes the one-line mechanism summary of each cluster and never
    decides membership, and `on_walk_error`, told of each trace the simulator could not walk.
    """

    def __call__(
        self,
        traces: Sequence[Trace],
        simulator: Simulator | None = None,
        summarize: Summarizer | None = None,
        on_walk_error: WalkErrorHandler | None = None,
    ) -> list[FailureCluster]: ...


class OverfitScreen(Protocol):
    """A change may not carry literals copied from the training traces.

    `name` identifies the screen in the decisions it gates: a recomputation of a recorded decision is only
    meaningful under the screen that made it.
    """

    name: str

    def training_literals(self, traces: Iterable[Trace]) -> Literals:
        """Every literal the training traces contain that a general change would not name."""
        ...

    def lint(self, parent: Harness, candidate: Harness, literals: Literals) -> list[dict[str, str]]:
        """One `{"where", "category", "literal"}` hit for each literal the candidate's new text carries."""
        ...


def locate(trace: Trace, walk: Walk | None, reason: str) -> tuple[int, Mode]:
    """The seq of the event that caused `reason`, and whether it was an act or an omission.

    The failing step is the earliest tool call after which the reason holds and keeps holding, from grading
    intermediate states. A reason that holds before the agent acts and is never cleared is an omission,
    located at the trace's last event.
    """
    end = last_seq(trace)
    if walk is None or walk.initial_reasons is None or any(s.reasons_after is None for s in walk.steps):
        return _locate_by_mention(trace, reason)
    n = normalize(reason)
    holds = [n in _norms(s.reasons_after) for s in walk.steps]
    i = len(holds)
    while i > 0 and holds[i - 1]:
        i -= 1
    if i == len(holds) or (i == 0 and n in _norms(walk.initial_reasons)):
        return end, "omission"
    return walk.steps[i].seq, "commission"


def _norms(reasons: Sequence[str] | None) -> set[str]:
    return {normalize(r) for r in reasons or ()}


def _locate_by_mention(trace: Trace, reason: str) -> tuple[int, Mode]:
    """Without intermediate grading: the last tool call whose arguments name an id the reason names."""
    ids = set(_IDLIKE.findall(reason))
    hit: int | None = None
    for e in trace.events:
        if e.kind == "tool_call" and ids & set(_IDLIKE.findall(json.dumps(call_of(e)["args"]))):
            hit = e.seq
    if hit is not None:
        return hit, "commission"
    return last_seq(trace), "unlocated"


def render_event(e: Event, limit: int = 400) -> str:
    body = json.dumps(e.payload, sort_keys=True, default=str)
    if len(body) > limit:
        body = body[:limit] + "...(truncated)"
    return f"[{e.seq}] {e.kind}: {body}"


def excerpt(trace: Trace, seq: int, before: int = 8, after: int = 2) -> str:
    """The events around `seq`, the failing step marked, for a model to read."""
    idx = next((i for i, e in enumerate(trace.events) if e.seq >= seq), len(trace.events) - 1)
    lo, hi = max(0, idx - before), min(len(trace.events), idx + after + 1)
    lines = [render_event(e) + ("    <== FAILING STEP" if e.seq == seq else "") for e in trace.events[lo:hi]]
    return "\n".join(lines)


def _walk_trace(
    trace: Trace, simulator: Simulator | None, on_walk_error: WalkErrorHandler | None
) -> Walk | None:
    if simulator is None:
        return None
    try:
        return simulator.walk(trace)
    except Exception as exc:  # one unreplayable trace must not sink the diagnosis
        if on_walk_error is not None:
            on_walk_error(trace, exc)
        return None


def open_diagnose(
    traces: Sequence[Trace],
    simulator: Simulator | None = None,
    summarize: Summarizer | None = None,
    on_walk_error: WalkErrorHandler | None = None,
) -> list[FailureCluster]:
    """The open baseline: one cluster for each distinct reason the grader gave, ids and numbers normalised.

    Every failure point joins the cluster of its reason, located with `locate`: the failing step when a
    simulator can grade intermediate states, else the last tool call that names an id the reason names. The
    cluster id is the first ten hex digits of the sha256 of its canonical key, so it is the same on every
    machine. This groups by what the grader said and nothing else; it does not tell apart two mechanisms
    that fail with the same words.
    """
    groups: dict[str, tuple[dict[str, str], list[FailurePoint]]] = {}
    by_run: dict[str, Trace] = {}
    for t in traces:
        if t.outcome.passed or is_infra_failure(t):  # an endpoint failure says nothing about the harness
            continue
        by_run[t.run_id] = t
        walk = _walk_trace(t, simulator, on_walk_error)
        for reason in t.outcome.reasons or ["failed without a reason"]:
            seq, mode = locate(t, walk, reason)
            key = {"reason": normalize(reason), "mode": mode}
            cid = sha256_hex(canonical_json(key))[:10]
            groups.setdefault(cid, (key, []))[1].append(
                FailurePoint(t.run_id, t.case_id, seq, reason, mode, _tool_at(t, seq))
            )
    clusters: list[FailureCluster] = []
    for cid, (key, members) in sorted(groups.items(), key=lambda kv: (-len(kv[1][1]), kv[0])):
        what = "did" if key["mode"] == "commission" else "never did"
        summary = f"{len(members)} failure(s): the agent {what} something that led to '{key['reason']}'."
        traces_of = {m.run_id: by_run[m.run_id] for m in members}
        if summarize is not None:
            try:
                summary = summarize(key, members, traces_of) or summary
            except Exception as exc:  # the deterministic summary stands, and says why
                summary += f" (model summary unavailable: {type(exc).__name__})"
        clusters.append(FailureCluster(cid, key, members, summary, traces_of))
    return clusters


def _tool_at(trace: Trace, seq: int) -> str:
    at = next((e for e in trace.events if e.seq == seq), None)
    return call_of(at)["name"] if at is not None and at.kind == "tool_call" else "<end>"


_MIN_LITERAL = 4


def _argument_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _argument_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _argument_strings(v)


def _is_specific(value: str) -> bool:
    """A string that names one record rather than a kind of thing: it has a digit or an address sign."""
    return len(value) >= _MIN_LITERAL and (any(c.isdigit() for c in value) or "@" in value)


def new_text(parent: Harness, candidate: Harness) -> list[tuple[str, str]]:
    """(where, text) for every piece of text the candidate adds to its parent."""
    old_g, old_p = {g.id for g in parent.guards}, {p.id for p in parent.procedures}
    out = [(f"guard {g.id}", f"{g.description}\n{g.source}") for g in candidate.guards if g.id not in old_g]
    out += [
        (f"procedure {p.id}", "\n".join([p.name, p.when, *p.steps]))
        for p in candidate.procedures
        if p.id not in old_p
    ]
    if candidate.system_prompt != parent.system_prompt:
        added = candidate.system_prompt.removeprefix(parent.system_prompt.rstrip())
        out.append(("system prompt", added))
    return out


class OpenOverfitScreen:
    """The open baseline: a candidate may not repeat a specific string the training traces passed to a tool.

    The literals are the string values of the tool-call arguments in the training traces that are at least
    four characters long and hold a digit or an "@", the shape of a record id, an amount written out or an
    address. Plain words are not literals, since every guard names the tools and states it guards. The lint
    reports each literal that the candidate's new text, the guards, procedures and system prompt it adds
    over its parent, carries word for word. Only `Literals.ids` is read and written.
    """

    name = "open-literals"

    def training_literals(self, traces: Iterable[Trace]) -> Literals:
        lit = Literals()
        for t in traces:
            for e in t.events:
                if e.kind != "tool_call":
                    continue
                lit.ids.update(s for s in _argument_strings(call_of(e)["args"]) if _is_specific(s))
        return lit

    def lint(self, parent: Harness, candidate: Harness, literals: Literals) -> list[dict[str, str]]:
        hits: list[dict[str, str]] = []
        for where, text in new_text(parent, candidate):
            for ident in sorted(literals.ids):
                if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(ident)}(?![A-Za-z0-9_-])", text):
                    hits.append({"where": where, "category": "id", "literal": ident})
        return hits


@cache
def installed_diagnoser() -> Diagnoser:
    """The installed `diagnoser` entry of the `ratchet.failures` group, else the open baseline."""
    found = _installed(DIAGNOSER_ENTRY)
    if found is None:
        return open_diagnose
    made: Diagnoser = found()
    return made


@cache
def installed_overfit_screen() -> OverfitScreen:
    """The installed `overfit` entry of the `ratchet.failures` group, else the open baseline."""
    found = _installed(OVERFIT_ENTRY)
    if found is None:
        return OpenOverfitScreen()
    made: OverfitScreen = found()
    return made


def _installed(name: str) -> Callable[[], Any] | None:
    found = [e for e in entry_points(group=GROUP) if e.name == name]
    if len({e.value for e in found}) > 1:
        raise LookupError(f"{len(found)} distributions register {name!r} in {GROUP!r}: {found}")
    if not found:
        return None
    factory: Callable[[], Any] = found[0].load()
    return factory


__all__ = [
    "Diagnoser",
    "FailureCluster",
    "FailurePoint",
    "Literals",
    "Mode",
    "OpenOverfitScreen",
    "OverfitScreen",
    "Summarizer",
    "excerpt",
    "installed_diagnoser",
    "installed_overfit_screen",
    "locate",
    "new_text",
    "normalize",
    "open_diagnose",
    "render_event",
]
