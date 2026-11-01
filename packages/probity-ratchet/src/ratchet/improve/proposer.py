"""The proposer seam: what the loop asks for new candidates, and how a proposer is found.

The loop (`ratchet.improve.loop`) owns everything that decides: diagnosis, the overfit screen, replay,
evaluation, the referee's admission and activation. A proposer only writes changes, and every change it
writes is built into a candidate by `ratchet.improve.candidates.make_candidate`, so a proposer cannot name
a candidate id, a harness version or a target of its own. Whatever writes the changes, admission decides.

Two ways to give the loop a proposer:

- pass an object that satisfies `Proposer` as `Lab(proposer=...)`. `FixedProposer` is the one this package
  ships: it proposes a declared list of changes and calls no model, so a run built on it repeats exactly;
- install a distribution that registers a factory in the `ratchet.proposers` entry-point group and name it
  (`load_proposer("model", chat)`). The factory takes the improver model and returns a `Proposer`.

Parent selection for the version archive is found the same way, in the `ratchet.parent_choosers` group,
by `load_parent_chooser`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, Protocol

from ratchet_cases.types import Trace, sha256_hex

from ratchet.canonical import canonical_json
from ratchet.improve.candidates import Candidate, Instructions, Proposal, collect
from ratchet.improve.diagnose import FailureCluster, FailurePoint
from ratchet.improve.llm import Chat, Meter
from ratchet.improve.replay import ReplayReport, WalkCache
from ratchet.types import Harness

PROPOSERS = "ratchet.proposers"
PARENT_CHOOSERS = "ratchet.parent_choosers"
DEFAULT_PROPOSER = "model"


class Proposer(Protocol):
    """Writes changes for the loop. Each method sees training material only; the loop never hands it a
    held-out trace, a decision's checks or the referee's tables."""

    @property
    def seed(self) -> Instructions:
        """The instructions the loop starts with when the caller names none."""
        ...

    def summarize(
        self,
        key: Mapping[str, str],
        members: Sequence[FailurePoint],
        traces: Mapping[str, Trace],
        meter: Meter,
    ) -> str | None:
        """A one-sentence mechanism for a failure cluster, or None to keep the deterministic summary."""
        ...

    def propose(
        self,
        cluster: FailureCluster,
        harness: Harness,
        *,
        instructions: Instructions,
        passing: Sequence[Trace],
        walks: WalkCache | None,
        meter: Meter,
        n: int,
        inspiration: Harness | None,
    ) -> Proposal:
        """Up to `n` candidates for one cluster, each a child of `harness`."""
        ...

    def revise_guard(
        self,
        candidate: Candidate,
        report: ReplayReport,
        cluster: FailureCluster,
        parent: Harness,
        *,
        instructions: Instructions,
        walks: WalkCache | None,
        meter: Meter,
    ) -> Candidate | str:
        """One repair of a guard that failed training replay, or the reason there is none."""
        ...

    def revise_instructions(
        self, champion: Instructions, scores: Mapping[str, Any], examples: Sequence[str], meter: Meter
    ) -> Instructions | None:
        """A challenger to the champion instructions, or None (then level 2 makes no claim)."""
        ...


class ArchiveChoice(Protocol):
    """One generation's choice from the version archive, as the loop records it."""

    @property
    def version(self) -> str: ...

    @property
    def rebase_required(self) -> bool: ...

    def to_payload(self) -> dict[str, Any]: ...

    def decision_context(self) -> dict[str, Any]: ...


class ParentChooser(Protocol):
    """The archive's parent selection: where ideas come from. It never changes the comparison parent."""

    def __call__(self, tip: str, generation: int) -> ArchiveChoice: ...


@dataclass(frozen=True)
class FixedProposer:
    """Proposes a declared list of changes and calls no model.

    `changes` maps a failure cluster id to the changes proposed for it; the key `"*"` applies to every
    cluster. A change is the dict `make_candidate` reads: `{"kind": "guard", "description", "source"}`,
    `{"kind": "procedure", "name", "when", "steps"}` or `{"kind": "prompt_edit", "text"}`, each with an
    optional `"rationale"`. Cluster ids are deterministic (`ratchet.improve.diagnose`), so a declared list
    names the same clusters on every run. It never repairs a guard and never revises its instructions,
    whose text records the digest of the declared list."""

    changes: Mapping[str, Sequence[Mapping[str, Any]]] = field(default_factory=dict)

    @property
    def seed(self) -> Instructions:
        digest = sha256_hex(canonical_json({k: list(v) for k, v in sorted(self.changes.items())}))
        return Instructions.build(f"fixed changes {digest}")

    def summarize(
        self,
        key: Mapping[str, str],
        members: Sequence[FailurePoint],
        traces: Mapping[str, Trace],
        meter: Meter,
    ) -> str | None:
        return None

    def propose(
        self,
        cluster: FailureCluster,
        harness: Harness,
        *,
        instructions: Instructions,
        passing: Sequence[Trace] = (),
        walks: WalkCache | None = None,
        meter: Meter | None = None,
        n: int = 4,
        inspiration: Harness | None = None,
    ) -> Proposal:
        raws = [dict(c) for c in [*self.changes.get(cluster.id, ()), *self.changes.get("*", ())]]
        return collect(raws[:n], cluster, harness, instructions)

    def revise_guard(
        self,
        candidate: Candidate,
        report: ReplayReport,
        cluster: FailureCluster,
        parent: Harness,
        *,
        instructions: Instructions,
        walks: WalkCache | None = None,
        meter: Meter | None = None,
    ) -> Candidate | str:
        return "a fixed proposer does not revise"

    def revise_instructions(
        self, champion: Instructions, scores: Mapping[str, Any], examples: Sequence[str], meter: Meter
    ) -> Instructions | None:
        return None

    @classmethod
    def from_json(cls, text: str) -> FixedProposer:
        doc = json.loads(text)
        if not isinstance(doc, dict) or not all(isinstance(v, list) for v in doc.values()):
            raise ValueError("fixed changes are a JSON object mapping a cluster id (or '*') to a list")
        return cls({str(k): [dict(c) for c in v] for k, v in doc.items()})


class NotInstalledError(LookupError):
    """No distribution registers that name in the entry-point group."""


def installed(group: str) -> list[str]:
    """The names registered in `group` by the installed distributions."""
    return sorted({e.name for e in entry_points(group=group)})


def _factory(group: str, name: str) -> Callable[..., Any]:
    found = [e for e in entry_points(group=group) if e.name == name]
    if not found:
        have = ", ".join(installed(group)) or "none"
        raise NotInstalledError(f"no {group!r} entry named {name!r} is installed (installed: {have})")
    if len({e.value for e in found}) > 1:
        raise NotInstalledError(f"{len(found)} distributions register {name!r} in {group!r}: {found}")
    factory: Callable[..., Any] = found[0].load()
    return factory


def load_proposer(name: str, model: Chat | None) -> Proposer:
    """The proposer an installed distribution registers as `name`, built over the improver model."""
    proposer: Proposer = _factory(PROPOSERS, name)(model)
    return proposer


def load_parent_chooser(name: str, store: Any, **options: Any) -> ParentChooser:
    """The parent chooser an installed distribution registers as `name`, over the run's store."""
    chooser: ParentChooser = _factory(PARENT_CHOOSERS, name)(store, **options)
    return chooser
