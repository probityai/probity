"""The values a proposer hands the loop: candidates, the instructions they were written under, and proposals.

These are part of the record: a candidate's payload enters the generation record and the context of every
signed decision, and an instructions version is stored and compared at level 2. They are built only here,
so a candidate id and a harness version mean the same thing whichever proposer produced the change.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ratchet_cases.types import sha256_hex

from ratchet.canonical import canonical_json
from ratchet.improve.diagnose import FailureCluster, FailurePoint
from ratchet.types import Guard, Harness, Procedure

Kind = Literal["guard", "procedure", "prompt_edit"]
KINDS: tuple[Kind, ...] = ("guard", "procedure", "prompt_edit")


@dataclass(frozen=True)
class Instructions:
    """The improver's own proposal instructions: a content-addressed, versioned artifact."""

    version: str
    parent: str | None
    text: str

    @classmethod
    def build(cls, text: str, parent: str | None = None) -> Instructions:
        return cls(sha256_hex(text.encode("utf-8"))[:12], parent, text)


@dataclass(frozen=True)
class Candidate:
    id: str
    kind: Kind
    cluster_id: str
    instructions_version: str
    harness: Harness
    change: dict[str, Any]
    rationale: str
    targets: list[FailurePoint] = field(default_factory=list)

    def new_guards(self, parent: Harness) -> list[Guard]:
        old = {g.id for g in parent.guards}
        return [g for g in self.harness.guards if g.id not in old]

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "cluster_id": self.cluster_id,
            "instructions_version": self.instructions_version,
            "harness_version": self.harness.version,
            "change": self.change,
            "rationale": self.rationale,
            "targets": [t.id for t in self.targets],
        }


@dataclass
class Proposal:
    candidates: list[Candidate] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    duplicates: int = 0


def check_guard_source(source: str) -> str | None:
    """A reason the source cannot be a guard, or None. Compiling never executes it."""
    if not re.search(r"^def check\(\s*call\s*,\s*view\s*,\s*history\s*\)", source, re.MULTILINE):
        return "source does not define check(call, view, history) at top level"
    try:
        compile(source, "<guard>", "exec")
    except (SyntaxError, ValueError) as exc:
        return f"does not compile: {exc}"
    return None


def _short(*parts: str) -> str:
    return sha256_hex(canonical_json(list(parts)))[:8]


def make_candidate(
    raw: dict[str, Any], cluster: FailureCluster, parent: Harness, instructions: Instructions
) -> Candidate | str:
    """A candidate harness from one proposed change, or the reason it was rejected."""
    kind = raw.get("kind")
    rationale = str(raw.get("rationale", ""))
    origin = [m.id for m in cluster.members]
    if kind == "guard":
        source = str(raw.get("source", ""))
        problem = check_guard_source(source)
        if problem:
            return f"guard rejected: {problem}"
        gid = f"g-{cluster.id}-{_short(source)}"
        guard = Guard(gid, str(raw.get("description", ""))[:300], source, origin)
        child = parent.child(guards=[*parent.guards, guard], created_by="improver")
        return Candidate(f"c-{gid}", "guard", cluster.id, instructions.version, child, asdict(guard),
                         rationale, list(cluster.members))  # fmt: skip
    if kind == "procedure":
        steps = [str(s) for s in raw.get("steps") or [] if str(s).strip()]
        name, when = str(raw.get("name", "")).strip(), str(raw.get("when", "")).strip()
        if not (steps and name and when):
            return "procedure rejected: needs name, when and steps"
        pid = f"p-{cluster.id}-{_short(name, when, *steps)}"
        proc = Procedure(pid, name, when, steps, origin)
        child = parent.child(procedures=[*parent.procedures, proc], created_by="improver")
        return Candidate(f"c-{pid}", "procedure", cluster.id, instructions.version, child, asdict(proc),
                         rationale, list(cluster.members))  # fmt: skip
    if kind == "prompt_edit":
        text = str(raw.get("text", "")).strip()
        if not text:
            return "prompt_edit rejected: empty text"
        eid = f"e-{cluster.id}-{_short(text)}"
        child = parent.child(system_prompt=f"{parent.system_prompt}\n\n{text}", created_by="improver")
        return Candidate(f"c-{eid}", "prompt_edit", cluster.id, instructions.version, child, {"append": text},
                         rationale, list(cluster.members))  # fmt: skip
    return f"unknown kind {kind!r}"


def collect(raws: Any, cluster: FailureCluster, harness: Harness, instructions: Instructions) -> Proposal:
    """A proposal from a list of proposed changes: unusable items are kept in `rejected` with the reason,
    repeats and no-op changes are counted as duplicates."""
    out = Proposal()
    seen: set[str] = set()
    for raw in raws or []:
        made = (
            make_candidate(raw, cluster, harness, instructions) if isinstance(raw, dict) else "not an object"
        )
        if isinstance(made, str):
            out.rejected.append({"cluster_id": cluster.id, "reason": made})
        elif made.id in seen or made.harness.version == harness.version:
            out.duplicates += 1
        else:
            seen.add(made.id)
            out.candidates.append(made)
    return out
