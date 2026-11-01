"""A test double for the proposer seam: a proposer that drives a scripted `Chat`.

The loop's shipped proposers are `FixedProposer` and whatever plug-in is installed. These tests exercise the
loop's mechanics (diagnosis, replay, admission, composition, the held-out boundary) with a scripted chat
standing in for the writer of changes, so they build the prompts' cues here and read the chat's JSON back.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from ratchet_cases.types import Trace

from ratchet.improve.candidates import Candidate, Instructions, Proposal, collect, make_candidate
from ratchet.improve.diagnose import FailureCluster, FailurePoint, excerpt
from ratchet.improve.llm import Chat, Meter, ask_json
from ratchet.improve.replay import ReplayReport, WalkCache
from ratchet.types import Harness

SEED = Instructions.build("You write minimal changes that fix one failure mechanism.")


class ChatProposer:
    def __init__(self, model: Chat | None) -> None:
        if model is None:
            raise ValueError("the scripted proposer needs a chat")
        self.model = model

    @property
    def seed(self) -> Instructions:
        return SEED

    def summarize(
        self,
        key: Mapping[str, str],
        members: Sequence[FailurePoint],
        traces: Mapping[str, Trace],
        meter: Meter,
    ) -> str | None:
        shown = "\n\n".join(excerpt(traces[m.run_id], m.seq) for m in members[:2])
        user = (
            f"Cluster key: {json.dumps(dict(key))}\nReasons: {sorted({m.reason for m in members})}\n\n{shown}"
        )
        system = "Name the failure mechanism in one sentence: the failure mechanism in one sentence."
        return str(ask_json(self.model, system, user, meter)["mechanism"])

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
        shown = "\n\n".join(
            f"Failure {m.id} (reason: {m.reason}; failing step {m.seq}, {m.mode}):\n"
            + excerpt(cluster.traces[m.run_id], m.seq)
            for m in cluster.members[:3]
        )
        parts = [
            instructions.text,
            f"Failure cluster {cluster.id} ({len(cluster.members)} failures): {cluster.summary}\n"
            f"Mechanism key: {json.dumps(cluster.key)}",
            shown,
        ]
        if inspiration is not None and inspiration.version != harness.version:
            parts.append(f"An earlier admitted harness, for ideas only:\n{inspiration.system_prompt}")
        parts.append(f"Propose {n} candidates.")
        try:
            reply = ask_json(
                self.model, "Reply with one JSON object only.", "\n\n".join(parts), meter or Meter()
            )
        except Exception as exc:
            out = Proposal()
            out.rejected.append({"cluster_id": cluster.id, "reason": f"model call failed: {exc}"})
            return out
        return collect(reply.get("candidates"), cluster, harness, instructions)

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
        user = (
            f"Guard for cluster {cluster.id}:\n{candidate.change.get('source', '')}\n\n"
            + excerpt(cluster.traces[cluster.members[0].run_id], cluster.members[0].seq)
            + '\n\nReturn the corrected guard as JSON: {"description": "...", "source": "..."}'
        )
        try:
            reply = ask_json(self.model, "Reply with one JSON object only.", user, meter or Meter())
        except Exception as exc:
            return f"revision failed: {exc}"
        return make_candidate({**reply, "kind": "guard"}, cluster, parent, instructions)

    def revise_instructions(
        self, champion: Instructions, scores: Mapping[str, Any], examples: Sequence[str], meter: Meter
    ) -> Instructions | None:
        user = f"Current instructions:\n{champion.text}\n\nResults:\n" + "\n".join(examples[:12])
        try:
            reply = ask_json(self.model, "You maintain the instructions an improver follows.", user, meter)
        except Exception:
            return None
        text = str(reply.get("text", "")).strip()
        if not text or text == champion.text:
            return None
        return Instructions.build(text, parent=champion.version)
