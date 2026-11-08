"""The authority: the only holder of the signing key, the judge of every permit, the journal writer.

It decides whether one exact activity call may run, binds the decision to the human approval it
rests on (approval-binding/v1, judged by the published reader), enforces single use, and writes
every decision and outcome to a signed, hash-chained journal (probity-records).

``LocalAuthority`` keeps its key, state and journal in one directory, locked with ``flock`` so
several worker processes on one host share it. In production it runs outside the worker's trust
domain, and the system of record accepts only permits it signed.
"""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from probity_records import (
    TOOL_CALL_RECORD, Journal, Signer, build_approval_binding, build_uncertain_effect, canonical,
    embed_approval_binding, judge_approval_binding, key_id, load_public, sign_permit,
    tool_call_predicate, verify_approval,
)

POLICY_RELEASE = {"firstServedAt": "2000-01-01T00:00:00Z", "graceSeconds": 0,
                  "lastServedAt": "2999-01-01T00:00:00Z", "lookup": "ok", "releaseId": "probity-temporal-local"}
EVENT = "temporal/activity"
PHASE = "pre-execution"


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class EffectOwner(Protocol):
    """The system of record for one kind of effect, asked by idempotency key (the permit id)."""

    id: str

    def lookup(self, key: str) -> str | None:
        """``"present"``, ``"absent"`` (a final answer), or ``None`` when it cannot say."""

    def count(self, key: str) -> int | None:
        """How many effects the owner holds for ``key``, or ``None`` when it cannot say."""


@dataclass(frozen=True)
class Request:
    """One activity call as the worker is about to run it."""

    workflow_id: str
    run_id: str
    activity_id: str
    activity_type: str
    attempt: int
    args: list[Any]
    args_sha256: str
    tool_call_id: str
    principal: str
    approval: Mapping[str, Any] | None
    tool_identity: str | None = None


@dataclass
class Decision:
    ok: bool
    reason: str
    permit: dict[str, Any] | None = None
    outcome: str | None = None

    @property
    def permit_id(self) -> str | None:
        return None if self.permit is None else self.permit["claims"]["permitId"]


@dataclass
class LocalAuthority:
    """Authority state in ``directory``: ``authority.pem`` (0600), ``state.json``, ``journal.jsonl``."""

    directory: Path
    approvers: Mapping[str, bytes]
    owners: Mapping[str, EffectOwner] = field(default_factory=dict)
    clock: Callable[[], str] = utc_now

    def __post_init__(self) -> None:
        self.directory = Path(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        keyfile = self.directory / "authority.pem"
        if not keyfile.exists():
            try:
                fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(Signer.generate().private_pem())
            except FileExistsError:
                pass  # another worker process created it first
        self.signer = Signer.from_pem(keyfile.read_bytes())
        (self.directory / "authority.pub").write_bytes(self.signer.public_pem())
        self.journal = Journal(self.directory, self.signer)

    @contextmanager
    def _state(self):
        with (self.directory / "state.lock").open("w") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            path = self.directory / "state.json"
            state = json.loads(path.read_text()) if path.exists() else {"consumed": [], "operations": {}}
            yield state
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
            os.replace(tmp, path)

    def public_pem(self) -> bytes:
        return self.signer.public_pem()

    def checkpoint(self) -> dict[str, Any]:
        return self.journal.checkpoint()

    def _record(self, req: Request, permit_id: str | None, **fields: Any) -> None:
        context = {"activityId": req.activity_id, "activityType": req.activity_type, "attempt": req.attempt,
                   "engine": "temporal", "workflowId": req.workflow_id}
        if req.tool_identity:
            context["toolIdentity"] = req.tool_identity  # joins a pre-release finding to each approved call
        self.journal.append(TOOL_CALL_RECORD, f"tool-call:{req.tool_call_id}", req.args_sha256, tool_call_predicate(
            run_id=req.run_id, tool_call_id=req.tool_call_id, tool=req.activity_type,
            args_sha256_hex=req.args_sha256, permit_id=permit_id, context=context, **fields))

    def _deny(self, req: Request, permit_id: str | None, reason: str, binding: dict | None = None) -> Decision:
        self._record(req, permit_id, phase="authorize", decision="deny", reason=reason, approval_binding=binding)
        return Decision(False, reason)

    def refuse(self, req: Request, reason: str) -> Decision:
        """Record a refusal the worker side decided (for example, arguments changed after schedule)."""
        return self._deny(req, None, reason)

    def _permit(self, req: Request, pid: str) -> dict[str, Any]:
        return sign_permit(self.signer, {"activityId": req.activity_id, "activityType": req.activity_type,
                                         "argsSha256": req.args_sha256, "approvalId": pid,
                                         "issuedAt": self.clock(), "permitId": pid, "runId": req.run_id,
                                         "workflowId": req.workflow_id})

    def authorize(self, req: Request) -> Decision:
        """A signed single-use permit for exactly this call, or a recorded refusal."""
        if req.approval is None:
            return self._deny(req, None, "approval_missing")
        body = verify_approval(req.approval, self.approvers)
        if body is None:
            return self._deny(req, None, "approval_signature_invalid")
        pid = str(body.get("approvalId", ""))
        with self._state() as state:
            op = state["operations"].get(pid)
            if op is not None and op["activityId"] == req.activity_id and op["runId"] == req.run_id:
                return self._resume(req, pid, op)
            approver = str(body.get("approver"))
            record, payload = build_approval_binding(
                body, {"approvalId": pid, "event": EVENT, "phase": PHASE, "principal": req.principal,
                       "target": req.workflow_id, "tool": req.activity_type, "usedAt": self.clock()},
                canonical(req.args), state["consumed"], {approver: key_id(load_public(self.approvers[approver]))},
                self.clock(), POLICY_RELEASE)
            verdict = judge_approval_binding(record, payload)
            embedded = embed_approval_binding(record, payload)
            if verdict["decision"] != "allow":
                return self._deny(req, pid, verdict["reason"], embedded)
            state["consumed"].append(pid)
            state["operations"][pid] = {"activityId": req.activity_id, "attempts": [], "runId": req.run_id,
                                        "settled": None}
            self._record(req, pid, phase="authorize", decision="allow", reason="bound", approval_binding=embedded)
            return Decision(True, "bound", self._permit(req, pid))

    def _resume(self, req: Request, pid: str, op: dict[str, Any]) -> Decision:
        """A later attempt of an activity whose permit was already used: never a blind resend."""
        if op["settled"] is not None:
            return Decision(False, f"outcome_{op['settled']}", outcome=op["settled"])
        if op["attempts"] and op["attempts"][-1]["reply"] is None:
            op["attempts"][-1]["reply"] = "connection_lost"  # the worker never reported back
        owner = self.owners.get(req.activity_type)
        answer = owner.lookup(pid) if owner else None
        if answer is not None:
            op.setdefault("reconciliations", []).append({"at": self.clock(), "final": True, "result": answer})
        if answer == "absent":
            self._record(req, pid, phase="authorize", decision="allow", reason="reconciled_absent_retry")
            return Decision(True, "reconciled_absent_retry", self._permit(req, pid))
        outcome = "committed" if answer == "present" else "unknown"
        self._close(req, pid, op, outcome, None)
        return Decision(False, f"outcome_{outcome}", outcome=outcome)

    def intent(self, req: Request, permit_id: str) -> None:
        """Record, durably, that the call is about to leave the worker."""
        with self._state() as state:
            state["operations"][permit_id]["attempts"].append({"dispatchedAt": self.clock(), "reply": None})
        self._record(req, permit_id, phase="intent")

    def effect(self, req: Request, permit_id: str, reply: str, result_sha256: str | None) -> str:
        """Record the reply and the outcome the owner's answers support; returns that outcome."""
        with self._state() as state:
            op = state["operations"][permit_id]
            op["attempts"][-1]["reply"] = reply
            if reply == "confirmed":
                outcome = "committed"
            elif reply == "no_effect":
                outcome = "not_run"
            else:
                owner = self.owners.get(req.activity_type)
                answer = owner.lookup(permit_id) if owner else None
                if answer is not None:
                    op.setdefault("reconciliations", []).append({"at": self.clock(), "final": True, "result": answer})
                outcome = {"present": "committed", "absent": "not_run"}.get(answer or "", "unknown")
            return self._close(req, permit_id, op, outcome, result_sha256)

    def _close(self, req: Request, pid: str, op: dict[str, Any], outcome: str, result_sha256: str | None) -> str:
        owner = self.owners.get(req.activity_type)
        counted = owner.count(pid) if owner else None
        record = build_uncertain_effect(
            record_id=f"{req.workflow_id}/{req.activity_id}", action=req.activity_type, operation_id=pid,
            idempotency_key=pid, args_sha256_hex=req.args_sha256,
            attempts=[{"dispatchedAt": a["dispatchedAt"], "reply": a["reply"] or "connection_lost"}
                      for a in op["attempts"]],
            owner_id=owner.id if owner else "unreported", owner_effects=counted or 0, outcome=outcome,
            as_of=self.clock(), reconciliations=op.get("reconciliations"))
        record["ownerEffectsObserved"] = counted is not None
        op["settled"] = None if outcome == "not_run" else outcome
        self._record(req, pid, phase="effect", outcome=outcome, result_sha256=result_sha256,
                     uncertain_effect=record)
        return outcome
