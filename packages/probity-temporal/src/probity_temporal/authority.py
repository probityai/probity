"""The authority: the only holder of the signing key, the judge of every permit, the journal writer.

It decides whether one exact activity call may run, binds the decision to the human approvals it rests
on (approval-binding/v1, judged by the published reader, one record per approver, M of N), enforces
single use, and writes every decision and outcome to a signed, hash-chained journal (probity-records).

Check order (each refusal has its own stable code, see ``errors.CHECK_ORDER``); the worker side runs
the first three before it calls the authority:

 1. local activity blocked          (worker)     7. approver key revoked
 2. arguments admissible            (worker)     8. approval (permit) revoked
 3. arguments unchanged since schedule (worker)  9. content guard over the exact argument bytes
 4. approvals present, else asked of the        10. an earlier attempt of this same call: reconcile
    approval source (pending is retryable)          with the effect owner, never a blind resend
 5. revocation state fresh (stale is retryable) 11. the published approval-binding reader, per approver
 6. approval signatures valid                   12. M of N distinct approvers; consume; journal; permit

State: the journal (``journal.jsonl``) is the source of truth and is fsynced before a permit leaves.
``authority.db`` (SQLite, WAL) is an index of the operations the journal describes, updated in the same
transaction as each append and rebuilt from the journal tail on open after a crash, so a permit is
never issued twice even if the index lost its last commit. Several worker processes on one host share
the directory; ``BEGIN IMMEDIATE`` serialises their decisions.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from probity_records import (
    TOOL_CALL_RECORD, Journal, RevocationCache, Signer, StaleRevocations, Trust, build_approval_binding,
    build_uncertain_effect, canonical, embed_approval_binding, judge_approval_binding, key_id, load_public,
    sign_permit, tool_call_predicate,
)
from probity_records.core import APPROVAL_DOMAIN, _unb64
from probity_records.quorum import approval_policy, count_bindings, validate_policy

from . import errors
from .keys import KeyResolver, load_signer

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


class ResultOwner(EffectOwner, Protocol):
    def result(self, key: str) -> Any:
        """The committed effect's result, as the activity would have returned it, or ``None``."""


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
    approvals: Sequence[Mapping[str, Any]] = ()
    tool_identity: str | None = None
    namespace: str = ""
    task_queue: str = ""


@dataclass
class Decision:
    ok: bool
    reason: str
    permit: dict[str, Any] | None = None
    outcome: str | None = None
    result: Any = None
    shadow: bool = False

    @property
    def code(self) -> str | None:
        if (self.ok and (not self.shadow or self.permit is not None)) or self.outcome == "committed":
            return None  # an allow (shadow or not) or a committed outcome is a success, never a refusal
        if self.outcome == "unknown":
            return errors.OUTCOME_UNKNOWN
        return errors.code_for(self.reason.removeprefix("shadow:"))

    @property
    def permit_id(self) -> str | None:
        return None if self.permit is None else self.permit["claims"]["permitId"]


#: ``approval_source(request)`` returns the approvals, ``None`` while a human has not decided yet
#: (retryable), or ``[]`` when none will come.
ApprovalSource = Callable[[Request], Sequence[Mapping[str, Any]] | None]
#: ``content_guard(tool, canonical_args)`` returns ``{"action": "allow"|"block", ...}``.
ContentGuard = Callable[[str, bytes], Mapping[str, Any]]


class Pending(Exception):  # noqa: N818 - control flow
    pass


@dataclass
class LocalAuthority:
    """Authority state in ``directory``: key (unless ``key`` resolves it), ``journal.jsonl``, ``authority.db``."""

    directory: Path
    approvers: Mapping[str, bytes] = field(default_factory=dict)
    owners: Mapping[str, EffectOwner] = field(default_factory=dict)
    clock: Callable[[], str] = utc_now
    threshold: int = 1
    #: Per-tool quorum policies (``probity_records.quorum``: policyId, threshold, approver raw keys),
    #: the same objects an auditor pins in ``Trust.quorum_policies`` to re-count every allow.
    tool_policies: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    revocations: RevocationCache | None = None
    approval_source: ApprovalSource | None = None
    content_guard: ContentGuard | None = None
    mode: Literal["enforce", "shadow"] = "enforce"
    key: KeyResolver | None = None

    def __post_init__(self) -> None:
        self.directory = Path(self.directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.mode not in ("enforce", "shadow"):
            raise ValueError("mode must be 'enforce' or 'shadow'")
        self.default_policy = (approval_policy("default", self.approvers, self.threshold)
                               if self.approvers else None)
        if self.default_policy is None and not self.tool_policies:
            raise ValueError("an authority needs approvers or tool_policies")
        policies = [*self.tool_policies.values(), *([self.default_policy] if self.default_policy else [])]
        by_id: dict[str, Mapping[str, Any]] = {}
        for policy in policies:
            validate_policy(policy)
            if by_id.setdefault(policy["policyId"], policy) != policy:
                raise ValueError(f"two different policies share the id {policy['policyId']!r}")
        self._policies = by_id
        self.signer = load_signer(self.key) if self.key is not None else self._file_key()
        (self.directory / "authority.pub").write_bytes(self.signer.public_pem())
        self.journal = Journal(self.directory, self.signer)
        self._local = threading.local()
        self._keys: dict[bytes, Any] = {}
        with self._txn():
            pass  # creates the schema and catches the index up with the journal

    def _file_key(self) -> Signer:
        keyfile = self.directory / "authority.pem"
        if not keyfile.exists():
            try:
                fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(Signer.generate().private_pem())
            except FileExistsError:
                pass  # another worker process created it first
        return Signer.from_pem(keyfile.read_bytes())

    # ---- the index -------------------------------------------------------------------------------
    def _db(self) -> sqlite3.Connection:
        db = getattr(self._local, "db", None)
        if db is None:
            db = sqlite3.connect(self.directory / "authority.db", isolation_level=None, timeout=60)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")  # the fsynced journal is the durable copy
            db.executescript("""
                CREATE TABLE IF NOT EXISTS ops (pid TEXT PRIMARY KEY, run_id TEXT, activity_id TEXT, tool TEXT,
                    workflow_id TEXT, args_sha256 TEXT, tool_call_id TEXT,
                    attempts TEXT NOT NULL DEFAULT '[]', reconciliations TEXT NOT NULL DEFAULT '[]',
                    settled TEXT, task_token TEXT);
                CREATE INDEX IF NOT EXISTS ops_token ON ops(task_token);
                CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
            """)
            self._local.db = db
        return db

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Connection]:
        db = self._db()
        db.execute("BEGIN IMMEDIATE")
        try:
            self._catch_up(db)
            yield db
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise

    def _catch_up(self, db: sqlite3.Connection) -> None:
        row = db.execute("SELECT v FROM meta WHERE k='seq'").fetchone()
        indexed = row[0] if row else 0
        seq, _ = self.journal._tail()  # noqa: SLF001 - O(new bytes), never a rescan
        if seq == indexed:
            return
        for body in self.journal.statements()[indexed:]:  # only after a crash between append and commit
            self._apply(db, body["predicate"])

    def _apply(self, db: sqlite3.Connection, pred: Mapping[str, Any]) -> None:
        """Fold one journal record into the index; the only writer of ``ops``."""
        pid, phase = pred.get("permitId"), pred.get("phase")
        ctx = pred.get("context") or {}
        if pid and phase == "authorize" and pred.get("decision") == "allow":
            db.execute("INSERT OR IGNORE INTO ops(pid, run_id, activity_id, tool, workflow_id, args_sha256,"
                       " tool_call_id) VALUES (?,?,?,?,?,?,?)",
                       (pid, pred.get("runId"), ctx.get("activityId"), pred.get("tool"), ctx.get("workflowId"),
                        pred.get("argsSha256"), pred.get("toolCallId")))
        elif pid and phase == "intent":
            attempts = json.loads(db.execute("SELECT attempts FROM ops WHERE pid=?", (pid,)).fetchone()[0])
            attempts.append({"dispatchedAt": pred.get("at"), "reply": None})
            db.execute("UPDATE ops SET attempts=?, task_token=COALESCE(?, task_token) WHERE pid=?",
                       (json.dumps(attempts), ctx.get("taskToken"), pid))
        elif pid and phase == "effect":
            record = pred.get("uncertainEffect") or {}
            outcome = pred.get("outcome")
            attempts = [{"dispatchedAt": a["dispatchedAt"], "reply": a["reply"]} for a in record.get("attempts", [])]
            recon = [{k: v for k, v in r.items() if k != "idempotencyKey"} for r in record.get("reconciliations", [])]
            db.execute("UPDATE ops SET attempts=?, reconciliations=?, settled=? WHERE pid=?",
                       (json.dumps(attempts), json.dumps(recon), None if outcome == "not_run" else outcome, pid))
        db.execute("INSERT INTO meta(k, v) VALUES('seq', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                   (pred.get("seq"),))

    def _append(self, db: sqlite3.Connection, req: Request, permit_id: str | None, **fields: Any) -> None:
        context = {"activityId": req.activity_id, "activityType": req.activity_type, "attempt": req.attempt,
                   "engine": "temporal", "workflowId": req.workflow_id, "idempotencyKey": permit_id,
                   **({"namespace": req.namespace} if req.namespace else {}),
                   **({"taskQueue": req.task_queue} if req.task_queue else {}),
                   **fields.pop("context", {})}
        if req.tool_identity:
            context["toolIdentity"] = req.tool_identity  # joins a pre-release finding to each approved call
        envelope = self.journal.append(
            TOOL_CALL_RECORD, f"tool-call:{req.tool_call_id}", req.args_sha256, tool_call_predicate(
                run_id=req.run_id, tool_call_id=req.tool_call_id, tool=req.activity_type,
                args_sha256_hex=req.args_sha256, permit_id=permit_id, context=context, **fields))
        import base64  # noqa: PLC0415

        self._apply(db, json.loads(base64.b64decode(envelope["payload"]))["predicate"])

    def _op(self, db: sqlite3.Connection, pid: str) -> dict[str, Any] | None:
        row = db.execute("SELECT run_id, activity_id, attempts, reconciliations, settled, task_token FROM ops"
                         " WHERE pid=?", (pid,)).fetchone()
        if row is None:
            return None
        return {"runId": row[0], "activityId": row[1], "attempts": json.loads(row[2]),
                "reconciliations": json.loads(row[3]), "settled": row[4], "taskToken": row[5]}

    # ---- public surface --------------------------------------------------------------------------
    def public_pem(self) -> bytes:
        return self.signer.public_pem()

    def checkpoint(self) -> dict[str, Any]:
        return self.journal.checkpoint()

    def trust(self) -> Trust:
        """What an auditor pins to re-check this authority's journal: its quorum policies and the
        current revocation state. Publish it out of band; never read it back from the records."""
        state = self.revocations.state() if self.revocations is not None else None
        return Trust(quorum_policies=dict(self._policies), revocations=state)

    def policy_for(self, tool: str) -> Mapping[str, Any]:
        policy = self.tool_policies.get(tool, self.default_policy)
        if policy is None:
            raise LookupError(f"no approval policy for {tool!r}")
        return policy

    def refuse(self, req: Request, reason: str) -> Decision:
        """Record a refusal the worker side decided (for example, arguments changed after schedule)."""
        with self._txn() as db:
            return self._deny(db, req, None, reason)

    def _deny(self, db: sqlite3.Connection, req: Request, permit_id: str | None, reason: str,
              bindings: list[dict] | None = None, context: Mapping[str, Any] | None = None) -> Decision:
        shadow = self.mode == "shadow"
        ctx = {**(context or {}), **({"shadow": True} if shadow else {})}
        self._append(db, req, permit_id, phase="authorize", decision="deny", reason=reason,
                     approval_bindings=bindings, context=ctx)
        if shadow:
            return Decision(True, f"shadow:{reason}", shadow=True)
        return Decision(False, reason)

    def _permit(self, req: Request, pid: str) -> dict[str, Any]:
        return sign_permit(self.signer, {"activityId": req.activity_id, "activityType": req.activity_type,
                                         "argsSha256": req.args_sha256, "approvalId": pid,
                                         "idempotencyKey": pid, "issuedAt": self.clock(), "permitId": pid,
                                         "runId": req.run_id, "workflowId": req.workflow_id})

    def _public(self, raw_b64: str) -> Any:
        key = self._keys.get(raw_b64)
        if key is None:
            key = self._keys[raw_b64] = load_public(_unb64(raw_b64))
        return key

    def _verified(self, signed: Any, policy: Mapping[str, Any]) -> dict[str, Any] | None:
        """The approval body when its signature verifies under the key ``policy`` pins for its approver."""
        if not isinstance(signed, Mapping) or not isinstance(signed.get("body"), dict):
            return None
        body = signed["body"]
        raw = policy["approvers"].get(str(body.get("approver", "")))
        if raw is None:
            return None
        try:
            self._public(raw).verify(_unb64(signed.get("sig")), APPROVAL_DOMAIN + canonical(body))
        except Exception:  # noqa: BLE001 - any failure to verify is a refusal of that approval
            return None
        return body

    def _approvals(self, req: Request) -> Sequence[Mapping[str, Any]]:
        if req.approvals:
            return req.approvals
        if self.approval_source is None:
            return ()
        got = self.approval_source(req)
        if got is None:
            raise Pending
        return got

    def authorize(self, req: Request) -> Decision:  # noqa: C901, PLR0911, PLR0912 - the check order, one step per branch
        """A signed single-use permit for exactly this call, or a recorded refusal (see module docstring)."""
        policy = self.policy_for(req.activity_type)
        try:
            approvals = list(self._approvals(req))
        except Pending:
            return Decision(False, "approval_pending")  # not journalled: nothing was decided yet
        state = None
        if self.revocations is not None:
            try:
                state = self.revocations.state()
            except StaleRevocations:
                return Decision(False, "revocation_state_stale")  # retryable; decided nothing
        guard_verdict = None
        if self.content_guard is not None:
            try:
                guard_verdict = dict(self.content_guard(req.activity_type, canonical(req.args)))
            except Exception as exc:  # noqa: BLE001 - a guard that cannot answer blocks (fail closed)
                guard_verdict = {"action": "block", "reason": "classifier_error", "error": type(exc).__name__}
        with self._txn() as db:
            if not approvals:
                return self._deny(db, req, None, "approval_missing")
            signed_bodies: list[tuple[dict[str, Any], str]] = []
            for signed in approvals:
                body = self._verified(signed, policy)
                if body is not None:
                    signed_bodies.append((body, str(signed["sig"])))
            bodies = [b for b, _ in signed_bodies]
            if not bodies:
                return self._deny(db, req, None, "approval_signature_invalid")
            ids = {str(b.get("approvalId", "")) for b in bodies}
            if len(ids) != 1:
                return self._deny(db, req, None, "approval_id_ambiguous")
            pid = ids.pop()
            if state is not None:
                now = self.clock()
                if any(state.key_revoked(key_id(self._public(policy["approvers"][str(b["approver"])])), now)
                       for b in bodies):
                    return self._deny(db, req, pid, "approver_revoked", context={"revocationSeq": state.seq})
                if state.permit_revoked(pid, now):
                    return self._deny(db, req, pid, "permit_revoked", context={"revocationSeq": state.seq})
            if guard_verdict is not None and guard_verdict.get("action") != "allow":
                return self._deny(db, req, pid, "content_blocked", context={"contentGuard": guard_verdict})
            op = self._op(db, pid)
            if op is not None and op["activityId"] == req.activity_id and op["runId"] == req.run_id:
                return self._resume(db, req, pid, op)
            consumed = [pid] if op is not None else []
            bindings, reader_allowed, first_refusal = [], set(), None
            payload_bytes = canonical(req.args)
            for body, sig in signed_bodies:
                approver = str(body.get("approver"))
                record, payload = build_approval_binding(
                    body, {"approvalId": pid, "event": EVENT, "phase": PHASE, "principal": req.principal,
                           "target": req.workflow_id, "tool": req.activity_type, "usedAt": self.clock()},
                    payload_bytes, consumed,
                    {approver: key_id(self._public(policy["approvers"][approver]))}, self.clock(), POLICY_RELEASE)
                verdict = judge_approval_binding(record, payload)
                bindings.append(embed_approval_binding(record, payload, sig))
                if verdict["decision"] == "allow":
                    reader_allowed.add(approver)
                elif first_refusal is None:
                    first_refusal = verdict["reason"]
            # The same count the offline verifier runs under the auditor's pinned policy.
            signed_ok, _ = count_bindings(policy, bindings, self.clock(),
                                          state.key_revoked if state is not None else None)
            allowed = signed_ok & reader_allowed
            quorum = {"approval_policy": policy["policyId"], "threshold": policy["threshold"]}
            if len(allowed) < policy["threshold"]:
                reason = first_refusal if first_refusal is not None else "approval_threshold_not_met"
                return self._deny(db, req, pid, reason, bindings,
                                  context={"approvers": sorted(allowed), "threshold": policy["threshold"]})
            shadow = self.mode == "shadow"
            self._append(db, req, pid, phase="authorize", decision="allow", reason="bound",
                         approval_bindings=bindings, context={"shadow": True} if shadow else {}, **quorum)
            if shadow:  # observed, not enforced: the permit still lets the worker journal intent and effect
                return Decision(True, "shadow:bound", self._permit(req, pid), shadow=True)
            return Decision(True, "bound", self._permit(req, pid))

    def _resume(self, db: sqlite3.Connection, req: Request, pid: str, op: dict[str, Any]) -> Decision:
        """A later attempt of an activity whose permit was already used: never a blind resend."""
        owner = self.owners.get(req.activity_type)
        if op["settled"] == "committed":
            return Decision(False, "outcome_committed", outcome="committed", result=self._result(owner, pid))
        if op["settled"] is not None:
            return Decision(False, f"outcome_{op['settled']}", outcome=op["settled"])
        if op["attempts"] and op["attempts"][-1]["reply"] is None:
            op["attempts"][-1]["reply"] = "connection_lost"  # the worker never reported back
        answer = owner.lookup(pid) if owner else None
        if answer is not None:
            op["reconciliations"].append({"at": self.clock(), "final": True, "result": answer})
        if answer == "absent":
            db.execute("UPDATE ops SET attempts=?, reconciliations=? WHERE pid=?",
                       (json.dumps(op["attempts"]), json.dumps(op["reconciliations"]), pid))
            self._append(db, req, pid, phase="authorize", decision="allow", reason="reconciled_absent_retry")
            return Decision(True, "reconciled_absent_retry", self._permit(req, pid))
        outcome = "committed" if answer == "present" else "unknown"
        self._close(db, req, pid, op, outcome, None)
        if outcome == "committed":
            return Decision(False, "outcome_committed", outcome="committed", result=self._result(owner, pid))
        return Decision(False, "outcome_unknown", outcome="unknown")

    @staticmethod
    def _result(owner: EffectOwner | None, pid: str) -> Any:
        getter = getattr(owner, "result", None)
        return getter(pid) if getter is not None else None

    def intent(self, req: Request, permit_id: str, task_token: bytes | None = None) -> None:
        """Record, durably, that the call is about to leave the worker."""
        with self._txn() as db:
            ctx = {"taskToken": task_token.hex()} if task_token else {}
            self._append(db, req, permit_id, phase="intent", context=ctx)

    def effect(self, req: Request, permit_id: str, reply: str, result_sha256: str | None) -> tuple[str, Any]:
        """Record the reply and the outcome the owner's answers support.

        Returns ``(outcome, committed_result)``: when a lost reply is reconciled as committed, the
        owner's own record of the result (``ResultOwner.result``) so the workflow receives success.
        """
        owner = self.owners.get(req.activity_type)
        with self._txn() as db:
            op = self._op(db, permit_id)
            if op is None:
                raise LookupError(f"no operation for permit {permit_id[:12]}")
            op["attempts"][-1]["reply"] = reply
            if reply == "confirmed":
                outcome = "committed"
            elif reply == "no_effect":
                outcome = "not_run"
            else:
                answer = owner.lookup(permit_id) if owner else None
                if answer is not None:
                    op["reconciliations"].append({"at": self.clock(), "final": True, "result": answer})
                outcome = {"present": "committed", "absent": "not_run"}.get(answer or "", "unknown")
            self._close(db, req, permit_id, op, outcome, result_sha256)
        committed = self._result(owner, permit_id) if outcome == "committed" and reply != "confirmed" else None
        return outcome, committed

    def operation_for_token(self, task_token: bytes) -> tuple[str, dict[str, Any]] | None:
        """The permit id and operation an async-completing activity left open under ``task_token``."""
        db = self._db()
        row = db.execute("SELECT pid FROM ops WHERE task_token=?", (task_token.hex(),)).fetchone()
        return None if row is None else (row[0], self._op(db, row[0]) or {})

    def request_for(self, permit_id: str) -> Request:
        """The call a permit was issued for, as the index holds it (for async completion)."""
        row = self._db().execute("SELECT workflow_id, run_id, activity_id, tool, args_sha256, tool_call_id,"
                                 " attempts FROM ops WHERE pid=?", (permit_id,)).fetchone()
        if row is None:
            raise LookupError(f"no operation for permit {permit_id[:12]}")
        return Request(workflow_id=row[0] or "", run_id=row[1] or "", activity_id=row[2] or "",
                       activity_type=row[3] or "", attempt=len(json.loads(row[6])), args=[],
                       args_sha256=row[4] or "", tool_call_id=row[5] or "", principal="")

    def is_revoked(self, permit_id: str) -> bool:
        if self.revocations is None:
            return False
        try:
            state = self.revocations.state()
        except StaleRevocations:
            return True  # fail closed: a permit is not honoured on revocation state nobody can vouch for
        return state.permit_revoked(permit_id, self.clock())

    def _close(self, db: sqlite3.Connection, req: Request, pid: str, op: dict[str, Any], outcome: str,
               result_sha256: str | None) -> None:
        owner = self.owners.get(req.activity_type)
        counted = owner.count(pid) if owner else None
        record = build_uncertain_effect(
            record_id=f"{req.workflow_id}/{req.activity_id}", action=req.activity_type, operation_id=pid,
            idempotency_key=pid, args_sha256_hex=req.args_sha256,
            attempts=[{"dispatchedAt": a["dispatchedAt"], "reply": a["reply"] or "connection_lost"}
                      for a in op["attempts"]],
            owner_id=owner.id if owner else "unreported", owner_effects=counted or 0, outcome=outcome,
            as_of=self.clock(), reconciliations=op.get("reconciliations") or None)
        record["ownerEffectsObserved"] = counted is not None
        self._append(db, req, pid, phase="effect", outcome=outcome, result_sha256=result_sha256,
                     uncertain_effect=record)
