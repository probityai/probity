"""The refund demo: a gated ``refund_payment`` activity, a mock payment processor that applies only
authority-signed permits, and the six steps of the walkthrough.

    probity-temporal demo run --dir demo-out     # starts a local Temporal dev server
    probity-temporal demo worker --dir demo-out --target HOST:PORT  # one worker (step 4)

Everything the outsider needs lands in ``--dir``: ``authority.pub``, ``journal.jsonl`` and
``checkpoint.json``; step 5 verifies them with the network disabled.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

with workflow.unsafe.imports_passed_through():
    from probity_records import Signer, canonical, sha256_hex, sign_approval, verify_permit

    from .authority import EVENT, PHASE, LocalAuthority
    from .plugin import (COMMITTED, REFUSED, UNCERTAIN, ProbityPlugin, check_approval, current_permit,
                         execute_gated_activity, pending_approval)

TASK_QUEUE = "probity-refunds"
TOOL = "refund_payment"
APPROVER = "human:ops-lead"


# ---- the system of record ---------------------------------------------------------------------
class Bank:
    """A JSON-file payment processor. It applies a refund only under an authority-signed permit for
    exactly these arguments, once per permit id (its idempotency key)."""

    id = "mock-bank"

    def __init__(self, root: Path) -> None:
        self.path = Path(root) / "bank.json"

    @contextmanager
    def _ledger(self):
        with self.path.with_suffix(".lock").open("w") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            state = json.loads(self.path.read_text()) if self.path.exists() else {"applied": [], "refused": []}
            yield state
            self.path.write_text(json.dumps(state, indent=2, sort_keys=True))

    def apply(self, args: dict[str, Any], permit: dict[str, Any] | None) -> dict[str, Any]:
        pub = (self.path.parent / "authority.pub").read_bytes()
        claims = verify_permit(permit, pub) if permit else None
        with self._ledger() as state:
            if claims is None or claims["argsSha256"] != sha256_hex(canonical([args])):
                state["refused"].append({"args": args, "reason": "no_valid_permit"})
                return {"status": "refused"}
            hits = [e for e in state["applied"] if e["key"] == claims["permitId"]]
            if hits:
                return {"status": "applied", "ref": hits[0]["ref"], "deduplicated": True}
            ref = f"RF-{len(state['applied']) + 1:04d}"
            state["applied"].append({"args": args, "key": claims["permitId"], "ref": ref})
            return {"status": "applied", "ref": ref}

    def ledger(self) -> dict[str, Any]:
        return json.loads(self.path.read_text()) if self.path.exists() else {"applied": [], "refused": []}

    def lookup(self, key: str) -> str | None:
        return "present" if any(e["key"] == key for e in self.ledger()["applied"]) else "absent"

    def count(self, key: str) -> int | None:
        return sum(1 for e in self.ledger()["applied"] if e["key"] == key)


@activity.defn(name=TOOL)
async def refund_payment(args: dict[str, Any]) -> dict[str, Any]:
    root = Path(os.environ["PROBITY_DEMO_DIR"])
    receipt = Bank(root).apply(args, current_permit())
    if os.environ.get("PROBITY_DEMO_HANG_AFTER_COMMIT") == "1":
        (root / "committed.flag").write_text(receipt.get("ref", ""))
        await asyncio.sleep(3600)  # the reply never comes back; the test kills this worker here
    return receipt


# ---- the workflow ----------------------------------------------------------------------------
@workflow.defn
class RefundWorkflow:
    @workflow.init
    def __init__(self, request: dict[str, Any]) -> None:
        # Computed before any handler runs, so the Update validator sees it even on a cold replay.
        args = {k: request[k] for k in ("customer_id", "amount_cents", "payee_account")}
        self._pending: dict[str, Any] | None = pending_approval(TOOL, [args], "call-refund-1")
        self._approval: dict[str, Any] | None = None

    @workflow.run
    async def run(self, request: dict[str, Any]) -> dict[str, Any]:
        args = {k: request[k] for k in ("customer_id", "amount_cents", "payee_account")}
        await workflow.wait_condition(lambda: self._approval is not None or request.get("skip_approval", False))
        if request.get("tamper_amount_cents"):
            args = {**args, "amount_cents": request["tamper_amount_cents"]}  # an edit after approval
        try:
            receipt = await execute_gated_activity(
                refund_payment, args, approval=self._approval, principal=f"customer:{args['customer_id']}",
                tool_call_id="call-refund-1", start_to_close_timeout=timedelta(seconds=4),
                retry_policy=RetryPolicy(maximum_attempts=3, initial_interval=timedelta(milliseconds=200)))
        except ActivityError as err:
            cause = err.cause
            if isinstance(cause, ApplicationError) and cause.type in (REFUSED, UNCERTAIN, COMMITTED):
                detail = cause.details[0] if cause.details else {}
                branch = {UNCERTAIN: "needs_reconciliation", COMMITTED: "reconciled_committed"}.get(cause.type, "refused")
                return {"status": branch, "reason": detail.get("reason", str(cause))}
            raise
        return {"status": "done", "receipt": receipt}

    @workflow.query
    def pending(self) -> dict[str, Any] | None:
        return self._pending

    @workflow.update
    def approve(self, signed: dict[str, Any]) -> str:
        if self._approval is None:
            self._approval = signed
        return self._pending["permitId"] if self._pending else ""

    @approve.validator
    def _check(self, signed: dict[str, Any]) -> None:
        if self._pending is None:
            raise ValueError("nothing_pending")
        check_approval(self._pending, signed)


# ---- the approver's side ---------------------------------------------------------------------
def sign_for(approver: Signer, pending: dict[str, Any], principal: str, minutes: int = 10) -> dict[str, Any]:
    """What a human approver's tool signs: this pause, these bytes, this tool, this workflow."""
    now = datetime.now(UTC)
    stamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    return sign_approval(approver, {
        "approvalId": pending["permitId"], "approver": APPROVER, "event": EVENT,
        "expiresAt": stamp(now + timedelta(minutes=minutes)), "issuedAt": stamp(now - timedelta(seconds=5)),
        "keyId": approver.key_id, "payloadSha256": pending["argsSha256"], "phase": PHASE,
        "principal": principal, "target": pending["workflowId"], "tool": pending["tool"]})


def approver_key(root: Path) -> Signer:
    path = root / "approver.pem"
    if not path.exists():
        path.write_bytes(Signer.generate().private_pem())
        os.chmod(path, 0o600)
    return Signer.from_pem(path.read_bytes())


def authority_for(root: Path, with_owner: bool) -> LocalAuthority:
    approver = approver_key(root)
    owners = {TOOL: Bank(root)} if with_owner else {}
    return LocalAuthority(root, {APPROVER: approver.public_pem()}, owners=owners)


async def run_worker(client: Any, root: Path, with_owner: bool) -> None:
    from temporalio.worker import Worker  # noqa: PLC0415

    os.environ["PROBITY_DEMO_DIR"] = str(root)
    plugin = ProbityPlugin(authority_for(root, with_owner), gated_activities=[TOOL])
    async with Worker(client, task_queue=TASK_QUEUE, workflows=[RefundWorkflow], activities=[refund_payment],
                      plugins=[plugin], max_cached_workflows=0):
        await asyncio.Event().wait()


# ---- the six steps ---------------------------------------------------------------------------
@contextmanager
def no_network():
    """Refuse every socket for the duration: the verification below runs fully offline."""
    real = socket.socket

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise OSError("network disabled for offline verification")

    socket.socket = refuse  # type: ignore[assignment,misc]
    try:
        yield
    finally:
        socket.socket = real  # type: ignore[misc]


async def _wait_pending(handle: Any) -> dict[str, Any]:
    for _ in range(200):
        pending = await handle.query(RefundWorkflow.pending)
        if pending:
            return pending
        await asyncio.sleep(0.05)
    raise TimeoutError("workflow never paused for approval")


async def demo(root: Path) -> int:
    from temporalio.client import Client, WorkflowUpdateFailedError  # noqa: PLC0415
    from temporalio.testing import WorkflowEnvironment  # noqa: PLC0415

    from probity_records import verify_journal  # noqa: PLC0415

    root.mkdir(parents=True, exist_ok=True)
    approver = approver_key(root)
    authority_for(root, with_owner=False)  # creates the authority key before any worker runs
    async with await WorkflowEnvironment.start_local() as env:
        client: Client = env.client
        target = env.client.service_client.config.target_host
        worker = asyncio.create_task(run_worker(client, root, with_owner=False))
        req = {"customer_id": "alice", "amount_cents": 4000, "payee_account": "acct-alice"}

        print("1-2. A $40 refund pauses for approval; the approver approves through an Update.")
        h1 = await client.start_workflow(RefundWorkflow.run, req, id="refund-1", task_queue=TASK_QUEUE)
        p1 = await _wait_pending(h1)
        signed = sign_for(approver, p1, "customer:alice")
        await h1.execute_update(RefundWorkflow.approve, signed, id=p1["permitId"])
        print("   result:", await h1.result())

        print("3. The same approval again is a no-op; an edit to $4,000 after approval is refused.")
        try:
            await h1.execute_update(RefundWorkflow.approve, signed, id=p1["permitId"])
        except WorkflowUpdateFailedError:
            pass  # the run has closed; nothing can use the approval again
        print("   refunds in the bank for refund-1:", Bank(root).count(p1["permitId"]))
        h2 = await client.start_workflow(RefundWorkflow.run, {**req, "tamper_amount_cents": 400000},
                                         id="refund-2", task_queue=TASK_QUEUE)
        p2 = await _wait_pending(h2)
        await h2.execute_update(RefundWorkflow.approve, sign_for(approver, p2, "customer:alice"), id=p2["permitId"])
        print("   result:", await h2.result())
        h3 = await client.start_workflow(RefundWorkflow.run, req, id="refund-3", task_queue=TASK_QUEUE)
        p3 = await _wait_pending(h3)
        try:
            await h3.execute_update(RefundWorkflow.approve, signed, id=p3["permitId"])  # refund-1's approval
        except WorkflowUpdateFailedError as exc:
            print("   refund-1's approval replayed into refund-3 is rejected:", exc.cause)
        await h3.terminate("demo: no approval given")

        print("4. The worker dies after the bank commits but before the reply returns.")
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        env_vars = {**os.environ, "PROBITY_DEMO_DIR": str(root), "PROBITY_DEMO_HANG_AFTER_COMMIT": "1"}
        dying = subprocess.Popen([sys.executable, "-m", "probity_temporal.cli", "demo", "worker", "--dir", str(root),
                                  "--target", target], env=env_vars)
        h4 = await client.start_workflow(RefundWorkflow.run, {**req, "amount_cents": 2500},
                                         id="refund-4", task_queue=TASK_QUEUE)
        p4 = await _wait_pending(h4)
        await h4.execute_update(RefundWorkflow.approve, sign_for(approver, p4, "customer:alice"), id=p4["permitId"])
        while not (root / "committed.flag").exists():
            await asyncio.sleep(0.1)
        dying.send_signal(signal.SIGKILL)
        dying.wait()
        worker = asyncio.create_task(run_worker(client, root, with_owner=False))
        print("   result:", await h4.result())
        print("   refunds in the bank for refund-4:", Bank(root).count(p4["permitId"]))
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        (root / "checkpoint.json").write_text(json.dumps(authority_for(root, False).checkpoint()))
        for wf in ("refund-1", "refund-2", "refund-4"):
            history = await client.get_workflow_handle(wf).fetch_history()
            (root / f"history-{wf}.json").write_text(history.to_json())

    print("5. An outsider verifies with the public key alone, network disabled.")
    with no_network():
        report = verify_journal(root, [(root / "authority.pub").read_bytes()],
                                json.loads((root / "checkpoint.json").read_text()))
    print(f"   {report['verdict']}: {report['verified']} of {report['records']} records verified;"
          f" outcomes {report['outcomes']}; failures {report['failures']}")
    print("6. The event history is your log. This is the record your customer's auditor can check without you.")
    return 0 if report["verdict"] == "PASS" else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m probity_temporal.demo")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--dir", type=Path, default=Path("probity-demo"))
    w = sub.add_parser("worker")
    w.add_argument("--dir", type=Path, required=True)
    w.add_argument("--target", required=True)
    w.add_argument("--with-owner", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        return asyncio.run(demo(a.dir.resolve()))

    async def worker() -> None:
        from temporalio.client import Client  # noqa: PLC0415

        await run_worker(await Client.connect(a.target), a.dir.resolve(), a.with_owner)

    asyncio.run(worker())
    return 0


if __name__ == "__main__":
    time.sleep(0)
    sys.exit(main())
