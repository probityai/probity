"""probity-temporal against a real Temporal dev server: permits, refusals, a killed worker, offline
verification, and cache-disabled replay of every recorded history."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from temporalio.client import WorkflowUpdateFailedError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Replayer

from probity_records import verify_journal
from probity_temporal import ProbityPlugin, Request
from probity_temporal.demo import (APPROVER, TOOL, Bank, RefundWorkflow, _wait_pending, approver_key,
                                   authority_for, no_network, run_worker, sign_for)

REQ = {"customer_id": "alice", "amount_cents": 4000, "payee_account": "acct-alice"}


@pytest.fixture
async def env():
    async with await WorkflowEnvironment.start_local() as e:
        yield e


async def _approved(client, root, wf, req, approver=None):
    approver = approver or approver_key(root)
    h = await client.start_workflow(RefundWorkflow.run, req, id=wf, task_queue="probity-refunds")
    pending = await _wait_pending(h)
    signed = sign_for(approver, pending, "customer:alice")
    try:
        await h.execute_update(RefundWorkflow.approve, signed, id=pending["permitId"])
    except WorkflowUpdateFailedError as exc:
        raise AssertionError(f"approval update refused: {exc.cause!r}") from exc
    return h, pending, signed


def _verify(root: Path, authority) -> dict:
    with no_network():
        return verify_journal(root, [authority.public_pem()], authority.checkpoint(),
                              trust=authority.trust())


async def _stop(task):
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


async def test_approved_call_runs_once_replayed_approval_is_noop_and_verifies_offline(env, tmp_path):
    authority = authority_for(tmp_path, with_owner=False)
    worker = asyncio.create_task(run_worker(env.client, tmp_path, with_owner=False))
    try:
        h, pending, signed = await _approved(env.client, tmp_path, "wf-ok", REQ)
        assert (await h.result())["status"] == "done"
        try:  # the same approval again: deduplicated by Update id, or refused once the run has closed
            await h.execute_update(RefundWorkflow.approve, signed, id=pending["permitId"])
        except WorkflowUpdateFailedError:
            pass
        assert Bank(tmp_path).count(pending["permitId"]) == 1
        assert len(Bank(tmp_path).ledger()["applied"]) == 1
        history = await h.fetch_history()
    finally:
        await _stop(worker)
    report = _verify(tmp_path, authority)
    assert (report["verdict"], report["verified"], report["records"]) == ("PASS", 3, 3), report["failures"]
    assert report["outcomes"] == {"committed": 1}
    replayer = Replayer(workflows=[RefundWorkflow], plugins=[ProbityPlugin(None, gated_activities=[TOOL])])
    await replayer.replay_workflow(history)


async def test_args_edited_after_approval_are_refused_and_recorded(env, tmp_path):
    authority = authority_for(tmp_path, with_owner=False)
    worker = asyncio.create_task(run_worker(env.client, tmp_path, with_owner=False))
    try:
        h, _, _ = await _approved(env.client, tmp_path, "wf-edit", {**REQ, "tamper_amount_cents": 400000})
        result = await h.result()
    finally:
        await _stop(worker)
    assert (result["status"], result["reason"]) == ("refused", "payload_mismatch")
    assert Bank(tmp_path).ledger()["applied"] == []
    report = _verify(tmp_path, authority)
    assert report["verdict"] == "PASS", report["failures"]
    assert [s["predicate"]["reason"] for s in report["statements"]] == ["payload_mismatch"]


async def test_no_approval_is_refused_and_approval_for_another_run_is_rejected(env, tmp_path):
    authority = authority_for(tmp_path, with_owner=False)
    worker = asyncio.create_task(run_worker(env.client, tmp_path, with_owner=False))
    try:
        h = await env.client.start_workflow(RefundWorkflow.run, {**REQ, "skip_approval": True}, id="wf-none",
                                            task_queue="probity-refunds")
        assert (await h.result())["reason"] == "approval_missing"
        _, _, signed = await _approved(env.client, tmp_path, "wf-a", REQ)
        h2 = await env.client.start_workflow(RefundWorkflow.run, REQ, id="wf-b", task_queue="probity-refunds")
        p2 = await _wait_pending(h2)
        with pytest.raises(WorkflowUpdateFailedError):
            await h2.execute_update(RefundWorkflow.approve, signed, id=p2["permitId"])
        await h2.terminate("test")
    finally:
        await _stop(worker)
    assert len(Bank(tmp_path).ledger()["applied"]) == 1
    assert _verify(tmp_path, authority)["verdict"] == "PASS"


def test_authority_refuses_a_second_use_and_a_forged_approval(tmp_path):
    authority = authority_for(tmp_path, with_owner=False)
    approver = approver_key(tmp_path)
    from probity_records import args_sha256
    digest = args_sha256([REQ])
    pending = {"permitId": "p" * 64, "argsSha256": digest, "tool": TOOL, "workflowId": "wf"}
    signed = sign_for(approver, pending, "customer:alice")

    def req(activity_id, approval):
        return Request("wf", "run", activity_id, TOOL, 1, [REQ], digest, "call", "customer:alice", [approval])

    assert authority.authorize(req("1", signed)).ok
    assert authority.authorize(req("2", signed)).reason == "approval_replayed"
    forged = {**signed, "body": {**signed["body"], "approver": APPROVER, "payloadSha256": "0" * 64}}
    assert authority.authorize(req("3", forged)).reason == "approval_signature_invalid"


@pytest.mark.parametrize("with_owner,expected", [(False, "needs_reconciliation"), (True, "done")])
async def test_worker_killed_mid_call_never_reads_as_success_or_pays_twice(env, tmp_path, with_owner, expected):
    authority = authority_for(tmp_path, with_owner=with_owner)
    target = env.client.service_client.config.target_host
    extra = ["--with-owner"] if with_owner else []
    dying = subprocess.Popen([sys.executable, "-m", "probity_temporal.cli", "demo", "worker", "--dir", str(tmp_path),
                              "--target", target, *extra],
                             env={**os.environ, "PROBITY_DEMO_DIR": str(tmp_path), "PROBITY_DEMO_HANG_AFTER_COMMIT": "1"})
    try:
        h, pending, _ = await _approved(env.client, tmp_path, "wf-kill", REQ)
        for _ in range(300):
            if (tmp_path / "committed.flag").exists():
                break
            await asyncio.sleep(0.1)
        assert (tmp_path / "committed.flag").exists()
    finally:
        dying.send_signal(signal.SIGKILL)
        dying.wait()
    worker = asyncio.create_task(run_worker(env.client, tmp_path, with_owner=with_owner))
    try:
        result = await asyncio.wait_for(h.result(), 60)
    finally:
        await _stop(worker)
    assert result["status"] == expected
    if with_owner:  # the committed refund comes back as success, with the bank's own receipt
        assert result["receipt"] == {"status": "applied", "ref": "RF-0001"}
    assert Bank(tmp_path).count(pending["permitId"]) == 1  # paid once, never twice
    report = _verify(tmp_path, authority)
    assert report["verdict"] == "PASS", report["failures"]
    assert report["outcomes"] == {"committed" if with_owner else "unknown": 1}
    effect = [s["predicate"] for s in report["statements"] if s["predicate"]["phase"] == "effect"][0]
    assert effect["uncertainEffect"]["attempts"][0]["reply"] == "connection_lost"
    assert json.dumps(effect).count("confirmed") == 0


def test_retry_after_lost_reply_needs_a_final_absent_answer(tmp_path):
    class Owner:
        id = "bank"
        answer = "absent"

        def lookup(self, key):
            return self.answer

        def count(self, key):
            return 1 if self.answer == "present" else 0

    from probity_records import args_sha256
    from probity_temporal import LocalAuthority
    owner = Owner()
    approver = approver_key(tmp_path)
    authority = LocalAuthority(tmp_path, {APPROVER: approver.public_pem()}, owners={TOOL: owner})
    digest = args_sha256([REQ])
    signed = sign_for(approver, {"permitId": "p" * 64, "argsSha256": digest, "tool": TOOL, "workflowId": "wf"},
                      "customer:alice")
    req = Request("wf", "run", "1", TOOL, 1, [REQ], digest, "call", "customer:alice", [signed])
    first = authority.authorize(req)
    authority.intent(req, first.permit_id)  # the worker dies here
    import dataclasses
    retry = authority.authorize(dataclasses.replace(req, attempt=2))
    assert (retry.ok, retry.reason) == (True, "reconciled_absent_retry")
    authority.intent(req, retry.permit_id)
    assert authority.effect(req, retry.permit_id, "confirmed", "ab" * 32) == ("committed", None)
    report = _verify(tmp_path, authority)
    assert report["verdict"] == "PASS", report["failures"]
    owner.answer = None
    again = authority.authorize(req)
    assert (again.ok, again.outcome) == (False, "committed")
