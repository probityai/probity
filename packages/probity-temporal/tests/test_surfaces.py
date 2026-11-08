"""probity-temporal surfaces against a real Temporal dev server: local activities, async completion,
signal and update allowlists, continue-as-new and metrics. Each test reads the signed journal back
offline, so a surface that works but leaves no record fails."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from temporalio.client import Client, WorkflowFailureError, WorkflowUpdateFailedError
from temporalio.runtime import MetricBuffer, Runtime, TelemetryConfig
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from probity_records import verify_journal
from probity_temporal import LocalAuthority, ProbityPlugin, errors, probity_principal
from probity_temporal.demo import APPROVER, approver_key, no_network, sign_for
from probity_temporal.plugin import complete_gated_async

from surface_flows import ACTIVITIES, SHIP, SHIP_ASYNC, TASK_QUEUE, SurfaceWorkflow

ARGS = {"sku": "sku-1", "qty": 2}
PRINCIPAL = "customer:alice"


@pytest.fixture
async def env():
    async with await WorkflowEnvironment.start_local() as e:
        yield SimpleNamespace(client=await _with_plugin(e.client))


async def _with_plugin(client):
    """The same dev server through a client that carries the plugin, as an application's client does."""
    return await Client.connect(client.service_client.config.target_host, namespace=client.namespace,
                                plugins=[ProbityPlugin(None)])


def _authority(root: Path) -> LocalAuthority:
    return LocalAuthority(root, {APPROVER: approver_key(root).public_pem()})


def _worker(client, root: Path, authority: LocalAuthority, **plugin_options):
    os.environ["PROBITY_SURFACE_DIR"] = str(root)
    plugin = ProbityPlugin(authority, gated_activities=[SHIP, SHIP_ASYNC], **plugin_options)
    return Worker(client, task_queue=TASK_QUEUE, workflows=[SurfaceWorkflow], activities=list(ACTIVITIES.values()),
                  plugins=[plugin], max_cached_workflows=0)


async def _pending(handle):
    for _ in range(200):
        pending = await handle.query(SurfaceWorkflow.pending)
        if pending:
            return pending
        await asyncio.sleep(0.05)
    raise TimeoutError("workflow never paused for approval")


async def _approve(handle, root: Path, principal: str = PRINCIPAL):
    pending = await _pending(handle)
    signed = sign_for(approver_key(root), pending, principal)
    await handle.execute_update(SurfaceWorkflow.approve, signed, id=pending["permitId"])
    return pending


def _verify(root: Path, authority: LocalAuthority) -> dict:
    with no_network():
        return verify_journal(root, [authority.public_pem()], authority.checkpoint(), trust=authority.trust())


def _request(tool: str = SHIP, **extra):
    return {"tool": tool, "args": ARGS, "principal": PRINCIPAL, **extra}


async def test_local_activity_is_refused_by_default_and_gated_when_allowed(env, tmp_path):
    authority = _authority(tmp_path)
    async with _worker(env.client, tmp_path, authority):
        blocked = await env.client.start_workflow(SurfaceWorkflow.run, _request(local=True), id="wf-local-no",
                                                  task_queue=TASK_QUEUE)
        await _approve(blocked, tmp_path)
        with pytest.raises(WorkflowFailureError) as refused:
            await blocked.result()
        assert refused.value.cause.type == errors.LOCAL_ACTIVITY_BLOCKED
    assert not (tmp_path / "shipped.jsonl").exists()
    async with _worker(env.client, tmp_path, authority, allow_local_activities=True):
        allowed = await env.client.start_workflow(SurfaceWorkflow.run, _request(local=True), id="wf-local-yes",
                                                  task_queue=TASK_QUEUE)
        pending = await _approve(allowed, tmp_path)
        assert (await allowed.result())["result"] == {"shipped": "sku-1"}
    assert (tmp_path / "shipped.jsonl").read_text().count(pending["permitId"]) == 1
    report = _verify(tmp_path, authority)
    assert (report["verdict"], report["outcomes"]) == ("PASS", {"committed": 1}), report["failures"]


async def test_approval_signed_for_other_bytes_is_rejected_before_any_local_activity_runs(env, tmp_path):
    authority = _authority(tmp_path)
    async with _worker(env.client, tmp_path, authority, allow_local_activities=True):
        h = await env.client.start_workflow(SurfaceWorkflow.run, _request(local=True), id="wf-local-bad",
                                            task_queue=TASK_QUEUE)
        pending = await _pending(h)
        other = {**pending, "argsSha256": "0" * 64}  # an approval signed for different bytes
        with pytest.raises(WorkflowUpdateFailedError):
            await h.execute_update(SurfaceWorkflow.approve, sign_for(approver_key(tmp_path), other, PRINCIPAL),
                                   id=pending["permitId"])
        await h.terminate("test")
    assert not (tmp_path / "shipped.jsonl").exists()


async def test_async_completion_records_the_confirmed_outcome_then_completes(env, tmp_path):
    authority = _authority(tmp_path)
    async with _worker(env.client, tmp_path, authority):
        h = await env.client.start_workflow(SurfaceWorkflow.run, _request(SHIP_ASYNC), id="wf-async",
                                            task_queue=TASK_QUEUE)
        await _approve(h, tmp_path)
        token_file = tmp_path / "task-token"
        for _ in range(200):
            if token_file.exists():
                break
            await asyncio.sleep(0.05)
        assert token_file.exists()
        token = token_file.read_bytes()
        await complete_gated_async(env.client, authority, token, {"shipped": "sku-1"})
        assert (await h.result())["result"] == {"shipped": "sku-1"}
    report = _verify(tmp_path, authority)
    assert (report["verdict"], report["outcomes"]) == ("PASS", {"committed": 1}), report["failures"]
    with pytest.raises(LookupError):
        await complete_gated_async(env.client, authority, b"\x00unknown-token", {})


async def test_unlisted_signal_is_dropped_and_unlisted_update_is_rejected_with_a_stable_code(env, tmp_path):
    authority = _authority(tmp_path)
    async with _worker(env.client, tmp_path, authority, authorized_signals=["mark"],
                       authorized_updates=["approve"]):
        h = await env.client.start_workflow(SurfaceWorkflow.run, _request(), id="wf-allow", task_queue=TASK_QUEUE)
        await _pending(h)
        await h.signal(SurfaceWorkflow.tamper, "evil")
        await h.signal(SurfaceWorkflow.mark, "fine")
        with pytest.raises(WorkflowUpdateFailedError) as rejected:
            await h.execute_update(SurfaceWorkflow.poke)
        assert rejected.value.cause.type == errors.UPDATE_NOT_AUTHORIZED
        await _approve(h, tmp_path)
        out = await h.result()
    assert out["marks"] == ["fine"], "an unlisted signal must change nothing, and must not fail the run"
    assert _verify(tmp_path, authority)["verdict"] == "PASS"


async def test_without_an_allowlist_every_signal_and_update_still_works(env, tmp_path):
    authority = _authority(tmp_path)
    async with _worker(env.client, tmp_path, authority):
        h = await env.client.start_workflow(SurfaceWorkflow.run, _request(), id="wf-open", task_queue=TASK_QUEUE)
        await _pending(h)
        await h.signal(SurfaceWorkflow.tamper, "x")
        assert await h.execute_update(SurfaceWorkflow.poke) == "poked"
        await _approve(h, tmp_path)
        assert (await h.result())["marks"] == ["TAMPERED:x"]


async def test_principal_survives_continue_as_new_so_the_next_run_can_still_be_approved(env, tmp_path):
    authority = _authority(tmp_path)
    async with _worker(env.client, tmp_path, authority):
        with probity_principal(PRINCIPAL):
            h = await env.client.start_workflow(SurfaceWorkflow.run, _request(hop=True, principal=None), id="wf-hop",
                                                task_queue=TASK_QUEUE)
        latest = env.client.get_workflow_handle("wf-hop")  # follows the chain to the newest run
        pending = await _approve(latest, tmp_path, PRINCIPAL)
        assert (await latest.result())["status"] == "done"
        assert pending["workflowId"] == "wf-hop"
    report = _verify(tmp_path, authority)
    assert (report["verdict"], report["outcomes"]) == ("PASS", {"committed": 1}), report["failures"]
    assert h.id == "wf-hop"


async def test_metrics_carry_the_tool_and_a_stable_code_and_never_argument_values(tmp_path):
    buffer = MetricBuffer(10_000)
    runtime = Runtime(telemetry=TelemetryConfig(metrics=buffer))
    async with await WorkflowEnvironment.start_local(runtime=runtime) as env:
        authority = _authority(tmp_path)
        async with _worker(env.client, tmp_path, authority):
            ok = await env.client.start_workflow(SurfaceWorkflow.run, _request(), id="wf-m-ok", task_queue=TASK_QUEUE)
            await _approve(ok, tmp_path)
            await ok.result()
            nope = await env.client.start_workflow(SurfaceWorkflow.run, _request(skip_approval=True, args={"sku": "sku-2"}),
                                                   id="wf-m-no", task_queue=TASK_QUEUE)
            with pytest.raises(WorkflowFailureError):
                await nope.result()  # refused: no approval was ever given
    seen = {}
    for update in buffer.retrieve_updates():
        if update.metric.name.startswith("probity_"):
            seen.setdefault(update.metric.name, []).append(dict(update.attributes))
    labels = {"tool": SHIP, "workflow_type": "SurfaceWorkflow"}
    assert labels.items() <= seen["probity_activities_authorized"][0].items()
    assert {**labels, "code": errors.APPROVAL_MISSING}.items() <= seen["probity_activities_denied"][0].items()
    assert "probity_authorization_latency" in seen
    flat = repr(seen)
    assert "sku-1" not in flat and "sku-2" not in flat, "argument values must never become metric labels"


async def test_gated_nexus_operation_runs_once_under_a_permit_and_is_recorded(tmp_path):
    from surface_flows import NEXUS_ENDPOINT, NEXUS_OP, NEXUS_QUEUE, NexusCaller, ShipHandler

    authority = _authority(tmp_path)
    os.environ["PROBITY_SURFACE_DIR"] = str(tmp_path)
    async with await WorkflowEnvironment.start_local(
            dev_server_extra_args=["--dynamic-config-value", "system.enableNexus=true"]) as env:
        await env.create_nexus_endpoint(NEXUS_ENDPOINT, NEXUS_QUEUE)
        handler = Worker(env.client, task_queue=NEXUS_QUEUE, nexus_service_handlers=[ShipHandler()],
                         plugins=[ProbityPlugin(authority, gated_nexus_operations=[NEXUS_OP])])
        caller = Worker(env.client, task_queue=TASK_QUEUE, workflows=[NexusCaller],
                        plugins=[ProbityPlugin(None, gated_nexus_operations=[NEXUS_OP])], max_cached_workflows=0)
        async with handler, caller:
            ok = await env.client.start_workflow(NexusCaller.run, {"args": ARGS, "principal": PRINCIPAL},
                                                 id="wf-nexus", task_queue=TASK_QUEUE)
            pending = await _pending_q(ok)
            signed = sign_for(approver_key(tmp_path), pending, PRINCIPAL)
            await ok.execute_update(NexusCaller.approve, signed, id=pending["permitId"])
            assert (await ok.result())["result"] == {"shipped": "sku-1"}
            nope = await env.client.start_workflow(
                NexusCaller.run, {"args": {"sku": "sku-9"}, "principal": PRINCIPAL, "skip_approval": True},
                id="wf-nexus-no", task_queue=TASK_QUEUE)
            with pytest.raises(WorkflowFailureError):
                await nope.result()
    shipped = (tmp_path / "nexus.jsonl").read_text().splitlines()
    assert len(shipped) == 1 and pending["permitId"] in shipped[0], "the unapproved operation must never start"
    report = _verify(tmp_path, authority)
    assert (report["verdict"], report["outcomes"]) == ("PASS", {"committed": 1}), report["failures"]


async def _pending_q(handle):
    for _ in range(200):
        pending = await handle.query("pending")
        if pending:
            return pending
        await asyncio.sleep(0.05)
    raise TimeoutError("workflow never paused for approval")
