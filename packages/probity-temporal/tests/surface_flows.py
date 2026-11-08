"""Workflows and activities for the live dev-server tests of the plugin surfaces: local activities, async
completion, signal and update allowlists, continue-as-new and metrics."""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

from temporalio import activity, workflow

with workflow.unsafe.imports_passed_through():
    from probity_temporal.plugin import (check_approval, current_permit, execute_gated_activity,
                                         execute_gated_local_activity, pending_approval)

TASK_QUEUE = "probity-surfaces"
SHIP = "ship_item"
SHIP_ASYNC = "ship_async"


@activity.defn(name=SHIP)
async def ship_item(args: dict[str, Any]) -> dict[str, Any]:
    root = Path(os.environ["PROBITY_SURFACE_DIR"])
    permit = current_permit()
    assert permit is not None, "a gated call must run under a permit"
    with (root / "shipped.jsonl").open("a") as out:
        out.write(json.dumps({"sku": args["sku"], "permit": permit["claims"]["permitId"]}) + "\n")
    return {"shipped": args["sku"]}


@activity.defn(name=SHIP_ASYNC)
async def ship_async(args: dict[str, Any]) -> dict[str, Any]:
    (Path(os.environ["PROBITY_SURFACE_DIR"]) / "task-token").write_bytes(activity.info().task_token)
    activity.raise_complete_async()


ACTIVITIES = {SHIP: ship_item, SHIP_ASYNC: ship_async}


@workflow.defn
class SurfaceWorkflow:
    """Waits for one approval, then makes one gated call the way the request says."""

    @workflow.init
    def __init__(self, request: dict[str, Any]) -> None:
        self._tool = request["tool"]
        self._approval: dict[str, Any] | None = None
        self._marks: list[str] = []
        # a hop run continues as new before any pause, so only its successor can be approved
        self._pending = None if request.get("hop") else pending_approval(self._tool, [request["args"]], "call-s1")

    @workflow.run
    async def run(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("hop"):
            workflow.continue_as_new({**request, "hop": False})
        if not request.get("skip_approval"):
            await workflow.wait_condition(lambda: self._approval is not None)
        call = execute_gated_local_activity if request.get("local") else execute_gated_activity
        result = await call(ACTIVITIES[self._tool], request["args"], approvals=[self._approval] if self._approval else [],
                            tool_call_id="call-s1", principal=request.get("principal"), start_to_close_timeout=timedelta(seconds=30))
        return {"status": "done", "result": result, "marks": list(self._marks)}

    @workflow.query
    def pending(self) -> dict[str, Any] | None:
        return self._pending

    @workflow.query
    def marks(self) -> list[str]:
        return list(self._marks)

    @workflow.signal
    def mark(self, value: str) -> None:
        self._marks.append(value)

    @workflow.signal
    def tamper(self, value: str) -> None:
        self._marks.append("TAMPERED:" + value)

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

    @workflow.update
    def poke(self) -> str:
        return "poked"


# ---- Nexus ----------------------------------------------------------------------------------
import nexusrpc

with workflow.unsafe.imports_passed_through():
    from probity_temporal.plugin import gated_call

NEXUS_ENDPOINT = "probity-ship-endpoint"
NEXUS_QUEUE = "probity-nexus-handler"
NEXUS_OP = "ShipService/ship"


@nexusrpc.service
class ShipService:
    ship: nexusrpc.Operation[dict, dict]


@nexusrpc.handler.service_handler(service=ShipService)
class ShipHandler:
    @nexusrpc.handler.sync_operation
    async def ship(self, ctx: nexusrpc.handler.StartOperationContext, input: dict) -> dict:
        permit = current_permit()
        assert permit is not None, "a gated Nexus start must run under a permit"
        with (Path(os.environ["PROBITY_SURFACE_DIR"]) / "nexus.jsonl").open("a") as out:
            out.write(json.dumps({"sku": input["sku"], "permit": permit["claims"]["permitId"]}) + "\n")
        return {"shipped": input["sku"]}


@workflow.defn
class NexusCaller:
    @workflow.init
    def __init__(self, request: dict[str, Any]) -> None:
        self._approval: dict[str, Any] | None = None
        self._pending = pending_approval(NEXUS_OP, [request["args"]], "call-n1")

    @workflow.run
    async def run(self, request: dict[str, Any]) -> dict[str, Any]:
        if not request.get("skip_approval"):
            await workflow.wait_condition(lambda: self._approval is not None)
        client = workflow.create_nexus_client(service=ShipService, endpoint=NEXUS_ENDPOINT)
        with gated_call(approvals=[self._approval] if self._approval else [], tool_call_id="call-n1",
                        principal=request["principal"]):
            result = await client.execute_operation(ShipService.ship, request["args"])
        return {"status": "done", "result": result}

    @workflow.query
    def pending(self) -> dict[str, Any] | None:
        return self._pending

    @workflow.update
    def approve(self, signed: dict[str, Any]) -> str:
        if self._approval is None:
            self._approval = signed
        return self._pending["permitId"]

    @approve.validator
    def _check(self, signed: dict[str, Any]) -> None:
        check_approval(self._pending, signed)
