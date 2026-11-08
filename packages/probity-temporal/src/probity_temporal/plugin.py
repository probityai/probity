"""The Temporal plugin: a workflow outbound interceptor that stamps each gated call's argument digest
at schedule time, and an activity inbound interceptor that refuses the call without a single-use
permit for exactly those bytes and records what came back.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from temporalio import activity, workflow
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadConverter
from temporalio.exceptions import ApplicationError
from temporalio.plugin import SimplePlugin
from temporalio.worker import (
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    Interceptor,
    StartActivityInput,
    WorkflowInboundInterceptor,
    WorkflowInterceptorClassInput,
    WorkflowOutboundInterceptor,
)
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner

from probity_records import canonical, permit_id, sha256_hex

from .authority import LocalAuthority, Request

HEADER_DIGEST = "probity-args-sha256"
HEADER_APPROVAL = "probity-approval"
HEADER_PRINCIPAL = "probity-principal"
HEADER_CALL = "probity-tool-call-id"
REFUSED = "ProbityRefused"
UNCERTAIN = "ProbityOutcomeUncertain"
COMMITTED = "ProbityOutcomeCommitted"
PASSTHROUGH = ("probity_records", "probity_temporal", "jcs_admit", "cryptography",
               "agent_evidence_vectors", "agent_evidence_verify")

_PERMIT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("probity_permit", default=None)
_GATED_CALL: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("probity_gated_call", default=None)


class NoEffect(Exception):  # noqa: N818 - a signal, not an error class users catch broadly
    """Raise from a gated activity when the system of record answered that nothing happened."""


def current_permit() -> dict[str, Any] | None:
    """Inside a gated activity: the authority-signed permit to hand the system of record."""
    return _PERMIT.get()


def json_values(converter: PayloadConverter, args: Sequence[Any]) -> list[Any]:
    """The JSON value of each argument, exactly as Temporal serialises it into history."""
    return [json.loads(p.data) for p in converter.to_payloads(list(args))]


def call_sha256(converter: PayloadConverter, args: Sequence[Any]) -> str:
    """SHA-256 of the JCS bytes of the argument list: what an outsider recomputes from history."""
    return sha256_hex(canonical(json_values(converter, args)))


def _text(value: str) -> Payload:
    return Payload(metadata={"encoding": b"json/plain"}, data=json.dumps(value).encode())


def _read(headers: Mapping[str, Payload], name: str) -> Any:
    payload = headers.get(name)
    return None if payload is None else json.loads(payload.data)


# ---- workflow side ---------------------------------------------------------------------------
def pause_token(tool: str, args: Sequence[Any]) -> str:
    """Deterministic token for one pause of this run: workflow, run, tool and argument digest."""
    info = workflow.info()
    return sha256_hex(canonical({"argsSha256": call_sha256(workflow.payload_converter(), args),
                                 "runId": info.run_id, "tool": tool, "workflowId": info.workflow_id}))


def pending_approval(tool: str, args: Sequence[Any], tool_call_id: str) -> dict[str, Any]:
    """What an approver needs to sign for one call; ``permitId`` is also the Update id to send."""
    digest = call_sha256(workflow.payload_converter(), args)
    token = pause_token(tool, args)
    return {"argsSha256": digest, "pauseToken": token, "permitId": permit_id(token, tool_call_id, digest),
            "tool": tool, "toolCallId": tool_call_id, "workflowId": workflow.info().workflow_id}


def check_approval(pending: Mapping[str, Any], signed: Mapping[str, Any]) -> None:
    """Update validator: refuse an approval that is not for this pause and these exact bytes.

    The signature itself is checked by the authority, outside the workflow sandbox.
    """
    body = signed.get("body") if isinstance(signed, Mapping) else None
    if not isinstance(body, Mapping):
        raise ValueError("approval_shape")
    if body.get("approvalId") != pending["permitId"] or body.get("payloadSha256") != pending["argsSha256"]:
        raise ValueError("approval_not_for_this_call")
    if body.get("tool") != pending["tool"] or body.get("target") != pending["workflowId"]:
        raise ValueError("approval_not_for_this_call")


async def execute_gated_activity(activity_fn: Any, *args: Any, approval: Mapping[str, Any] | None,
                                 principal: str, tool_call_id: str, **options: Any) -> Any:
    """``workflow.execute_activity`` for a gated activity, carrying the approval in headers."""
    token = _GATED_CALL.set({"approval": approval, "principal": principal, "toolCallId": tool_call_id})
    try:
        return await workflow.execute_activity(activity_fn, args=list(args), **options)
    finally:
        _GATED_CALL.reset(token)


def _workflow_interceptor(gated: frozenset[str]) -> type[WorkflowInboundInterceptor]:
    class _Outbound(WorkflowOutboundInterceptor):
        def start_activity(self, input: StartActivityInput) -> workflow.ActivityHandle[Any]:
            if input.activity in gated:
                headers = dict(input.headers)
                headers[HEADER_DIGEST] = _text(call_sha256(workflow.payload_converter(), input.args))
                call = _GATED_CALL.get() or {}
                headers[HEADER_APPROVAL] = Payload(metadata={"encoding": b"json/plain"},
                                                   data=json.dumps(call.get("approval")).encode())
                headers[HEADER_PRINCIPAL] = _text(str(call.get("principal", "")))
                headers[HEADER_CALL] = _text(str(call.get("toolCallId", "")))
                input = dataclasses.replace(input, headers=headers)
            return super().start_activity(input)

    class _Inbound(WorkflowInboundInterceptor):
        def init(self, outbound: WorkflowOutboundInterceptor) -> None:
            super().init(_Outbound(outbound))

    return _Inbound


# ---- activity side ---------------------------------------------------------------------------
class _ActivityInbound(ActivityInboundInterceptor):
    def __init__(self, next: ActivityInboundInterceptor, plugin: _Interceptor) -> None:
        super().__init__(next)
        self.plugin = plugin

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:
        info = activity.info()
        if info.activity_type not in self.plugin.gated:
            return await self.next.execute_activity(input)
        authority = self.plugin.authority
        converter = activity.payload_converter()
        values = json_values(converter, input.args)
        req = Request(workflow_id=info.workflow_id or "", run_id=info.workflow_run_id or "",
                      activity_id=info.activity_id, activity_type=info.activity_type, attempt=info.attempt,
                      args=values, args_sha256=sha256_hex(canonical(values)),
                      tool_call_id=_read(input.headers, HEADER_CALL) or info.activity_id,
                      principal=_read(input.headers, HEADER_PRINCIPAL) or "",
                      approval=_read(input.headers, HEADER_APPROVAL),
                      tool_identity=self.plugin.tool_identities.get(info.activity_type))
        if _read(input.headers, HEADER_DIGEST) != req.args_sha256:
            await asyncio.to_thread(authority.refuse, req, "arguments_changed_after_schedule")
            raise ApplicationError("probity: arguments changed after schedule", type=REFUSED, non_retryable=True)
        decision = await asyncio.to_thread(authority.authorize, req)
        if not decision.ok:
            kind = {"committed": COMMITTED, "unknown": UNCERTAIN}.get(decision.outcome or "", REFUSED)
            raise ApplicationError(f"probity: {decision.reason}", {"reason": decision.reason,
                                   "outcome": decision.outcome}, type=kind, non_retryable=True)
        pid = decision.permit_id or ""
        await asyncio.to_thread(authority.intent, req, pid)
        token = _PERMIT.set(decision.permit)
        try:
            result = await self.next.execute_activity(input)
        except NoEffect:
            await asyncio.to_thread(authority.effect, req, pid, "no_effect", None)
            raise
        except BaseException as exc:
            reply = "timeout" if isinstance(exc, TimeoutError) else "connection_lost"
            outcome = await asyncio.to_thread(authority.effect, req, pid, reply, None)
            if outcome == "unknown":
                raise ApplicationError(f"probity: outcome uncertain after {type(exc).__name__}",
                                       {"reason": "outcome_unknown", "outcome": "unknown"},
                                       type=UNCERTAIN, non_retryable=True) from exc
            raise
        finally:
            _PERMIT.reset(token)
        digest = hashlib.sha256(converter.to_payloads([result])[0].data).hexdigest()
        await asyncio.to_thread(authority.effect, req, pid, "confirmed", digest)
        return result


class _Interceptor(Interceptor):
    def __init__(self, authority: LocalAuthority | None, gated: frozenset[str],
                 tool_identities: Mapping[str, str]) -> None:
        self.authority = authority
        self.gated = gated
        self.tool_identities = dict(tool_identities)
        self._workflow_class = _workflow_interceptor(gated)

    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:
        if self.authority is None:
            raise RuntimeError("ProbityPlugin on a worker that runs gated activities needs an authority")
        return _ActivityInbound(next, self)

    def workflow_interceptor_class(self, input: WorkflowInterceptorClassInput) -> type[WorkflowInboundInterceptor]:
        return self._workflow_class


def _runner(existing: Any) -> Any:
    if isinstance(existing, SandboxedWorkflowRunner):
        return dataclasses.replace(existing, restrictions=existing.restrictions.with_passthrough_modules(*PASSTHROUGH))
    return existing


class ProbityPlugin(SimplePlugin):
    """``Worker(..., plugins=[ProbityPlugin(authority, gated_activities=["refund_payment"])])``."""

    def __init__(self, authority: LocalAuthority | None, gated_activities: Iterable[str],
                 tool_identities: Mapping[str, str] | None = None) -> None:
        super().__init__("probity.ProbityPlugin",
                         interceptors=[_Interceptor(authority, frozenset(gated_activities), tool_identities or {})],
                         workflow_runner=_runner)
