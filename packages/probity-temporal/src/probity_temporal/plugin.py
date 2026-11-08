"""The Temporal plugin.

* Client: ``with probity_principal("customer:alice"):`` stamps the principal on every workflow the
  client starts; the workflow keeps it for every gated call and across continue-as-new.
* Workflow: each gated activity's argument digest is stamped at schedule time (after admission), the
  Web UI summary names the gate, unlisted signals are dropped and unlisted updates rejected.
* Activity: a gated call runs only with a single-use permit for exactly those bytes, inside an
  idempotency-key context, under a span and metrics with bounded labels; what came back is recorded.
* Nexus: every start of a gated operation goes through the same authority, decorator or not.
"""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import hashlib
import json
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any

from temporalio import activity, workflow
from temporalio.api.common.v1 import Payload
from temporalio.client import Interceptor as ClientInterceptor
from temporalio.client import OutboundInterceptor as ClientOutbound
from temporalio.client import StartWorkflowInput
from temporalio.converter import PayloadConverter
from temporalio.exceptions import ApplicationError
from temporalio.plugin import SimplePlugin
from temporalio.worker import (
    ActivityInboundInterceptor,
    ContinueAsNewInput,
    ExecuteActivityInput,
    ExecuteNexusOperationStartInput,
    ExecuteWorkflowInput,
    HandleSignalInput,
    HandleUpdateInput,
    Interceptor,
    NexusOperationInboundInterceptor,
    StartActivityInput,
    StartLocalActivityInput,
    StartNexusOperationInput,
    WorkflowInboundInterceptor,
    WorkflowInterceptorClassInput,
    WorkflowOutboundInterceptor,
)
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner

from probity_records import canonical, permit_id, sha256_hex

from . import errors
from .admission import NotAdmissible, admit
from .authority import Decision, LocalAuthority, Request

HEADER_DIGEST = "probity-args-sha256"
HEADER_APPROVALS = "probity-approvals"
HEADER_PRINCIPAL = "probity-principal"
HEADER_CALL = "probity-tool-call-id"
HEADER_WORKFLOW = "probity-caller-workflow"
SUMMARY_PREFIX = "[probity gated]"
PASSTHROUGH = ("probity_records", "probity_temporal", "jcs_admit", "cryptography",
               "agent_evidence_vectors", "agent_evidence_verify")
GATED_ATTR = "__probity_gated__"

_PERMIT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("probity_permit", default=None)
_GATED_CALL: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("probity_gated_call", default=None)
_CLIENT_PRINCIPAL: contextvars.ContextVar[str | None] = contextvars.ContextVar("probity_client_principal", default=None)
_RUN_PRINCIPAL: dict[str, str] = {}  # run id -> principal, set by the workflow inbound interceptor


class NoEffect(Exception):  # noqa: N818 - a signal, not an error class users catch broadly
    """Raise from a gated activity when the system of record answered that nothing happened."""


def gated(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Mark an activity function as gated; ``ProbityPlugin`` finds it among the worker's activities."""
    setattr(fn, GATED_ATTR, True)
    return fn


def current_permit() -> dict[str, Any] | None:
    """Inside a gated activity or Nexus handler: the authority-signed permit to hand the system of record."""
    return _PERMIT.get()


def current_idempotency_key() -> str | None:
    """Inside a gated call: the key to give the system of record. Stable across retries of this call,
    distinct across calls, runs and approvals; it is the permit id every record carries."""
    permit = _PERMIT.get()
    return None if permit is None else permit["claims"]["idempotencyKey"]


@contextmanager
def probity_principal(principal: str) -> Iterator[None]:
    """Workflows started by a client inside this block carry ``principal`` for their gated calls."""
    token = _CLIENT_PRINCIPAL.set(principal)
    try:
        yield
    finally:
        _CLIENT_PRINCIPAL.reset(token)


def json_values(converter: PayloadConverter, args: Sequence[Any]) -> list[Any]:
    """The JSON value of each argument, exactly as Temporal serialises it into history."""
    return [json.loads(p.data) for p in converter.to_payloads(list(args))]


def call_sha256(converter: PayloadConverter, args: Sequence[Any]) -> str:
    """SHA-256 of the JCS bytes of the argument list: what an outsider recomputes from history."""
    return sha256_hex(canonical(json_values(converter, args)))


def _text(value: Any) -> Payload:
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
    try:
        admit(args)
    except NotAdmissible as exc:
        raise errors.ProbityWorkflowError(errors.ARGS_NOT_ADMISSIBLE, str(exc)) from exc
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


@contextmanager
def gated_call(*, approvals: Sequence[Mapping[str, Any]], tool_call_id: str, principal: str | None = None) -> Iterator[None]:
    """Carry approvals (M of N) into the gated call started inside this block: an activity, a local
    activity or a Nexus operation. ``principal`` defaults to the one the starting client stamped."""
    token = _GATED_CALL.set({"approvals": list(approvals), "principal": principal, "toolCallId": tool_call_id})
    try:
        yield
    finally:
        _GATED_CALL.reset(token)


async def execute_gated_activity(activity_fn: Any, *args: Any, approvals: Sequence[Mapping[str, Any]],
                                 tool_call_id: str, principal: str | None = None, **options: Any) -> Any:
    """``workflow.execute_activity`` for a gated activity, carrying its approvals (M of N) in headers."""
    with gated_call(approvals=approvals, tool_call_id=tool_call_id, principal=principal):
        return await workflow.execute_activity(activity_fn, args=list(args), **options)


async def execute_gated_local_activity(activity_fn: Any, *args: Any, approvals: Sequence[Mapping[str, Any]],
                                       tool_call_id: str, principal: str | None = None, **options: Any) -> Any:
    """The local-activity form; the permit check runs on the worker exactly as for a normal activity."""
    with gated_call(approvals=approvals, tool_call_id=tool_call_id, principal=principal):
        return await workflow.execute_local_activity(activity_fn, args=list(args), **options)


def _gate_headers(headers: Mapping[str, Payload], args: Sequence[Any]) -> dict[str, Payload]:
    try:
        admit(args)
    except NotAdmissible as exc:
        raise errors.ProbityWorkflowError(errors.ARGS_NOT_ADMISSIBLE, str(exc)) from exc
    call = _GATED_CALL.get() or {}
    info = workflow.info()
    principal = call.get("principal") or _RUN_PRINCIPAL.get(info.run_id, "")
    out = dict(headers)
    out[HEADER_DIGEST] = _text(call_sha256(workflow.payload_converter(), args))
    out[HEADER_APPROVALS] = _text(call.get("approvals") or [])
    out[HEADER_PRINCIPAL] = _text(principal)
    out[HEADER_CALL] = _text(str(call.get("toolCallId", "")))
    return out


def _summary(existing: str | None, tool: str) -> str:
    return f"{SUMMARY_PREFIX} {tool}" + (f": {existing}" if existing else "")


def _workflow_interceptor(plugin: _Interceptor) -> type[WorkflowInboundInterceptor]:
    gated_names = plugin.gated

    class _Outbound(WorkflowOutboundInterceptor):
        def start_activity(self, input: StartActivityInput) -> workflow.ActivityHandle[Any]:
            if input.activity in gated_names:
                input = dataclasses.replace(input, headers=_gate_headers(input.headers, input.args),
                                            summary=_summary(input.summary, input.activity))
            return super().start_activity(input)

        def start_local_activity(self, input: StartLocalActivityInput) -> workflow.ActivityHandle[Any]:
            if input.activity in gated_names:
                if not plugin.allow_local:
                    raise errors.ProbityWorkflowError(errors.LOCAL_ACTIVITY_BLOCKED,
                                                      f"gated activity {input.activity} run as a local activity")
                input = dataclasses.replace(input, headers=_gate_headers(input.headers, input.args),
                                            summary=_summary(input.summary, input.activity))
            return super().start_local_activity(input)

        async def start_nexus_operation(self, input: StartNexusOperationInput) -> Any:
            name = f"{input.service}/{input.operation}"
            if name in plugin.gated_nexus:
                call = _GATED_CALL.get() or {}
                info = workflow.info()
                try:
                    admit([input.input])
                except NotAdmissible as exc:
                    raise errors.ProbityWorkflowError(errors.ARGS_NOT_ADMISSIBLE, str(exc)) from exc
                headers = {**(input.headers or {}),
                           HEADER_DIGEST: call_sha256(workflow.payload_converter(), [input.input]),
                           HEADER_APPROVALS: json.dumps(call.get("approvals") or []),
                           HEADER_PRINCIPAL: call.get("principal") or _RUN_PRINCIPAL.get(info.run_id, ""),
                           HEADER_CALL: str(call.get("toolCallId", "")),
                           HEADER_WORKFLOW: json.dumps({"workflowId": info.workflow_id, "runId": info.run_id})}
                input = dataclasses.replace(input, headers=headers, summary=_summary(input.summary, name))
            return await super().start_nexus_operation(input)

        def continue_as_new(self, input: ContinueAsNewInput) -> Any:
            principal = _RUN_PRINCIPAL.get(workflow.info().run_id)
            if principal and HEADER_PRINCIPAL not in input.headers:
                input = dataclasses.replace(input, headers={**input.headers, HEADER_PRINCIPAL: _text(principal)})
            return super().continue_as_new(input)

    class _Inbound(WorkflowInboundInterceptor):
        def init(self, outbound: WorkflowOutboundInterceptor) -> None:
            super().init(_Outbound(outbound))

        async def execute_workflow(self, input: ExecuteWorkflowInput) -> Any:
            run_id = workflow.info().run_id
            principal = _read(input.headers, HEADER_PRINCIPAL)
            if principal:
                _RUN_PRINCIPAL[run_id] = principal
            try:
                return await super().execute_workflow(input)
            finally:
                _RUN_PRINCIPAL.pop(run_id, None)

        async def handle_signal(self, input: HandleSignalInput) -> None:
            if plugin.authorized_signals is not None and input.signal not in plugin.authorized_signals:
                if not workflow.unsafe.is_replaying():
                    workflow.logger.warning("probity: dropped unlisted signal")
                return  # dropped, never raised: an outsider must not be able to fail the run
            await super().handle_signal(input)

        def handle_update_validator(self, input: HandleUpdateInput) -> None:
            if plugin.authorized_updates is not None and input.update not in plugin.authorized_updates:
                raise errors.ProbityWorkflowError(errors.UPDATE_NOT_AUTHORIZED, "update not on the allowlist")
            super().handle_update_validator(input)

        async def handle_update_handler(self, input: HandleUpdateInput) -> Any:
            if plugin.authorized_updates is not None and input.update not in plugin.authorized_updates:
                raise errors.ProbityWorkflowError(errors.UPDATE_NOT_AUTHORIZED, "update not on the allowlist")
            return await super().handle_update_handler(input)

    return _Inbound


# ---- telemetry --------------------------------------------------------------------------------
class _Telemetry:
    """A span per decision (OpenTelemetry, when installed) and Temporal-native metrics with bounded
    labels: the tool and a stable code, never free text, never argument values."""

    def __init__(self) -> None:
        try:
            from opentelemetry import trace  # noqa: PLC0415 - optional

            self.tracer = trace.get_tracer("probity_temporal")
        except ImportError:
            self.tracer = None

    @contextmanager
    def span(self, tool: str) -> Iterator[dict[str, Any]]:
        attrs: dict[str, Any] = {"probity.tool": tool}
        if self.tracer is None:
            yield attrs
            return
        with self.tracer.start_as_current_span("probity.authorize") as span:
            yield attrs
            for k, v in attrs.items():
                span.set_attribute(k, v)

    @staticmethod
    def record(tool: str, workflow_type: str, code: str | None, seconds: float) -> None:
        try:
            meter = activity.metric_meter()
        except RuntimeError:
            return
        labels = {"tool": tool, "workflow_type": workflow_type}
        if code is None:
            meter.create_counter("probity_activities_authorized", "gated calls allowed").add(1, labels)
        else:
            meter.create_counter("probity_activities_denied", "gated calls refused").add(1, {**labels, "code": code})
        meter.create_histogram_float("probity_authorization_latency", "authority decision time", "s").record(
            seconds, {"tool": tool})


# ---- activity side ---------------------------------------------------------------------------
def _refusal(decision: Decision) -> ApplicationError:
    code = decision.code or errors.OUTCOME_UNKNOWN
    return errors.refusal(code, decision.reason, outcome=decision.outcome)


class _ActivityInbound(ActivityInboundInterceptor):
    def __init__(self, next: ActivityInboundInterceptor, plugin: _Interceptor) -> None:
        super().__init__(next)
        self.plugin = plugin

    async def execute_activity(self, input: ExecuteActivityInput) -> Any:  # noqa: C901, PLR0912 - the gate sequence
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
                      approvals=_read(input.headers, HEADER_APPROVALS) or [],
                      tool_identity=self.plugin.tool_identities.get(info.activity_type),
                      namespace=info.workflow_namespace, task_queue=info.task_queue)
        telemetry = self.plugin.telemetry
        started = time.perf_counter()
        with telemetry.span(info.activity_type) as attrs:
            if _read(input.headers, HEADER_DIGEST) != req.args_sha256:
                await asyncio.to_thread(authority.refuse, req, "arguments_changed_after_schedule")
                attrs["probity.code"] = errors.ARGS_CHANGED_AFTER_SCHEDULE
                telemetry.record(info.activity_type, info.workflow_type, errors.ARGS_CHANGED_AFTER_SCHEDULE,
                                 time.perf_counter() - started)
                raise errors.refusal(errors.ARGS_CHANGED_AFTER_SCHEDULE, "arguments changed after schedule")
            decision = await asyncio.to_thread(authority.authorize, req)
            attrs["probity.decision"] = "allow" if decision.ok else "deny"
            attrs["probity.code"] = decision.code or "OK"
            telemetry.record(info.activity_type, info.workflow_type, decision.code, time.perf_counter() - started)
        if decision.shadow and decision.permit is None:
            # observe only: the refusal is recorded and the call runs as it would without us. A shadow
            # allow carries a permit and goes on below, so its intent and effect are journalled too.
            return await self.next.execute_activity(input)
        if not decision.ok:
            if decision.outcome == "committed":  # this call already happened: hand back its result
                return decision.result if decision.result is not None else _committed(decision)
            raise _refusal(decision)
        pid = decision.permit_id or ""
        await asyncio.to_thread(authority.intent, req, pid, info.task_token)
        token = _PERMIT.set(decision.permit)
        try:
            result = await self.next.execute_activity(input)
        except NoEffect:
            await asyncio.to_thread(authority.effect, req, pid, "no_effect", None)
            raise
        except activity._CompleteAsyncError:  # noqa: SLF001 - completed later through complete_gated_async
            raise
        except BaseException as exc:
            reply = "timeout" if isinstance(exc, TimeoutError) else "connection_lost"
            outcome, committed = await asyncio.to_thread(authority.effect, req, pid, reply, None)
            if outcome == "committed":
                return committed if committed is not None else _committed(Decision(False, "outcome_committed",
                                                                                   decision.permit, "committed"))
            if outcome == "unknown":
                raise errors.refusal(errors.OUTCOME_UNKNOWN, f"outcome uncertain after {type(exc).__name__}",
                                     outcome="unknown") from exc
            raise
        finally:
            _PERMIT.reset(token)
        digest = hashlib.sha256(converter.to_payloads([result])[0].data).hexdigest()
        await asyncio.to_thread(authority.effect, req, pid, "confirmed", digest)
        return result


def _committed(decision: Decision) -> dict[str, Any]:
    """The typed success a reconciled call returns when its owner cannot hand back the original result."""
    return {"probityOutcome": "committed", "permitId": decision.permit_id, "reconciled": True}


async def complete_gated_async(client: Any, authority: LocalAuthority, task_token: bytes, result: Any) -> None:
    """Complete an activity that called ``activity.raise_complete_async()``: refuse when its permit was
    revoked meanwhile, record the confirmed outcome with the result digest, then complete it."""
    found = authority.operation_for_token(task_token)
    if found is None:
        raise LookupError("no gated operation is open under this task token")
    pid, _ = found
    if authority.is_revoked(pid):
        await client.get_async_activity_handle(task_token=task_token).fail(
            errors.refusal(errors.PERMIT_REVOKED, "permit revoked before async completion"))
        return
    req = authority.request_for(pid)
    digest = hashlib.sha256(client.data_converter.payload_converter.to_payloads([result])[0].data).hexdigest()
    await asyncio.to_thread(authority.effect, req, pid, "confirmed", digest)
    await client.get_async_activity_handle(task_token=task_token).complete(result)


# ---- Nexus ------------------------------------------------------------------------------------
class _NexusInbound(NexusOperationInboundInterceptor):
    def __init__(self, next: NexusOperationInboundInterceptor, plugin: _Interceptor) -> None:
        super().__init__(next)
        self.plugin = plugin

    async def execute_nexus_operation_start(self, input: ExecuteNexusOperationStartInput) -> Any:
        ctx = input.ctx
        name = f"{ctx.service}/{ctx.operation}"
        if name not in self.plugin.gated_nexus:
            return await self.next.execute_nexus_operation_start(input)
        headers = {k.lower(): v for k, v in (ctx.headers or {}).items()}
        values = json_values(PayloadConverter.default, [input.input])
        caller = json.loads(headers.get(HEADER_WORKFLOW, "{}") or "{}")
        req = Request(workflow_id=caller.get("workflowId", ""), run_id=caller.get("runId", ""),
                      activity_id=f"nexus:{ctx.request_id}", activity_type=name, attempt=1, args=values,
                      args_sha256=sha256_hex(canonical(values)), tool_call_id=headers.get(HEADER_CALL, ""),
                      principal=headers.get(HEADER_PRINCIPAL, ""),
                      approvals=json.loads(headers.get(HEADER_APPROVALS, "[]") or "[]"),
                      tool_identity=self.plugin.tool_identities.get(name))
        authority = self.plugin.authority
        if headers.get(HEADER_DIGEST) != req.args_sha256:
            await asyncio.to_thread(authority.refuse, req, "arguments_changed_after_schedule")
            raise errors.refusal(errors.ARGS_CHANGED_AFTER_SCHEDULE, "arguments changed after schedule")
        decision = await asyncio.to_thread(authority.authorize, req)
        if decision.shadow and decision.permit is None:
            return await self.next.execute_nexus_operation_start(input)
        if not decision.ok:
            if decision.outcome == "committed":
                raise errors.refusal(errors.OPERATION_ALREADY_COMMITTED,
                                     "operation already started for this approval", outcome="committed",
                                     permitId=decision.permit_id)
            raise _refusal(decision)
        pid = decision.permit_id or ""
        await asyncio.to_thread(authority.intent, req, pid)
        token = _PERMIT.set(decision.permit)
        try:
            started = await self.next.execute_nexus_operation_start(input)
        except BaseException:
            await asyncio.to_thread(authority.effect, req, pid, "connection_lost", None)
            raise
        finally:
            _PERMIT.reset(token)
        marker = getattr(started, "value", None) if hasattr(started, "value") else getattr(started, "token", None)
        digest = sha256_hex(canonical(json_values(PayloadConverter.default, [marker])))
        await asyncio.to_thread(authority.effect, req, pid, "confirmed", digest)
        return started


# ---- wiring -----------------------------------------------------------------------------------
class _ClientOutbound(ClientOutbound):
    async def start_workflow(self, input: StartWorkflowInput) -> Any:
        principal = _CLIENT_PRINCIPAL.get()
        if principal and HEADER_PRINCIPAL not in (input.headers or {}):
            input.headers = {**(input.headers or {}), HEADER_PRINCIPAL: _text(principal)}
        return await super().start_workflow(input)


class _Interceptor(Interceptor, ClientInterceptor):
    def __init__(self, plugin: ProbityPlugin) -> None:
        self.p = plugin
        self._workflow_class = _workflow_interceptor(self)
        self.telemetry = _Telemetry()

    authority = property(lambda self: self.p.authority)
    gated = property(lambda self: self.p.gated)
    gated_nexus = property(lambda self: self.p.gated_nexus)
    tool_identities = property(lambda self: self.p.tool_identities)
    authorized_signals = property(lambda self: self.p.authorized_signals)
    authorized_updates = property(lambda self: self.p.authorized_updates)
    allow_local = property(lambda self: self.p.allow_local_activities)

    def intercept_client(self, next: ClientOutbound) -> ClientOutbound:
        return _ClientOutbound(next)

    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:
        if self.authority is None:
            raise RuntimeError("ProbityPlugin on a worker that runs gated activities needs an authority")
        return _ActivityInbound(next, self)

    def intercept_nexus_operation(self, next: NexusOperationInboundInterceptor) -> NexusOperationInboundInterceptor:
        return _NexusInbound(next, self) if self.gated_nexus else next

    def workflow_interceptor_class(self, input: WorkflowInterceptorClassInput) -> type[WorkflowInboundInterceptor]:
        return self._workflow_class


def _runner(existing: Any) -> Any:
    if isinstance(existing, SandboxedWorkflowRunner):
        return dataclasses.replace(existing, restrictions=existing.restrictions.with_passthrough_modules(*PASSTHROUGH))
    return existing


def _activity_name(fn: Any) -> str:
    defn = getattr(fn, "__temporal_activity_definition", None)
    return defn.name if defn is not None and defn.name else getattr(fn, "__name__", str(fn))


class ProbityPlugin(SimplePlugin):
    """``Worker(..., plugins=[ProbityPlugin(authority, gated_activities=[refund_payment])])``.

    ``gated_activities`` takes names or activity functions; activities marked ``@gated`` are found
    among the worker's own. A gated name the worker does not register refuses the worker, so a typo
    can never leave a call ungated. Pass ``authority=None`` on a Replayer or a client-only plugin.
    """

    def __init__(self, authority: LocalAuthority | None, gated_activities: Iterable[Any] = (), *,
                 gated_nexus_operations: Iterable[str] = (), tool_identities: Mapping[str, str] | None = None,
                 authorized_signals: Iterable[str] | None = None, authorized_updates: Iterable[str] | None = None,
                 allow_local_activities: bool = False) -> None:
        self.authority = authority
        self.gated = frozenset(n if isinstance(n, str) else _activity_name(n) for n in gated_activities)
        self.gated_nexus = frozenset(gated_nexus_operations)
        self.tool_identities = dict(tool_identities or {})
        self.authorized_signals = None if authorized_signals is None else frozenset(authorized_signals)
        self.authorized_updates = None if authorized_updates is None else frozenset(authorized_updates)
        for label, allow in (("authorized_signals", self.authorized_signals),
                             ("authorized_updates", self.authorized_updates)):
            if allow is not None and not allow:
                raise ValueError(f"{label} is empty; pass None to allow every name")
        self.allow_local_activities = allow_local_activities
        self._configured = False
        super().__init__("probity.ProbityPlugin", interceptors=[_Interceptor(self)], workflow_runner=_runner,
                         workflow_failure_exception_types=[errors.ProbityWorkflowError])

    def configure_worker(self, config: Any) -> Any:
        if self._configured:
            raise RuntimeError("one ProbityPlugin instance per worker; build another for this worker")
        self._configured = True
        registered = {_activity_name(fn): fn for fn in config.get("activities") or []}
        self.gated = self.gated | {n for n, fn in registered.items() if getattr(fn, GATED_ATTR, False)}
        missing = sorted(self.gated - set(registered)) if registered or self.gated else []
        if missing and registered:
            raise ValueError(f"gated activities not registered on this worker: {missing}")
        return super().configure_worker(config)
