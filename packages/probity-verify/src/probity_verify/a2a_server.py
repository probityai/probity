"""Optional A2A 1.0 transport for operator-configured Verify and Lab reads."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import ipaddress
import sys
from collections import OrderedDict
from importlib.metadata import version as _distribution_version
from pathlib import Path
from urllib.parse import urlsplit

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Part,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.errors import InvalidParamsError, UnsupportedOperationError
from google.protobuf.json_format import MessageToDict
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from .common import _read_input
from .core import CaseError, adjudicate, canonical_json, render_packet
from .json_input import parse_json


def _package_version() -> str:
    """The installed distribution's version, so the agent card cannot name a stale one."""
    return _distribution_version("probity-verify")


CASE_MIME = "application/vnd.probity.case+json"
DECISION_MIME = "application/vnd.probity.decision+json"
LAB_QUERY_MIME = "application/vnd.probity.lab-query+json"
LAB_RECORD_MIME = "application/vnd.probity.lab-record+json"
MAX_CASE_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 384 * 1024
MAX_RETAINED_TASKS = 128


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_raw(raw: bytes) -> object:
    """Use bounded duplicate-key and non-JSON-number admission rules."""
    return parse_json(raw, max_bytes=16 * 1024 * 1024, max_depth=32, max_nodes=32768)


def read_bounded(path: Path, limit: int) -> bytes:
    return _read_input(path, limit, "configured input")


class BoundedTaskStore(InMemoryTaskStore):
    """Retain the latest completed tasks through the SDK's public store API."""

    def __init__(self, limit: int = MAX_RETAINED_TASKS) -> None:
        super().__init__()
        if limit < 1:
            raise ValueError("task retention limit must be positive")
        self.limit = limit
        self.completed = OrderedDict()
        self.retention_lock = asyncio.Lock()

    async def save(self, task, context) -> None:
        async with self.retention_lock:
            await super().save(task, context)
            if task.status.state == TaskState.TASK_STATE_COMPLETED:
                self.completed[task.id] = context
                self.completed.move_to_end(task.id)
                while len(self.completed) > self.limit:
                    expired, owner = self.completed.popitem(last=False)
                    await super().delete(expired, owner)


class VerifyExecutor(AgentExecutor):
    def __init__(self, policy: bytes, artifact_root: Path,
                 lab_register: bytes | None = None,
                 lab_register_sha256: str | None = None) -> None:
        self.policy = parse_raw(policy)
        if not isinstance(self.policy, dict):
            raise CaseError("consumer policy must be a JSON object")
        self.policy_sha256 = digest(canonical_json(self.policy))
        self.policy_source_sha256 = digest(policy)
        self.artifact_root = artifact_root.absolute()
        if not self.artifact_root.is_dir():
            raise CaseError("artifact root must be a directory")
        self.records: dict[str, dict] = {}
        self.lab_register_sha256 = None
        if lab_register is not None:
            if digest(lab_register) != lab_register_sha256:
                raise CaseError("Lab register digest differs from the operator pin")
            register = parse_raw(lab_register)
            if not isinstance(register, dict) or not isinstance(register.get("records"), list):
                raise CaseError("Lab register must contain records")
            for record in register["records"]:
                if (not isinstance(record, dict) or not isinstance(record.get("id"), str)
                        or not record["id"] or record["id"] in self.records):
                    raise CaseError("Lab record IDs must be distinct non-empty strings")
                self.records[record["id"]] = record
            self.lab_register_sha256 = lab_register_sha256
        elif lab_register_sha256 is not None:
            raise CaseError("Lab register pin needs a configured register")
        self.capacity = asyncio.Semaphore(4)

    def assess(self, part: Part) -> tuple[bytes, str, dict, str | None]:
        if part.WhichOneof("content") != "raw" or not part.raw or len(part.raw) > MAX_CASE_BYTES:
            raise CaseError("supply one bounded raw JSON part")
        metadata = MessageToDict(part.metadata)
        raw_hash = digest(part.raw)
        expected = {"sha256", "length", "policy_sha256" if part.media_type == CASE_MIME
                    else "register_sha256"}
        if (set(metadata) != expected or metadata.get("sha256") != raw_hash
                or isinstance(metadata.get("length"), bool)
                or metadata.get("length") != len(part.raw)):
            raise CaseError("raw part binding is missing or differs")
        value = parse_raw(part.raw)
        if part.media_type == CASE_MIME:
            if metadata["policy_sha256"] != self.policy_sha256:
                raise CaseError("consumer policy digest differs")
            result = adjudicate(value, copy.deepcopy(self.policy), self.artifact_root)
            bindings = {"case_sha256": raw_hash, "policy_sha256": self.policy_sha256,
                        "policy_source_sha256": self.policy_source_sha256}
            return canonical_json(result), DECISION_MIME, bindings, render_packet(result)
        if part.media_type == LAB_QUERY_MIME:
            if (not self.lab_register_sha256
                    or metadata["register_sha256"] != self.lab_register_sha256):
                raise CaseError("Lab register digest differs")
            if (not isinstance(value, dict) or set(value) != {"record_id"}
                    or not isinstance(value["record_id"], str)
                    or value["record_id"] not in self.records):
                raise CaseError("unknown Lab record ID")
            result = {"schema_version": "probity-lab-record/v1",
                      "register_sha256": self.lab_register_sha256,
                      "record": self.records[value["record_id"]]}
            return canonical_json(result), LAB_RECORD_MIME, {
                "register_sha256": self.lab_register_sha256}, None
        raise CaseError("unsupported input media type")

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = context.message
        if (not message or len(message.parts) != 1
                or not context.task_id or not context.context_id):
            raise InvalidParamsError(message="Supply a new request with one raw JSON part")
        try:
            async with self.capacity:
                raw, mime, bindings, packet = await asyncio.to_thread(self.assess, message.parts[0])
        except (CaseError, ValueError, OSError, RecursionError) as exc:
            raise InvalidParamsError(message=str(exc)) from exc
        await event_queue.enqueue_event(Task(
            id=context.task_id, context_id=context.context_id,
            status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED), history=[message]))
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        parts = [Part(raw=raw, media_type=mime,
                      metadata={**bindings, "sha256": digest(raw), "length": len(raw)})]
        if packet is not None:
            parts.append(Part(text=packet, media_type="text/plain"))
        await updater.add_artifact(parts, name="probity-result", last_chunk=True)
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise UnsupportedOperationError(message="Assessments complete in one request")


class BoundedJSON:
    """Admit bounded raw HTTP JSON before the SDK's protocol parsing."""

    def __init__(self, app: Starlette) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            event = await receive()
            if event["type"] == "http.disconnect":
                return
            body.extend(event.get("body", b""))
            if len(body) > MAX_REQUEST_BYTES:
                response = JSONResponse({"error": "request exceeds the byte limit"}, status_code=413)
                await response(scope, receive, send)
                return
            if not event.get("more_body", False):
                break
        try:
            value = parse_raw(bytes(body))
        except (CaseError, ValueError, RecursionError) as exc:
            response = JSONResponse({"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32600, "message": str(exc)}})
            await response(scope, receive, send)
            return
        if isinstance(value, dict) and isinstance(value.get("params"), dict):
            message = value["params"].get("message")
            if isinstance(message, dict) and (message.get("taskId") or message.get("task_id")):
                response = JSONResponse({"jsonrpc": "2.0", "id": value.get("id"),
                                         "error": {"code": -32602,
                                                   "message": "Supply a new assessment request"}})
                await response(scope, receive, send)
                return

        async def replay():
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)


def create_app(policy: bytes, artifact_root: Path, base_url: str,
               lab_register: bytes | None = None,
               lab_register_sha256: str | None = None):
    url = urlsplit(base_url)
    if url.scheme not in {"http", "https"} or not url.netloc or url.path not in {"", "/"}:
        raise CaseError("base URL must be an HTTP origin")
    if url.username or url.password or url.query or url.fragment:
        raise CaseError("base URL must be an HTTP origin")
    base_url = base_url.rstrip("/")
    executor = VerifyExecutor(policy, artifact_root, lab_register, lab_register_sha256)
    skills = [AgentSkill(id="verify_case", name="Verify a pinned case",
                        description="Assess raw case bytes against operator-held policy and artifacts.",
                        tags=["evidence", "verification"], input_modes=[CASE_MIME],
                        output_modes=[DECISION_MIME, "text/plain"])]
    if executor.lab_register_sha256:
        skills.append(AgentSkill(id="read_lab_record", name="Read a pinned Lab record",
                                 description="Return one retained publisher record from the configured register.",
                                 tags=["evidence", "research"], input_modes=[LAB_QUERY_MIME],
                                 output_modes=[LAB_RECORD_MIME]))
    card = AgentCard(name="Probity Verify", version=_package_version(),
                     description="Consumer-policy assessments and pinned Lab record reads.",
                     documentation_url="https://github.com/probityai/probity/blob/main/packages/probity-verify/docs/a2a.md",
                     capabilities=AgentCapabilities(streaming=False, push_notifications=False),
                     default_input_modes=[skill.input_modes[0] for skill in skills],
                     default_output_modes=list(dict.fromkeys(mode for skill in skills
                                                              for mode in skill.output_modes)), skills=skills,
                     supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", protocol_version="1.0",
                                                           url=base_url + "/a2a/jsonrpc")])
    handler = DefaultRequestHandler(executor, BoundedTaskStore(), card)
    discovery = ("# Probity Verify\n\nA2A 1.0 JSON-RPC.\n"
                 f"Agent card: {base_url}/.well-known/agent-card.json\n"
                 f"POST: {base_url}/a2a/jsonrpc\n"
                 f"Consumer policy SHA-256: {executor.policy_sha256}\n"
                 f"Policy source SHA-256: {executor.policy_source_sha256}\n"
                 "Send raw JSON case bytes with length, SHA-256 and consumer policy digest.\n"
                 "Results are byte-bound Verify decision packets. The latest 128 tasks last for this process.\n")
    if executor.lab_register_sha256:
        discovery += f"Lab register SHA-256: {executor.lab_register_sha256}\n"

    async def llms(request):
        return PlainTextResponse(discovery)

    routes = create_agent_card_routes(card) + create_jsonrpc_routes(handler, "/a2a/jsonrpc")
    routes.append(Route("/llms.txt", llms))
    return BoundedJSON(Starlette(routes=routes))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probity-a2a")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--lab-register", type=Path)
    parser.add_argument("--lab-register-sha256")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=41241)
    args = parser.parse_args(argv)
    try:
        if not ipaddress.ip_address(args.host).is_loopback or not 1 <= args.port <= 65535:
            raise CaseError("bind to a loopback address and a valid port")
        origin = f"http://[{args.host}]:{args.port}" if ":" in args.host else f"http://{args.host}:{args.port}"
        app = create_app(read_bounded(args.policy, 4 * 1024 * 1024), args.artifact_root, origin,
                         read_bounded(args.lab_register, 16 * 1024 * 1024) if args.lab_register else None,
                         args.lab_register_sha256)
    except (CaseError, ValueError, OSError, RecursionError) as exc:
        print(f"probity-a2a: {exc}", file=sys.stderr)
        return 2
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, access_log=False, limit_concurrency=16)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
