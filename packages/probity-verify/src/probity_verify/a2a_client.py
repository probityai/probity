"""Official-SDK client for the optional Verify A2A service."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import (
    GetTaskRequest, Message, Part, Role, SendMessageConfiguration,
    SendMessageRequest, TaskState,
)
from a2a.utils.errors import A2AError
from google.protobuf.json_format import MessageToDict

from .a2a_server import (
    CASE_MIME, DECISION_MIME, LAB_QUERY_MIME, LAB_RECORD_MIME, MAX_CASE_BYTES,
    digest, parse_raw, read_bounded,
)
from .core import CaseError, canonical_json


async def request(base_url: str, raw: bytes, mime: str, pin: str) -> tuple[bytes, str]:
    if not raw or len(raw) > MAX_CASE_BYTES:
        raise CaseError("request bytes exceed the input limit")
    expected_mime = DECISION_MIME if mime == CASE_MIME else LAB_RECORD_MIME
    pin_name = "policy_sha256" if mime == CASE_MIME else "register_sha256"
    origin = urlsplit(base_url)
    if (origin.scheme not in {"http", "https"} or not origin.netloc or origin.path not in {"", "/"}
            or origin.username or origin.password or origin.query or origin.fragment):
        raise CaseError("base URL must be an HTTP origin")
    use_environment = origin.hostname not in {"127.0.0.1", "::1", "localhost"}
    async with httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=use_environment) as http:
        card = await A2ACardResolver(http, base_url).get_agent_card()
        interfaces = [i for i in card.supported_interfaces
                      if i.protocol_binding == "JSONRPC" and i.protocol_version == "1.0"]
        if (len(interfaces) != 1 or urlsplit(interfaces[0].url).scheme != origin.scheme
                or urlsplit(interfaces[0].url).netloc != origin.netloc
                or urlsplit(interfaces[0].url).path != "/a2a/jsonrpc"):
            raise CaseError("agent card must name its own A2A 1.0 JSON-RPC route")
        client = ClientFactory(ClientConfig(streaming=False, httpx_client=http,
                                            supported_protocol_bindings=["JSONRPC"])).create(card)
        message = Message(message_id=str(uuid4()), role=Role.ROLE_USER,
                          parts=[Part(raw=raw, media_type=mime, metadata={
                              "length": len(raw), "sha256": digest(raw), pin_name: pin})])
        task = None
        try:
            async for response in client.send_message(SendMessageRequest(
                    message=message, configuration=SendMessageConfiguration(return_immediately=False))):
                if response.HasField("task"):
                    task = response.task
            if task is None or task.status.state != TaskState.TASK_STATE_COMPLETED:
                raise CaseError("A2A request did not complete")
            retained = await client.get_task(GetTaskRequest(id=task.id))
            if retained != task:
                raise CaseError("retained task differs from the completed response")
            parts = [part for artifact in task.artifacts for part in artifact.parts
                     if part.media_type == expected_mime]
            if len(parts) != 1 or parts[0].WhichOneof("content") != "raw":
                raise CaseError("expected one raw result artifact")
            result = parts[0].raw
            metadata = MessageToDict(parts[0].metadata)
            if (metadata.get("sha256") != digest(result) or metadata.get("length") != len(result)
                    or metadata.get(pin_name) != pin):
                raise CaseError("result binding differs")
            if mime == CASE_MIME and metadata.get("case_sha256") != digest(raw):
                raise CaseError("result case binding differs")
            parse_raw(result)
            return result, task.id
        finally:
            await client.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probity-a2a-client")
    parser.add_argument("--url", default="http://127.0.0.1:41241")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("case", type=Path)
    verify.add_argument("--policy", type=Path, required=True)
    lab = commands.add_parser("lab-record")
    lab.add_argument("record_id")
    lab.add_argument("--register-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            raw = read_bounded(args.case, MAX_CASE_BYTES)
            policy = parse_raw(read_bounded(args.policy, 4 * 1024 * 1024))
            pin = digest(canonical_json(policy))
            mime = CASE_MIME
        else:
            raw = canonical_json({"record_id": args.record_id})
            pin = args.register_sha256
            mime = LAB_QUERY_MIME
        result, _ = asyncio.run(request(args.url, raw, mime, pin))
    except (CaseError, ValueError, OSError, RecursionError, httpx.InvalidURL,
            httpx.HTTPError, A2AError) as exc:
        print(f"probity-a2a-client: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
