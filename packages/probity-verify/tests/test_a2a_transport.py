"""Run an actual loopback HTTP server and the official SDK client."""

import asyncio
import json
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

pytest.importorskip("a2a")
import httpx
import uvicorn
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.server.context import ServerCallContext
from a2a.types import Message, Part, Role, SendMessageRequest, Task, TaskState, TaskStatus
from a2a.utils.errors import InvalidParamsError

from probity_verify.a2a_client import request
from probity_verify import a2a_client
from probity_verify.a2a_server import (
    CASE_MIME, LAB_QUERY_MIME, MAX_CASE_BYTES, MAX_REQUEST_BYTES,
    BoundedTaskStore, VerifyExecutor, create_app, digest, parse_raw,
)
from probity_verify.core import CaseError, adjudicate, canonical_json

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples/source-coverage"


def test_client_command_binds_exact_policy_and_case(monkeypatch, capsys):
    captured = []
    answer = b'{"retained":"decision"}\n'

    async def transport(url, raw, mime, pin):
        captured.append((url, raw, mime, pin))
        return answer, "retained-task"

    monkeypatch.setattr(a2a_client, "request", transport)
    assert a2a_client.main(["verify", str(SOURCE / "case.json"), "--policy",
                            str(SOURCE / "policy-june.json")]) == 0
    assert capsys.readouterr().out.encode() == answer
    url, raw, mime, pin = captured[0]
    assert url == "http://127.0.0.1:41241"
    assert raw == (SOURCE / "case.json").read_bytes()
    assert mime == CASE_MIME
    assert pin == digest(canonical_json(parse_raw((SOURCE / "policy-june.json").read_bytes())))
    assert a2a_client.main(["lab-record", "record-42", "--register-sha256", "a" * 64]) == 0
    assert capsys.readouterr().out.encode() == answer
    assert captured[1][1:] == (canonical_json({"record_id": "record-42"}), LAB_QUERY_MIME, "a" * 64)


def test_client_command_connection_failure_has_no_verdict(monkeypatch, capsys):
    async def failed(*args):
        raise httpx.ConnectError("selected server is unavailable")

    monkeypatch.setattr(a2a_client, "request", failed)
    assert a2a_client.main(["lab-record", "record-42", "--register-sha256", "a" * 64]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "selected server is unavailable" in captured.err


@contextmanager
def server(policy, root, register=None):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    pin = digest(register) if register is not None else None
    app = create_app(policy, root, url, register, pin)
    running = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    thread = threading.Thread(target=running.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not running.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert running.started, "loopback server did not start"
        yield url
    finally:
        running.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive(), "loopback server did not stop"


@pytest.mark.parametrize("directory,case_name,policy_name", [
    ("source-coverage", "case.json", "policy-june.json"),
    ("source-coverage", "case-complete.json", "policy-complete.json"),
    ("source-coverage", "case.json", "policy-april.json"),
    ("operand-lineage", "case.json", "policy.json"),
    ("authority-anchor", "case.json", "policy.json"),
    ("event-absence", "case.json", "policy.json"),
    ("spend-reservation/accepted", "case.json", "policy.json"),
    ("spend-reservation/pending", "case.json", "policy.json"),
    ("spend-reservation/refused-overshoot", "case.json", "policy.json"),
    ("brokered-file-write/recorded", "case.json", "policy.json"),
    ("brokered-file-write/false-negative", "case.json", "policy.json"),
    ("brokered-file-write/missing-terminal", "case.json", "policy.json"),
])
def test_native_decision_bytes_and_retained_task(directory, case_name, policy_name):
    root = ROOT / "examples" / directory
    raw = (root / case_name).read_bytes()
    policy = (root / policy_name).read_bytes()
    expected = canonical_json(adjudicate(parse_raw(raw), parse_raw(policy), root))
    with server(policy, root) as url:
        result, task_id = asyncio.run(request(url, raw, CASE_MIME,
                                             digest(canonical_json(parse_raw(policy)))))
        assert result == expected
        assert task_id


@pytest.fixture
def configured():
    policy = (SOURCE / "policy-june.json").read_bytes()
    with server(policy, SOURCE) as url:
        yield url, digest(canonical_json(parse_raw(policy)))


@pytest.mark.parametrize("raw", [
    b'{"case_id":"source-coverage-demo","case_id":"source-coverage-demo"}',
    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
    b'{"case_id":"unknown"}', b'[]', b'{', b'\xff',
])
def test_malformed_case_is_protocol_error_without_verdict(configured, raw):
    url, pin = configured
    with pytest.raises(InvalidParamsError) as error:
        asyncio.run(request(url, raw, CASE_MIME, pin))
    assert "not_established" not in str(error.value)


def test_policy_mismatch_is_error_without_verdict(configured):
    url, _ = configured
    with pytest.raises(InvalidParamsError) as error:
        asyncio.run(request(url, (SOURCE / "case.json").read_bytes(), CASE_MIME, "0" * 64))
    assert "consumer policy digest differs" in str(error.value)
    assert "not_established" not in str(error.value)


async def send_parts(url, parts):
    async with httpx.AsyncClient(trust_env=False) as http:
        card = await A2ACardResolver(http, url).get_agent_card()
        client = ClientFactory(ClientConfig(streaming=False, httpx_client=http)).create(card)
        try:
            async for response in client.send_message(SendMessageRequest(message=Message(
                    message_id="malformed-part", role=Role.ROLE_USER, parts=parts))):
                pytest.fail(f"malformed input returned a result: {response}")
        finally:
            await client.close()


@pytest.mark.parametrize("kind", ["uri", "multiple", "extra-metadata", "wrong-length", "wrong-hash"])
def test_request_cannot_select_paths_or_rewrite_bindings(configured, kind):
    url, pin = configured
    raw = (SOURCE / "case.json").read_bytes()
    metadata = {"sha256": digest(raw), "length": len(raw), "policy_sha256": pin}
    if kind == "uri":
        parts = [Part(url="https://example.org/case.json", media_type=CASE_MIME)]
    else:
        if kind == "extra-metadata":
            metadata["artifact_root"] = "/tmp/other"
        if kind == "wrong-length":
            metadata["length"] += 1
        if kind == "wrong-hash":
            metadata["sha256"] = "0" * 64
        parts = [Part(raw=raw, media_type=CASE_MIME, metadata=metadata)]
        if kind == "multiple":
            parts *= 2
    with pytest.raises(InvalidParamsError):
        asyncio.run(send_parts(url, parts))


def test_http_duplicate_keys_and_request_limit(configured):
    url, _ = configured
    duplicate = httpx.post(url + "/a2a/jsonrpc", content=b'{"id":1,"id":2}', trust_env=False)
    assert duplicate.json()["error"]["code"] == -32600
    assert "duplicate JSON key" in duplicate.json()["error"]["message"]
    oversized = httpx.post(url + "/a2a/jsonrpc", content=b" " * (MAX_REQUEST_BYTES + 1), trust_env=False)
    assert oversized.status_code == 413


def test_client_case_limit(configured):
    url, pin = configured
    with pytest.raises(CaseError, match="input limit"):
        asyncio.run(request(url, b"x" * (MAX_CASE_BYTES + 1), CASE_MIME, pin))


def test_lab_record_preserves_publisher_and_scope():
    record = {"id": "transport-test", "operator": "fixture author",
              "reviewState": "fixture", "executedScope": "synthetic transport test"}
    register = canonical_json({"records": [record]})
    policy = (SOURCE / "policy-june.json").read_bytes()
    query = canonical_json({"record_id": record["id"]})
    with server(policy, SOURCE, register) as url:
        raw, _ = asyncio.run(request(url, query, LAB_QUERY_MIME, digest(register)))
        assert parse_raw(raw) == {"schema_version": "probity-lab-record/v1",
                                  "register_sha256": digest(register), "record": record}
        with pytest.raises(InvalidParamsError, match="Lab register digest differs"):
            asyncio.run(request(url, query, LAB_QUERY_MIME, "0" * 64))
        with pytest.raises(InvalidParamsError, match="unknown Lab record ID"):
            asyncio.run(request(url, canonical_json({"record_id": "other"}),
                                LAB_QUERY_MIME, digest(register)))


def test_operator_pins_register_before_serving():
    policy = (SOURCE / "policy-june.json").read_bytes()
    register = canonical_json({"records": []})
    with pytest.raises(CaseError, match="operator pin"):
        VerifyExecutor(policy, SOURCE, register, "0" * 64)
    duplicate = canonical_json({"records": [{"id": "same"}, {"id": "same"}]})
    with pytest.raises(CaseError, match="distinct"):
        VerifyExecutor(policy, SOURCE, duplicate, digest(duplicate))


def test_completed_task_retention_is_finite():
    async def retained():
        store = BoundedTaskStore(limit=2)
        context = ServerCallContext()
        for task_id in ("oldest", "middle", "latest"):
            await store.save(Task(id=task_id, context_id="fixture",
                                  status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED)), context)
        assert await store.get("oldest", context) is None
        assert (await store.get("middle", context)).id == "middle"
        assert (await store.get("latest", context)).id == "latest"
    asyncio.run(retained())


def test_card_and_discovery_match_configured_scope(configured):
    url, pin = configured
    card = httpx.get(url + "/.well-known/agent-card.json", trust_env=False).json()
    assert card["supportedInterfaces"] == [{"url": url + "/a2a/jsonrpc",
                                             "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]
    assert [skill["id"] for skill in card["skills"]] == ["verify_case"]
    assert card["defaultInputModes"] == [CASE_MIME]
    assert "application/vnd.probity.lab-record+json" not in card["defaultOutputModes"]
    assert not card.get("capabilities", {}).get("streaming", False)
    assert not card.get("capabilities", {}).get("pushNotifications", False)
    discovery = httpx.get(url + "/llms.txt", trust_env=False).text
    assert pin in discovery and url + "/a2a/jsonrpc" in discovery
    assert "Lab register SHA-256" not in discovery


def test_real_client_cli_and_invalid_server_config(configured):
    url, _ = configured
    result = subprocess.run([sys.executable, "-m", "probity_verify.a2a_client", "--url", url,
                             "verify", str(SOURCE / "case.json"), "--policy",
                             str(SOURCE / "policy-june.json")], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["decision"] == "contradicted"
    bad = subprocess.run([sys.executable, "-m", "probity_verify.a2a_server", "--policy",
                          str(SOURCE / "policy-june.json"), "--artifact-root", str(SOURCE),
                          "--host", "0.0.0.0"], capture_output=True, check=False)
    assert bad.returncode == 2 and not bad.stdout


@pytest.mark.parametrize("kind", ["nested-policy", "invalid-url"])
def test_client_protocol_input_failure_exits_two_without_verdict(tmp_path, kind):
    policy = SOURCE / "policy-june.json"
    url = "http://127.0.0.1:41241"
    if kind == "nested-policy":
        policy = tmp_path / "nested-policy.json"
        policy.write_bytes(b'{"value":' + b"[" * 5000 + b"0" + b"]" * 5000 + b"}")
    else:
        url = "http://127.0.0.1:bad"
    result = subprocess.run([sys.executable, "-m", "probity_verify.a2a_client", "--url", url,
                             "verify", str(SOURCE / "case.json"), "--policy", str(policy)],
                            capture_output=True, check=False)
    assert result.returncode == 2
    assert not result.stdout
    assert result.stderr.startswith(b"probity-a2a-client:")
    assert b"Traceback" not in result.stderr
    assert b"not_established" not in result.stderr
