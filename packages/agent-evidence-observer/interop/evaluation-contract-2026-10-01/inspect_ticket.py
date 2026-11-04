"""Join native Inspect calls to selected AAE authority and HTTP ticket effects.

Controlled mock outputs exercise the real framework and service. A selected
pre-run plan and retained native bytes are trust inputs, not independent custody.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import uuid
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from evaluation_contract import decode, encode, require
from inspect_ticket_reader import (
    CASES,
    INSPECT_VERSION,
    PROFILE,
    SOURCE_FILES,
    read,
    sha,
    verify_saved,
)
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.aae_ticket import AaeTicketStore
from probity_observer.aae_ticket_records import (
    ticket_transaction,
)
from probity_observer.authorization import issue_grant
from probity_observer.crypto import SigningKey, VerificationError, canonical
from probity_observer.grant_records import (
    ActionRequest,
    GrantPolicy,
    utc_clock,
)
from probity_observer.ticket_service import running_server
from probity_observer.ticket_state import MAX_BODY

def write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def http_bytes(url: str, raw: bytes | None = None) -> tuple[int, bytes]:
    request = Request(url, data=raw, headers={"Content-Type": "application/json"})
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        value = response.read(MAX_BODY + 1)
        require(len(value) <= MAX_BODY, "ticket_http_size")
        return response.code, value


def sources() -> dict[str, bytes]:
    import inspect_ai
    root = Path(__file__).resolve().parents[2]
    own = {name: (root / name).read_bytes() for name in SOURCE_FILES}
    installed = Path(inspect_ai.__file__).parent
    for name in ("_eval/eval.py", "agent/_react.py", "model/_providers/mockllm.py", "scorer/_match.py", "tool/_tool.py"):
        own["inspect/" + name] = (installed / name).read_bytes()
    distribution = importlib.metadata.distribution("inspect-ai")
    own["inspect/METADATA"] = distribution.read_text("METADATA").encode()
    own["inspect/LICENSE"] = Path(distribution.locate_file(f"inspect_ai-{INSPECT_VERSION}.dist-info/licenses/LICENSE")).read_bytes()
    own["inspect/runtime-files.json"] = encode({str(p.relative_to(installed)): sha(p.read_bytes()) for p in sorted(installed.rglob("*.py"))})
    return own


def prepare(output: Path, source_revision: str) -> tuple[dict, dict]:
    """Select all public authority inputs and source bytes before native calls."""
    output.mkdir(parents=True, exist_ok=False)
    require(importlib.metadata.version("inspect-ai") == INSPECT_VERSION, "ticket_inspect_version")
    run_id = "inspect-ticket-" + uuid.uuid4().hex
    now = utc_clock()
    hosts, cases = {}, []
    for name, disposition, final, target, launch, interrupt in CASES:
        folder = output / "stores" / name
        folder.mkdir(parents=True)
        issuer, key = SigningKey.generate(), SigningKey.generate()
        content = b'{"status":"DONE"}'
        request = ActionRequest(run_id, name, "request-" + name, "tenant", "principal", "ticket-update", "/work/tickets/" + name, sha(content))
        transaction = ticket_transaction(request)
        mandate = {"grants": [{"action_binding": native_digest("action", transaction["action"]), "type_fields": ["verb", "targetKind"], "disposition": disposition, "constraints": [{"type": "exact", "field": field, "value": value} for field, value in transaction.items() if field != "action"]}]}
        decision = {"mandate": mandate, "transaction": transaction, "record": enforce_check(mandate, transaction), "pinned_mandate_digest": native_digest("mandate", mandate)}
        policy = GrantPolicy(issuer.public_hex, max_validity_seconds=3600)
        grant = issue_grant(request, issuer, issued_at=now, expires_at=now + timedelta(seconds=3600))
        def fault(point: str, interrupted: bool = interrupt) -> None:
            if interrupted and point == "after-intent":
                raise VerificationError("declared interruption after durable intent")
        store = AaeTicketStore(folder / "store.sqlite", request, policy, key, crash_hook=fault, **decision)
        initial = store.initialize()
        case = {"id": name, "launch": launch, "final": final, "target": target, "interruptAfterIntent": interrupt, "request": asdict(request), "policy": asdict(policy), "serviceKey": key.public_hex, "grant": grant, "contentHex": content.hex(), "decision": decision, "configuration": store.configuration, "initial": initial}
        hosts[name] = store
        cases.append(case)
    retained = sources()
    for name, raw in retained.items():
        write(output / "sources" / name, raw)
    source_manifest = {name: sha(raw) for name, raw in retained.items()}
    write(output / "source-manifest-before-run.json", encode(source_manifest))
    plan = {"profile": PROFILE, "runId": run_id, "sourceRevision": source_revision, "sourceManifestSha256": sha(encode(source_manifest)), "inspectVersion": INSPECT_VERSION, "selectedTime": now.isoformat(), "input": "Run the one selected ticket dispatch.", "cases": cases}
    write(output / "plan-before-run.json", encode(plan))
    return plan, hosts


def execute(output: Path, plan: dict, case: dict, store: AaeTicketStore) -> dict:
    """Run real ReAct; its registered tool performs one native HTTP request."""
    import inspect_ai
    from inspect_ai.agent import react
    from inspect_ai.dataset import Sample
    from inspect_ai.model import (
        ChatMessageAssistant,
        ModelOutput,
        ModelUsage,
        get_model,
    )
    from inspect_ai.scorer import match
    from inspect_ai.tool import ToolCall, tool

    with running_server(store) as server:
        @tool
        def dispatch_ticket():
            async def dispatch(content: str) -> str:
                """Dispatch the exact selected ticket update.

                Args:
                    content: Literal selected status, DONE.
                """
                require(content == "DONE", "ticket_native_tool_argument")
                request_raw = canonical({"request": case["request"], "grant": case["grant"], "contentHex": case["contentHex"]})
                status, response = http_bytes(server.url + "/dispatch", request_raw)
                read_status, readback = http_bytes(server.url + "/tickets/tenant/" + case["id"])
                packet = {"endpoint": server.url, "postPath": "/dispatch", "getPath": "/tickets/tenant/" + case["id"], "postRequestHex": request_raw.hex(), "postStatus": status, "postResponseHex": response.hex(), "getStatus": read_status, "getResponseHex": readback.hex()}
                packet_raw = encode(packet)
                write(output / "artifacts" / (case["id"] + "-http.json"), packet_raw)
                return canonical({"httpSha256": sha(packet_raw), "postStatus": status, "nativeRevision": decode(readback)["revision"]}).decode()
            return dispatch
        outputs = [ModelOutput.from_message(ChatMessageAssistant(content="", tool_calls=[ToolCall(id="call-" + case["id"], function="dispatch_ticket", arguments={"content": "DONE"})]), stop_reason="tool_calls")]
        if case["final"] is not None:
            outputs.append(ModelOutput.from_content(model="mockllm", content=case["final"]))
        for item in outputs:
            item.usage = ModelUsage(input_tokens=0, output_tokens=0, total_tokens=0)
        model = get_model("mockllm/model", custom_outputs=outputs)
        task = inspect_ai.Task(dataset=[Sample(id=case["id"], input=plan["input"], target=case["target"])], solver=react(tools=[dispatch_ticket()], submit=False), scorer=match(), name=case["id"], version=1, message_limit=12, metadata={"probity_ticket_profile": PROFILE, "probity_plan_sha256": sha(encode(plan))})
        log_dir = output / "native" / case["id"]
        inspect_ai.eval(task, model=model, display="none", log_format="json", log_dir=str(log_dir), epochs=1, retry_on_error=0, max_samples=1, fail_on_error=True)
    files = list(log_dir.glob("*.json"))
    require(len(files) == 1, "ticket_native_log_population")
    raw = files[0].read_bytes()
    write(output / "artifacts" / (case["id"] + "-native.json"), raw)
    native = decode(raw)
    return {"sha256": sha(raw), "runId": native["eval"]["run_id"], "evalId": native["eval"]["eval_id"]}


def run(output: Path, source_revision: str = "working-tree") -> dict:
    plan, hosts = prepare(output, source_revision)
    bindings = {}
    for case in plan["cases"]:
        if case["launch"]:
            bindings[case["id"]] = execute(output, plan, case, hosts[case["id"]])
    manifest = {"bindings": bindings, "artifacts": {p.name: sha(p.read_bytes()) for p in (output / "artifacts").iterdir()}}
    write(output / "artifact-manifest.json", encode(manifest))
    selected = {"planSha256": sha(read(output, "plan-before-run.json")), "sourceManifestSha256": sha(read(output, "source-manifest-before-run.json")), "artifactManifestSha256": sha(encode(manifest)), "evaluationTime": utc_clock().isoformat()}
    write(output / "consumer-pins.json", encode(selected))
    report = verify_saved(output, selected)
    write(output / "report.json", encode(report))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-revision", default="working-tree")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--pins-file", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.pins_file is None:
            parser.error("--verify requires externally selected --pins-file")
        result = verify_saved(args.output, decode(args.pins_file.read_bytes()))
    else:
        if args.pins_file is not None:
            parser.error("--pins-file requires --verify")
        result = run(args.output, args.source_revision)
    print(json.dumps(result, indent=2))
