"""Offline reader for the joined native Inspect, AAE authority and ticket-effect packet.

Controlled mock outputs exercised the real framework and service. A selected
pre-run plan and retained native bytes are trust inputs, not independent custody.
The producing operation is run by the operator's runtime; this module only reads
and verifies what it retained.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

from evaluation_contract import decode, encode, require, withheld_for
from probity_observer.aae_enforce import enforce_check, native_digest
from probity_observer.aae_ticket_records import (
    ticket_transaction,
    verify_aae_ticket_result,
)
from probity_observer.crypto import canonical
from probity_observer.crypto import digest as domain_digest
from probity_observer.grant_records import ActionRequest, GrantPolicy, verify_grant
from probity_observer.ticket_state import DOMAIN, checked_record, state_schema

PROFILE = "probity-inspect-aae-ticket-v0"
INSPECT_VERSION = "0.3.281"
CASES = (
    ("permit-pass", "allow", "DONE", "DONE", True, False),
    ("permit-task-fail", "allow", "wrong", "DONE", True, False),
    ("kernel-deny", "forbid", "DENIED", "DENIED", True, False),
    ("pending-effect", "allow", "INCOMPLETE", "INCOMPLETE", True, True),
    ("model-error-after-effect", "allow", None, "DONE", True, False),
    ("planned-unstarted", "allow", "DONE", "DONE", False, False),
)
SOURCE_FILES = (
    "interop/evaluation-contract-2026-10-01/inspect_ticket.py",
    "interop/evaluation-contract-2026-10-01/evaluation_contract.py",
    "src/probity_observer/aae_ticket.py", "src/probity_observer/aae_enforce.py",
    "src/probity_observer/ticket_service.py", "src/probity_observer/authorization.py",
    "src/probity_observer/crypto.py", "tests/fixtures/aae-enforce/source-manifest.json",
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read(root: Path, name: str) -> bytes:
    path = root / name
    cursor = path
    while cursor != root.parent:
        require(not cursor.is_symlink(), "ticket_packet_symlink")
        if cursor == root:
            break
        cursor = cursor.parent
    require(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink(), "ticket_packet_path")
    with path.open("rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "ticket_packet_size")
    return raw

def check_sources(output: Path, manifest: dict, withheld: dict) -> None:
    """Match the embedded sources to the manifest; an omitted file needs its exact digest."""
    names = set(SOURCE_FILES) | {"inspect/" + n for n in ("_eval/eval.py", "agent/_react.py", "model/_providers/mockllm.py", "scorer/_match.py", "tool/_tool.py", "METADATA", "LICENSE", "runtime-files.json")}
    require(set(manifest) == names, "ticket_source_population")
    present = {str(p.relative_to(output / "sources")) for p in (output / "sources").rglob("*") if p.is_file()}
    omitted = {name.removeprefix("sources/"): pin for name, pin in withheld.items()}
    require(present | set(omitted) == names, "ticket_source_population")
    for name in sorted(names - present):
        require(omitted[name] == manifest[name], "ticket_source_pin")
    for name in sorted(present):
        require(sha(read(output / "sources", name)) == manifest[name], "ticket_source_pin")


def signed_state(case: dict, snapshot: dict) -> dict:
    """Authenticate a native snapshot under the selected service configuration."""
    require(set(snapshot) == {"tenantId", "ticketId", "contentHex", "revision", "effectId", "receipt"}, "ticket_snapshot_fields")
    state = checked_record(snapshot["receipt"], case["serviceKey"])
    state_schema(state, receipt=True)
    require(snapshot["tenantId"] == "tenant" and snapshot["ticketId"] == case["id"], "ticket_snapshot_identity")
    require(state["request"] == case["request"] and state["authorityKey"] == case["policy"]["issuer_key"], "ticket_snapshot_request")
    require(state["configuration"] == domain_digest(DOMAIN + "-configuration", case["configuration"]), "ticket_snapshot_configuration")
    require(type(snapshot["revision"]) is int and snapshot["revision"] == state["revision"] and snapshot["effectId"] == state["effectId"], "ticket_snapshot_relation")
    require(state["witnessScope"] == "PEER" and state["coverage"] == "one-native-ticket-row-and-service-events", "ticket_snapshot_scope")
    if state["revision"] == 0:
        require(snapshot["contentHex"] is None, "ticket_snapshot_zero_content")
    return state


def _same(actual: object, expected: object, reason: str) -> None:
    require(encode(actual) == encode(expected), reason)


def native_sample(raw: bytes, selected: dict, plan: dict, case: dict, packet_raw: bytes) -> tuple[str, str]:
    """Reconstruct task status and join actual call/event/result IDs to HTTP bytes."""
    require(sha(raw) == selected["sha256"], "ticket_native_pin")
    log = decode(raw)
    require(log.get("version") == 2 and log.get("status") in {"success", "error", "started"}, "ticket_native_log")
    ev = log["eval"]
    require(ev["run_id"] == selected["runId"] and ev["eval_id"] == selected["evalId"], "ticket_native_identity")
    require(ev["task"] == case["id"] and type(ev["task_version"]) is int and ev["task_version"] == 1 and ev["model"] == "mockllm/model" and ev["packages"]["inspect_ai"] == INSPECT_VERSION, "ticket_native_task")
    _same(ev["metadata"], {"probity_ticket_profile": PROFILE, "probity_plan_sha256": sha(encode(plan))}, "ticket_native_plan")
    conf = ev["config"]
    require(all(type(conf[k]) is int and conf[k] == v for k, v in {"epochs": 1, "retry_on_error": 0, "max_samples": 1, "message_limit": 12}.items()) and conf["log_samples"] is True and conf["score_on_error"] is False, "ticket_native_config")
    require(ev["dataset"]["sample_ids"] == [case["id"]] and ev["dataset"]["samples"] == 1, "ticket_native_population")
    require(len(ev["scorers"]) == 1 and ev["scorers"][0]["name"] == "match" and ev["scorers"][0]["options"] == {}, "ticket_native_scorer")
    steps = log["plan"]["steps"]
    require(len(steps) == 1 and steps[0]["solver"] == "react", "ticket_native_solver")
    params = steps[0]["params"]
    require(params["submit"] is False and type(params["attempts"]) is int and params["attempts"] == 1 and params["truncation"] == "disabled", "ticket_native_solver_options")
    _same(params["tools"], [{"type": "tool", "name": "dispatch_ticket", "params": {}}], "ticket_native_tools")
    require(all(params.get(k) is None for k in ("model", "on_continue", "retry_refusals", "compaction", "approval", "review")), "ticket_native_solver_options")
    require(type(log["samples"]) is list and len(log["samples"]) == 1, "ticket_native_sample_population")
    sample = log["samples"][0]
    require(sample["id"] == case["id"] and type(sample["epoch"]) is int and sample["epoch"] == 1 and sample["input"] == plan["input"] and sample["target"] == case["target"] and sample.get("error_retries", []) == [], "ticket_native_sample")
    try:
        start = datetime.fromisoformat(sample["started_at"])
        end = None if sample.get("completed_at") is None else datetime.fromisoformat(sample["completed_at"])
    except (ValueError, TypeError):
        require(False, "ticket_native_timestamp")
    require(start.tzinfo is not None and (end is None or (end.tzinfo is not None and end >= start)), "ticket_native_timestamp")
    events = [e for e in sample["events"] if e.get("event") == "tool"]
    calls = [c for m in sample["messages"] if m["role"] == "assistant" for c in m.get("tool_calls", [])]
    replies = [m for m in sample["messages"] if m["role"] == "tool"]
    require(len(events) == len(calls) == len(replies) == 1, "ticket_native_call_population")
    event, call, reply = events[0], calls[0], replies[0]
    require(event["id"] == call["id"] == reply["tool_call_id"] == "call-" + case["id"] and event["function"] == call["function"] == reply["function"] == "dispatch_ticket", "ticket_native_call_identity")
    _same(event["arguments"], {"content": "DONE"}, "ticket_native_argument")
    _same(call["arguments"], event["arguments"], "ticket_native_argument")
    packet = decode(packet_raw)
    result = canonical({"httpSha256": sha(packet_raw), "postStatus": packet["postStatus"], "nativeRevision": decode(bytes.fromhex(packet["getResponseHex"]))["revision"]}).decode()
    require(event.get("error") is None and reply.get("error") is None and event["result"] == reply["content"] == result, "ticket_native_http_join")
    if sample.get("error") is not None:
        require(log["status"] == "error" and sample.get("scores") in ({}, None), "ticket_native_error_score")
        return "error", "unknown"
    if end is None:
        require(log["status"] != "success" and not sample.get("scores"), "ticket_native_incomplete_score")
        return "incomplete", "unknown"
    require(log["status"] == "success", "ticket_native_completion")
    scores = sample["scores"]
    require(set(scores) == {"match"} and scores["match"]["value"] in {"C", "I"}, "ticket_native_score")
    output = sample["output"]["choices"][0]["message"]["content"]
    require(output == case["final"], "ticket_native_output")
    expected = "C" if output == case["target"] else "I"
    require(scores["match"]["value"] == expected, "ticket_native_score_recomputed")
    return "complete", "pass" if expected == "C" else "fail"


def verify_saved(output: Path, selected: dict, withheld: dict | None = None) -> dict:
    """Offline reader; selected pins must be carried separately from this packet."""
    require(not output.is_symlink() and not any(p.is_symlink() for p in output.rglob("*")), "ticket_packet_symlink")
    require(set(selected) == {"planSha256", "sourceManifestSha256", "artifactManifestSha256", "evaluationTime"}, "ticket_consumer_pins")
    plan_raw, source_raw, manifest_raw = (read(output, name) for name in ("plan-before-run.json", "source-manifest-before-run.json", "artifact-manifest.json"))
    for raw, field in ((plan_raw, "planSha256"), (source_raw, "sourceManifestSha256"), (manifest_raw, "artifactManifestSha256")):
        require(type(selected[field]) is str and sha(raw) == selected[field], "ticket_external_pin_" + field)
    plan, source_manifest, manifest = map(decode, (plan_raw, source_raw, manifest_raw))
    require(plan["profile"] == PROFILE and plan["inspectVersion"] == INSPECT_VERSION and plan["sourceManifestSha256"] == sha(source_raw), "ticket_plan_profile")
    check_sources(output, source_manifest, withheld or {})
    require(set(manifest) == {"bindings", "artifacts"}, "ticket_manifest_fields")
    cases = plan["cases"]
    require([c["id"] for c in cases] == [c[0] for c in CASES], "ticket_plan_population")
    allowed = {c["id"] for c in cases if c["launch"]}
    require(set(manifest["bindings"]) <= allowed, "ticket_binding_population")
    require(set(manifest["artifacts"]) == {a + suffix for a in manifest["bindings"] for suffix in ("-native.json", "-http.json")}, "ticket_artifact_population")
    artifacts = {name: read(output / "artifacts", name) for name in manifest["artifacts"]}
    require({p.name for p in (output / "artifacts").iterdir()} == set(artifacts), "ticket_artifact_population")
    require(all(sha(raw) == manifest["artifacts"][name] for name, raw in artifacts.items()), "ticket_artifact_pin")
    native_root = output / "native"
    require(native_root.is_dir() and {p.name for p in native_root.iterdir()} == set(manifest["bindings"]), "ticket_original_native_population")
    for aid in manifest["bindings"]:
        folder = native_root / aid
        require(folder.is_dir(), "ticket_original_native_population")
        originals = list(folder.iterdir())
        require(len(originals) == 1 and originals[0].is_file() and originals[0].suffix == ".json", "ticket_original_native_population")
        require(read(output, str(originals[0].relative_to(output))) == artifacts[aid + "-native.json"], "ticket_original_native_bytes")
    now = datetime.fromisoformat(selected["evaluationTime"])
    require(now.tzinfo is not None and now >= datetime.fromisoformat(plan["selectedTime"]), "ticket_consumer_time")
    records = []
    for case, definition in zip(cases, CASES, strict=True):
        name, disposition, final, target, launch, interrupted = definition
        _same({k: case[k] for k in ("id", "launch", "final", "target", "interruptAfterIntent")}, {"id": name, "launch": launch, "final": final, "target": target, "interruptAfterIntent": interrupted}, "ticket_declared_case")
        request, policy = ActionRequest(**case["request"]), GrantPolicy(**case["policy"])
        require(request.run_id == plan["runId"] and request.attempt_id == name and request.request_id == "request-" + name and request.target_path == "/work/tickets/" + name, "ticket_request_identity")
        require(sha(bytes.fromhex(case["contentHex"])) == request.content_sha256, "ticket_selected_content")
        decision = case["decision"]
        require(native_digest("mandate", decision["mandate"]) == decision["pinned_mandate_digest"], "ticket_mandate_pin")
        _same(decision["transaction"], ticket_transaction(request), "ticket_transaction")
        actual = enforce_check(decision["mandate"], decision["transaction"])
        _same(decision["record"], actual, "ticket_decision_replay")
        require(actual["verdict"] == ("DENY" if disposition == "forbid" else "PERMIT"), "ticket_kernel_verdict")
        # Same strict commitment relation used by the host, including bounded DENY.
        from probity_observer.aae_ticket_records import decision_commitment
        commitment = decision_commitment(decision["mandate"], decision["transaction"], decision["record"], request, decision["pinned_mandate_digest"], require_permit=False)
        _same(case["configuration"], {"request": case["request"], "policy": case["policy"], "serviceKey": case["serviceKey"], "decisionDigest": commitment}, "ticket_selected_configuration")
        initial = signed_state(case, case["initial"])
        require(initial["phase"] == "ready" and initial["eventCount"] == 1 and initial["revoked"] is False, "ticket_selected_initial")
        authorized = verify_grant(case["grant"], request, policy, now=now)
        if name not in manifest["bindings"]:
            records.append({"attemptId": name, "status": "not-started" if not launch else "start-unknown", "taskOutcome": "unknown", "kernelVerdict": actual["verdict"], "effectOutcome": "unknown", "effectId": None})
            continue
        packet_raw = artifacts[name + "-http.json"]
        status, task_outcome = native_sample(artifacts[name + "-native.json"], manifest["bindings"][name], plan, case, packet_raw)
        packet = decode(packet_raw)
        require(set(packet) == {"endpoint", "postPath", "getPath", "postRequestHex", "postStatus", "postResponseHex", "getStatus", "getResponseHex"}, "ticket_http_fields")
        require(type(packet["endpoint"]) is str and packet["endpoint"].startswith("http://127.0.0.1:") and packet["endpoint"].removeprefix("http://127.0.0.1:").isdigit(), "ticket_http_endpoint")
        require(packet["postPath"] == "/dispatch" and packet["getPath"] == "/tickets/tenant/" + name and type(packet["getStatus"]) is int and packet["getStatus"] == 200 and type(packet["postStatus"]) is int, "ticket_http_route")
        require(bytes.fromhex(packet["postRequestHex"]) == canonical({"request": case["request"], "grant": case["grant"], "contentHex": case["contentHex"]}), "ticket_http_request")
        response, readback = (decode(bytes.fromhex(packet[k])) for k in ("postResponseHex", "getResponseHex"))
        state = signed_state(case, readback)
        if disposition == "forbid":
            require(packet["postStatus"] == 409 and response.get("status") == "refused", "ticket_deny_response")
            _same(readback, case["initial"], "ticket_denied_native_state")
            effect = "not-recorded-local-row"
        elif interrupted:
            require(packet["postStatus"] == 409 and response.get("status") == "refused" and state["phase"] == "pending" and state["revision"] == 0 and state["eventCount"] == 2 and not state["revoked"], "ticket_pending_effect")
            expected_effect = domain_digest(DOMAIN + "-effect", {"configuration": state["configuration"], "requestId": request.request_id, "grantDigest": authorized.grant_digest})
            require(state["effectId"] == expected_effect and state["grantDigest"] == authorized.grant_digest, "ticket_pending_identity")
            from probity_observer.ticket_state import parse_time
            verify_grant(case["grant"], request, policy, now=parse_time(state["intentTime"]))
            require(now >= parse_time(state["intentTime"]), "ticket_pending_time")
            effect = "incomplete-no-automatic-replay"
        else:
            require(packet["postStatus"] == 200, "ticket_completion_response")
            verify_aae_ticket_result(**decision, receipt=response, readback=readback, request=request, policy=policy, service_key=case["serviceKey"], grant=case["grant"], now=now)
            effect = "verified-local-ticket-update"
        records.append({"attemptId": name, "status": status, "taskOutcome": task_outcome, "kernelVerdict": actual["verdict"], "effectOutcome": effect, "effectId": state["effectId"]})
    return {"profile": PROFILE, "status": "verified", "plannedAttempts": len(records), "records": records, "providerCalls": "none-mock-provider", "taskScope": "controlled-native-match-score", "effectScope": "one-selected-local-ticket-per-attempt", "issuerAuthentication": "not-established", "independentCustody": "not-established", "priorSelection": "local-pre-run-plan-not-authenticated-witness", "coverage": "finite-declared-population-original-logs-and-retained-HTTP-bytes"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--pins-file", type=Path, required=True)
    parser.add_argument("--withheld-sources", type=Path)
    args = parser.parse_args()
    omitted = withheld_for(args.withheld_sources, args.output) if args.withheld_sources else None
    print(json.dumps(verify_saved(args.output, decode(args.pins_file.read_bytes()), omitted), indent=2))
