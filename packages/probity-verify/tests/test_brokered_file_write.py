"""Authenticated positive/negative controls for bounded recorded completion."""

import copy
import hashlib
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from probity_verify import CaseError, adjudicate
from probity_verify.broker_records import parse_record
from probity_verify.bundle import create_bundle, replay_bundle

ROOT = Path(__file__).parents[1]
GENERATOR = runpy.run_path(str(ROOT / "examples/brokered-file-write/generate.py"))
BUILD = GENERATOR["build"]
ENCODE = GENERATOR["encode"]


def fixture(tmp_path, **options):
    files, case, policy = BUILD(**options)
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    return case, policy


def replace(tmp_path, case, policy, role, data):
    """Select new consumer bytes so a control reaches the actual record check."""
    metadata = case["artifacts"][role]
    (tmp_path / metadata["path"]).write_bytes(data)
    metadata.update(length=len(data), sha256=hashlib.sha256(data).hexdigest())
    assessment = policy["assessments"][case["case_id"]]
    selector = assessment["report"] if role == "report" else (
        assessment["retained_target"] if role == "target" else policy["witnesses"]["broker"]["record"][role])
    selector["sha256"] = metadata["sha256"]


@pytest.mark.parametrize("options,decision", [
    ({}, "supported"), ({"completion": False}, "contradicted"),
    ({"write": False}, "contradicted"), ({"write": False, "completion": False}, "supported"),
    ({"gap": True}, "supported"), ({"write": False, "gap": True}, "not_established"),
    ({"write": False, "gap": True, "completion": False}, "not_established"),
    ({"report_content": "c" * 64}, "contradicted"),
    ({"report_content": "c" * 64, "completion": False}, "supported"),
    ({"intended_content": "c" * 64}, "supported"),
    ({"target": False}, "supported"), ({"extension": True}, "supported"),
    ({"state": "missing_terminal"}, "not_established"),
    ({"state": "missing_terminal", "pending": True}, "not_established"),
])
def test_meaningful_assertions_and_separate_intent(tmp_path, options, decision):
    case, policy = fixture(tmp_path, **options)
    answer = adjudicate(case, policy, tmp_path)
    assert answer["decision"] == decision
    assert answer["scope"]["witness_scope"] == "PEER"
    if options.get("intended_content"):
        assert answer["scope"]["recorded_content_matches_intent"] is False
        assert answer["scope"]["report_assertion"]["content_sha256"] != options["intended_content"]


def test_later_different_target_is_not_historical_contradiction(tmp_path):
    case, policy = fixture(tmp_path)
    replace(tmp_path, case, policy, "target", b"a later replacement\n")
    answer = adjudicate(case, policy, tmp_path)
    assert answer["decision"] == "supported"
    assert answer["scope"]["retained_target"]["matches_recorded_content"] is False
    assert answer["scope"]["retained_target"]["historical_completion_predicate"] is False


@pytest.mark.parametrize("field,value", [("interval_id", "another-interval"), ("request_id", "another-request"),
                                         ("path", "/work/another.txt")])
def test_report_outside_context_is_not_assessed(tmp_path, field, value):
    case, policy = fixture(tmp_path)
    report = json.loads((tmp_path / "report.json").read_bytes())
    report[field] = value
    replace(tmp_path, case, policy, "report", ENCODE(report))
    assert adjudicate(case, policy, tmp_path)["reason"] == "report_outside_consumer_context"


@pytest.mark.parametrize("field", ["interval_id", "authority_scope"])
def test_authentic_record_outside_consumer_context_is_not_assessed(tmp_path, field):
    case, policy = fixture(tmp_path)
    policy["assessments"][case["case_id"]]["context"][field] = "another" if field == "interval_id" else "/different"
    if field == "authority_scope":
        policy["assessments"][case["case_id"]]["context"]["path"] = "/different/result.txt"
    assert adjudicate(case, policy, tmp_path)["reason"] == "record_outside_consumer_context"


@pytest.mark.parametrize("role", ["report", "packet", "history", "ledger", "head"])
def test_genuine_missing_artifact_has_explicit_uncertainty(tmp_path, role):
    case, policy = fixture(tmp_path)
    (tmp_path / case["artifacts"][role]["path"]).unlink()
    assert adjudicate(case, policy, tmp_path)["decision"] == "not_established"


def test_missing_history_cannot_hide_bad_present_signature(tmp_path):
    case, policy = fixture(tmp_path)
    (tmp_path / "history.jsonl").unlink()
    packet = json.loads((tmp_path / "packet.json").read_bytes())
    packet["claimSignature"] = "A" * 86 + "=="
    replace(tmp_path, case, policy, "packet", ENCODE(packet))
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(claimSignature="A" * 86 + "=="),
    lambda p: p["commitment"].update(signature="A" * 86 + "=="),
    lambda p: p["checkpoint"].update(signature="A" * 86 + "=="),
    lambda p: p["startCheckpoint"].update(count=True),
    lambda p: p["claim"]["coverage"].update(noDetectedGap=1),
    lambda p: p["claim"].update(witnessScope="INDEPENDENT"),
    lambda p: p["claim"].update(sealedAt="2026-02-30T00:00:00Z"),
    lambda p: p["authority"].update(scope="/work/../other"),
    lambda p: p["claim"].update(writes={}),
    lambda p: p["checkpoint"]["ledgerReceipt"].update(phase=[]),
    lambda p: p["checkpoint"]["ledgerReceipt"].update(observerKey="f" * 64),
    lambda p: p.update(extra="unsupported extension"),
    lambda p: p.update(startCheckpoint=p["checkpoint"]),
])
def test_candidate_record_faults_refuse_without_verdict(tmp_path, mutation):
    case, policy = fixture(tmp_path)
    packet = json.loads((tmp_path / "packet.json").read_bytes())
    mutation(packet)
    replace(tmp_path, case, policy, "packet", ENCODE(packet))
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("field,value", [("observer_key", "f" * 64), ("witness_key", "f" * 64),
                                         ("witness_scope", "INDEPENDENT")])
def test_external_key_and_boundary_pins_are_required(tmp_path, field, value):
    case, policy = fixture(tmp_path)
    policy["witnesses"]["broker"][field] = value
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


def test_observer_and_witness_key_reuse_refuses(tmp_path):
    case, policy = fixture(tmp_path)
    witness = policy["witnesses"]["broker"]
    witness["witness_key"] = witness["observer_key"]
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("mutate", [
    lambda events: [events[0], events[2]],
    lambda events: events + [copy.deepcopy(events[-1])],
    lambda events: [events[0], {**events[1], "contentDigest": "d" * 64}, events[2]],
    lambda events: [events[0], {**events[1], "path": "/work/other.txt"}, events[2]],
    lambda events: [events[0], {**events[1], "requestId": "another"}, events[2]],
    lambda events: [events[0], {**events[1], "beforeRoot": "d" * 64}, events[2]],
    lambda events: events + [{"kind": "retry", "requestId": "absent", "path": "/work/result.txt"}],
    lambda events: events + [copy.deepcopy(events[0])],
    lambda events: events + [{"kind": "surprise"}],
])
def test_genuinely_signed_inconsistent_history_refuses(tmp_path, mutate):
    # Independent fixture signer recomputes all signatures, hashes and pins.
    # The refusal must come from the semantic history relation, not bad bytes.
    case, policy = fixture(tmp_path, event_transform=mutate)
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("change", ["truncate", "reorder", "drop", "duplicate", "boolean-sequence"])
def test_raw_history_chain_faults_refuse(tmp_path, change):
    case, policy = fixture(tmp_path)
    lines = (tmp_path / "history.jsonl").read_bytes().splitlines(keepends=True)
    if change == "truncate":
        data = b"".join(lines)[:-1]
    elif change == "reorder":
        data = b"".join(reversed(lines))
    elif change == "drop":
        data = b"".join(lines[:1] + lines[2:])
    elif change == "duplicate":
        data = b"".join(lines + lines[-1:])
    else:
        first = json.loads(lines[0]); first["sequence"] = True
        data = ENCODE(first) + b"\n" + b"".join(lines[1:])
    replace(tmp_path, case, policy, "history", data)
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":9007199254740992}',
                                  b'{"x":"\\u00e9"}', b' {"x":1}', b'[]\n', b'[' * 33 + b'0' + b']' * 33,
                                  b'[' + b'0,' * 32769 + b'0]', b'"' + b'a' * (1024 * 1024) + b'"'])
def test_restricted_record_admission_refuses(raw):
    with pytest.raises(CaseError):
        parse_record(raw)


@pytest.mark.parametrize("value", [None, 0, 1, "true", [], {}])
def test_completion_assertion_is_exact_boolean(tmp_path, value):
    case, policy = fixture(tmp_path)
    report = json.loads((tmp_path / "report.json").read_bytes())
    report["completion_recorded"] = value
    replace(tmp_path, case, policy, "report", ENCODE(report))
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


def test_typed_state_cannot_hide_existing_terminal(tmp_path):
    files, case, policy = BUILD()
    files.pop("packet.json")
    files, case, policy = GENERATOR["bind"](files, state="missing_terminal")
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    with pytest.raises(CaseError, match="terminal receipt"):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("field", ["keyid", "signature", "request", "claimDigest", "grantDigest", "profile"])
def test_protected_action_extension_is_checked_not_discarded(tmp_path, field):
    case, policy = fixture(tmp_path, extension=True)
    packet = json.loads((tmp_path / "packet.json").read_bytes())
    binding = packet["authorizationBinding"]
    if field == "keyid":
        binding[field] = "f" * 64
    elif field == "signature":
        binding[field] = "A" * 86 + "=="
    elif field == "request":
        binding["payload"][field]["request_id"] = "another"
    else:
        binding["payload"][field] = "another"
    replace(tmp_path, case, policy, "packet", ENCODE(packet))
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


def test_public_bundle_replays_the_new_contract(tmp_path):
    case, policy = fixture(tmp_path)
    (tmp_path / "case.json").write_bytes(ENCODE(case))
    (tmp_path / "policy.json").write_bytes(ENCODE(policy))
    bundle = tmp_path / "bundle.zip"
    expected = create_bundle(tmp_path / "case.json", tmp_path / "policy.json", bundle)
    assert replay_bundle(bundle) == expected
    assert expected["decision"] == "supported"


@pytest.mark.parametrize("fault", ["signature", "boolean", "deep-case", "non-utf8-case"])
def test_actual_cli_refuses_cleanly(tmp_path, fault):
    case, policy = fixture(tmp_path)
    if fault == "signature":
        packet = json.loads((tmp_path / "packet.json").read_bytes())
        packet["claimSignature"] = "A" * 86 + "=="
        replace(tmp_path, case, policy, "packet", ENCODE(packet))
    elif fault == "boolean":
        report = json.loads((tmp_path / "report.json").read_bytes()); report["completion_recorded"] = 1
        replace(tmp_path, case, policy, "report", ENCODE(report))
    case_raw = ENCODE(case)
    if fault == "deep-case":
        case_raw = b'[' * 1000 + b'0' + b']' * 1000
    elif fault == "non-utf8-case":
        case_raw = b'\xff'
    (tmp_path / "case.json").write_bytes(case_raw)
    (tmp_path / "policy.json").write_bytes(ENCODE(policy))
    result = subprocess.run([sys.executable, "-m", "probity_verify.cli", str(tmp_path / "case.json"),
                             "--policy", str(tmp_path / "policy.json"), "--json"], capture_output=True, timeout=5)
    assert result.returncode == 2
    assert result.stdout == b""
    assert result.stderr.startswith(b"probity-verify:")
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("value", [True, 1.0])
@pytest.mark.parametrize("role", ["checkpoint", "head", "receipt-sequence", "history-sequence"])
@pytest.mark.parametrize("partial", [False, True])
def test_validly_signed_wrong_numeric_types_refuse(tmp_path, value, role, partial):
    # The independent signer authenticates the malformed scalar exactly.
    # A real signature cannot authorize a boolean or float as an integer.
    import base64
    sign, key, digest = (GENERATOR[name] for name in ("sign", "key", "digest"))
    case, policy = fixture(tmp_path)
    if partial:
        (tmp_path / "report.json").unlink()
    if role == "checkpoint":
        packet = json.loads((tmp_path / "packet.json").read_bytes())
        point = packet["startCheckpoint"]
        point["count"] = value
        payload = {name: point[name] for name in ("count", "head")}
        point["signature"] = sign(key(2), "probity-checkpoint-v0", payload)
        key(2).public_key().verify(base64.b64decode(point["signature"]), b"probity-checkpoint-v0\0" + ENCODE(payload))
        replace(tmp_path, case, policy, "packet", ENCODE(packet))
    elif role == "head":
        head = json.loads((tmp_path / "head.json").read_bytes()); head["count"] = value
        payload = {name: head[name] for name in ("format", "count", "head")}
        head["signature"] = sign(key(2), "probity-witness-ledger-head-v0", payload)
        key(2).public_key().verify(base64.b64decode(head["signature"]), b"probity-witness-ledger-head-v0\0" + ENCODE(payload))
        replace(tmp_path, case, policy, "head", ENCODE(head))
    elif role == "receipt-sequence":
        receipts = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_bytes().splitlines()]
        first = receipts[0]; first["sequence"] = value
        payload = {name: first[name] for name in ("sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase", "checkpoint")}
        first["hash"] = digest("probity-witness-receipt-v0", payload)
        first["signature"] = sign(key(2), "probity-witness-receipt-v0", payload)
        key(2).public_key().verify(base64.b64decode(first["signature"]), b"probity-witness-receipt-v0\0" + ENCODE(payload))
        replace(tmp_path, case, policy, "ledger", b"".join(ENCODE(item) + b"\n" for item in receipts))
    else:
        entries = [json.loads(line) for line in (tmp_path / "history.jsonl").read_bytes().splitlines()]
        first = entries[0]; first["sequence"] = value
        payload = {name: first[name] for name in ("sequence", "previous", "event")}
        first["hash"] = digest("probity-history-entry-v0", payload)
        replace(tmp_path, case, policy, "history", b"".join(ENCODE(item) + b"\n" for item in entries))
    with pytest.raises(CaseError):
        adjudicate(case, policy, tmp_path)


def test_missing_packet_cannot_hide_inconsistent_present_history(tmp_path):
    case, policy = fixture(tmp_path, event_transform=lambda events: [events[0], events[2]])
    (tmp_path / "packet.json").unlink()
    with pytest.raises(CaseError, match="unique durable intent"):
        adjudicate(case, policy, tmp_path)


def test_missing_ledger_cannot_hide_false_empty_signed_head(tmp_path):
    sign, key = GENERATOR["sign"], GENERATOR["key"]
    case, policy = fixture(tmp_path)
    (tmp_path / "ledger.jsonl").unlink()
    head = json.loads((tmp_path / "head.json").read_bytes()); head["count"] = 0
    payload = {name: head[name] for name in ("format", "count", "head")}
    head["signature"] = sign(key(2), "probity-witness-ledger-head-v0", payload)
    replace(tmp_path, case, policy, "head", ENCODE(head))
    with pytest.raises(CaseError, match="genesis"):
        adjudicate(case, policy, tmp_path)


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_actual_cli_refuses_unsafe_control_file(tmp_path, kind):
    import os
    case, policy = fixture(tmp_path)
    safe = tmp_path / "case-original.json"; safe.write_bytes(ENCODE(case))
    selected = tmp_path / "case.json"
    if kind == "symlink":
        selected.symlink_to(safe)
    else:
        os.mkfifo(selected)
    (tmp_path / "policy.json").write_bytes(ENCODE(policy))
    result = subprocess.run([sys.executable, "-m", "probity_verify.cli", str(selected),
                             "--policy", str(tmp_path / "policy.json"), "--json"], capture_output=True, timeout=5)
    assert result.returncode == 2 and result.stdout == b""
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("field", ["sequence", "checkpoint-count"])
@pytest.mark.parametrize("resign", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_receipt_inclusion_requires_exact_authenticated_bytes(tmp_path, field, resign, partial):
    case, policy = fixture(tmp_path)
    if partial:
        (tmp_path / "report.json").unlink()
    packet = json.loads((tmp_path / "packet.json").read_bytes())
    receipt = packet["startCheckpoint"]["ledgerReceipt"]
    if field == "sequence":
        receipt["sequence"] = True
    else:
        point = receipt["checkpoint"]; point["count"] = True
        if resign:
            payload = {name: point[name] for name in ("count", "head")}
            point["signature"] = GENERATOR["sign"](GENERATOR["key"](2), "probity-checkpoint-v0", payload)
    if resign:
        payload = {name: receipt[name] for name in ("sequence", "previous", "intervalId", "authorityDigest", "observerKey", "phase", "checkpoint")}
        receipt["hash"] = GENERATOR["digest"]("probity-witness-receipt-v0", payload)
        receipt["signature"] = GENERATOR["sign"](GENERATOR["key"](2), "probity-witness-receipt-v0", payload)
    replace(tmp_path, case, policy, "packet", ENCODE(packet))
    with pytest.raises(CaseError, match="exact selected ledger inclusion"):
        adjudicate(case, policy, tmp_path)



def test_public_manifest_excludes_environment_and_binds_real_streams(tmp_path):
    manifest = runpy.run_path(str(ROOT / "scripts/manifest-brokered-file-write.py"))["build"]
    (tmp_path / "native").mkdir(); (tmp_path / "native/result.stdout").write_bytes(b"real output\n")
    (tmp_path / "consumer").mkdir(); (tmp_path / "consumer/unselected.txt").write_bytes(b"unselected")
    result = manifest(tmp_path)
    assert result["base_directory"] == "."
    assert result["files"] == [{"path": "native/result.stdout", "bytes": 12,
                                "sha256": hashlib.sha256(b"real output\n").hexdigest()}]


@pytest.mark.parametrize("kind", ["selected-directory-symlink", "file-symlink", "fifo"])
def test_public_manifest_refuses_nonregular_capture_paths(tmp_path, kind):
    import os
    manifest = runpy.run_path(str(ROOT / "scripts/manifest-brokered-file-write.py"))["build"]
    if kind == "selected-directory-symlink":
        (tmp_path / "other").mkdir(); (tmp_path / "native").symlink_to(tmp_path / "other", target_is_directory=True)
    else:
        (tmp_path / "native").mkdir()
        if kind == "fifo":
            os.mkfifo(tmp_path / "native/selected")
        else:
            (tmp_path / "other.txt").write_bytes(b"unselected")
            (tmp_path / "native/selected").symlink_to(tmp_path / "other.txt")
    with pytest.raises(ValueError):
        manifest(tmp_path)


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"])
def test_actual_cli_refuses_other_report_wire_encodings(tmp_path, encoding):
    case, policy = fixture(tmp_path)
    report = (tmp_path / "report.json").read_bytes().decode("ascii").encode(encoding)
    replace(tmp_path, case, policy, "report", report)
    (tmp_path / "case.json").write_bytes(ENCODE(case));(tmp_path / "policy.json").write_bytes(ENCODE(policy))
    result = subprocess.run([sys.executable, "-m", "probity_verify.cli", str(tmp_path / "case.json"),
                             "--policy", str(tmp_path / "policy.json"), "--json"], capture_output=True, timeout=5)
    assert result.returncode == 2 and result.stdout == b""
    assert b"Traceback" not in result.stderr


def test_ascii_report_whitespace_preserves_the_current_contract(tmp_path):
    case, policy = fixture(tmp_path)
    report = json.loads((tmp_path / "report.json").read_bytes())
    replace(tmp_path, case, policy, "report", json.dumps(report, indent=2).encode("ascii") + b"\n")
    assert adjudicate(case, policy, tmp_path)["decision"] == "supported"


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_generic_control_json_keeps_utf8_without_encoding_inference(encoding):
    from probity_verify.json_input import parse_json
    raw = '{"control":"unchanged"}'.encode(encoding)
    with pytest.raises(CaseError):
        parse_json(raw, max_bytes=1024, max_depth=8, max_nodes=64)
    assert parse_json('{"control":"café"}'.encode("utf-8"), max_bytes=1024,
                      max_depth=8, max_nodes=64) == {"control": "café"}
