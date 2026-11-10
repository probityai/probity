"""OTel audit export: our verifier's checks, and a real collector running the stock verifyprocessor.

The collector tests need an ``otelcol`` built with the contrib ``verifyprocessor`` and the file exporter
(``PROBITY_OTELCOL`` names the binary; ``scripts/otelcol/build.sh`` builds it). Without it they fail,
never skip: a missing collector is a test that did not run.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import time
import urllib.error
from pathlib import Path

import pytest

from probity_records import Journal, Signer, tool_call_predicate
from probity_records.otel import (AuditStream, Reveal, certificate_pem, export_journal, fingerprint,
                                  integrity_hash, post_logs, reveal_matches, signing_payload, verify_stream,
                                  witness_signer)


def _attrs(actor: str = "agent:orders") -> dict:
    return {"audit.actor.id": actor, "audit.actor.type": "service", "audit.action": "EXECUTE",
            "audit.outcome": "success", "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "create_order"}


def _stream(witness: Signer | None = None) -> AuditStream:
    return AuditStream(Signer.generate(), witness=witness_signer(witness) if witness else None)


def test_signing_payload_matches_the_processor_encoding() -> None:
    record = {"event_name": "e", "timestamp": 1714041600000000000, "observed_timestamp": 0,
              "trace_id": "00000000000000000000000000000000",
              "attributes": {"i": 9007199254740993, "b": True, "s": "<x>", "l": [1, "a"], "m": {"k": 2},
                             "audit.integrity.value": "dropped", "audit.verification.status": "dropped"}}
    assert signing_payload(record) == (
        b'{"attributes":{"b":{"boolValue":true},"i":{"intValue":"9007199254740993"},'
        b'"l":[{"intValue":"1"},{"stringValue":"a"}],"m":{"k":{"intValue":"2"}},"s":{"stringValue":"<x>"}},'
        b'"event_name":"e","timestamp":"1714041600000000000"}')


def test_a_whole_stream_verifies_and_chains() -> None:
    stream = _stream()
    for _ in range(3):
        stream.emit("probity.tool_call.effect", _attrs())
    report = verify_stream([stream.export_request()], [stream.certificate])
    assert report.ok and report.records == 3 and report.streams == {stream.stream_id: 3}


def test_a_dropped_record_is_refused_by_the_chain() -> None:
    stream = _stream()
    for _ in range(3):
        stream.emit("probity.tool_call.effect", _attrs())
    report = verify_stream([stream.export_request([stream.records[0], stream.records[2]])], [stream.certificate])
    assert report.verified == 2 and not report.ok
    assert [r["reason"] for r in report.refused] == ["sequence_gap"]


def test_an_edited_or_reordered_record_is_refused() -> None:
    stream = _stream()
    for _ in range(2):
        stream.emit("probity.tool_call.effect", _attrs())
    stream.records[1]["attributes"]["audit.outcome"] = "failure"
    assert [r["reason"] for r in verify_stream([stream.export_request()], [stream.certificate]).refused] == [
        "integrity_mismatch"]


def test_a_forged_chain_signed_by_another_key_is_refused() -> None:
    stream, other = _stream(), _stream()
    other.emit("probity.tool_call.effect", _attrs())
    assert verify_stream([other.export_request()], [stream.certificate]).refused[0]["reason"] == "certificate_mismatch"


def test_nothing_may_follow_the_end_of_a_stream() -> None:
    stream = _stream()
    stream.emit("a", _attrs(), end=True)
    with pytest.raises(ValueError):
        stream.emit("b", _attrs())


def test_a_redacted_record_verifies_and_the_value_is_proven_by_reveal() -> None:
    stream = _stream()
    record, reveals = stream.emit("probity.tool_call.intent", _attrs(),
                                  redact={"gen_ai.tool.call.arguments": {"card": "4111111111111111"}})
    wire = json.dumps(stream.export_request())
    assert "4111111111111111" not in wire
    assert verify_stream([json.loads(wire)], [stream.certificate]).ok
    assert reveal_matches(record, reveals[0])
    assert not reveal_matches(record, Reveal(reveals[0].field, {"card": "4000000000000000"}, reveals[0].salt))


def test_a_stripped_redaction_hash_is_refused() -> None:
    stream = _stream()
    record, _ = stream.emit("probity.tool_call.intent", _attrs(), redact={"gen_ai.tool.call.arguments": {"a": 1}})
    del record["attributes"]["gen_ai.tool.call.arguments.redacted_sha256"]
    reasons = [r["reason"] for r in verify_stream([stream.export_request()], [stream.certificate]).refused]
    assert reasons == ["integrity_mismatch"]


def test_a_witness_cosigns_the_real_head_and_catches_a_fork() -> None:
    witness = Signer.generate()
    stream = _stream(witness)
    stream.emit("a", _attrs())
    stream.emit("b", _attrs())
    stream.checkpoint()
    report = verify_stream([stream.export_request()], [stream.certificate], witness_keys=[witness.public_pem()],
                           require_witness=True)
    assert report.ok and report.witnessed == {stream.stream_id: 1}
    # The producer holds its key and forks: a second chain under the same stream id with record 2 changed.
    fork = AuditStream(stream.signer, stream_id=stream.stream_id, certificate=stream.certificate,
                       witness=lambda s, n, h: {"keyId": witness.key_id,
                                                "sig": stream.records[2]["attributes"]["probity.witness.signature"]})
    fork.emit("a", _attrs())
    fork.emit("b", _attrs("agent:someone-else"))
    fork.checkpoint()
    reasons = [r["reason"] for r in verify_stream([fork.export_request()], [stream.certificate],
                                                  witness_keys=[witness.public_pem()]).refused]
    assert reasons == ["witness_signature_invalid"]


def test_an_unpinned_witness_and_a_missing_witness_are_refused() -> None:
    witness = Signer.generate()
    stream = _stream(witness)
    stream.emit("a", _attrs())
    stream.checkpoint()
    assert [r["reason"] for r in verify_stream([stream.export_request()], [stream.certificate]).refused] == [
        "witness_key_unpinned"]
    bare = _stream()
    bare.emit("a", _attrs())
    assert [r["reason"] for r in verify_stream([bare.export_request()], [bare.certificate],
                                               require_witness=True).refused] == ["witness_missing"]


def test_the_journal_export_carries_each_record_digest_and_a_missing_line_is_named(tmp_path: Path) -> None:
    journal = Journal(tmp_path, Signer.generate())
    for phase in ("authorize", "intent", "effect"):
        journal.append("https://example.test/tool-call", "call", "0" * 64, tool_call_predicate(
            phase=phase, run_id="run-1", tool_call_id="tc-1", tool="create_order", args_sha256_hex="a" * 64,
            permit_id="p" * 64, decision="allow" if phase == "authorize" else None,
            outcome="committed" if phase == "effect" else None))
    stream = _stream()
    export_journal(stream, journal.path, actor_id="agent:orders")
    lines = journal.path.read_bytes().splitlines()
    import hashlib
    digests = {hashlib.sha256(line).hexdigest(): stream.stream_id for line in lines}
    assert verify_stream([stream.export_request()], [stream.certificate], journal_digests=digests).ok
    first = stream.records[0]["attributes"]
    assert first["gen_ai.tool.name"] == "create_order" and first["probity.permit.id"] == "p" * 64
    short = verify_stream([stream.export_request(stream.records[:2])], [stream.certificate], journal_digests=digests)
    assert [r["reason"] for r in short.refused] == ["journal_record_missing"]


# The stock collector.

OTELCOL = os.environ.get("PROBITY_OTELCOL", "")


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Collector:
    def __init__(self, tmp: Path, cert_pem: bytes, failure_mode: str) -> None:
        self.port, self.out = _port(), tmp / f"out-{failure_mode}.jsonl"
        (tmp / "cert.pem").write_bytes(cert_pem)
        config = f"""
receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:{self.port}
processors:
  verify:
    failure_mode: {failure_mode}
    key_source:
      type: file
      file:
        certificate: {tmp / "cert.pem"}
exporters:
  file:
    path: {self.out}
    flush_interval: 50ms
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    logs:
      receivers: [otlp]
      processors: [verify]
      exporters: [file]
"""
        (tmp / f"config-{failure_mode}.yaml").write_text(config)
        self.proc = subprocess.Popen([OTELCOL, "--config", str(tmp / f"config-{failure_mode}.yaml")],
                                     stdout=subprocess.DEVNULL, stderr=open(tmp / f"col-{failure_mode}.log", "wb"))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            time.sleep(0.1)
        self.proc.kill()
        raise RuntimeError("the collector did not open its OTLP port")

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/logs"

    def stored(self, want: int, timeout: float = 10.0) -> list[dict]:
        deadline = time.monotonic() + timeout
        records: list[dict] = []
        while time.monotonic() < deadline:
            records = []
            if self.out.exists():
                for line in self.out.read_text().splitlines():
                    if line.strip():
                        records.append(json.loads(line))
            if sum(len(sl["logRecords"]) for r in records for rl in r["resourceLogs"] for sl in rl["scopeLogs"]) >= want:
                break
            time.sleep(0.1)
        return records

    def close(self) -> None:
        self.proc.terminate()
        self.proc.wait(timeout=10)


@pytest.fixture
def collector_factory(tmp_path: Path):
    assert OTELCOL and Path(OTELCOL).exists(), "PROBITY_OTELCOL must name an otelcol built with verifyprocessor"
    started: list[Collector] = []

    def start(cert_pem: bytes, failure_mode: str) -> Collector:
        col = Collector(tmp_path, cert_pem, failure_mode)
        started.append(col)
        return col

    yield start
    for col in started:
        col.close()


def _status(records: list[dict]) -> list[str]:
    out = []
    for request in records:
        for rl in request["resourceLogs"]:
            resource = {a["key"]: a["value"].get("stringValue") for a in rl["resource"]["attributes"]}
            for sl in rl["scopeLogs"]:
                scope = {a["key"]: a["value"].get("stringValue") for a in sl.get("scope", {}).get("attributes", [])}
                for lr in sl["logRecords"]:
                    attrs = {a["key"]: a["value"].get("stringValue") for a in lr["attributes"]}
                    out.append(attrs.get("audit.verification.status") or scope.get("audit.verification.status")
                               or resource.get("audit.verification.status") or "")
    return out


def test_the_stock_verifyprocessor_verifies_our_export_unchanged(collector_factory) -> None:
    witness = Signer.generate()
    stream = _stream(witness)
    stream.emit("probity.tool_call.authorize", _attrs())
    stream.emit("probity.tool_call.intent", _attrs(), redact={"gen_ai.tool.call.arguments": {"card": "4111"}})
    stream.emit("probity.tool_call.effect", {**_attrs(), "probity.record.seq": 3}, body={"result": [1, 2.5, True]})
    stream.checkpoint()
    col = collector_factory(certificate_pem(stream.certificate), "mark")
    assert post_logs(col.endpoint, stream.export_request()) == 200
    stored = col.stored(4)
    assert _status(stored) == ["verified"] * 4
    # What the sink stored is still ours to verify, chain and witness included.
    assert verify_stream(stored, [stream.certificate], witness_keys=[witness.public_pem()],
                         require_witness=True).ok


def test_a_dropped_record_passes_the_stock_processor_and_is_refused_by_ours(collector_factory) -> None:
    stream = _stream()
    for _ in range(3):
        stream.emit("probity.tool_call.effect", _attrs())
    col = collector_factory(certificate_pem(stream.certificate), "strict")
    assert post_logs(col.endpoint, stream.export_request([stream.records[0], stream.records[2]])) == 200
    stored = col.stored(2)
    assert sum(len(sl["logRecords"]) for r in stored for rl in r["resourceLogs"] for sl in rl["scopeLogs"]) == 2
    assert [r["reason"] for r in verify_stream(stored, [stream.certificate]).refused] == ["sequence_gap"]


def test_a_tampered_record_is_refused_by_the_stock_processor(collector_factory) -> None:
    stream = _stream()
    stream.emit("probity.tool_call.effect", _attrs())
    stream.records[0]["attributes"]["audit.outcome"] = "failure"
    col = collector_factory(certificate_pem(stream.certificate), "strict")
    with pytest.raises(urllib.error.HTTPError) as refused:
        post_logs(col.endpoint, stream.export_request())
    # The OTLP/HTTP receiver of v0.165.0 answers a strict-mode refusal with 500 (measured 8 Nov 2026).
    assert refused.value.code == 500
    time.sleep(0.5)
    assert col.stored(1, timeout=1.0) == []
    assert fingerprint(stream.certificate).startswith("sha256:") and integrity_hash(stream.records[0])
    assert base64.b64decode(stream.records[0]["attributes"]["audit.integrity.value"])
