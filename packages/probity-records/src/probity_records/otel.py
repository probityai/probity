"""OpenTelemetry audit-log export of signed records, and the stream verifier that refuses a dropped record.

Every record becomes one OTLP log record carrying the ``audit.*`` attributes of the OpenTelemetry audit
logging data model, GenAI semantic-convention attributes where they exist, and our record digest
(``probity.record.sha256``). Each log record is signed exactly as the collector-contrib
``signingprocessor`` signs one: Ed25519 (``EdDSA``) over the RFC 8785 bytes of the type-tagged payload,
with ``audit.integrity.*`` excluded. So a stock ``verifyprocessor`` checks our export unchanged.

What the stock processor cannot see, :func:`verify_stream` checks:

* the hash chain of each stream (``audit.sequence.number``, ``previous_hash``, ``previous_record_id``),
  so a record dropped in transit is refused although every record that arrived carries a good signature;
* witness checkpoints: a key the producer does not hold cosigns the stream's size and head, so a producer
  that forks its own stream is caught (the audit data model leaves this to "an external witness");
* field-level redaction: a sensitive value never leaves as cleartext. The record carries
  ``<field>.redacted_sha256`` (salted SHA-256 over the value's RFC 8785 bytes) and lists the field in
  ``probity.redacted``; the redacted record verifies, a stripped hash is refused, and the holder of the
  value and salt proves it with :func:`reveal_matches`.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import time
import urllib.request
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from .core import Signer, canonical, key_id, load_public, sha256_hex

INTEGRITY_PREFIX = "audit.integrity."
VERIFICATION_PREFIX = "audit.verification."
SCHEMA_VERSION = "probity-audit/1"
WITNESS_DOMAIN = b"probity-otel-witness-v1\x00"
REDACTED_SUFFIX = ".redacted_sha256"
CHECKPOINT_EVENT = "probity.witness.checkpoint"
SCOPE_NAME = "probity-records"


# The signing payload, byte for byte as signingprocessor and verifyprocessor build it.

def _signing_value(value: Any) -> Any:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, (bytes, bytearray)):
        return {"bytesValue": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        return [_signing_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _signing_value(item) for key, item in value.items()}
    if value is None:
        return None
    raise TypeError(f"no OTLP value for {type(value).__name__}")


def signing_payload(record: Mapping[str, Any]) -> bytes:
    """The RFC 8785 bytes a ``signingprocessor`` signs for one log record (our internal record form).

    ``record`` holds ``event_name``, ``body``, ``timestamp`` and ``observed_timestamp`` (nanoseconds),
    ``trace_id``, ``span_id`` (hex) and ``attributes`` (plain Python values).
    """
    data: dict[str, Any] = {}
    if record.get("event_name"):
        data["event_name"] = record["event_name"]
    if record.get("body") is not None:
        data["body"] = _signing_value(record["body"])
    for name in ("timestamp", "observed_timestamp"):
        if record.get(name):
            data[name] = str(int(record[name]))
    for name in ("trace_id", "span_id"):
        if record.get(name) and set(str(record[name])) != {"0"}:
            data[name] = str(record[name]).lower()
    attrs = {key: _signing_value(value) for key, value in record.get("attributes", {}).items()
             if not key.startswith(INTEGRITY_PREFIX) and not key.startswith(VERIFICATION_PREFIX)}
    if attrs:
        data["attributes"] = attrs
    return canonical(data)


def integrity_hash(record: Mapping[str, Any]) -> str:
    """The audit data model's ``IntegrityHash``: SHA-256 (hex) of the signing payload."""
    return sha256_hex(signing_payload(record))


# OTLP/JSON wire form.

def _otlp_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, (bytes, bytearray)):
        return {"bytesValue": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        return {"arrayValue": {"values": [_otlp_value(item) for item in value]}}
    if isinstance(value, Mapping):
        return {"kvlistValue": {"values": [{"key": str(k), "value": _otlp_value(v)} for k, v in value.items()]}}
    raise TypeError(f"no OTLP value for {type(value).__name__}")


def _from_otlp(value: Mapping[str, Any]) -> Any:
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        return int(value["intValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "bytesValue" in value:
        return base64.b64decode(value["bytesValue"])
    if "arrayValue" in value:
        return [_from_otlp(item) for item in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return {item["key"]: _from_otlp(item.get("value", {})) for item in value["kvlistValue"].get("values", [])}
    return None


def _attrs(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"key": key, "value": _otlp_value(value)} for key, value in values.items()]


def to_otlp_record(record: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"attributes": _attrs(record.get("attributes", {}))}
    if record.get("event_name"):
        out["eventName"] = record["event_name"]
    if record.get("body") is not None:
        out["body"] = _otlp_value(record["body"])
    if record.get("timestamp"):
        out["timeUnixNano"] = str(int(record["timestamp"]))
    if record.get("observed_timestamp"):
        out["observedTimeUnixNano"] = str(int(record["observed_timestamp"]))
    for name, wire in (("trace_id", "traceId"), ("span_id", "spanId")):
        if record.get(name):
            out[wire] = record[name]
    return out


def from_otlp_record(item: Mapping[str, Any]) -> dict[str, Any]:
    """Our internal record form from one OTLP/JSON log record (what a sink stored)."""
    record: dict[str, Any] = {"attributes": {a["key"]: _from_otlp(a.get("value", {}))
                                             for a in item.get("attributes", [])}}
    if item.get("eventName"):
        record["event_name"] = item["eventName"]
    if "body" in item and item["body"]:
        record["body"] = _from_otlp(item["body"])
    if item.get("timeUnixNano"):
        record["timestamp"] = int(item["timeUnixNano"])
    if item.get("observedTimeUnixNano"):
        record["observed_timestamp"] = int(item["observedTimeUnixNano"])
    for wire, name in (("traceId", "trace_id"), ("spanId", "span_id")):
        if item.get(wire):
            record[name] = item[wire]
    return record


# Keys: the verifyprocessor resolves the signing key through an X.509 certificate.

def self_signed_certificate(signer: Signer, common_name: str = "probity audit producer") -> bytes:
    """A DER certificate for the producer's Ed25519 key, which a verifyprocessor is configured with."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    start = _dt.datetime(2026, 1, 1, tzinfo=_dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(signer.public)
            .serial_number(int.from_bytes(hashlib.sha256(signer.public_pem()).digest()[:8], "big"))
            .not_valid_before(start).not_valid_after(start + _dt.timedelta(days=3650))
            .sign(signer.key, None))
    return cert.public_bytes(Encoding.DER)


def certificate_pem(der: bytes) -> bytes:
    return x509.load_der_x509_certificate(der).public_bytes(Encoding.PEM)


def fingerprint(der: bytes) -> str:
    return "sha256:" + hashlib.sha256(der).hexdigest()


def _cert_key(der: bytes) -> Ed25519PublicKey:
    key = x509.load_der_x509_certificate(der).public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("the audit certificate must carry an Ed25519 key")
    return key


# Redaction and witness.

@dataclass(frozen=True)
class Reveal:
    """What the holder of a redacted value keeps to prove it later: never exported."""

    field: str
    value: Any
    salt: bytes


def redacted_sha256(value: Any, salt: bytes) -> str:
    return hashlib.sha256(salt + canonical(value)).hexdigest()


def reveal_matches(record: Mapping[str, Any], reveal: Reveal) -> bool:
    """Whether the redacted field in ``record`` commits to the revealed value and salt."""
    committed = record.get("attributes", {}).get(reveal.field + REDACTED_SUFFIX)
    return committed is not None and committed == redacted_sha256(reveal.value, reveal.salt)


def witness_body(stream_id: str, size: int, head: str) -> bytes:
    return WITNESS_DOMAIN + canonical({"head": head, "size": size, "streamId": stream_id})


def witness_signer(signer: Signer) -> Callable[[str, int, str], dict[str, str]]:
    """A witness callable over a key held by another party (in production, behind its own service)."""
    def cosign(stream_id: str, size: int, head: str) -> dict[str, str]:
        sig = signer.sign(witness_body(stream_id, size, head))
        return {"keyId": signer.key_id, "sig": base64.b64encode(sig).decode("ascii")}
    return cosign


# The producer side.

def _now_ns() -> int:
    return time.time_ns()


@dataclass
class AuditStream:
    """One hash-chained audit stream, signed by ``signer`` as a producer-tier signingprocessor would.

    ``witness`` (optional) cosigns each checkpoint with a key the producer does not hold.
    """

    signer: Signer
    service_name: str = "probity"
    stream_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    witness: Callable[[str, int, str], Mapping[str, str]] | None = None
    certificate: bytes = b""
    records: list[dict[str, Any]] = field(default_factory=list)
    _seq: int = 0
    _head: str | None = None
    _head_id: str | None = None
    _ended: bool = False

    def __post_init__(self) -> None:
        if not self.certificate:
            self.certificate = self_signed_certificate(self.signer)
        if _cert_key(self.certificate).public_bytes_raw() != self.signer.public.public_bytes_raw():
            raise ValueError("the certificate does not carry the signer's key")

    @property
    def resource_attributes(self) -> dict[str, Any]:
        return {"service.name": self.service_name, "audit.integrity.algorithm": "EdDSA",
                "audit.integrity.certificate": fingerprint(self.certificate)}

    def emit(self, event_name: str, attributes: Mapping[str, Any], *, body: Any = None,
             redact: Mapping[str, Any] | None = None, timestamp: int | None = None,
             trace_id: str | None = None, span_id: str | None = None, end: bool = False,
             record_id: str | None = None) -> tuple[dict[str, Any], list[Reveal]]:
        """Sign and keep one record; returns it and the reveals of its redacted fields."""
        if self._ended:
            raise ValueError("the stream was closed with audit.sequence.end")
        attrs = dict(attributes)
        reveals = []
        for name, value in (redact or {}).items():
            salt = os.urandom(32)
            attrs[name + REDACTED_SUFFIX] = redacted_sha256(value, salt)
            reveals.append(Reveal(name, value, salt))
        if reveals:
            attrs["probity.redacted"] = sorted(r.field for r in reveals)
        self._seq += 1
        rid = record_id or str(uuid.uuid4())
        attrs.update({"audit.record.id": rid, "audit.schema.version": SCHEMA_VERSION,
                      "audit.integrity.canonicalization": "jcs",
                      "audit.sequence.stream_id": self.stream_id, "audit.sequence.number": self._seq})
        if self._head is not None:
            attrs["audit.sequence.previous_hash"] = self._head
            attrs["audit.sequence.previous_record_id"] = self._head_id
        if end:
            attrs["audit.sequence.end"] = True
        stamp = timestamp or _now_ns()
        record: dict[str, Any] = {"event_name": event_name, "timestamp": stamp, "observed_timestamp": stamp,
                                  "attributes": attrs}
        if body is not None:
            record["body"] = body
        if trace_id:
            record["trace_id"] = trace_id
        if span_id:
            record["span_id"] = span_id
        payload = signing_payload(record)
        attrs["audit.integrity.value"] = base64.b64encode(self.signer.sign(payload)).decode("ascii")
        attrs["audit.integrity.signer"] = "producer"
        self._head, self._head_id = sha256_hex(payload), rid
        self._ended = end
        self.records.append(record)
        return record, reveals

    def checkpoint(self, *, end: bool = False) -> dict[str, Any]:
        """A checkpoint record naming the stream's size and head, cosigned by the witness."""
        if self.witness is None:
            raise ValueError("this stream has no witness")
        size, head = self._seq, self._head or ""
        cosigned = self.witness(self.stream_id, size, head)
        record, _ = self.emit(CHECKPOINT_EVENT, {
            "audit.actor.id": "witness:" + cosigned["keyId"], "audit.actor.type": "service",
            "audit.action": "ATTEST", "audit.outcome": "success",
            "probity.witness.size": size, "probity.witness.head": head,
            "probity.witness.key_id": cosigned["keyId"], "probity.witness.signature": cosigned["sig"]}, end=end)
        return record

    def export_request(self, records: Iterable[Mapping[str, Any]] | None = None) -> dict[str, Any]:
        """An OTLP/JSON ``ExportLogsServiceRequest`` for ``records`` (default: every record)."""
        chosen = list(self.records if records is None else records)
        return {"resourceLogs": [{
            "resource": {"attributes": _attrs(self.resource_attributes)},
            "scopeLogs": [{"scope": {"name": SCOPE_NAME}, "logRecords": [to_otlp_record(r) for r in chosen]}]}]}


def post_logs(endpoint: str, request: Mapping[str, Any], timeout: float = 10.0) -> int:
    """POST an export request to an OTLP/HTTP receiver (``.../v1/logs``); returns the HTTP status."""
    data = json.dumps(request).encode("utf-8")
    req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as reply:  # noqa: S310 - the caller names its collector
        return int(reply.status)


# Mapping our signed records to audit records.

_ACTION = {"authorize": "AUTHORIZE", "intent": "EXECUTE", "effect": "EXECUTE"}
_OUTCOME = {"committed": "success", "confirmed": "success", "allow": "success", "not_run": "failure",
            "no_effect": "failure", "deny": "failure", "unknown": "unknown"}


def tool_call_attributes(envelope_line: bytes, statement: Mapping[str, Any], *,
                         actor_id: str, actor_type: str = "service") -> dict[str, Any]:
    """Audit and GenAI attributes for one journal line (a DSSE envelope over a tool-call statement).

    ``probity.record.sha256`` is the SHA-256 of the envelope line, the same digest the journal chains by,
    so the OTel record and the signed record are joined offline.
    """
    pred = statement.get("predicate", {})
    phase = str(pred.get("phase", ""))
    outcome = pred.get("outcome") or pred.get("decision") or "unknown"
    attrs: dict[str, Any] = {
        "audit.actor.id": actor_id, "audit.actor.type": actor_type,
        "audit.action": _ACTION.get(phase, phase.upper() or "RECORD"),
        "audit.outcome": _OUTCOME.get(str(outcome), "unknown"),
        "probity.record.sha256": hashlib.sha256(envelope_line.rstrip(b"\n")).hexdigest(),
        "probity.record.predicate_type": str(statement.get("predicateType", "")),
        "probity.record.seq": int(pred.get("seq", 0)),
    }
    if pred.get("tool"):
        attrs.update({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": pred["tool"],
                      "audit.target.id": pred["tool"], "audit.target.type": "gen_ai.tool"})
    if pred.get("toolCallId"):
        attrs["gen_ai.tool.call.id"] = pred["toolCallId"]
    if pred.get("runId"):
        attrs["gen_ai.conversation.id"] = pred["runId"]
    for source, name in (("permitId", "probity.permit.id"), ("argsSha256", "probity.args.sha256"),
                         ("grantDigest", "probity.grant.sha256"), ("reason", "probity.reason"),
                         ("phase", "probity.phase")):
        if pred.get(source):
            attrs[name] = str(pred[source])
    return attrs


def export_journal(stream: AuditStream, journal_path: os.PathLike[str] | str, *, actor_id: str,
                   redact_fields: Iterable[str] = ()) -> list[Reveal]:
    """Emit one audit record per journal line, in journal order; returns the reveals kept back."""
    reveals: list[Reveal] = []
    wanted = set(redact_fields)
    with open(journal_path, "rb") as handle:
        for line in handle:
            if not line.strip():
                continue
            envelope = json.loads(line)
            statement = json.loads(base64.b64decode(envelope["payload"]))
            attrs = tool_call_attributes(line, statement, actor_id=actor_id)
            pred = statement.get("predicate", {})
            redact = {name: pred[key] for key, name in (("context", "probity.context"),)
                      if name in wanted and pred.get(key)}
            _, kept = stream.emit("probity.tool_call." + str(pred.get("phase", "record")), attrs, redact=redact)
            reveals.extend(kept)
    return reveals


# The stream verifier.

@dataclass
class StreamReport:
    """Verdicts with their denominators: ``verified`` counts records whose signature checked; ``ok`` only
    when every record verified and no record, chain, witness or journal check refused."""

    records: int = 0
    verified: int = 0
    refused: list[dict[str, Any]] = field(default_factory=list)
    streams: dict[str, int] = field(default_factory=dict)
    witnessed: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.records > 0 and not self.refused and self.verified == self.records

    def refuse(self, where: str, reason: str) -> None:
        self.refused.append({"record": where, "reason": reason})


def _records_of(request: Mapping[str, Any]) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    for rl in request.get("resourceLogs", []):
        resource = {a["key"]: _from_otlp(a.get("value", {})) for a in rl.get("resource", {}).get("attributes", [])}
        for sl in rl.get("scopeLogs", []):
            for item in sl.get("logRecords", []):
                yield resource, from_otlp_record(item)


def verify_stream(requests: Iterable[Mapping[str, Any]], certificates: Iterable[bytes], *,
                  witness_keys: Iterable[bytes] = (), require_witness: bool = False,
                  journal_digests: Mapping[str, str] | None = None) -> StreamReport:
    """Verify OTLP/JSON export requests as a sink received them, in arrival order.

    Signatures are checked as a ``verifyprocessor`` checks them (certificate by ``sha256:`` fingerprint).
    Then, per ``audit.sequence.stream_id``: numbers run 1, 2, ... with no gap, each ``previous_hash`` is the
    preceding record's integrity hash, nothing follows ``audit.sequence.end``, every witness checkpoint is
    cosigned by a pinned witness key over the chain's real size and head, and every field listed in
    ``probity.redacted`` carries its hash. ``journal_digests`` (``probity.record.sha256`` -> stream id)
    names the signed journal lines that must each appear.
    """
    certs = {fingerprint(der): _cert_key(der) for der in certificates}
    witnesses = {key_id(load_public(pem)): load_public(pem) for pem in witness_keys}
    report = StreamReport()
    chains: dict[str, list[tuple[int, str, str, dict[str, Any]]]] = {}
    seen_digests: set[str] = set()
    for index, (resource, record) in enumerate(_records_of_all(requests)):
        report.records += 1
        attrs = record["attributes"]
        where = str(attrs.get("audit.record.id", f"#{index}"))
        key = certs.get(str(resource.get("audit.integrity.certificate", "")))
        if resource.get("audit.integrity.algorithm") != "EdDSA" or key is None:
            report.refuse(where, "certificate_mismatch")
            continue
        try:
            key.verify(base64.b64decode(str(attrs.get("audit.integrity.value", "")), validate=True),
                       signing_payload(record))
        except (InvalidSignature, ValueError):
            report.refuse(where, "integrity_mismatch")
            continue
        missing = [name for name in attrs.get("probity.redacted", []) if name + REDACTED_SUFFIX not in attrs]
        if missing:
            report.refuse(where, "redaction_hash_missing")
            continue
        stream = str(attrs.get("audit.sequence.stream_id", ""))
        number = attrs.get("audit.sequence.number")
        if not stream or not isinstance(number, int):
            report.refuse(where, "sequence_missing")
            continue
        chains.setdefault(stream, []).append((number, where, integrity_hash(record), record))
        if attrs.get("probity.record.sha256"):
            seen_digests.add(str(attrs["probity.record.sha256"]))
        report.verified += 1
    for stream, items in chains.items():
        _check_chain(stream, sorted(items, key=lambda item: item[0]), witnesses, require_witness, report)
    for digest in (journal_digests or {}):
        if digest not in seen_digests:
            report.refuse(digest, "journal_record_missing")
    return report


def _records_of_all(requests: Iterable[Mapping[str, Any]]) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    for request in requests:
        yield from _records_of(request)


def _check_chain(stream: str, items: list[tuple[int, str, str, dict[str, Any]]],
                 witnesses: Mapping[str, Ed25519PublicKey], require_witness: bool, report: StreamReport) -> None:
    report.streams[stream] = len(items)
    previous: tuple[int, str, str] | None = None
    ended = False
    heads: dict[int, str] = {}
    for number, where, digest, record in items:
        attrs = record["attributes"]
        expected = 1 if previous is None else previous[0] + 1
        if ended:
            report.refuse(where, "record_after_end")
        elif number != expected:
            report.refuse(where, "sequence_gap" if number > expected else "sequence_duplicate")
        elif previous is None and "audit.sequence.previous_hash" in attrs:
            report.refuse(where, "genesis_has_previous")
        elif previous is not None and (attrs.get("audit.sequence.previous_hash") != previous[2]
                                       or attrs.get("audit.sequence.previous_record_id") != previous[1]):
            report.refuse(where, "previous_hash_mismatch")
        heads[number] = digest
        if record.get("event_name") == CHECKPOINT_EVENT:
            _check_witness(stream, where, attrs, heads, witnesses, report)
        ended = ended or attrs.get("audit.sequence.end") is True
        previous = (number, where, digest)
    if require_witness and report.witnessed.get(stream, 0) == 0:
        report.refuse(stream, "witness_missing")


def _check_witness(stream: str, where: str, attrs: Mapping[str, Any], heads: Mapping[int, str],
                   witnesses: Mapping[str, Ed25519PublicKey], report: StreamReport) -> None:
    size, head = attrs.get("probity.witness.size"), attrs.get("probity.witness.head")
    key = witnesses.get(str(attrs.get("probity.witness.key_id", "")))
    if key is None:
        report.refuse(where, "witness_key_unpinned")
        return
    try:
        key.verify(base64.b64decode(str(attrs.get("probity.witness.signature", "")), validate=True),
                   witness_body(stream, int(size), str(head)))  # type: ignore[arg-type]
    except (InvalidSignature, ValueError, TypeError):
        report.refuse(where, "witness_signature_invalid")
        return
    if not isinstance(size, int) or heads.get(size, "") != head:
        report.refuse(where, "witness_head_mismatch")
        return
    report.witnessed[stream] = report.witnessed.get(stream, 0) + 1


__all__ = ["AuditStream", "Reveal", "StreamReport", "certificate_pem", "export_journal", "fingerprint",
           "from_otlp_record", "integrity_hash", "post_logs", "redacted_sha256", "reveal_matches",
           "self_signed_certificate", "signing_payload", "to_otlp_record", "tool_call_attributes",
           "verify_stream", "witness_signer"]
