"""``declared_versus_acted/v1``: did every call an agent made go where a verified discovery record declared?

Discovery (a DNS-AID SVCB record and its ``sig``) declares where an agent may be reached and under
which key. A verified binding says nothing about where the calls went. ``agent-evidence-observer``
records both sides at call time in one witnessed trajectory (``probity_observer.resolution``): a
``resolution`` event per discovery answer (owner name, SVCB records in presentation format, the
``sig`` as received, the JWKS URL and SHA-256 of the bytes fetched, the SHA-256 of the DNSSEC chain
as received) and a ``call`` event per request (endpoint, the resolution it relied on, the clock).
This adapter joins them.

It first verifies the trajectory against the consumer's pins, sharing no code with the observer:
each line is the RFC 8785 form of ``{"seq", "prev", "event"}``, ``seq`` counts from 1 without gaps,
``prev`` is the SHA-256 of the previous line (the first names the genesis digest of the trajectory
id), and the head, signed with Ed25519 in the ``probity-trajectory-head-v1`` domain by the witness
key the consumer pins, fixes the count and the last digest. A dropped tail, an entry past the head,
a broken link or a head of another trajectory or key is ``contradicted``: a call the observer did
not record is missing, never clean.

Then every call is judged at its own instant against the records it could have relied on (the
resolution it names, or every earlier resolution when it names none):

- ``contradicted`` when no record declares the call's host and port (``call_not_declared``), or
  every declaring record's binding is contradicted at the call's instant (expired, a foreign key,
  parameters that do not match the signature): a call that went elsewhere, or after ``exp``;
- ``not_established`` when the best binding is endpoint-only, unsigned, has no key authority, or its
  JWKS or chain bytes were not supplied;
- ``supported`` when a declaring record's binding is ``supported`` under ``dns_aid_sig/v1`` rules
  (full coverage, key authorised for the zone, inside its window) at the call's instant.

The trajectory's verdict is the least favourable call's; a trajectory with no call is
``not_established`` (``no_calls_recorded``). The scope carries the denominator: events, resolutions,
calls, and calls bound, contradicted and unestablished. The JWKS and chain bytes are case artifacts
the assessment lists under ``evidence``; each resolution selects them by the SHA-256 it recorded.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..common import CaseError
from ..ijson import IJSONError, parse_ijson
from . import dns_aid_sig, jcs_canonical

CLAIM_TYPE = "declared_versus_acted/v1"
GENESIS_FORMAT = "probity-trajectory-genesis-v1"
HEAD_FORMAT = "probity-trajectory-head-v1"
CANONICALIZATIONS = ("jcs_integer_only_v1", "rfc8785")
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: SvcParamKeys by number (RFC 9460 section 14.3.2) and the DNS-AID private-use keys.
_KEY_NAMES = {0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port", 4: "ipv4hint", 5: "ech",
              6: "ipv6hint", 65400: "cap", 65401: "cap-sha256", 65402: "bap", 65403: "policy",
              65404: "realm", 65405: "sig", 65406: "connect-class", 65407: "connect-meta",
              65408: "enroll-uri", 65409: "well-known"}
_SEVERITY = {"supported": 0, "not_established": 1, "contradicted": 2}


class _Refused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _canonical(value: Any) -> bytes:
    return jcs_canonical.canonical("rfc8785", json.dumps(value, ensure_ascii=False))


def genesis(trajectory_id: str) -> str:
    return hashlib.sha256(_canonical({"format": GENESIS_FORMAT, "trajectory": trajectory_id})).hexdigest()


def verify_trajectory(raw: bytes, head_raw: bytes, trajectory_id: str, witness_key: str,
                      canonicalization: str) -> list[dict]:
    """The trajectory's events, in order, once every link and the witnessed head verify."""
    try:
        head = parse_ijson(head_raw)
    except IJSONError as exc:
        raise _Refused("trajectory_head_malformed") from exc
    if not isinstance(head, dict) or set(head) != {"format", "trajectory", "count", "head", "keyid",
                                                    "signature"}:
        raise _Refused("trajectory_head_malformed")
    if head["format"] != HEAD_FORMAT or not isinstance(head["count"], int) or isinstance(
            head["count"], bool) or head["count"] < 0 or not isinstance(head["signature"], str):
        raise _Refused("trajectory_head_malformed")
    if head["trajectory"] != trajectory_id:
        raise _Refused("trajectory_head_other_trajectory")
    if head["keyid"] != witness_key:
        raise _Refused("trajectory_head_other_key")
    payload = {m: head[m] for m in ("format", "trajectory", "count", "head")}
    try:
        signature = base64.b64decode(head["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(witness_key)).verify(
            signature, HEAD_FORMAT.encode("ascii") + b"\x00" + _canonical(payload))
    except (InvalidSignature, ValueError, binascii.Error, TypeError) as exc:
        raise _Refused("trajectory_head_signature_invalid") from exc
    if raw and not raw.endswith(b"\n"):
        raise _Refused("trajectory_line_incomplete")
    events, previous = [], genesis(trajectory_id)
    for number, line in enumerate(raw.splitlines(), start=1):
        try:
            entry = parse_ijson(line, integers_only=canonicalization == "jcs_integer_only_v1")
        except IJSONError as exc:
            raise _Refused("trajectory_entry_malformed") from exc
        if not isinstance(entry, dict) or set(entry) != {"seq", "prev", "event"} or not isinstance(
                entry["event"], dict):
            raise _Refused("trajectory_entry_malformed")
        if _canonical(entry) != line:
            raise _Refused("trajectory_entry_not_canonical")
        if entry["seq"] != number or isinstance(entry["seq"], bool):
            raise _Refused("trajectory_sequence_gap")
        if entry["prev"] != previous:
            raise _Refused("trajectory_link_broken")
        previous = hashlib.sha256(line).hexdigest()
        events.append(entry)
    if len(events) < head["count"]:
        raise _Refused("trajectory_tail_missing")
    if len(events) > head["count"]:
        raise _Refused("trajectory_entries_past_head")
    if previous != head["head"]:
        raise _Refused("trajectory_head_mismatch")
    return events


def _unquote(text: str) -> str:
    """An SVCB parameter value: RFC 1035 character-string with ``\\X`` and ``\\DDD`` escapes."""
    out, index = bytearray(), 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            if re.fullmatch(r"\d{3}", text[index + 1:index + 4]):
                out.append(int(text[index + 1:index + 4]))
                index += 4
                continue
            if index + 1 >= len(text):
                raise ValueError("dangling escape")
            char = text[index + 1]
            index += 1
        out += char.encode("utf-8")
        index += 1
    return out.decode("utf-8")


def parse_svcb(text: Any) -> tuple[int, str, dict[str, str]]:
    """``(priority, target, params)`` of one SVCB record in presentation format (RFC 9460 section 2.1)."""
    if not isinstance(text, str) or not text.isascii():
        raise ValueError("expected an ASCII SVCB record")
    tokens = re.findall(r'(?:[^\s"\\]|\\.)*"(?:[^"\\]|\\.)*"|(?:[^\s"\\]|\\.)+', text)
    if len(tokens) < 2 or not tokens[0].isdigit():
        raise ValueError("expected '<priority> <target> [key=value ...]'")
    params: dict[str, str] = {}
    for token in tokens[2:]:
        key, _, value = token.partition("=")
        number = re.fullmatch(r"key(\d{1,5})", key)
        name = _KEY_NAMES.get(int(number.group(1)), key) if number else key
        if not re.fullmatch(r"[a-z0-9-]+", name) or name in params:
            raise ValueError(f"malformed or repeated SvcParamKey {key!r}")
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        params[name] = _unquote(value)
    return int(tokens[0]), tokens[1], params


def _records(event: dict, zone: str) -> list[dict]:
    """The served records of one resolution, in the shape ``dns_aid_sig`` judges."""
    out = []
    for text in event["svcb"]:
        try:
            priority, target, params = parse_svcb(text)
        except ValueError:
            out.append({"_malformed": True})
            continue
        if priority == 0:
            continue  # AliasMode names another owner; it declares no endpoint itself
        port = params.get("port")
        record: dict[str, Any] = {
            "fqdn": event["name"], "target": event["name"] if target == "." else target,
            "port": int(port) if port is not None and port.isdigit() and int(port) <= 65535 else None,
            "alpn": params.get("alpn", ""), "zone": zone,
            "params": {k: params[k] for k in dns_aid_sig.COVERED_PARAMS if k in params},
            "sig": params.get("sig", event.get("sig")), "_sig_in_record": "sig" in params}
        if "proto" in params:
            record["proto"] = params["proto"]
        if isinstance(event.get("jwks"), dict):
            record["jwks_url"] = event["jwks"].get("url")
        out.append(record)
    return out


def _endpoint(text: Any) -> tuple[str, int]:
    if not isinstance(text, str) or not text.isascii():
        raise ValueError("endpoint")
    parts = urlsplit(text if "://" in text else "//" + text)
    port = parts.port
    if port is None:
        port = {"https": 443, "http": 80}.get(parts.scheme)
    host = dns_aid_sig.dns_name(parts.hostname)
    if port is None or host is None:
        raise ValueError("endpoint")
    return host, port


def _event_shape(event: dict) -> bool:
    if event.get("kind") == "resolution":
        jwks = event.get("jwks")
        return (isinstance(event.get("name"), str) and isinstance(event.get("svcb"), list)
                and all(isinstance(r, str) for r in event["svcb"])
                and (event.get("sig") is None or isinstance(event["sig"], str))
                and (jwks is None or (isinstance(jwks, dict) and set(jwks) == {"url", "sha256"}
                                      and isinstance(jwks["url"], str)
                                      and isinstance(jwks["sha256"], str)))
                and (event.get("dnssec_chain_sha256") is None
                     or isinstance(event["dnssec_chain_sha256"], str))
                and isinstance(event.get("at"), str))
    if event.get("kind") == "call":
        resolution = event.get("resolution")
        return (isinstance(event.get("endpoint"), str) and isinstance(event.get("at"), str)
                and (resolution is None or (isinstance(resolution, int)
                                            and not isinstance(resolution, bool))))
    return True


def _judge_record(record: dict, event: dict, supplied: dict[str, bytes], at, authority: Any,
                  authority_evidence: dict) -> dns_aid_sig.Binding:
    if record.get("_malformed") or record.get("port") is None:
        return dns_aid_sig.Binding("contradicted", "record_malformed", "invalid", "none")
    if record["sig"] is None:
        return dns_aid_sig.Binding("not_established", "record_unsigned", "unsigned", "none")
    if record["_sig_in_record"] and event.get("sig") is not None and event["sig"] != record["sig"]:
        return dns_aid_sig.Binding("contradicted", "resolution_sig_inconsistent", "invalid", "none")
    served = {k: v for k, v in record.items() if not k.startswith("_")}
    jwks = event.get("jwks")
    jwks_raw = supplied.get(jwks["sha256"]) if isinstance(jwks, dict) else None
    extra = dict(authority_evidence)
    if isinstance(authority, dict) and authority.get("kind") == "dnssec-chain" and "chain" not in authority:
        extra["dnssec_chain"] = supplied.get(event.get("dnssec_chain_sha256") or "")
    kind = authority.get("kind") if isinstance(authority, dict) else None
    return dns_aid_sig.judge(served, jwks_raw, at, authority, extra, kind)


def adjudicate(case, policy, artifact_root):
    """Join the witnessed resolution and call events of one trajectory."""
    from ..key_authority import KINDS, evidence
    from .bound_records import assessment_for, bound, decision
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"trajectory", "head", "trajectory_id", "witness_key", "zone"},
        {"key_authority", "evidence", "canonicalization"})
    trajectory_id, witness_key = assessment["trajectory_id"], assessment["witness_key"]
    if not isinstance(trajectory_id, str) or not trajectory_id or not trajectory_id.isascii():
        raise CaseError("assessment.trajectory_id: expected a non-empty ASCII string")
    if not isinstance(witness_key, str) or not _HEX64.fullmatch(witness_key):
        raise CaseError("assessment.witness_key: expected a raw Ed25519 public key as 64 lowercase hex")
    zone = dns_aid_sig.dns_name(assessment["zone"])
    if zone is None:
        raise CaseError("assessment.zone: expected a DNS name")
    canonicalization = assessment.get("canonicalization", "jcs_integer_only_v1")
    if canonicalization not in CANONICALIZATIONS:
        raise CaseError(f"assessment.canonicalization: expected one of {list(CANONICALIZATIONS)}")
    authority = assessment.get("key_authority")
    if authority is not None and (not isinstance(authority, dict) or authority.get("kind") not in KINDS):
        raise CaseError(f"assessment.key_authority.kind: expected one of {list(KINDS)}")
    names = assessment.get("evidence", [])
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise CaseError("assessment.evidence: expected a list of case artifact names")
    raw, trajectory_binding = bound(artifacts, artifact_root, assessment["trajectory"],
                                    "assessment.trajectory")
    head_raw, head_binding = bound(artifacts, artifact_root, assessment["head"], "assessment.head")
    scope: dict = {"trajectory": trajectory_binding, "head": head_binding, "zone": zone,
                   "trajectory_id": trajectory_id}
    supplied: dict[str, bytes] = {}
    scope["evidence"] = []
    for name in names:
        data, binding = bound(artifacts, artifact_root, name, "assessment.evidence")
        scope["evidence"].append(binding)
        if data is not None:
            supplied[hashlib.sha256(data).hexdigest()] = data
    authority_evidence = evidence(authority, artifacts, artifact_root, scope)
    if raw is None or head_raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "trajectory_unavailable")
    try:
        entries = verify_trajectory(raw, head_raw, trajectory_id, witness_key, canonicalization)
    except _Refused as refusal:
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", refusal.reason,
                        [{"id": "trajectory", "status": "fail", "reason": refusal.reason}])
    checks: list[dict] = [{"id": "trajectory", "status": "pass", "count": len(entries)}]
    resolutions: dict[int, dict] = {}
    tally = {"events": len(entries), "resolutions": 0, "calls": 0, "calls_bound": 0,
             "calls_contradicted": 0, "calls_unestablished": 0}
    worst = ("supported", "every_call_declared_and_bound")
    for entry in entries:
        event = entry["event"]
        if not _event_shape(event):
            return decision(case_id, CLAIM_TYPE, scope | {"denominator": tally}, "contradicted",
                            "trajectory_event_malformed", checks)
        if event.get("kind") == "resolution":
            resolutions[entry["seq"]] = event
            tally["resolutions"] += 1
        if event.get("kind") != "call":
            continue
        tally["calls"] += 1
        call = _judge_call(entry["seq"], event, resolutions, zone, supplied, authority,
                           authority_evidence)
        checks.append(call)
        outcome = {"pass": "supported", "fail": "contradicted", "unavailable": "not_established"}[
            call["status"]]
        tally[{"supported": "calls_bound", "contradicted": "calls_contradicted",
               "not_established": "calls_unestablished"}[outcome]] += 1
        if _SEVERITY[outcome] > _SEVERITY[worst[0]]:
            worst = (outcome, call["reason"])
    scope["denominator"] = tally
    if tally["calls"] == 0:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "no_calls_recorded", checks)
    return decision(case_id, CLAIM_TYPE, scope, worst[0], worst[1], checks)


def _judge_call(seq: int, event: dict, resolutions: dict[int, dict], zone: str,
                supplied: dict[str, bytes], authority: Any, authority_evidence: dict) -> dict:
    check: dict[str, Any] = {"id": "call", "seq": seq, "endpoint": event["endpoint"],
                             "at": event["at"], "resolution": event["resolution"]}
    try:
        at = dns_aid_sig.instant(event["at"], f"call {seq}.at")
    except CaseError:
        return check | {"status": "fail", "reason": "call_time_malformed"}
    try:
        host, port = _endpoint(event["endpoint"])
    except ValueError:
        return check | {"status": "fail", "reason": "call_endpoint_malformed"}
    if event["resolution"] is None:
        candidates = list(resolutions.values())
    elif event["resolution"] in resolutions:
        candidates = [resolutions[event["resolution"]]]
    else:
        return check | {"status": "fail", "reason": "call_names_unknown_resolution"}
    declaring = [(record, source) for source in candidates for record in _records(source, zone)
                 if not record.get("_malformed") and record.get("port") == port
                 and dns_aid_sig.dns_name(record.get("target")) == host]
    if not declaring:
        return check | {"status": "fail", "reason": "call_not_declared"}
    bindings = [_judge_record(r, s, supplied, at, authority, authority_evidence) for r, s in declaring]
    best = min(bindings, key=lambda b: _SEVERITY[b.decision])  # the record the call could rely on
    status = {"supported": "pass", "contradicted": "fail", "not_established": "unavailable"}[best.decision]
    reason = "call_declared_and_bound" if best.decision == "supported" else best.reason
    return check | {"status": status, "reason": reason, "binding": best.scope() | {
        "decision": best.decision, "reason": best.reason, "checks": best.checks}}
