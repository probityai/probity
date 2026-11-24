"""``dns_aid_sig/v1``: does a DNS-AID discovery record's ``sig`` bind the record to its zone owner?

A DNS-AID record (an SVCB record under ``_agents.<zone>``) may carry ``sig`` (SvcParam key65405): a
compact JWS, ES256, whose payload names the endpoint (``fqdn``, ``target``, ``port``, ``alpn``), a
validity window (``iat``, ``exp``) and, optionally, ``svcb``: the SHA-256 of the other DNS-AID
parameters, ``svcb1:`` followed by their JSON form with sorted keys, absent parameters left out.
The signing key is published as a JWKS at ``https://dns-aid.<zone>/``. This reader shares no code
with the publisher's implementation and imports no DNS library.

A signature that verifies under the key the evidence carries proves nothing by itself: whoever
forges the record ships their own JWKS beside it. So the verdict is ``supported`` only when the
consumer's ``key_authority`` (:mod:`agent_evidence_verify.key_authority`: a pin, a DNSSEC-validated
key record, a key-transparency inclusion, a DID document or a registry) authorises the key that
verified, for the record's zone, at the consumer's instant. The rules of the
``dns-aid-sig-binding/v1`` profile, each a check of its own:

- The JWS is three strict, canonical base64url parts (RFC 7515 section 2 and RFC 4648 section 5,
  no padding, no other alphabet, no non-zero trailing bits), and header and payload are I-JSON
  objects (RFC 7493: a repeated member name is refused, so a first-wins and a last-wins reader
  cannot bind two different values to one signature).
- ``crit`` in the header is refused (RFC 7515 section 4.1.11: this reader understands no
  extension), and ``alg`` is ``ES256`` with a 64-byte signature.
- ``port``, ``iat`` and ``exp`` are JSON integers: ``443.0`` is not ``443``. The record's ``port``
  is a port, 0 to 65535, and a window whose ``exp`` is at or before its ``iat`` is refused.
- The record is expired when ``exp`` is at or before the instant, and not yet valid when ``iat`` is
  more than 300 seconds after it.
- The signed endpoint is the served one: ``fqdn`` and ``target`` compared as DNS names (case and a
  trailing dot ignored), ``port`` exactly, and ``alpn`` against the record's ``proto`` when it
  carries one (draft-dawn-dnsaid-00 Table 1: ``alpn`` names the transport, ``proto`` the agent
  protocol) and against its ``alpn`` otherwise (the draft -02 shape).
- When the payload carries ``svcb``, it equals the digest of the served parameters, where an empty
  value is a value and only an absent parameter is left out: a parameter the publisher never set
  cannot be injected as ``""``. A payload without ``svcb`` attests the endpoint only, and the
  verdict is ``not_established`` with ``signature_coverage`` ``endpoint_only``.
- A JWKS URL in the record is ``https://dns-aid.<zone>/...`` or the zone apex, never another host,
  read so that every common client reads the same host (:func:`url_authority`): a backslash, a
  userinfo part, a control character, a percent-encoded or otherwise non-hostname host and a port
  outside 0 to 65535 are refused, because ``https://evil.example\\@dns-aid.example.com/`` names
  ``dns-aid.example.com`` to Python's ``urlsplit`` and ``evil.example`` to urllib3 and browsers.

Every malformed input that a record, its signature or its JWKS can carry yields a verdict, never an
exception; only the consumer's own policy is refused as a case error. Every decision states the
SHA-256 key-set fingerprint of the JWKS it read (``jwks_key_set_sha256``) and, when the authority
was asked, the fingerprint of the keys the authority trusted; a decision past the signature check
names the ``fqdn`` and ``zone`` the record claimed, because the zone is the record's own word and
the authority was asked about that zone alone.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..common import CaseError
from ..identifiers import identifier
from ..ijson import IJSONError, parse_ijson
from . import jcs_canonical

CLAIM_TYPE = "dns_aid_sig/v1"
PROFILE = identifier("agent-evidence-vectors/profile/dns-aid-sig-binding/v1")

SIGNATURE_COVERAGE_TERM = "https://w3id.org/agent-evidence/vocab/v1/signature_coverage"
SKEW_SECONDS = 300
#: The DNS-AID parameters ``svcb`` covers: every DNS-AID SvcParam except ``sig`` itself.
COVERED_PARAMS = ("cap", "cap-sha256", "bap", "policy", "realm", "connect-class", "connect-meta",
                  "enroll-uri", "well-known")
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_RECORD_MEMBERS = {"fqdn", "target", "port", "alpn", "zone", "params", "sig"}
_RECORD_OPTIONAL = {"proto", "jwks_url"}
_HOSTNAME = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?")


class _Refused(Exception):
    """A record-side refusal: the decision and reason it maps to."""

    def __init__(self, decision: str, reason: str, status: str) -> None:
        super().__init__(reason)
        self.decision, self.reason, self.status = decision, reason, status


@dataclass
class Binding:
    """One verdict over one record: decision, reason, the dns-aid status and the checks made."""

    decision: str
    reason: str
    status: str
    coverage: str
    checks: list[dict] = field(default_factory=list)
    jwks_key_set_sha256: str = ""
    key_sha256: str | None = None
    endpoint: tuple[str, int] | None = None
    window: tuple[int, int] | None = None
    claimed: tuple[str, str] | None = None  # (fqdn, zone) as the record names them

    def scope(self) -> dict:
        out = {"profile": PROFILE, "dns_aid_status": self.status,
               "signature_coverage": {"term": SIGNATURE_COVERAGE_TERM, "value": self.coverage},
               "jwks_key_set_sha256": self.jwks_key_set_sha256}
        if self.key_sha256 is not None:
            out["signing_key_sha256"] = self.key_sha256
        if self.endpoint is not None:
            out["endpoint"] = {"target": self.endpoint[0], "port": self.endpoint[1]}
        if self.window is not None:
            out["window"] = {"iat": self.window[0], "exp": self.window[1]}
        if self.claimed is not None:
            out["fqdn"], out["zone"] = self.claimed
        return out


def b64url(text: Any) -> bytes:
    """Strict canonical unpadded base64url, or :class:`ValueError`."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not base64url") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != text:
        raise ValueError("base64url not in canonical form")
    return raw


def dns_name(value: Any) -> str | None:
    """A name compared as DNS compares it: lowercase ASCII, no trailing dot; None if not a name."""
    if not isinstance(value, str) or not value or not value.isascii():
        return None
    return value.rstrip(".").lower()


def within(name: Any, zone: Any) -> bool:
    n, z = dns_name(name), dns_name(zone)
    return n is not None and z is not None and (n == z or n.endswith("." + z))


def url_authority(text: Any, *, default_scheme: bool = False) -> tuple[str, str, int | None]:
    """``(scheme, host, port)`` of a URL every common client reads alike, or :class:`ValueError`.

    Python's ``urlsplit``, urllib3 and the WHATWG URL parser disagree on a backslash, on userinfo,
    on tabs and newlines and on percent-encoded hosts, so a URL carrying any of them names one host
    to this reader and another to the client that fetched or called it. Such a URL is refused, as is
    a host that is neither a hostname nor an IP literal and a port outside 0 to 65535. With
    ``default_scheme`` a bare ``host:port`` is read as an authority.
    """
    if not isinstance(text, str) or not text.isascii() or "\\" in text or any(
            ord(char) <= 0x20 or ord(char) == 0x7F for char in text):
        raise ValueError("URL carries a character clients read differently")
    parts = urlsplit(text if "://" in text or not default_scheme else "//" + text)  # ValueError on [
    if "@" in parts.netloc:
        raise ValueError("URL carries userinfo")
    host, port = parts.hostname, parts.port  # .port raises ValueError outside 0..65535
    if not host:
        raise ValueError("URL names no host")
    if "%" in host:
        raise ValueError("URL host carries a percent sign or an IPv6 zone")
    if ":" in host:
        ipaddress.IPv6Address(host.strip("[]"))
    elif not _HOSTNAME.fullmatch(host):
        raise ValueError("URL host is not a hostname")
    return parts.scheme, host.rstrip(".").lower(), port


def svcb1(params: dict[str, str | None]) -> str:
    """``svcb1:`` digest of the covered parameters: RFC 8785 of the present ones, base64url SHA-256.

    For a map of ASCII names to strings, RFC 8785 is byte for byte the sorted, compact JSON the
    publisher hashes, so the digest is the publisher's without sharing its code.
    """
    present = {name: value for name, value in params.items() if value is not None}
    text = json.dumps(present, ensure_ascii=False)
    digest = hashlib.sha256(b"svcb1:" + jcs_canonical.canonical("rfc8785", text)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _json_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def read_record(raw: Any) -> dict:
    """The served record as an object, or :class:`_Refused` (contradicted, record_malformed)."""
    try:
        record = parse_ijson(raw) if isinstance(raw, (bytes, str)) else raw
    except IJSONError as exc:
        raise _Refused("contradicted", "record_not_ijson", "invalid") from exc
    ok = (isinstance(record, dict) and _RECORD_MEMBERS <= set(record)
          and set(record) <= _RECORD_MEMBERS | _RECORD_OPTIONAL
          and all(dns_name(record[m]) for m in ("fqdn", "target", "zone"))
          and _json_int(record["port"]) and 0 <= record["port"] <= 0xFFFF
          and isinstance(record["alpn"], str)
          and isinstance(record.get("proto", ""), str) and isinstance(record["sig"], str)
          and isinstance(record.get("jwks_url", ""), str) and isinstance(record["params"], dict)
          and set(record["params"]) <= set(COVERED_PARAMS)
          and all(v is None or isinstance(v, str) for v in record["params"].values()))
    if not ok:
        raise _Refused("contradicted", "record_malformed", "invalid")
    return record


def jwks_keys(raw: bytes | None) -> tuple[list[tuple[str | None, bytes]], str]:
    """The P-256 signing keys of a JWKS as ``(kid, 0x04||x||y)``, and their key-set fingerprint."""
    from ..key_authority import jwk_key_bytes, key_set_fingerprint, key_sha256
    if raw is None:
        raise _Refused("not_established", "jwks_unavailable", "no_key")
    try:
        document = parse_ijson(raw)
    except IJSONError as exc:
        raise _Refused("not_established", "jwks_malformed", "no_key") from exc
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise _Refused("not_established", "jwks_malformed", "no_key")
    keys = []
    for jwk in document["keys"]:
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            continue
        if jwk.get("use", "sig") != "sig" or ("key_ops" in jwk and (
                not isinstance(jwk["key_ops"], list) or "verify" not in jwk["key_ops"])):
            continue
        try:
            point = jwk_key_bytes(jwk, "jwks")
        except CaseError:
            continue
        kid = jwk.get("kid")
        keys.append((kid if isinstance(kid, str) else None, point))
    return keys, key_set_fingerprint(key_sha256(k) for _, k in keys)


def _verifies(point: bytes, signature: bytes, signing_input: bytes) -> bool:
    try:
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                   int.from_bytes(signature[32:], "big"))
        public.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False
    return True


def _jws(sig: str) -> tuple[dict, bytes, bytes, bytes]:
    """Header, payload bytes, signature and signing input of a compact ES256 JWS."""
    parts = sig.split(".")
    if len(parts) != 3:
        raise _Refused("contradicted", "jws_malformed", "invalid")
    try:
        header_bytes, payload_bytes = b64url(parts[0]), b64url(parts[1])
    except ValueError as exc:
        raise _Refused("contradicted", "jws_malformed", "invalid") from exc
    try:
        header = parse_ijson(header_bytes)
    except IJSONError as exc:
        raise _Refused("contradicted", "jws_header_not_ijson", "invalid") from exc
    if not isinstance(header, dict):
        raise _Refused("contradicted", "jws_header_not_object", "invalid")
    if "crit" in header:
        raise _Refused("contradicted", "jws_crit_unsupported", "invalid")
    if header.get("alg") != "ES256":
        raise _Refused("contradicted", "jws_alg_not_es256", "invalid")
    try:
        signature = b64url(parts[2])
    except ValueError as exc:
        raise _Refused("contradicted", "jws_signature_malformed", "invalid") from exc
    if len(signature) != 64:
        raise _Refused("contradicted", "jws_signature_malformed", "invalid")
    return header, payload_bytes, signature, f"{parts[0]}.{parts[1]}".encode("ascii")


def _posix(at: datetime.datetime) -> int:
    return int(at.timestamp())


def judge(record_raw: Any, jwks_raw: bytes | None, at: datetime.datetime, authority: Any,
          authority_evidence: dict | None = None, subject_kind: str | None = None) -> Binding:
    """Judge one served record at the consumer's instant ``at``; never raises on record input."""
    from ..key_authority import (
        AUTHORIZED,
        UNAUTHORIZED,
        authorize,
        key_set_fingerprint,
        key_sha256,
    )
    checks: list[dict] = []
    fingerprint = key_set_fingerprint([])
    try:
        keys, fingerprint = jwks_keys(jwks_raw)  # first, so every verdict names the key set read
        unreadable = None
    except _Refused as refusal:
        keys, unreadable = [], refusal
    try:
        record = read_record(record_raw)
        header, payload_bytes, signature, signing_input = _jws(record["sig"])
        if unreadable is not None:
            raise unreadable
        kid = header.get("kid") if isinstance(header.get("kid"), str) else None
        candidates = [k for k_id, k in keys if kid is not None and k_id == kid] or [k for _, k in keys]
        if not candidates:
            raise _Refused("not_established", "jwks_no_usable_key", "no_key")
        verifying = next((k for k in candidates
                          if _verifies(k, signature, signing_input)), None)
        if verifying is None:
            raise _Refused("contradicted", "signature_invalid", "invalid")
        checks.append({"id": "jws_signature", "status": "pass", "alg": "ES256",
                       "key_sha256": key_sha256(verifying)})
        try:
            payload = parse_ijson(payload_bytes)
        except IJSONError as exc:
            raise _Refused("contradicted", "payload_not_ijson", "invalid") from exc
        if not isinstance(payload, dict):
            raise _Refused("contradicted", "payload_not_object", "invalid")
        if not all(_json_int(payload.get(m)) for m in ("port", "iat", "exp")):
            raise _Refused("contradicted", "payload_member_not_integer", "invalid")
        window = (payload["iat"], payload["exp"])
        if payload["exp"] <= payload["iat"]:
            raise _Refused("contradicted", "payload_window_inverted", "invalid")
        now = _posix(at)
        if payload["exp"] <= now:
            raise _Refused("contradicted", "binding_expired", "expired")
        protocol = record.get("proto") or record["alpn"]
        if not (dns_name(payload.get("fqdn")) == dns_name(record["fqdn"])
                and dns_name(payload.get("target")) == dns_name(record["target"])
                and payload["port"] == record["port"] and payload.get("alpn") == protocol):
            raise _Refused("contradicted", "endpoint_not_bound", "unbound")
        checks.append({"id": "endpoint_binding", "status": "pass", "protocol_from":
                       "proto" if record.get("proto") else "alpn"})
        coverage = "endpoint_only"
        if "svcb" in payload:
            params = {name: record["params"].get(name) for name in COVERED_PARAMS}
            if payload["svcb"] != svcb1(params):
                raise _Refused("contradicted", "params_not_bound", "unbound")
            coverage = "full"
            checks.append({"id": "svcb_binding", "status": "pass", "digest": payload["svcb"]})
        if not within(record["fqdn"], record["zone"]):
            raise _Refused("not_established", "zone_does_not_contain_record", "no_key")
        url = record.get("jwks_url")
        if url is not None:
            try:
                scheme, host, _ = url_authority(url)
            except ValueError as exc:
                raise _Refused("contradicted", "jwks_url_malformed", "invalid") from exc
            zone = dns_name(record["zone"])
            if scheme != "https" or host not in (f"dns-aid.{zone}", zone):
                raise _Refused("contradicted", "jwks_host_not_zone", "invalid")
        zone = dns_name(record["zone"])
        subject = f"did:web:{zone}" if subject_kind == "did-web" else zone
        answer = authorize(authority, verifying, kid=kid, subject=subject, at=at,
                           **(authority_evidence or {}))
        checks.append(answer.check())
        base = Binding("", "", "", coverage, checks, fingerprint, key_sha256(verifying),
                       (dns_name(record["target"]) or "", record["port"]), window,
                       (dns_name(record["fqdn"]) or "", zone))
        if answer.outcome == UNAUTHORIZED:
            base.decision, base.reason, base.status = "contradicted", answer.reason, "invalid"
            return base
        if payload["iat"] > now + SKEW_SECONDS:
            base.decision, base.reason, base.status = "not_established", "binding_not_yet_valid", \
                "not_yet_valid"
            return base
        if answer.outcome != AUTHORIZED:
            base.decision, base.reason, base.status = "not_established", answer.reason, coverage
            return base
        if coverage != "full":
            base.decision, base.reason, base.status = "not_established", "endpoint_only", \
                "endpoint_only"
            return base
        base.decision, base.reason, base.status = "supported", "binding_verified", "full"
        return base
    except _Refused as refusal:
        return Binding(refusal.decision, refusal.reason, refusal.status,
                       "none" if refusal.decision == "contradicted" or refusal.status == "no_key"
                       else "endpoint_only", checks, fingerprint)
    except RecursionError:
        return Binding("contradicted", "input_too_deep", "invalid", "none", checks, fingerprint)


def instant(value: Any, label: str) -> datetime.datetime:
    """The consumer's RFC 3339 instant as an aware ``datetime`` (seconds; a fraction is dropped)."""
    from ..key_authority import parse_instant, posix_seconds
    seconds = posix_seconds(parse_instant(value, label))
    return datetime.datetime.fromtimestamp(seconds, datetime.UTC)


def adjudicate(case, policy, artifact_root):
    """Judge the bound record and JWKS under the consumer's key authority at its instant."""
    from ..key_authority import KINDS, evidence
    from .bound_records import assessment_for, bound, decision
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, {"record", "jwks", "at"},
                                                    {"key_authority"})
    at = instant(assessment["at"], "assessment.at")
    authority = assessment.get("key_authority")
    if authority is not None and (not isinstance(authority, dict) or authority.get("kind") not in KINDS):
        raise CaseError(f"assessment.key_authority.kind: expected one of {list(KINDS)}")
    record_raw, record_binding = bound(artifacts, artifact_root, assessment["record"], "assessment.record")
    jwks_raw, jwks_binding = bound(artifacts, artifact_root, assessment["jwks"], "assessment.jwks")
    scope: dict = {"record": record_binding, "jwks": jwks_binding, "at": assessment["at"]}
    supplied = evidence(authority, artifacts, artifact_root, scope)
    if record_raw is None:
        scope.update(Binding("", "", "no_key", "none").scope())
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "record_unavailable")
    result = judge(record_raw, jwks_raw, at, authority, supplied,
                   authority.get("kind") if isinstance(authority, dict) else None)
    scope.update(result.scope())
    return decision(case_id, CLAIM_TYPE, scope, result.decision, result.reason, result.checks)
