"""``capability_credential/v1``: is this agent capability credential valid for the consumer, now, and are its
signers distinct?

The ``capability-credential/v1`` profile is one verifier input for every agent credential format: an issuer, a
subject agent, a capability list, a validity window, an optional revocation reference and use limit, an optional
required number of cosigners, and Ed25519 signatures by key id. A format-specific reader maps its own record into
this input; the rules below then apply the same way to every format.

The verifier state is the consumer's, never the credential's: the trusted issuers and their keys, the cosigner keys
and the authority each belongs to, a pinned clock and a revocation list. A flag the credential carries about itself
(``revoked: true``) is not an input.

Checks, in order; each failure has its own code and the first one is the reason:

1. reading the credential, before any signature: a repeated member (``duplicate_member``), a member the profile
   does not define, including a case variant such as ``Capabilities`` that a case-insensitive decoder would read as
   the signed list (``unknown_member``), a number token that is not its own canonical spelling, such as ``-0`` or
   ``1.0`` (``noncanonical_number``), and a time that carries any JSON escape, a non-ASCII digit, a trailing line
   feed or anything outside ``YYYY-MM-DDTHH:MM:SSZ`` (``timestamp_grammar``);
2. ``issuer_untrusted``: the issuer is not one the consumer trusts;
3. ``signature_invalid``: the issuer's signature does not verify over ``capability-credential/v1 || 0x00 ||
   RFC 8785 (the credential without signatures)``;
4. signer distinctness, per the ``signer_distinctness`` term: a named cosigner whose signature is absent or does
   not verify, or two signatures under one key id (``key_named_not_signing``), the issuer's own key listed as a
   cosigner (``own_key_as_cosigner``), one key under two key ids counted twice (``one_key_two_ids``), a threshold met
   only by keys of one authority (``one_authority_threshold``), and fewer distinct keys than required
   (``below_threshold``); a cosigner key the consumer does not know is ``cosigner_untrusted``;
5. ``not_yet_valid`` and ``expired`` against the consumer's pinned clock;
6. ``revoked``: the credential id is on the consumer's revocation list.

Otherwise ``supported`` / ``credential_valid``. Every refusal is ``contradicted``.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import json
import json.decoder
import json.scanner
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..common import CaseError, _string
from ..ijson import MAX_SAFE_INTEGER
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "capability_credential/v1"
SCHEMA = "capability-credential/v1"
REQUIRED = ("schema_version", "id", "issuer", "subject", "capabilities", "issued_at", "not_after", "signatures")
OPTIONAL = ("revocation_ref", "max_uses", "cosigners_required")
SIGNATURE_MEMBERS = {"kid", "value"}
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", re.ASCII)
LIMIT = ("Checks one credential against the consumer's trusted issuers, cosigner keys and authorities, pinned "
         "clock and revocation list. It shows the credential is intact, in force and signed by distinct "
         "authorities as required; it does not show that a capability was used as granted.")


class Refused(ValueError):
    """The credential is refused: (code, detail)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code, self.detail = code, detail


class _Escaped(str):
    """A decoded string whose JSON spelling held an escape."""


def _scanstring(text: str, end: int, strict: bool = True) -> tuple[str, int]:
    value, after = json.decoder.py_scanstring(text, end, strict)
    return (_Escaped(value) if "\\" in text[end:after - 1] else value), after


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Refused("duplicate_member", f"member {key!r} appears twice")
        out[key] = value
    return out


def _integer(text: str) -> int:
    value = int(text)
    if str(value) != text:
        raise Refused("noncanonical_number", f"the number {text!r} is not its canonical spelling")
    if abs(value) > MAX_SAFE_INTEGER:
        raise Refused("noncanonical_number", f"the number {text!r} is outside the I-JSON range")
    return value


def _no_float(text: str) -> Any:
    raise Refused("noncanonical_number", f"the number {text!r} is not an integer token")


def _no_constant(text: str) -> Any:
    raise Refused("noncanonical_number", f"{text} is not a JSON number")


def parse(data: bytes) -> Any:
    """Strict reading that keeps what a lenient decoder throws away: escapes, number spellings, repeats."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refused("record_shape", "the credential is not UTF-8") from exc
    decoder = json.JSONDecoder(object_pairs_hook=_pairs, parse_int=_integer, parse_float=_no_float,
                               parse_constant=_no_constant)
    decoder.parse_string = _scanstring
    decoder.scan_once = json.scanner.py_make_scanner(decoder)
    try:
        return decoder.decode(text)
    except Refused:
        raise
    except (ValueError, RecursionError) as exc:
        raise Refused("record_shape", f"the credential is not JSON ({exc})") from exc


def _time(value: Any, label: str) -> datetime.datetime:
    if isinstance(value, _Escaped):
        raise Refused("timestamp_grammar", f"{label} is written with a JSON escape")
    if not isinstance(value, str) or not TIME.fullmatch(value):
        raise Refused("timestamp_grammar", f"{label} is not YYYY-MM-DDTHH:MM:SSZ in ASCII digits")
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError as exc:
        raise Refused("timestamp_grammar", f"{label} is not a calendar time") from exc


def _shape(credential: Any) -> dict:
    if not isinstance(credential, dict):
        raise Refused("record_shape", "the credential is an object")
    unknown = sorted(set(credential) - set(REQUIRED) - set(OPTIONAL))
    if unknown:
        raise Refused("unknown_member", f"the profile defines no member {unknown}")
    if not set(REQUIRED) <= set(credential) or credential["schema_version"] != SCHEMA:
        raise Refused("record_shape", f"a {SCHEMA} credential carries {list(REQUIRED)}")
    for member in ("id", "issuer", "subject") + (("revocation_ref",) if "revocation_ref" in credential else ()):
        if not isinstance(credential[member], str) or not credential[member]:
            raise Refused("record_shape", f"{member} is a string")
    caps = credential["capabilities"]
    if not isinstance(caps, list) or any(not isinstance(c, str) or not c for c in caps) or len(set(caps)) != len(caps):
        raise Refused("record_shape", "capabilities is a list of distinct strings")
    for member in ("max_uses", "cosigners_required"):
        if member in credential:
            value = credential[member]
            if isinstance(value, bool) or not isinstance(value, int) or value < (1 if member == "cosigners_required" else 0):
                raise Refused("record_shape", f"{member} is an integer of at least "
                              f"{1 if member == 'cosigners_required' else 0}")
    sigs = credential["signatures"]
    if not isinstance(sigs, list) or not sigs:
        raise Refused("record_shape", "signatures is a nonempty list")
    for i, sig in enumerate(sigs):
        if not isinstance(sig, dict):
            raise Refused("record_shape", f"signatures[{i}] is an object")
        if set(sig) - SIGNATURE_MEMBERS:
            raise Refused("unknown_member", f"signatures[{i}] carries {sorted(set(sig) - SIGNATURE_MEMBERS)}")
        if set(sig) != SIGNATURE_MEMBERS or not all(isinstance(sig[m], str) and sig[m] for m in SIGNATURE_MEMBERS):
            raise Refused("record_shape", f"signatures[{i}] carries kid and value")
    credential["_issued_at"] = _time(credential["issued_at"], "issued_at")
    credential["_not_after"] = _time(credential["not_after"], "not_after")
    return credential


def signing_input(credential: dict) -> bytes:
    body = {k: v for k, v in credential.items() if k != "signatures" and not k.startswith("_")}
    return SCHEMA.encode("ascii") + b"\x00" + jcs_canonical._value(body).encode("utf-8")


def _b64url(text: str) -> bytes:
    if "=" in text or set(text) - set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"):
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise ValueError("not the canonical base64url spelling")
    return raw


def _verifies(key_hex: str, value: str, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(_b64url(value), message)
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def check(credential_raw: bytes, state: dict) -> tuple[str, list[dict]]:
    """(reason, checks) for a credential the state accepts; raises :class:`Refused` otherwise."""
    credential = _shape(parse(credential_raw))
    checks = [{"id": "record_shape", "status": "pass", "detail": "strict reading under the profile"}]
    issuer = credential["issuer"]
    if issuer not in state["issuers"]:
        raise Refused("issuer_untrusted", f"the consumer trusts no issuer {issuer!r}")
    issuer_key = state["issuers"][issuer]
    message = signing_input(credential)
    own = [s for s in credential["signatures"] if s["kid"] == issuer]
    if len(own) > 1:
        raise Refused("key_named_not_signing", "two signatures name the issuer's key id")
    if len(own) != 1 or not _verifies(issuer_key, own[0]["value"], message):
        raise Refused("signature_invalid", "the issuer's signature is absent or does not verify")
    checks.append({"id": "signature", "status": "pass", "detail": "the issuer's signature verifies"})
    cosigs = [s for s in credential["signatures"] if s["kid"] != issuer]
    kids = [s["kid"] for s in cosigs]
    if len(set(kids)) != len(kids):
        raise Refused("key_named_not_signing", "two signatures name one key id: one signature cannot verify under two keys")
    keys: dict[str, str] = {}
    for sig in cosigs:
        known = state["cosigners"].get(sig["kid"])
        if known is None:
            raise Refused("cosigner_untrusted", f"the consumer knows no cosigner key {sig['kid']!r}")
        if not _verifies(known["public_key"], sig["value"], message):
            raise Refused("key_named_not_signing", f"no signature verifies under the named key {sig['kid']!r}")
        if known["public_key"] == issuer_key:
            raise Refused("own_key_as_cosigner", f"{sig['kid']!r} is the issuer's own key; the issuer never counts")
        keys[sig["kid"]] = known["public_key"]
    required = credential.get("cosigners_required", 0)
    distinct_keys = set(keys.values())
    authorities = {state["cosigners"][kid]["authority"] for kid in keys}
    if required:
        if len(keys) >= required and len(distinct_keys) < required:
            raise Refused("one_key_two_ids", "the required count is met only by counting one key under two ids")
        if len(distinct_keys) < required:
            raise Refused("below_threshold", f"{len(distinct_keys)} distinct cosigner keys of {required} required")
        if len(authorities) < required:
            raise Refused("one_authority_threshold",
                          f"{len(distinct_keys)} keys resolve to {len(authorities)} authorities of {required} required")
    checks.append({"id": "signer_distinctness", "status": "pass",
                   "detail": f"{len(distinct_keys)} cosigner keys from {len(authorities)} authorities, {required} required"})
    if state["at"] < credential["_issued_at"]:
        raise Refused("not_yet_valid", "the pinned clock is before issued_at")
    if state["at"] >= credential["_not_after"]:
        raise Refused("expired", "the pinned clock is at or after not_after")
    checks.append({"id": "validity", "status": "pass", "detail": "in force at the pinned clock"})
    if credential["id"] in state["revoked"]:
        raise Refused("revoked", "the credential id is on the consumer's revocation list")
    checks.append({"id": "revocation", "status": "pass", "detail": "not on the consumer's revocation list"})
    return "credential_valid", checks


def _state(assessment: dict) -> dict:
    issuers = assessment["trusted_issuers"]
    if not isinstance(issuers, dict) or any(not isinstance(v, str) or len(v) != 64 for v in issuers.values()):
        raise CaseError("assessment.trusted_issuers: expected {issuer: hex Ed25519 key}")
    cosigners = assessment.get("cosigners", {})
    if not isinstance(cosigners, dict) or any(
            not isinstance(v, dict) or set(v) != {"public_key", "authority"} or not isinstance(v["public_key"], str)
            or len(v["public_key"]) != 64 or not isinstance(v["authority"], str) for v in cosigners.values()):
        raise CaseError("assessment.cosigners: expected {kid: {public_key, authority}}")
    at = _string(assessment["at"], "assessment.at")
    if not TIME.fullmatch(at):
        raise CaseError("assessment.at: expected YYYY-MM-DDTHH:MM:SSZ")
    revoked = assessment["revoked"]
    if not isinstance(revoked, list) or any(not isinstance(r, str) for r in revoked):
        raise CaseError("assessment.revoked: expected a list of credential ids")
    return {"issuers": {k: v.lower() for k, v in issuers.items()},
            "cosigners": {k: {"public_key": v["public_key"].lower(), "authority": v["authority"]}
                          for k, v in cosigners.items()},
            "at": datetime.datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc),
            "revoked": set(revoked)}


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Consumer claim adapter: one credential and the consumer's verifier state."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"credential", "trusted_issuers", "at", "revoked"}, {"cosigners"})
    state = _state(assessment)
    data, binding = bound(artifacts, artifact_root, assessment["credential"], "assessment.credential")
    scope = {"credential": binding, "at": assessment["at"], "trusted_issuers": len(state["issuers"]),
             "limit": LIMIT}
    if data is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "credential_unavailable")
    try:
        reason, checks = check(data, state)
    except Refused as refused:
        return {**decision(case_id, CLAIM_TYPE, scope, "contradicted", refused.code,
                           [{"id": refused.code, "status": "fail", "detail": refused.detail}]),
                "vantage": "independent"}
    return {**decision(case_id, CLAIM_TYPE, scope, "supported", reason, checks), "vantage": "independent"}
