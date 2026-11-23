"""``co_signed_receipt/v1``: which parties does a tool-call receipt bind, and may their keys speak?

The record class is a receipt an agent signs for one tool call, which the caller may co-sign: a
format version, the two parties' identifiers (``agentDid``, ``callerDid``), the tool name, hashes
of the task and of the result, the outcome (``success`` and a ``failureType`` that names the
failure, empty on success), the latency in milliseconds, a timestamp, and hex-encoded Ed25519
signatures (``signature`` by the agent, ``callerSignature`` by the caller). Both parties sign the
same bytes: the RFC 8785 form of the receipt with ``signature`` and ``callerSignature`` removed,
every other member as written, an absent member absent.

The member rules run first, because a valid signature over a malformed record is the case a
signature check alone admits. They are the ``co-signed-receipt`` rule set of
agent-evidence-admission, with its codes and its check order, so an admission gate and this
verifier refuse the same receipt under the same code (``tests/data/co-signed-receipt/admission``
holds that rule set's corpus and the parity test runs it): ``version-unknown``,
``member-missing``, ``hash-not-lowercase-hex64``, ``member-malformed``,
``signature-not-lowercase-hex128``, ``cosigner-missing``, ``cosignature-missing``,
``cosigner-is-signer``, ``failure-type-inconsistent``, ``latency-out-of-range``,
``instant-malformed``. A receipt that is not I-JSON is refused under the strict reader's code
(``duplicate-member``, ``lone-surrogate`` and the rest of :data:`agent_evidence_verify.ijson.CODES`),
one that is not a JSON object is ``receipt-shape-malformed``, as admission refuses them.

Then the signatures. The key of each party comes from the key set the case supplies (a JSON object
mapping each DID to its public JWK, the bytes the reader resolved), never from the receipt. A key
that is not an Ed25519 public JWK is ``key_malformed``: a private member, a JWK ``alg`` other than
``EdDSA``, or a non-canonical or small-order point, under which one signature verifies every
message; a key marked for encryption (``use`` other than ``sig``, ``key_ops`` without ``verify``)
is ``key_not_for_signing``; the same key for both parties is ``cosigner-is-signer`` (one key, one
party, shown as two). The agent's signature must verify (``signature-invalid``), and a
``callerSignature`` that is present must verify too (``cosignature-invalid``): a co-signature that
fails is not a weaker co-signature, it makes the receipt claim a binding it does not have. Every
party whose key the case supplies is checked before a missing key is reported, so a forged
signature is ``contradicted`` even when the other party's key was withheld; only then is a party
with no key ``not_established`` (``key_unavailable``).

Last, key authority (:mod:`agent_evidence_verify.key_authority`): the agent's key under the
consumer's ``key_authority`` with ``agentDid`` as the subject, the caller's under
``cosigner_key_authority`` with ``callerDid`` as the subject, each at the receipt's ``timestamp``.
Both authorised is ``supported`` (``receipt_signers_authorized``); any key refused is
``contradicted`` with the authority's reason; no authority, or missing evidence, is
``not_established``.

The ``evidence_attribution`` value (agent-evidence-vocabulary) says which parties the receipt
binds, so it is decided with key authority, not before it: a signature under a key that may not
speak for its party binds no party. ``co_signed`` is both signatures verifying under two distinct
keys that each party's authority lets speak for it, ``single_signed`` the agent's alone;
``unattributed_evidence`` is a present signature that does not verify, or a key an authority
refuses (a forger who signs as the agent and supplies a key for the agent's DID gets this, never
``co_signed``). While authority is undecided (no authority, missing evidence) no value is reported.
Two signatures bind two parties to one record. They do not show the record true, and they do not
show the parties independent: one operator can hold both keys.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any

from ..common import CaseError
from ..ijson import CODES as IJSON_CODES
from ..ijson import IJSONError, parse_ijson
from ..jose import ed25519_weak_key, jwk_signs, verify_signature
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "co_signed_receipt/v1"
LIMIT = ("Says which parties signed the receipt's bytes and whether the consumer's key authority "
         "lets their keys speak for them. Two signatures bind two parties to one record; they do "
         "not show the record true or the parties independent.")
VERSIONS = frozenset({"1"})
MEMBERS = ("formatVersion", "agentDid", "toolName", "taskHash", "resultHash", "success",
           "failureType", "latencyMs", "timestamp", "signature")
SIGNATURE_MEMBERS = ("signature", "callerSignature")
MAX_SAFE_INTEGER = 2**53 - 1
CO_SIGNED, SINGLE_SIGNED, UNATTRIBUTED = "co_signed", "single_signed", "unattributed_evidence"
#: Every code the member rules can return, in check order (the admission rule set's order).
RULE_CODES = (
    "receipt-shape-malformed", "version-unknown", "member-missing", "hash-not-lowercase-hex64",
    "member-malformed", "signature-not-lowercase-hex128", "cosigner-missing",
    "cosignature-missing", "cosigner-is-signer", "failure-type-inconsistent",
    "latency-out-of-range", "instant-malformed",
)
REASONS = RULE_CODES + IJSON_CODES + ("key_malformed", "key_not_for_signing", "signature-invalid",
                                      "cosignature-invalid")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
#: RFC 3339 section 5.6, as the admission rule set reads it: ``T`` and ``Z`` upper case, an
#: offset hour 00 to 23 and minute 00 to 59, up to nine fraction digits, nothing after the zone.
_INSTANT = re.compile(
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})(?P<frac>\.[0-9]{1,9})?"
    r"(?P<zone>Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])")
_SEVERITY = {"unauthorized": 2, "unknown": 1, "authorized": 0}
_REQUIRED = {"receipt"}
_OPTIONAL = {"keys", "key_authority", "cosigner_key_authority"}


class Refused(Exception):
    """A rule failed; ``args[0]`` is its code."""


class Unavailable(Exception):
    """Evidence a check needs was not supplied; ``args[0]`` is the not_established reason."""


def _instant_ok(text: Any) -> bool:
    if not isinstance(text, str) or not text.isascii():
        return False
    match = _INSTANT.fullmatch(text)
    if match is None:
        return False
    zone = "+00:00" if match["zone"] == "Z" else match["zone"]
    try:
        datetime.datetime.fromisoformat(f"{match['date']}T{match['time']}{zone}")
    except ValueError:
        return False
    return True


def _outcome_code(receipt: dict[str, Any]) -> str | None:
    if "success" not in receipt or "failureType" not in receipt:
        return None  # the members rule reports the absence
    success, failure = receipt["success"], receipt["failureType"]
    if not isinstance(success, bool) or not isinstance(failure, str):
        return "failure-type-inconsistent"
    if success == (failure != ""):
        return "failure-type-inconsistent"
    return None


def rule_codes(receipt: Any) -> list[str]:
    """Every member rule the receipt fails, in the admission rule set's check order."""
    if not isinstance(receipt, dict):
        return ["receipt-shape-malformed"]
    version = receipt.get("formatVersion")
    if not isinstance(version, str) or version not in VERSIONS:  # a list is unhashable
        return ["version-unknown"]  # an unknown version stops the rules, as admission does
    codes = []
    if any(member not in receipt for member in MEMBERS):
        codes.append("member-missing")
    if any(member in receipt and not (isinstance(receipt[member], str)
                                      and _HEX64.fullmatch(receipt[member]))
           for member in ("taskHash", "resultHash")):
        codes.append("hash-not-lowercase-hex64")
    if any(member in receipt and not (isinstance(receipt[member], str) and receipt[member])
           for member in ("agentDid", "toolName", "callerDid")):
        codes.append("member-malformed")
    if any(member in receipt and not (isinstance(receipt[member], str)
                                      and _HEX128.fullmatch(receipt[member]))
           for member in SIGNATURE_MEMBERS):
        codes.append("signature-not-lowercase-hex128")
    if "callerSignature" in receipt and "callerDid" not in receipt:
        codes.append("cosigner-missing")
    if "callerDid" in receipt and "callerSignature" not in receipt:
        codes.append("cosignature-missing")
    if ("callerDid" in receipt and receipt.get("callerDid") == receipt.get("agentDid")) or (
            "callerSignature" in receipt and receipt.get("callerSignature") == receipt.get(
                "signature")):
        codes.append("cosigner-is-signer")
    outcome = _outcome_code(receipt)
    if outcome:
        codes.append(outcome)
    latency = receipt.get("latencyMs", 0)
    if isinstance(latency, bool) or not isinstance(latency, int) or not (
            0 <= latency <= MAX_SAFE_INTEGER):
        codes.append("latency-out-of-range")
    if "timestamp" in receipt and not _instant_ok(receipt["timestamp"]):
        codes.append("instant-malformed")
    return codes


def read(data: bytes) -> dict[str, Any]:
    """The receipt, or :class:`Refused` with the first member rule it fails."""
    try:
        receipt = parse_ijson(data)
    except IJSONError as exc:
        raise Refused(exc.code) from exc
    codes = rule_codes(receipt)
    if codes:
        raise Refused(codes[0])
    return receipt


def signed_bytes(receipt: dict[str, Any]) -> bytes:
    """The bytes both parties sign: RFC 8785 of the receipt without its two signature members."""
    body = {name: value for name, value in receipt.items() if name not in SIGNATURE_MEMBERS}
    try:
        return jcs_canonical.serialize(body)
    except jcs_canonical.Refusal as exc:  # unreachable after the strict read; refused, never raised
        raise Refused("receipt-shape-malformed") from exc


def _party_key(keys: Any, did: str) -> bytes:
    from ..key_authority import jwk_key_bytes
    if not isinstance(keys, dict):
        raise Refused("key_malformed")
    if did not in keys:
        raise Unavailable("key_unavailable")
    jwk = keys[did]
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise Refused("key_malformed")
    try:
        raw = jwk_key_bytes(jwk, f"keys[{did}]")
    except CaseError as exc:
        raise Refused("key_malformed") from exc
    if jwk.get("alg", "EdDSA") != "EdDSA" or ed25519_weak_key(raw):
        raise Refused("key_malformed")
    if not jwk_signs(jwk):
        raise Refused("key_not_for_signing")
    return raw


def judge(receipt_bytes: bytes, keys: Any) -> tuple[dict[str, Any], list[tuple[str, bytes]], str]:
    """The receipt, its signers as (DID, key) and its attribution, or :class:`Refused`.

    The attribution travels on a refusal too, as ``args[1]``, when the refusal is a signature that
    does not verify.
    """
    receipt = read(receipt_bytes)
    message = signed_bytes(receipt)
    parties = [(receipt["agentDid"], "signature", "signature-invalid")]
    if "callerSignature" in receipt:
        parties.append((receipt["callerDid"], "callerSignature", "cosignature-invalid"))
    resolved, missing = [], False
    for did, member, code in parties:
        try:
            resolved.append((did, _party_key(keys, did), member, code))
        except Unavailable:
            missing = True  # judged after every party whose key the case supplies
    if len(resolved) == 2 and resolved[0][1] == resolved[1][1]:
        raise Refused("cosigner-is-signer")
    for _, key, member, code in resolved:
        if not verify_signature("EdDSA", key, message, bytes.fromhex(receipt[member])):
            raise Refused(code, UNATTRIBUTED)
    if missing:
        raise Unavailable("key_unavailable")
    attribution = CO_SIGNED if len(resolved) == 2 else SINGLE_SIGNED
    return receipt, [(did, key) for did, key, _, _ in resolved], attribution


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge the bound receipt, then ask each party's key authority about its key."""
    from ..key_authority import AUTHORIZED, UNAUTHORIZED, authorize, evidence
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, _REQUIRED, _OPTIONAL)
    scope: dict[str, Any] = {"limit": LIMIT}
    receipt_bytes, scope["receipt"] = bound(artifacts, artifact_root, assessment["receipt"],
                                            "assessment.receipt")
    keys_bytes = None
    if "keys" in assessment:
        keys_bytes, scope["keys"] = bound(artifacts, artifact_root, assessment["keys"],
                                          "assessment.keys")
    if receipt_bytes is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "receipt_unavailable")
    check: dict[str, Any] = {"id": "co_signed_receipt"}
    try:
        keys = None
        if keys_bytes is not None:
            try:
                keys = parse_ijson(keys_bytes)
            except IJSONError as exc:
                raise Refused("key_malformed") from exc
        if keys is None:
            read(receipt_bytes)  # a malformed receipt is refused before a missing key is reported
            raise Unavailable("key_unavailable")
        receipt, signers, attribution = judge(receipt_bytes, keys)
    except Refused as refusal:
        check.update(status="fail", reason=str(refusal.args[0]))
        if len(refusal.args) > 1:
            check["evidence_attribution"] = refusal.args[1]
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", str(refusal.args[0]), [check])
    except Unavailable as missing:
        check.update(status="unavailable", reason=str(missing.args[0]))
        return decision(case_id, CLAIM_TYPE, scope, "not_established", str(missing.args[0]),
                        [check])
    check.update(status="pass", reason="receipt_signatures_verify",
                 signers=[did for did, _ in signers])
    configs = [assessment.get("key_authority"), assessment.get("cosigner_key_authority")]
    answers = []
    for (did, key), config in zip(signers, configs):
        proved = evidence(config, artifacts, artifact_root, scope)
        answers.append(authorize(config, key, subject=did, at=receipt["timestamp"],
                                 **proved))
    authority = max(answers, key=lambda answer: _SEVERITY[answer.outcome])
    if authority.outcome == AUTHORIZED:
        check["evidence_attribution"] = attribution
    elif authority.outcome == UNAUTHORIZED:
        check["evidence_attribution"] = UNATTRIBUTED
    checks = [check] + [answer.check() for answer in answers]
    if authority.outcome == AUTHORIZED:
        return decision(case_id, CLAIM_TYPE, scope, "supported", "receipt_signers_authorized",
                        checks)
    if authority.outcome == UNAUTHORIZED:
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", authority.reason, checks)
    return decision(case_id, CLAIM_TYPE, scope, "not_established", authority.reason, checks)
