"""``cbor_receipt_chain/v1``: does this stream of signed CBOR receipts form one whole, ordered chain?

A class of authorization systems writes one signed receipt per decision as a CBOR map and links each
receipt to the one before it by the hash of its bytes. Every receipt in such a stream can verify while the
stream is not the one that was written: a receipt repeated, an authorization recorded twice, two
receipts swapped, the tail cut, a gap hidden by a restart, or a whole run signed by a key the
consumer never trusted. This claim type reads the class through a consumer-pinned format profile and
answers from the consumer's inputs, never from the stream.

The profile (an artifact the case pins, like every other input) names the outer map's member names,
the signed-message context bytes, whether keys and signatures are bare byte strings or ``[alg, bytes]``
pairs, and the payload's integer member keys by role. The decoder is strict: indefinite lengths,
tags, floats, repeated map keys, trailing bytes and nesting past 16 levels are refused. The signed
message is ``context || version byte || payload``; the link hash is SHA-256 of the whole receipt.

Checks run in this order and the first failure is the reason:

1. ``receipt_shape`` and ``signature``: every receipt is a well formed four-member map whose
   Ed25519 signature verifies under the key it carries;
2. ``signer_pinned``: every signing key is one the consumer pinned (the embedded key proves
   nothing alone: whoever re-signs a record embeds their own key);
3. ``no_duplicate_receipt``: no receipt appears twice;
4. ``single_use``: no signed request proof is allowed by two receipts (a re-issued authorization);
5. ``chain_order``: each receipt names the one before it in file order, and the first names the
   consumer's pinned predecessor (a receipt with no predecessor after the first is a restart:
   recorded, not refused);
6. ``head_anchor``: the last receipt and the count match the head the consumer kept outside the stream.

After the checks: a restart gives ``not_established`` / ``chain_reset`` (loss before a restart cannot
be excluded from the bytes); no pinned head gives ``not_established`` / ``head_not_anchored`` (a cut
tail leaves a valid prefix); a required effect with no effect member gives ``not_established`` /
``effect_not_recorded``; a required revocation commitment that is absent gives ``not_established`` /
``revocation_not_consulted``. Otherwise ``supported`` / ``receipt_chain_holds``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..common import CaseError, _object, _string
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "cbor_receipt_chain/v1"
PROFILE_SCHEMA = "cbor-receipt-profile/v1"
LIMIT = ("Reads the stream against the consumer's pinned signer keys, predecessor and head. It shows "
         "that the receipts form one ordered chain under those keys; it does not show that a "
         "recorded decision was enforced or that any effect happened, and a stream that stops "
         "before the pinned head cannot be told from one that was cut.")
MAX_DEPTH = 16
MAX_ITEMS = 4096
OUTER_MEMBERS = ("version", "payload", "signer_key", "signature")
REQUIRED_FIELDS = ("version", "prev_hash")
OPTIONAL_FIELDS = ("outcome", "request_hash", "proof", "revocation_hash", "effect")
HEX64 = frozenset("0123456789abcdef")


class Malformed(ValueError):
    """A defect in carried bytes."""


def _take(buf: bytes, pos: int, n: int) -> tuple[bytes, int]:
    if n < 0 or pos + n > len(buf):
        raise Malformed("truncated")
    return buf[pos:pos + n], pos + n


def _argument(buf: bytes, pos: int, info: int) -> tuple[int, int]:
    if info < 24:
        return info, pos
    if info > 27:
        raise Malformed("indefinite or reserved length")
    raw, pos = _take(buf, pos, 1 << (info - 24))
    return int.from_bytes(raw, "big"), pos


def _item(buf: bytes, pos: int, depth: int, budget: list[int]) -> tuple[Any, int]:
    budget[0] -= 1
    if depth > MAX_DEPTH or budget[0] < 0:
        raise Malformed("too deep or too large")
    head, pos = _take(buf, pos, 1)
    major, info = head[0] >> 5, head[0] & 31
    if major == 7:
        if info in (20, 21, 22):
            return {20: False, 21: True, 22: None}[info], pos
        raise Malformed("float or simple value")
    if major == 6:
        raise Malformed("tag")
    arg, pos = _argument(buf, pos, info)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        raw, pos = _take(buf, pos, arg)
        if major == 2:
            return raw, pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError as exc:
            raise Malformed("text is not UTF-8") from exc
    if arg > len(buf):
        raise Malformed("length past the end")
    if major == 4:
        items = []
        for _ in range(arg):
            value, pos = _item(buf, pos, depth + 1, budget)
            items.append(value)
        return items, pos
    out: dict[Any, Any] = {}
    for _ in range(arg):
        key, pos = _item(buf, pos, depth + 1, budget)
        if not isinstance(key, (int, str)) or isinstance(key, bool):
            raise Malformed("map key is not an integer or text")
        if key in out:
            raise Malformed("repeated map key")
        out[key], pos = _item(buf, pos, depth + 1, budget)
    return out, pos


def decode(data: bytes) -> Any:
    """Decode exactly one CBOR item, strictly."""
    value, pos = _item(data, 0, 0, [MAX_ITEMS])
    if pos != len(data):
        raise Malformed("trailing bytes")
    return value


def _profile(raw: bytes | None) -> dict:
    """The format profile, shape-checked: a malformed profile is a case error, never a verdict."""
    if raw is None:
        raise CaseError("profile: the artifact is unavailable")
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise CaseError("profile: not JSON") from exc
    profile = _object(value, "profile", {"schema_version", "profile_id", "line_member",
                                         "signature_context_hex", "outer", "key_form", "fields",
                                         "allow_outcome"})
    if profile["schema_version"] != PROFILE_SCHEMA:
        raise CaseError("profile: unsupported schema_version")
    _string(profile["profile_id"], "profile.profile_id")
    if profile["line_member"] is not None:
        _string(profile["line_member"], "profile.line_member")
    try:
        profile["context"] = bytes.fromhex(_string(profile["signature_context_hex"],
                                                   "profile.signature_context_hex"))
    except ValueError as exc:
        raise CaseError("profile.signature_context_hex: expected hex") from exc
    outer = _object(profile["outer"], "profile.outer", set(OUTER_MEMBERS))
    if len({_string(outer[m], f"profile.outer.{m}") for m in OUTER_MEMBERS}) != len(OUTER_MEMBERS):
        raise CaseError("profile.outer: member names must differ")
    if profile["key_form"] not in ("raw", "pair"):
        raise CaseError("profile.key_form: expected raw or pair")
    fields = _object(profile["fields"], "profile.fields", set(REQUIRED_FIELDS), set(OPTIONAL_FIELDS))
    numbers = list(fields.values())
    if any(isinstance(n, bool) or not isinstance(n, int) for n in numbers) or len(set(numbers)) != len(numbers):
        raise CaseError("profile.fields: expected distinct integer member keys")
    if profile["allow_outcome"] is not None:
        _string(profile["allow_outcome"], "profile.allow_outcome")
    if "proof" in fields and ("outcome" not in fields or profile["allow_outcome"] is None):
        raise CaseError("profile: a proof member needs an outcome member and allow_outcome")
    return profile


def _spec(assessment: dict) -> dict:
    keys = assessment["signer_keys"]
    if not isinstance(keys, list) or not keys:
        raise CaseError("assessment.signer_keys: expected a nonempty list of hex public keys")
    pinned = set()
    for key in keys:
        text = _string(key, "assessment.signer_keys[]").lower()
        if len(text) != 64 or not set(text) <= HEX64:
            raise CaseError("assessment.signer_keys[]: expected a 32-byte key in hex")
        pinned.add(text)
    first = assessment.get("first_prev")
    for label, value in (("first_prev", first), ("head", assessment.get("head"))):
        if value is not None and (not isinstance(value, str) or len(value) != 64
                                  or not set(value) <= HEX64):
            raise CaseError(f"assessment.{label}: expected lowercase SHA-256 or null")
    head, count = assessment.get("head"), assessment.get("count")
    if (head is None) != (count is None):
        raise CaseError("assessment: head and count are pinned together or not at all")
    if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 1):
        raise CaseError("assessment.count: expected a positive integer")
    for flag in ("require_effect", "require_revocation"):
        if not isinstance(assessment.get(flag, False), bool):
            raise CaseError(f"assessment.{flag}: expected a boolean")
    return {"signers": pinned, "first_prev": first, "head": head, "count": count,
            "require_effect": assessment.get("require_effect", False),
            "require_revocation": assessment.get("require_revocation", False)}


def _lines(data: bytes, profile: dict) -> list[str]:
    out = []
    for number, raw in enumerate(data.decode("ascii", "replace").splitlines(), 1):
        text = raw.strip()
        if not text:
            continue
        if profile["line_member"] is not None:
            try:
                text = json.loads(text)[profile["line_member"]]
            except (ValueError, KeyError, TypeError) as exc:
                raise Malformed(f"line {number}: no {profile['line_member']} member") from exc
        if not isinstance(text, str):
            raise Malformed(f"line {number}: receipt is not a string")
        out.append(text)
    return out


def _bytes_member(value: Any, form: str, size: int) -> bytes:
    if form == "pair":
        if not isinstance(value, list) or len(value) != 2:
            raise Malformed("expected an [alg, bytes] pair")
        value = value[1]
    if not isinstance(value, bytes) or len(value) != size:
        raise Malformed(f"expected {size} bytes")
    return value


def parse(wire_hex: str, profile: dict) -> dict[str, Any]:
    """One receipt: shape, then signature under its embedded key, then payload members."""
    try:
        raw = bytes.fromhex(wire_hex)
    except ValueError as exc:
        raise Malformed("receipt is not hex") from exc
    outer = decode(raw)
    names = profile["outer"]
    if not isinstance(outer, dict) or set(outer) != {names[m] for m in OUTER_MEMBERS}:
        raise Malformed("outer receipt is not the profile's four-member map")
    version, payload = outer[names["version"]], outer[names["payload"]]
    if isinstance(version, bool) or not isinstance(version, int) or not 0 <= version < 256:
        raise Malformed("version is not a byte")
    if not isinstance(payload, bytes):
        raise Malformed("payload is not a byte string")
    key = _bytes_member(outer[names["signer_key"]], profile["key_form"], 32)
    sig = _bytes_member(outer[names["signature"]], profile["key_form"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, profile["context"] + bytes([version]) + payload)
    except InvalidSignature as exc:
        raise ValueError("signature does not verify") from exc
    body = decode(payload)
    if not isinstance(body, dict) or any(not isinstance(k, int) or isinstance(k, bool) for k in body):
        raise Malformed("payload is not an integer-keyed map")
    fields = profile["fields"]
    if body.get(fields["version"]) != version:
        raise Malformed("payload version disagrees with the receipt")
    prev = body.get(fields["prev_hash"])
    if prev is not None and (not isinstance(prev, bytes) or len(prev) != 32):
        raise Malformed("predecessor hash is not 32 bytes")
    return {"signer": key.hex(), "digest": hashlib.sha256(raw).hexdigest(),
            "prev": prev.hex() if prev is not None else None,
            **{role: body.get(fields[role]) for role in OPTIONAL_FIELDS if role in fields}}


def check_records(lines: list[str], spec: dict, profile: dict) -> tuple[str, str, list[dict]]:
    """(decision, reason, checks) for one receipt stream against the consumer's inputs."""
    checks: list[dict] = []

    def fail(cid: str, detail: str) -> tuple[str, str, list[dict]]:
        checks.append({"id": cid, "status": "fail", "detail": detail})
        return "contradicted", cid, checks

    def ok(cid: str, detail: str, status: str = "pass") -> None:
        checks.append({"id": cid, "status": status, "detail": detail})

    if not lines:
        return fail("records_present", "the stream holds no receipts")
    parsed = []
    for i, wire in enumerate(lines):
        try:
            parsed.append(parse(wire, profile))
        except Malformed as exc:
            return fail("receipt_shape", f"receipt {i}: {exc}")
        except ValueError as exc:
            return fail("signature", f"receipt {i}: {exc}")
    ok("signature", f"{len(parsed)} signatures verify under their embedded keys")
    for i, p in enumerate(parsed):
        if p["signer"] not in spec["signers"]:
            return fail("signer_pinned", f"receipt {i} is signed by {p['signer'][:16]}, not a pinned key")
    ok("signer_pinned", "every signer is a consumer-pinned key")
    digests = [p["digest"] for p in parsed]
    if len(set(digests)) != len(digests):
        return fail("no_duplicate_receipt", "the same receipt appears more than once")
    ok("no_duplicate_receipt", "no receipt repeats")
    seen: dict[tuple, int] = {}
    if "proof" in profile["fields"]:
        for i, p in enumerate(parsed):
            if p.get("outcome") == profile["allow_outcome"] and isinstance(p.get("proof"), bytes):
                token = (p.get("request_hash"), p["proof"])
                if token in seen:
                    return fail("single_use", f"receipts {seen[token]} and {i} allow the same signed request")
                seen[token] = i
        ok("single_use", "no signed request is allowed twice")
    else:
        ok("single_use", "the profile has no request proof member: re-issue cannot be seen", "unavailable")
    resets = []
    for i, p in enumerate(parsed):
        if i == 0:
            if p["prev"] != spec["first_prev"]:
                return fail("chain_order", "the first receipt does not link to the consumer's pinned predecessor")
        elif p["prev"] is None:
            resets.append(i)
        elif p["prev"] != digests[i - 1]:
            return fail("chain_order", f"receipt {i} does not link to receipt {i - 1} in file order")
    if resets:
        ok("chain_order", f"the chain restarts at receipts {resets}: loss before each restart cannot be excluded",
           "unavailable")
    else:
        ok("chain_order", "each receipt links to the one before it")
    if spec["head"] is not None:
        if digests[-1] != spec["head"] or len(parsed) != spec["count"]:
            return fail("head_anchor", f"last receipt {digests[-1][:16]} of {len(parsed)} "
                        f"against pinned {spec['head'][:16]} of {spec['count']}")
        ok("head_anchor", "the last receipt and the count match the consumer's anchor")
    else:
        ok("head_anchor", "no head pinned: a cut tail cannot be seen", "unavailable")
    no_srl = [i for i, p in enumerate(parsed) if "revocation_hash" in p and p["revocation_hash"] is None]
    if "revocation_hash" in profile["fields"]:
        ok("revocation_consulted", f"receipts {no_srl} carry no revocation commitment" if no_srl
           else "every receipt commits to a revocation list", "unavailable" if no_srl else "pass")
    no_effect = [i for i, p in enumerate(parsed)
                 if p.get("outcome") == profile["allow_outcome"] and p.get("effect") is None]
    if "effect" in profile["fields"] and not no_effect:
        ok("effect_recorded", "every allowed receipt carries an effect member")
    else:
        ok("effect_recorded", "the format records the decision only" if "effect" not in profile["fields"]
           else f"allowed receipts {no_effect} carry no effect", "unavailable")
    if resets:
        return "not_established", "chain_reset", checks
    if spec["head"] is None:
        return "not_established", "head_not_anchored", checks
    if spec["require_effect"] and not ("effect" in profile["fields"] and not no_effect):
        return "not_established", "effect_not_recorded", checks
    if spec["require_revocation"] and ("revocation_hash" not in profile["fields"] or no_srl):
        return "not_established", "revocation_not_consulted", checks
    return "supported", "receipt_chain_holds", checks


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Consumer claim adapter: the stream, the format profile and the consumer's trust inputs."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"records", "profile", "signer_keys"},
        {"first_prev", "head", "count", "require_effect", "require_revocation"})
    spec = _spec(assessment)
    raw_profile, profile_binding = bound(artifacts, artifact_root, assessment["profile"], "assessment.profile")
    profile = _profile(raw_profile)
    data, records_binding = bound(artifacts, artifact_root, assessment["records"], "assessment.records")
    scope = {"records": records_binding, "profile": profile_binding, "profile_id": profile["profile_id"],
             "pinned_signers": len(spec["signers"]), "limit": LIMIT}
    if data is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "records_unavailable")
    try:
        lines = _lines(data, profile)
    except Malformed as exc:
        check = {"id": "receipt_shape", "status": "fail", "detail": str(exc)}
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", "receipt_shape", [check])
    result, reason, checks = check_records(lines, spec, profile)
    scope["receipts"] = len(lines)
    return {**decision(case_id, CLAIM_TYPE, scope, result, reason, checks), "vantage": "independent"}
