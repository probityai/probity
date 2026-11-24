"""``agent_identity_statement/v1``: was this key in force, and the agent active, when the decision was made?

An issuer keeps an agent's identity document as a signed history: one DSSE-signed in-toto Statement per
version, of predicate type ``https://w3id.org/agent-evidence/predicate/v1/agent-identity-statement``. Each
version names the agent (``issuer``, ``subject``), its number, the key set in force, a status (``active``,
``suspended`` or ``revoked``), when it was issued and when it takes effect, and is chained to the version
before it by the SHA-256 of that version's signed payload. A relying party that acted on an agent's
signature at some instant can later ask, offline, whether the key was in force and the agent active at
that instant, from the history and from pins it holds: the issuer's keys, the agent and the head of the
history it last fetched.

The checks run in the order of ``CHECKS``, and the first that fails names the reason. They are the 25
checks of the corpus reader ``agent_evidence_vectors.agentidentity`` (agent-evidence-vectors, corpus
``vectors-agent-identity-statement``), ported in the same order with the same codes:

1. the history is a non-empty strict JSON list of DSSE envelopes carrying in-toto payloads;
2. every envelope is signed by a pinned issuer key;
3. each payload is an in-toto Statement v1 of this predicate type with one subject and a well-formed
   predicate;
4. no version is ``active`` with no keys or takes effect after it was issued;
5. every version names the pinned agent;
6. the versions form one chain from version 1 with no fork, gap, missing link, backwards time or
   version after a revocation;
7. the chain ends at the head the consumer pinned;
8. the decision is well formed, its key is listed in some version and signed the decision;
9. at the decision's instant a version was in force (the highest version whose ``effectiveAt`` is not
   after it), the agent was neither suspended nor revoked in it, and the key was in its key set.

Two entry points share those checks. :func:`judge` reads one corpus member directory (``context.json``,
``history.json``, ``decision.json``) for corpus mode. :func:`adjudicate` judges a consumer's case: the
history and an optional decision envelope are bound artifacts, and the pins, the instant and the key come
from the policy. The policy may name the key by the SHA-256 of its raw bytes (``key_sha256``, the key id
the predicate and the revocation list use) or by its RFC 7638 JWK thumbprint (``jwk_thumbprint``, the
``keyid`` a Web Bot Auth signature carries), so a request ``web_bot_auth/v1`` verified can be checked
against the issuer's history for the same instant.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import strictb64
from ..common import CaseError
from ..json_input import parse_json
from .bound_records import assessment_for, bound, decision

SUITE = "agent-identity-statement/v1"
CLAIM_TYPE = "agent_identity_statement/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://w3id.org/agent-evidence/predicate/v1/agent-identity-statement"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATUSES = ("active", "suspended", "revoked")
KEY_TYPES = ("Ed25519",)
ACCEPT, REJECT = "accept", "reject"
ACCEPTED = "key_in_force"
MAX_RECORD_BYTES = 1 << 22
MAX_VERSION = 2**53 - 1
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "history_malformed",
    "statement_signature",
    "statement_malformed",
    "statement_type_wrong",
    "predicate_type_wrong",
    "subject_malformed",
    "predicate_malformed",
    "active_without_keys",
    "effective_after_issued",
    "agent_mismatch",
    "history_no_genesis",
    "history_forked",
    "history_previous_missing",
    "version_not_incremented",
    "version_gap",
    "history_time_reversed",
    "revoked_is_final",
    "history_head_mismatch",
    "decision_malformed",
    "key_unknown",
    "decision_signature",
    "decision_before_history",
    "agent_suspended",
    "agent_revoked",
    "key_not_in_force",
)
LIMIT = ("Checks the issuer-signed history the case binds, against the consumer's pinned issuer keys, agent "
         "and head. It does not establish that the consumer's head is the issuer's newest version (the head "
         "is as fresh as the consumer's last fetch), that the key was not revoked elsewhere (a revocation "
         "list is a separate record), or what the decision was about: a decision envelope is checked only "
         "for the key's signature over its bytes.")
REQUIRED = {"history", "issuer_keys", "agent", "head_sha256", "at"}
OPTIONAL = {"decision", "key_sha256", "jwk_thumbprint"}
# ASCII digits only: ``\d`` would admit another script's digits, which ``strptime`` also reads.
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_THUMBPRINT = re.compile(r"[A-Za-z0-9_-]{43}")


class Malformed(ValueError):
    """A value that breaks a shape rule; the caller names the check."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require(condition: bool, what: str) -> None:
    if not condition:
        raise Malformed(what)


def _strict(data: bytes | None) -> Any:
    _require(data is not None, "absent")
    try:
        return parse_json(data or b"", max_bytes=MAX_RECORD_BYTES, max_depth=32, max_nodes=1 << 18)
    except CaseError as exc:
        raise Malformed(str(exc)) from exc


def _members(value: Any, required: set[str], optional: frozenset[str] = frozenset()) -> None:
    _require(isinstance(value, dict), "not an object")
    present = set(value)
    _require(required <= present <= required | optional, f"members {sorted(present)}")


def _hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def parse_time(text: Any) -> datetime:
    """An RFC 3339 UTC time to whole seconds, ``YYYY-MM-DDTHH:MM:SSZ``."""
    _require(isinstance(text, str) and _TIME.fullmatch(text) is not None, "time")
    try:
        return datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise Malformed(str(exc)) from exc


def _text(value: Any) -> str:
    _require(isinstance(value, str) and value != "", "non-empty text")
    return str(value)


def _https(value: Any) -> str:
    text = _text(value)
    _require(text.startswith("https://") and len(text) > len("https://"), "https URL")
    _require(not any(c in text for c in " #") and text.isascii(), "https URL")
    return text


def principal(value: Any) -> dict[str, str]:
    """An agent principal: exactly ``issuer`` (an https URL) and ``subject`` (non-empty text)."""
    _members(value, {"issuer", "subject"})
    return {"issuer": _https(value["issuer"]), "subject": _text(value["subject"])}


def _b64(text: Any) -> bytes:
    _require(isinstance(text, str), "base64 text")
    try:
        return strictb64.std(text)
    except (ValueError, TypeError) as exc:
        raise Malformed("base64") from exc


def public_key(hex_key: Any) -> bytes:
    """The raw 32-byte key a 64-character lowercase hex text names."""
    _require(_hex64(hex_key), "public key")
    return bytes.fromhex(str(hex_key))


def key_id(raw: bytes) -> str:
    """A key's identifier: the SHA-256 of its raw bytes."""
    return _sha(raw)


def jwk_thumbprint(raw: bytes) -> str:
    """RFC 7638 thumbprint of an Ed25519 key as an OKP JWK (RFC 8037), base64url without padding."""
    x = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).decode("ascii").rstrip("=")


# -- the history ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Envelope:
    """One DSSE envelope: its payload type, payload bytes and signatures."""

    payload_type: str
    payload: bytes
    sigs: tuple[bytes, ...]

    @property
    def digest(self) -> str:
        return _sha(self.payload)


@dataclass(frozen=True)
class Version:
    """One signed, well-formed version of the identity document."""

    digest: str
    version: int
    previous: str | None
    issued: datetime
    effective: datetime
    status: str
    keys: frozenset[str]
    agent: dict[str, str]


def envelope(value: Any) -> Envelope:
    """A DSSE envelope with at least one signature; raise Malformed otherwise."""
    _members(value, {"payloadType", "payload", "signatures"})
    _require(isinstance(value["payloadType"], str), "payloadType")
    signatures = value["signatures"]
    _require(isinstance(signatures, list) and signatures != [], "signatures")
    sigs = []
    for item in signatures:
        _members(item, {"sig"}, frozenset({"keyid"}))
        if "keyid" in item:
            _require(isinstance(item["keyid"], str), "keyid")
        sigs.append(_b64(item["sig"]))
    return Envelope(str(value["payloadType"]), _b64(value["payload"]), tuple(sigs))


def history_envelopes(raw: bytes | None) -> list[Envelope]:
    """The history's envelopes, each carrying an in-toto payload; an exact repeat collapses to one."""
    value = _strict(raw)
    _require(isinstance(value, list) and value != [], "history is a non-empty list")
    out: dict[str, Envelope] = {}
    for item in value:
        env = envelope(item)
        _require(env.payload_type == PAYLOAD_TYPE, "payloadType")
        out.setdefault(env.digest, env)
    return list(out.values())


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(kind), kind, len(payload), payload)


def _ed25519(key: bytes, message: bytes, sig: bytes) -> bool:
    """One Ed25519 verification (RFC 8032, through OpenSSL); any refusal is False."""
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def signed_by(keys: list[bytes], env: Envelope) -> bytes | None:
    """The first of ``keys`` that signed ``env``, or None."""
    message = pae(env.payload_type, env.payload)
    for key in keys:
        if any(_ed25519(key, message, sig) for sig in env.sigs):
            return key
    return None


def _keys(value: Any) -> frozenset[str]:
    _require(isinstance(value, list), "keys")
    hexes = []
    for item in value:
        _members(item, {"type", "publicKey"})
        _require(isinstance(item["type"], str) and item["type"] in KEY_TYPES, "key type")
        public_key(item["publicKey"])
        hexes.append(str(item["publicKey"]))
    _require(hexes == sorted(set(hexes)), "keys sorted and distinct")
    return frozenset(hexes)


def predicate_fields(predicate: Any) -> dict[str, Any]:
    """The predicate's members, checked for shape; raise Malformed otherwise."""
    _members(predicate, {"agent", "version", "issuedAt", "effectiveAt", "status", "keys"},
             frozenset({"previous", "reason"}))
    version = predicate["version"]
    _require(type(version) is int and 1 <= version <= MAX_VERSION, "version")
    _require(("previous" in predicate) == (version > 1), "previous iff version > 1")
    previous = None
    if "previous" in predicate:
        _members(predicate["previous"], {"sha256"})
        previous = predicate["previous"]["sha256"]
        _require(_hex64(previous), "previous")
    _require(isinstance(predicate["status"], str) and predicate["status"] in STATUSES, "status")
    if "reason" in predicate:
        _text(predicate["reason"])
    return {"agent": principal(predicate["agent"]), "version": version, "previous": previous,
            "issued": parse_time(predicate["issuedAt"]),
            "effective": parse_time(predicate["effectiveAt"]),
            "status": predicate["status"], "keys": _keys(predicate["keys"])}


def statement_failure(env: Envelope) -> tuple[str | None, Version | None]:
    """The first Statement-shape check ``env``'s payload fails, else None and the version it carries."""
    try:
        statement = _strict(env.payload)
        _members(statement, {"_type", "subject", "predicateType", "predicate"})
    except Malformed:
        return "statement_malformed", None
    if statement["_type"] != STATEMENT_TYPE:
        return "statement_type_wrong", None
    if statement["predicateType"] != PREDICATE_TYPE:
        return "predicate_type_wrong", None
    try:
        subject = statement["subject"]
        _require(isinstance(subject, list) and len(subject) == 1, "one subject")
        _members(subject[0], {"name", "digest"})
        _text(subject[0]["name"])
        _members(subject[0]["digest"], {"sha256"})
        _require(_hex64(subject[0]["digest"]["sha256"]), "digest")
    except Malformed:
        return "subject_malformed", None
    try:
        fields = predicate_fields(statement["predicate"])
    except Malformed:
        return "predicate_malformed", None
    return None, Version(env.digest, fields["version"], fields["previous"], fields["issued"],
                         fields["effective"], fields["status"], fields["keys"], fields["agent"])


def chain_failure(versions: list[Version], head: str) -> str | None:
    """The first chain check that fails over signed, well-formed versions."""
    if not any(v.version == 1 for v in versions):
        return "history_no_genesis"
    children: dict[str | None, list[Version]] = {}
    for v in versions:
        children.setdefault(v.previous, []).append(v)
    if any(len(group) > 1 for group in children.values()):
        return "history_forked"
    by_digest = {v.digest: v for v in versions}
    if any(v.previous is not None and v.previous not in by_digest for v in versions):
        return "history_previous_missing"
    linked = [(v, by_digest[v.previous]) for v in versions if v.previous is not None]
    for v, parent in linked:
        if v.version <= parent.version:
            return "version_not_incremented"
        if v.version > parent.version + 1:
            return "version_gap"
    if any(v.effective < parent.effective or v.issued < parent.issued for v, parent in linked):
        return "history_time_reversed"
    if any(parent.status == "revoked" for _, parent in linked):
        return "revoked_is_final"
    tips = [v.digest for v in versions if v.digest not in children]
    if tips != [head]:
        return "history_head_mismatch"
    return None


def in_force(versions: list[Version], at: datetime) -> Version | None:
    """The version in force at ``at``: the highest whose ``effectiveAt`` is not after it."""
    standing = [v for v in versions if v.effective <= at]
    return max(standing, key=lambda v: v.version) if standing else None


# -- the question a decision asks ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Pins:
    """What the consumer holds: the issuer's keys, the agent, and the head of the history it fetched."""

    issuer_keys: tuple[bytes, ...]
    agent: dict[str, str]
    head: str


@dataclass(frozen=True)
class Question:
    """The instant the relying party acted and the key it relied on, named by ``kind`` (``sha256`` or
    ``jwk_thumbprint``); ``envelope`` is the decision the key signed, when one is held."""

    at: datetime
    kind: str
    key: str
    envelope: Envelope | None


def decision_record(raw: bytes | None) -> Question:
    """A corpus member's ``decision.json``: the instant and one DSSE envelope whose one signature names its key."""
    value = _strict(raw)
    _members(value, {"at", "envelope"})
    env_value = value["envelope"]
    env = envelope(env_value)
    signatures = env_value["signatures"]
    _require(len(signatures) == 1 and "keyid" in signatures[0], "one signature naming its key")
    keyid = signatures[0]["keyid"]
    _require(_hex64(keyid), "keyid")
    return Question(parse_time(value["at"]), "sha256", str(keyid), env)


def _resolve(versions: list[Version], question: Question) -> bytes | None:
    """The raw key, listed in some version, that the question names; None when no version lists it."""
    for v in versions:
        for hex_key in sorted(v.keys):
            raw = bytes.fromhex(hex_key)
            named = key_id(raw) if question.kind == "sha256" else jwk_thumbprint(raw)
            if named == question.key:
                return raw
    return None


@dataclass
class Outcome:
    """The first failing check, or None; the checks that ran; and what the verdict rests on."""

    failure: str | None
    ran: list[str]
    question: Question | None = None
    key: bytes | None = None
    standing: Version | None = None
    versions: list[Version] | None = None


def evaluate(pins: Pins, history_raw: bytes | None,
             question_source: Callable[[], Question]) -> Outcome:
    """Run the checks in order over a history and the decision ``question_source`` yields.

    ``question_source`` is called at the decision checks, so a decision that is not well formed fails there
    and not before the history checks. It raises :class:`Malformed` for ``decision_malformed``.
    """
    ran: list[str] = []

    def stop(code: str) -> Outcome:
        ran.append(code)
        return Outcome(code, ran)

    try:
        envelopes = history_envelopes(history_raw)
    except Malformed:
        return stop("history_malformed")
    ran.append("history_malformed")
    if any(signed_by(list(pins.issuer_keys), env) is None for env in envelopes):
        return stop("statement_signature")
    ran.append("statement_signature")
    versions: list[Version] = []
    failures: list[str] = []
    for env in envelopes:
        failure, version = statement_failure(env)
        if failure is not None:
            failures.append(failure)
        elif version is not None:
            versions.append(version)
    shape_checks = CHECKS[2:7]
    if failures:
        first = min(failures, key=CHECKS.index)
        ran.extend(shape_checks[:shape_checks.index(first)])
        return stop(first)
    ran.extend(shape_checks)
    version_rules: tuple[tuple[str, Callable[[Version], bool]], ...] = (
        ("active_without_keys", lambda v: v.status == "active" and not v.keys),
        ("effective_after_issued", lambda v: v.effective > v.issued),
        ("agent_mismatch", lambda v: v.agent != pins.agent),
    )
    for code, broken in version_rules:
        if any(broken(v) for v in versions):
            return stop(code)
        ran.append(code)
    chain = chain_failure(versions, pins.head)
    chain_checks = CHECKS[10:18]
    if chain is not None:
        ran.extend(chain_checks[:chain_checks.index(chain)])
        return stop(chain)
    ran.extend(chain_checks)
    try:
        question = question_source()
    except Malformed:
        return stop("decision_malformed")
    ran.append("decision_malformed")
    outcome = Outcome(None, ran, question, versions=versions)
    key = _resolve(versions, question)
    if key is None:
        outcome.failure = "key_unknown"
        ran.append("key_unknown")
        return outcome
    outcome.key = key
    ran.append("key_unknown")
    if question.envelope is not None and signed_by([key], question.envelope) is None:
        outcome.failure = "decision_signature"
        ran.append("decision_signature")
        return outcome
    ran.append("decision_signature")
    standing = in_force(versions, question.at)
    outcome.standing = standing
    final: tuple[tuple[str, bool], ...] = (
        ("decision_before_history", standing is None),
        ("agent_suspended", standing is not None and standing.status == "suspended"),
        ("agent_revoked", standing is not None and standing.status == "revoked"),
        ("key_not_in_force", standing is not None and key.hex() not in standing.keys),
    )
    for code, failed in final:
        ran.append(code)
        if failed:
            outcome.failure = code
            return outcome
    return outcome


# -- corpus mode -------------------------------------------------------------------------------------------------


def _read(directory: Path, name: str) -> bytes | None:
    path = directory / name
    return path.read_bytes() if path.is_file() else None


def _context(raw: bytes | None) -> Pins:
    context = _strict(raw)
    _members(context, {"issuerKeys", "agent", "head"})
    keys = context["issuerKeys"]
    _require(isinstance(keys, list) and keys != [], "issuerKeys")
    head = context["head"]
    _members(head, {"sha256"})
    _require(_hex64(head["sha256"]), "head")
    return Pins(tuple(public_key(k) for k in keys), principal(context["agent"]), str(head["sha256"]))


def judge(case_dir: Path) -> tuple[str, str]:
    """(decision, reason) for one corpus member directory.

    Pins that cannot be read leave nothing to judge the history against, so the member is refused with the
    first check's code, as the corpus reader refuses it.
    """
    try:
        pins = _context(_read(case_dir, "context.json"))
    except Malformed:
        return REJECT, CHECKS[0]
    outcome = evaluate(pins, _read(case_dir, "history.json"),
                       lambda: decision_record(_read(case_dir, "decision.json")))
    return (ACCEPT, ACCEPTED) if outcome.failure is None else (REJECT, outcome.failure)


# -- the claim type ----------------------------------------------------------------------------------------------


def _policy(assessment: dict[str, Any]) -> tuple[Pins, datetime, str, str]:
    """The consumer's pins, instant and key, each checked for shape; a malformed policy raises CaseError."""
    keys = assessment["issuer_keys"]
    if (not isinstance(keys, list) or not keys or not all(_hex64(k) for k in keys)
            or len(set(keys)) != len(keys)):
        raise CaseError("assessment.issuer_keys: expected distinct 64-character lowercase hex Ed25519 keys")
    try:
        agent = principal(assessment["agent"])
    except Malformed as exc:
        raise CaseError("assessment.agent: expected exactly issuer (an https URL) and subject") from exc
    if not _hex64(assessment["head_sha256"]):
        raise CaseError("assessment.head_sha256: expected a lowercase SHA-256")
    try:
        at = parse_time(assessment["at"])
    except Malformed as exc:
        raise CaseError("assessment.at: expected YYYY-MM-DDTHH:MM:SSZ") from exc
    named = [name for name in ("key_sha256", "jwk_thumbprint") if name in assessment]
    if len(named) != 1:
        raise CaseError("assessment: name the key by exactly one of key_sha256 and jwk_thumbprint")
    value = assessment[named[0]]
    if named[0] == "key_sha256" and not _hex64(value):
        raise CaseError("assessment.key_sha256: expected a lowercase SHA-256")
    if named[0] == "jwk_thumbprint" and not (isinstance(value, str) and _THUMBPRINT.fullmatch(value)):
        raise CaseError("assessment.jwk_thumbprint: expected an RFC 7638 SHA-256 thumbprint, base64url unpadded")
    pins = Pins(tuple(bytes.fromhex(k) for k in keys), agent, assessment["head_sha256"])
    return pins, at, "sha256" if named[0] == "key_sha256" else "jwk_thumbprint", str(value)


def _signed_decision(raw: bytes) -> Envelope:
    """The decision as a DSSE envelope with exactly one signature; its unsigned ``keyid`` is not read."""
    value = _strict(raw)
    env = envelope(value)
    _require(len(env.sigs) == 1, "one signature")
    return env


def _checks(outcome: Outcome) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = [{"id": code, "status": "met"} for code in outcome.ran]
    if outcome.failure is not None and out:
        out[-1]["status"] = "failed"
    return out


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict[str, Any]:
    """Judge whether the key the policy names was in force, and the agent active, at the policy's instant."""
    case_id, artifacts, assessment = assessment_for(case, policy, CLAIM_TYPE, REQUIRED, OPTIONAL)
    pins, at, kind, named_key = _policy(assessment)
    scope: dict[str, Any] = {"agent": pins.agent, "head_sha256": pins.head, "at": assessment["at"],
                             "issuer_keys": [k.hex() for k in pins.issuer_keys], kind: named_key,
                             "limit": LIMIT}
    history_raw, history_binding = bound(artifacts, artifact_root, assessment["history"], "assessment.history")
    scope["history"] = history_binding
    if history_raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "history_unavailable")
    decision_raw: bytes | None = None
    if "decision" in assessment:
        decision_raw, decision_binding = bound(artifacts, artifact_root, assessment["decision"],
                                               "assessment.decision")
        scope["decision"] = decision_binding
        if decision_raw is None:
            return decision(case_id, CLAIM_TYPE, scope, "not_established", "decision_unavailable")

    def question() -> Question:
        env = _signed_decision(decision_raw) if decision_raw is not None else None
        return Question(at, kind, named_key, env)

    outcome = evaluate(pins, history_raw, question)
    checks = _checks(outcome)
    if decision_raw is None:
        for check in checks:
            if check["id"] in ("decision_malformed", "decision_signature"):
                check["status"] = "not_applicable"
    if outcome.key is not None:
        scope["key_sha256"] = key_id(outcome.key)
        scope["jwk_thumbprint"] = jwk_thumbprint(outcome.key)
    if outcome.standing is not None:
        scope["version_in_force"] = {
            "version": outcome.standing.version, "sha256": outcome.standing.digest,
            "status": outcome.standing.status,
            "effectiveAt": outcome.standing.effective.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if outcome.failure is None:
        return decision(case_id, CLAIM_TYPE, scope, "supported", ACCEPTED, checks)
    return decision(case_id, CLAIM_TYPE, scope, "contradicted", outcome.failure, checks)
