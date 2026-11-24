"""``credential_reachability/v1``: does this signed probe record support its credential-reachability claim?

A probe ran inside an agent's environment, tried every ambient credential class of a closed list,
and a key outside the agent's reach signed what it found. The claim: this DSSE envelope is a
conforming Credential Reachability record (spec/predicates/credential-reachability.md of
probityai/agent-evidence-vectors, 26 ordered rules), signed by a key the consumer trusts, bound to
the environment, audience and challenge the consumer pinned, fresh at the time the consumer judges,
and every class verdict and the overall result are the ones its attempts derive.

Every trust input comes from the consumer's assessment, never from the record: the trusted signer
keys, the keys the agent holds, the environment name and contract digest, the audience, the
challenge, the judging time, the oldest accepted result and, optionally, the accepted probe
digests. A signature is checked only under a key of the assessment's ``trusted_signers``, chosen by
the ``keyid`` the envelope names; a key the agent holds is used only to refuse (``signed_by_agent_key``),
and a key the record carries is never read.

The rules are applied independently of the corpus's reference readers, with this package's strict
JSON and base64 helpers, and the tests run every member of the corpus through the kernel.

Decisions: a record that passes every rule is ``supported`` with the reason ``contained_verified``,
``exposed_verified`` or ``incomplete_verified``. A refusal is ``contradicted`` or ``not_established``
with the first failing rule's code as the reason. A malformed envelope is ``contradicted`` with
``malformed_envelope`` (the corpus's ``no_verdict`` has no place among the kernel's three decisions,
and ``supported`` it is not). A defect in the consumer's assessment raises ``CaseError``.
"""

from __future__ import annotations

import binascii
import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .. import strictb64
from ..common import CaseError, _digest, _instant, _string
from ..identifiers import identifier, same_identifier
from ..ijson import IJSONError, parse_ijson
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "credential_reachability/v1"
PREDICATE_TYPE = identifier("agent-evidence-vectors/predicate/v1/credential-reachability")
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CLASS_SET = "credential-reachability/v1"
LIMIT = ("Checks the record against the consumer's pinned keys, environment, audience, challenge and "
         "time, and recomputes each class verdict and the result from the attempts. It does not "
         "establish that the probe found every credential of a class, that its report was not "
         "altered inside the environment, or anything after probedAt.")

CLASSES = ("ssh-agent", "ssh-key-file", "cloud-metadata", "cloud-config-file",
           "registry-config-file", "browser-cookie-store", "environment-token",
           "cluster-service-account", "git-credential", "host-keyring")
VERDICTS = ("reachable", "not_reachable", "could_not_test")
OUTCOMES = ("found", "issued_to_agent", "placeholder", "absent", "denied", "error", "not_run")
#: Best first: a declared result earlier than the derived one overstates it.
RESULTS = ("contained", "incomplete", "exposed")
MEMBERS = ("classSet", "audience", "challenge", "probedAt", "vantage", "probe", "placeholders",
           "issuedToAgent", "classes", "result")
ATTEMPT_MEMBERS = frozenset({"locator", "outcome", "digestPrefix", "detail"})
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
MAX_SIGNATURES = 1024

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX12 = re.compile(r"[0-9a-f]{12}")
TEXT200 = re.compile(r"[\x20-\x7e]{1,200}")
TEXT512 = re.compile(r"[\x20-\x7e]{1,512}")
DETAIL = re.compile(r"[\x20-\x7e]{0,200}")
UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

REQUIRED = {"envelope", "trusted_signers", "agent_keys", "environment", "audience", "challenge",
            "judged_at", "max_age_seconds", "payload_type"}
OPTIONAL = {"probe_digests"}


class _Refusal(Exception):
    """The first rule that failed: a decision and a reason code."""

    def __init__(self, decision_value: str, reason: str) -> None:
        super().__init__(reason)
        self.decision, self.reason = decision_value, reason


def _refuse(reason: str) -> _Refusal:
    return _Refusal("contradicted", reason)


def _unestablished(reason: str) -> _Refusal:
    return _Refusal("not_established", reason)


def _pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(kind), kind, len(payload), payload)


def _verifies(key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


# The consumer's trust inputs ------------------------------------------------------------------

class _Trust:
    """The assessment's trust inputs, each checked for shape. A defect raises ``CaseError``."""

    def __init__(self, assessment: dict[str, Any]) -> None:
        self.trusted = self._keys(assessment["trusted_signers"], "trusted_signers")
        self.agent = self._keys(assessment["agent_keys"], "agent_keys")
        if not self.trusted:
            raise CaseError("assessment.trusted_signers: expected at least one key")
        if set(self.trusted.values()) & set(self.agent.values()):
            raise CaseError("assessment: a key is both a trusted signer and an agent key")
        env = assessment["environment"]
        if not isinstance(env, dict) or set(env) != {"name", "sha256"}:
            raise CaseError("assessment.environment: expected exactly name and sha256")
        self.env_name = _string(env["name"], "assessment.environment.name")
        self.env_digest = _digest(env["sha256"], "assessment.environment.sha256")
        self.audience = _string(assessment["audience"], "assessment.audience")
        self.challenge = _digest(assessment["challenge"], "assessment.challenge")
        self.judged_at: datetime = _instant(assessment["judged_at"], "assessment.judged_at")
        age = assessment["max_age_seconds"]
        if isinstance(age, bool) or not isinstance(age, int) or age < 0:
            raise CaseError("assessment.max_age_seconds: expected a non-negative integer")
        self.max_age = timedelta(seconds=age)
        self.payload_type = _string(assessment["payload_type"], "assessment.payload_type")
        pins = assessment.get("probe_digests", [])
        if not isinstance(pins, list):
            raise CaseError("assessment.probe_digests: expected a list")
        self.probe_pins = {_digest(p, "assessment.probe_digests") for p in pins}

    @staticmethod
    def _keys(table: Any, label: str) -> dict[str, bytes]:
        """``{keyid: raw key}``; a keyid is the lowercase hex SHA-256 of its raw 32-byte key."""
        if not isinstance(table, dict):
            raise CaseError(f"assessment.{label}: expected an object")
        keys: dict[str, bytes] = {}
        for keyid, encoded in table.items():
            try:
                raw = strictb64.std(encoded)
            except (binascii.Error, ValueError, TypeError) as exc:
                raise CaseError(f"assessment.{label}: a key is not canonical base64") from exc
            if len(raw) != 32 or hashlib.sha256(raw).hexdigest() != keyid:
                raise CaseError(f"assessment.{label}: a keyid is not the SHA-256 of its 32-byte key")
            keys[keyid] = raw
        return keys


# Envelope and signatures ----------------------------------------------------------------------

def _b64(value: Any) -> bytes:
    if not isinstance(value, str) or "\n" in value or "\r" in value:
        raise _refuse("malformed_envelope")
    try:
        return strictb64.std(value)
    except (binascii.Error, ValueError) as exc:
        raise _refuse("malformed_envelope") from exc


def _envelope(raw: bytes) -> tuple[str, bytes, list[tuple[str, bytes]]]:
    """Rule 1: ``(payloadType, payload, [(keyid, signature)])``."""
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise _refuse("malformed_envelope")
    try:
        doc = parse_ijson(raw)
    except IJSONError as exc:
        raise _refuse("malformed_envelope") from exc
    if not isinstance(doc, dict):
        raise _refuse("malformed_envelope")
    kind, entries = doc.get("payloadType"), doc.get("signatures")
    if not isinstance(kind, str) or not kind:
        raise _refuse("malformed_envelope")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_SIGNATURES:
        raise _refuse("malformed_envelope")
    sigs: list[tuple[str, bytes]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("keyid"), str):
            raise _refuse("malformed_envelope")
        sigs.append((entry["keyid"], _b64(entry.get("sig"))))
    return kind, _b64(doc.get("payload")), sigs


def _authenticate(kind: str, payload: bytes, sigs: list[tuple[str, bytes]], trust: _Trust) -> None:
    """Rules 3 and 4. An agent key is used only to refuse; the verifying key comes from the policy."""
    message = _pae(kind, payload)
    for _, signature in sigs:
        if any(_verifies(key, message, signature) for key in trust.agent.values()):
            raise _refuse("signed_by_agent_key")
    named = False
    for keyid, signature in sigs:
        key = trust.trusted.get(keyid)
        if key is None:
            continue
        named = True
        if _verifies(key, message, signature):
            return
    raise _refuse("signature_invalid" if named else "untrusted_key")


# Predicate well-formedness --------------------------------------------------------------------

def _text(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _exactly(value: Any, members: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == members


def _instant_or_none(value: Any) -> datetime | None:
    if not _text(value, UTC_SECONDS):
        return None
    try:
        return _instant(value, "probedAt")
    except CaseError:
        return None


def _attempt_wellformed(a: Any) -> bool:
    return (isinstance(a, dict) and _text(a.get("locator"), TEXT512)
            and a.get("outcome") in OUTCOMES and ("detail" not in a or _text(a["detail"], DETAIL)))


def _class_wellformed(c: Any) -> bool:
    return (_exactly(c, {"class", "verdict", "attempts"}) and c["class"] in CLASSES
            and c["verdict"] in VERDICTS and isinstance(c["attempts"], list) and bool(c["attempts"])
            and all(_attempt_wellformed(a) for a in c["attempts"]))


def _probe_wellformed(v: Any) -> bool:
    return (_exactly(v, {"name", "version", "digest"}) and _text(v["name"], TEXT200)
            and _text(v["version"], TEXT200) and _exactly(v["digest"], {"sha256"})
            and _text(v["digest"]["sha256"], HEX64))


def _listed(value: Any, members: set[str], valid: Any) -> bool:
    return isinstance(value, list) and all(_exactly(e, members) and valid(e) for e in value)


#: Rule 13 members in the order the rule names them.
FIELD_CHECKS: tuple[tuple[str, Any], ...] = (
    ("audience", lambda v: _text(v, TEXT200)),
    ("challenge", lambda v: _text(v, HEX64)),
    ("probedAt", lambda v: _instant_or_none(v) is not None),
    ("vantage", lambda v: _text(v, TEXT200)),
    ("probe", _probe_wellformed),
    ("placeholders", lambda v: _listed(v, {"prefix"}, lambda e: _text(e["prefix"], TEXT200))),
    ("issuedToAgent", lambda v: _listed(
        v, {"id", "digestPrefix"},
        lambda e: _text(e["id"], TEXT200) and _text(e["digestPrefix"], HEX12))),
    ("classes", lambda v: isinstance(v, list) and all(_class_wellformed(c) for c in v)),
    ("result", lambda v: v in RESULTS),
)


def _statement(payload: bytes, trust: _Trust) -> dict[str, Any]:
    """Rules 5 to 10: the Statement, its subject and the predicate object."""
    try:
        statement = parse_ijson(payload)
    except IJSONError:
        statement = None
    if not isinstance(statement, dict):
        raise _unestablished("payload_not_json_object")
    if statement.get("_type") != STATEMENT_TYPE:
        raise _unestablished("unsupported_statement_type")
    if not same_identifier(statement.get("predicateType"), PREDICATE_TYPE):

        raise _unestablished("unsupported_predicate")
    subjects = statement.get("subject")
    one: Any = subjects[0] if isinstance(subjects, list) and len(subjects) == 1 else None
    if not (_exactly(one, {"name", "digest"}) and _text(one["name"], TEXT512)
            and _exactly(one["digest"], {"sha256"}) and _text(one["digest"]["sha256"], HEX64)):
        raise _unestablished("subject_malformed")
    if one["name"] != trust.env_name or one["digest"]["sha256"] != trust.env_digest:
        raise _refuse("environment_mismatch")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise _unestablished("predicate_field_invalid:predicate")
    return predicate


def _wellformed(p: dict[str, Any]) -> None:
    """Rules 11 to 14."""
    if set(p) != set(MEMBERS):
        raise _unestablished("predicate_field_invalid:members")
    if p["classSet"] != CLASS_SET:
        raise _unestablished("class_set_unsupported")
    for name, valid in FIELD_CHECKS:
        if not valid(p[name]):
            raise _unestablished(f"predicate_field_invalid:{name}")
    for c in p["classes"]:
        for a in c["attempts"]:
            carries = a["outcome"] in ("found", "issued_to_agent")
            if (not set(a) <= ATTEMPT_MEMBERS or ("digestPrefix" in a) != carries
                    or (carries and not _text(a["digestPrefix"], HEX12))):
                raise _refuse("attempt_fields")


def _binding(p: dict[str, Any], trust: _Trust) -> None:
    """Rules 15 to 20: vantage, audience, challenge, time and probe pin."""
    if p["vantage"] != "agent-process":
        raise _unestablished("vantage_not_agent")
    if p["audience"] != trust.audience:
        raise _refuse("audience_mismatch")
    if p["challenge"] != trust.challenge:
        raise _refuse("challenge_mismatch")
    probed = _instant_or_none(p["probedAt"])
    if probed is None or probed > trust.judged_at:
        raise _refuse("probed_in_future")
    if trust.judged_at - probed > trust.max_age:
        raise _unestablished("result_stale")
    if trust.probe_pins and p["probe"]["digest"]["sha256"] not in trust.probe_pins:
        raise _unestablished("probe_not_pinned")


def _coverage(p: dict[str, Any]) -> None:
    """Rules 21 to 24: each class once, every class present, issued-to-agent and placeholder attempts declared."""
    seen: set[str] = set()
    for c in p["classes"]:
        if c["class"] in seen:
            raise _refuse(f"class_duplicate:{c['class']}")
        seen.add(c["class"])
    for name in CLASSES:
        if name not in seen:
            raise _refuse(f"class_missing:{name}")
    declared = {e["digestPrefix"] for e in p["issuedToAgent"]}
    attempts = [a for c in p["classes"] for a in c["attempts"]]
    if any(a["outcome"] == "issued_to_agent" and a["digestPrefix"] not in declared for a in attempts):
        raise _refuse("issued_to_agent_undeclared")
    if not p["placeholders"] and any(a["outcome"] == "placeholder" for a in attempts):
        raise _refuse("placeholder_undeclared")


def derive_verdict(attempts: list[dict[str, Any]]) -> str:
    """A class's verdict from its attempts: any found is reachable, any error or not_run is untested."""
    outcomes = {a["outcome"] for a in attempts}
    if "found" in outcomes:
        return "reachable"
    if outcomes & {"error", "not_run"}:
        return "could_not_test"
    return "not_reachable"


def derive_result(verdicts: list[str]) -> str:
    """The overall result from the class verdicts."""
    if "reachable" in verdicts:
        return "exposed"
    if "could_not_test" in verdicts:
        return "incomplete"
    return "contained"


def _derived(p: dict[str, Any]) -> str:
    """Rules 25 and 26: recompute each class verdict in list order, then the result."""
    by_class = {c["class"]: c for c in p["classes"]}
    verdicts = []
    for name in CLASSES:
        c = by_class[name]
        want = derive_verdict(c["attempts"])
        verdicts.append(want)
        if c["verdict"] == want:
            continue
        if c["verdict"] == "not_reachable":
            raise _refuse(f"{'reachable' if want == 'reachable' else 'untested'}_reported_clean:{name}")
        raise _refuse(f"class_verdict_mismatch:{name}")
    result = derive_result(verdicts)
    if p["result"] != result:
        overstated = RESULTS.index(p["result"]) < RESULTS.index(result)
        raise _refuse("result_overstates" if overstated else "result_mismatch")
    return result


def verify(raw: bytes, trust: _Trust) -> str:
    """The derived result of a conforming record; the first failed rule raises a refusal."""
    kind, payload, sigs = _envelope(raw)
    if kind != trust.payload_type:
        raise _unestablished("unsupported_payload_type")
    _authenticate(kind, payload, sigs, trust)
    predicate = _statement(payload, trust)
    _wellformed(predicate)
    _binding(predicate, trust)
    _coverage(predicate)
    return _derived(predicate)


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict[str, Any]:
    """Judge one bound probe record under the consumer's pinned keys, environment and challenge."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, REQUIRED, OPTIONAL)
    trust = _Trust(assessment)
    raw, binding = bound(artifacts, artifact_root, assessment["envelope"], "assessment.envelope")
    scope = {"envelope": binding, "predicate_type": PREDICATE_TYPE,
             "environment": {"name": trust.env_name, "sha256": trust.env_digest},
             "audience": trust.audience, "challenge": trust.challenge,
             "judged_at": assessment["judged_at"], "limit": LIMIT}
    if raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "envelope_unavailable")
    try:
        result = verify(raw, trust)
    except _Refusal as stop:
        check = {"id": "credential_reachability_rules", "status": "fail", "codes": [stop.reason]}
        return decision(case_id, CLAIM_TYPE, scope, stop.decision, stop.reason, [check])
    check = {"id": "credential_reachability_rules", "status": "pass", "result": result, "codes": []}
    return decision(case_id, CLAIM_TYPE, scope, "supported", f"{result}_verified", [check])
