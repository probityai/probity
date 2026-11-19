"""Read a decision record's action-binding attachment and report each dimension on its own.

The attachment format is the one whose documents carry ``"profile": "dps-action-binding"`` and
``"profile_version": "0.3.0"``: one document beside one decision record (``decision_id``), holding the
exact bytes of every action specification under its SHA-256 and the stages of one reviewed action
(proposal, review, outcome, standing approval and its revocation, authorised change, request,
recheck, attempt, result), optionally signed with an organisation seal whose signed bytes are named
``dps-signatures 0.2.0 organisation_seal``. This reader was written from the published text of that
format, its JSON schemas and its published test data, without its authors' code.

:func:`read` returns one result per attachment. Every check is its own dimension with a ``status``
of ``verified``, ``failed``, ``not_checked``, ``unavailable`` or ``not_supported``; no dimension
stands for another and nothing merges them into one pass. Two profiles decide what a relying party
accepts (:func:`verdict`):

* ``baseline`` reads the format as its text does: a dimension that failed refuses, and a dimension
  that could not be checked stays reported as such.
* ``strict`` adds the checks the format's text leaves to the relying party, each its own dimension
  under ``strict``: whether an approver is also the proposer, requester or executor; whether one
  request was observed to take effect twice; whether the people and authorities named are confirmed
  by a source the relying party holds; whether the issuer's times agree with an independent clock;
  whether this attachment is the latest the relying party knows for the decision; and whether it
  is signed. Under ``strict`` every one of them, and the issuer signature, must be ``verified``.

The reader does not read RFC 3161 tokens or other timestamps carried beside an attachment: where
one is supplied, ``time_assurance`` is ``not_supported`` and never ``verified``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field
from datetime import date
from fractions import Fraction
from typing import Any

from .ijson import IJSONError, parse_ijson

PROFILE = "dps-action-binding"
PROFILE_VERSION = "0.3.0"
POLICY_PROFILE = "dps-anchoring-trust-policy"
POLICY_VERSION = "0.2.0"
SIGNED_BYTES_REF = "dps-signatures 0.2.0 organisation_seal"
SUITE = "decision-record/v1"

VERIFIED, FAILED, NOT_CHECKED, UNAVAILABLE, NOT_SUPPORTED = (
    "verified", "failed", "not_checked", "unavailable", "not_supported")
STATUSES = (VERIFIED, FAILED, NOT_CHECKED, UNAVAILABLE, NOT_SUPPORTED)

#: The dimensions the binding checks report, in the order a refusal names the first that failed.
BINDING_DIMENSIONS = (
    "specification_digests", "specification_statements", "record_statements", "action_binding",
    "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")
#: The checks the strict profile adds, each a dimension of its own.
STRICT_DIMENSIONS = (
    "approver_independence", "single_effect_per_request", "identity_independent",
    "authority_independent", "time_independent", "latest_attachment", "signature_required")
PROFILES = ("baseline", "strict")

MAX_SAFE_INTEGER = 2**53 - 1
OUTCOME_WORDS = ("approved", "rejected", "escalated")
BOUNDS_MEMBERS = ("operation", "target", "policy_version", "input_version_refs", "parameters",
                  "max_requests", "valid_from", "valid_until")
SPEC_MEMBERS = ("operation", "target", "policy_version", "input_version_refs", "parameters")
_TIME = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?"
                   r"(Z|[+-][0-9]{2}:[0-9]{2})?$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_STAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DECISION_ID = re.compile(r"^DR-[0-9]{4}-[0-9]{3,}$")
_SEALED_AT = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_B64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")


class NotRead(ValueError):
    """Bytes this reader refuses to read at all (not UTF-8, not I-JSON, a member named twice)."""


# --- times ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Instant:
    """A time as written, read as an instant when it names one."""

    text: str
    seconds: Fraction | None  # None: the text names no instant
    why: str = ""

    @property
    def ok(self) -> bool:
        return self.seconds is not None


def instant(text: Any, *, offset_required: bool = True) -> Instant:
    """Read an RFC 3339 time as seconds on one axis; a date or second no calendar has is no instant."""
    if not isinstance(text, str):
        return Instant(repr(text), None, "not a time")
    match = _TIME.match(text)
    if match is None:
        return Instant(text, None, "not a time")
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    fraction, zone = match.group(7), match.group(8)
    if zone is None:
        return Instant(text, None, "no offset")
    if hour > 23 or minute > 59 or second > 59:
        return Instant(text, None, "no such time")
    try:
        ordinal = date(year, month, day).toordinal()
    except ValueError:
        return Instant(text, None, "no such date")
    offset = 0
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        oh, om = int(zone[1:3]), int(zone[4:6])
        if oh > 23 or om > 59:
            return Instant(text, None, "no such offset")
        offset = sign * (oh * 3600 + om * 60)
    total = Fraction(ordinal * 86400 + hour * 3600 + minute * 60 + second - offset)
    if fraction:
        total += Fraction(fraction[1:]) / 10 ** (len(fraction) - 1)
    return Instant(text, total)


# --- strict reading ------------------------------------------------------------------------------

def read_document(data: bytes) -> Any:
    """Read one document as I-JSON; a member named twice, at any depth, is not read."""
    try:
        return parse_ijson(data)
    except IJSONError as exc:
        raise NotRead(f"not read: {exc}") from exc


class _Unsafe(int):
    """An integer token outside I-JSON's exact range: read, so the bounds can be judged."""


def _read_bounds(data: bytes) -> Any:
    """Bounds as their bytes say: a number that is not finite, or a member twice, is unreadable."""
    def hook(text: str) -> int:
        value = int(text)
        return _Unsafe(value) if abs(value) > MAX_SAFE_INTEGER else value
    return parse_ijson(data, parse_int=hook)


def _same(left: Any, right: Any) -> bool:
    """JSON value equality with types kept apart: 1, 1.0 and true are three values."""
    numbers = (isinstance(left, int) and isinstance(right, int)
               and not isinstance(left, bool) and not isinstance(right, bool))
    if type(left) is not type(right) and not numbers:
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return bool(left == right)


def _json_integer(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool) and not isinstance(value, _Unsafe)
            and abs(value) <= MAX_SAFE_INTEGER)


def _b64(text: Any) -> bytes | None:
    if not isinstance(text, str) or len(text) < 4 or not _B64.match(text):
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- dimension helpers ---------------------------------------------------------------------------

def dim(status: str, *findings: str, **extra: Any) -> dict[str, Any]:
    """One dimension: its status, then anything it carries, then its findings."""
    out: dict[str, Any] = {"status": status}
    out.update(extra)
    if findings:
        out["findings"] = list(findings)
    return out


class Tally:
    """Findings of one dimension, worst first: failed over not checked over unavailable."""

    def __init__(self) -> None:
        self.failed: list[str] = []
        self.unchecked: list[str] = []
        self.unavailable: list[str] = []

    def fail(self, text: str) -> None:
        self.failed.append(text)

    def skip(self, text: str) -> None:
        self.unchecked.append(text)

    def gone(self, text: str) -> None:
        self.unavailable.append(text)

    def status(self, *, empty: str = VERIFIED) -> str:
        if self.failed:
            return FAILED
        if self.unchecked:
            return NOT_CHECKED
        if self.unavailable:
            return UNAVAILABLE
        return empty

    def result(self, *, empty: str = VERIFIED, **extra: Any) -> dict[str, Any]:
        return dim(self.status(empty=empty), *(self.failed + self.unchecked + self.unavailable),
                   **extra)


# --- structure -----------------------------------------------------------------------------------

_STAGE_SHAPES: dict[str, tuple[set[str], set[str]]] = {
    "proposal": ({"stage_id", "kind", "at", "origin", "spec_digest"},
                 {"deployer_role_pointer", "system_name", "version", "actor_ref"}),
    "review": ({"stage_id", "kind", "at", "reviewer_ref"},
               {"shown_spec_digest", "shown_bounds_digest", "proposal_ref", "edited_by",
                "shown_view_ref", "shown_view_digest"}),
    "outcome": ({"stage_id", "kind", "at", "review_ref", "outcome", "actor_ref", "method", "rationale"},
                {"approved_spec_digest", "authority", "request_limit", "escalated_to_ref",
                 "identity_evidence_ref", "legal_signature_ref", "core_ref"}),
    "standing_approval": ({"stage_id", "kind", "at", "review_ref", "actor_ref", "method", "authority",
                           "rationale", "bounds_digest", "bounds"},
                          {"identity_evidence_ref", "legal_signature_ref", "core_ref"}),
    "standing_revocation": ({"stage_id", "kind", "at", "revokes_ref", "actor_ref", "method",
                             "rationale"}, {"authority"}),
    "change_authorisation": ({"stage_id", "kind", "at", "from_ref", "spec_digest", "actor_ref",
                              "method", "authority", "rationale"},
                             {"request_limit", "identity_evidence_ref", "legal_signature_ref"}),
    "request": ({"stage_id", "kind", "at", "request_id", "authorised_by", "spec_digest",
                 "requested_by"}, set()),
    "recheck": ({"stage_id", "kind", "at", "request_ref", "result", "authority_source_ref"},
                {"detail"}),
    "attempt": ({"stage_id", "kind", "at", "request_ref", "recheck_ref", "spec_digest",
                 "executor_ref"}, {"trace_refs"}),
    "result": ({"stage_id", "kind", "at", "attempt_ref", "observed", "basis"},
               {"evidence_ref", "trace_refs"}),
}
_DIGEST_MEMBERS = ("spec_digest", "shown_spec_digest", "shown_bounds_digest", "approved_spec_digest",
                   "bounds_digest", "shown_view_digest")
_ID_MEMBERS = ("stage_id", "proposal_ref", "review_ref", "revokes_ref", "from_ref", "authorised_by",
               "request_ref", "recheck_ref", "attempt_ref")
_REF_MEMBERS = ("deployer_role_pointer", "system_name", "version", "actor_ref", "reviewer_ref",
                "edited_by", "shown_view_ref", "method", "escalated_to_ref", "identity_evidence_ref",
                "legal_signature_ref", "request_id", "requested_by", "authority_source_ref",
                "executor_ref", "evidence_ref")
_ENUMS = {"origin": ("ai", "human"), "outcome": OUTCOME_WORDS,
          "result": ("authorised", "not_authorised", "unavailable"),
          "observed": ("succeeded", "failed", "indeterminate"),
          "basis": ("target_response", "independent_observation", "executor_observation")}


def _is_ref(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 512 and bool(re.search(r"\S", value))


def _check_members(obj: Any, required: set[str], optional: set[str], where: str, tally: Tally) -> bool:
    if not isinstance(obj, dict):
        tally.fail(f"{where}: not an object")
        return False
    missing = sorted(required - obj.keys())
    extra = sorted(obj.keys() - required - optional)
    if missing:
        tally.fail(f"{where}: missing {', '.join(missing)}")
    if extra:
        tally.fail(f"{where}: members the format does not have: {', '.join(extra)}")
    return not missing and not extra


def _check_rationale(value: Any, where: str, tally: Tally) -> None:
    if not _check_members(value, {"timing"}, {"ai_assisted", "recorded_at", "text_ref"}, where, tally):
        return
    timing = value["timing"]
    if timing not in ("contemporaneous", "later_supplemented", "not_recorded"):
        tally.fail(f"{where}: timing {timing!r} is not one the format names")
    elif timing == "not_recorded":
        if value.keys() & {"ai_assisted", "recorded_at", "text_ref"}:
            tally.fail(f"{where}: a rationale not recorded states when or how it was recorded")
    elif "ai_assisted" not in value or "recorded_at" not in value:
        tally.fail(f"{where}: a recorded rationale states ai_assisted and recorded_at")
    if "ai_assisted" in value and not isinstance(value["ai_assisted"], bool):
        tally.fail(f"{where}: ai_assisted is not a boolean")
    if "recorded_at" in value and not _TIME.match(str(value["recorded_at"])):
        tally.fail(f"{where}: recorded_at is not a time with an offset")


def _check_core_ref(value: Any, where: str, tally: Tally) -> None:
    if not isinstance(value, dict) or value.get("field") not in ("affirmation_record", "review_log"):
        tally.fail(f"{where}: core_ref names no core field the format reads")
    elif value["field"] == "affirmation_record":
        _check_members(value, {"field"}, set(), where, tally)
    elif _check_members(value, {"field", "index"}, set(), where, tally):
        index = value["index"]
        integral = _json_integer(index) or (isinstance(index, float) and index.is_integer())
        if not integral or index < 0:
            tally.fail(f"{where}: review_log index is not an integer from 0")


def _check_stage_kind(stage: dict, where: str, tally: Tally) -> None:
    kind = stage["kind"]
    if kind == "proposal":
        ai = stage.get("origin") == "ai"
        if ai and ("deployer_role_pointer" not in stage or "actor_ref" in stage):
            tally.fail(f"{where}: an AI proposal names its deployer role and no person")
        if not ai and ("actor_ref" not in stage
                       or stage.keys() & {"deployer_role_pointer", "system_name", "version"}):
            tally.fail(f"{where}: a human proposal names its person and no AI system")
    elif kind == "review":
        if ("shown_spec_digest" in stage) == ("shown_bounds_digest" in stage):
            tally.fail(f"{where}: a review is shown exactly one of a specification and bounds")
    elif kind == "outcome":
        approved = stage.get("outcome") == "approved"
        carries = stage.keys() & {"approved_spec_digest", "authority", "request_limit"}
        if approved and not {"approved_spec_digest", "authority"} <= stage.keys():
            tally.fail(f"{where}: an approval carries its approved digest and its authority")
        if not approved and carries:
            tally.fail(f"{where}: a rejection or an escalation carries {', '.join(sorted(carries))}")
    for key in ("rationale",):
        if key in stage:
            _check_rationale(stage[key], f"{where}.{key}", tally)
    if "authority" in stage:
        _check_members(stage["authority"], {"authority_ref"}, set(), f"{where}.authority", tally)
    if "core_ref" in stage:
        _check_core_ref(stage["core_ref"], f"{where}.core_ref", tally)
    if "request_limit" in stage and not (_json_integer(stage["request_limit"])
                                         and stage["request_limit"] >= 1):
        tally.fail(f"{where}: request_limit is not an integer from 1")
    if kind == "standing_approval":
        _check_content(stage["bounds"], f"{where}.bounds", tally)


def _check_values(stage: dict, where: str, tally: Tally) -> None:
    for key in _DIGEST_MEMBERS:
        if key in stage and not (isinstance(stage[key], str) and _DIGEST.match(stage[key])):
            tally.fail(f"{where}: {key} is not a SHA-256 in lowercase hex")
    for key in _ID_MEMBERS:
        if key in stage and not (isinstance(stage[key], str) and _STAGE_ID.match(stage[key])):
            tally.fail(f"{where}: {key} is not a stage id")
    for key in _REF_MEMBERS:
        if key in stage and not _is_ref(stage[key]):
            tally.fail(f"{where}: {key} is not a reference")
    for key, allowed in _ENUMS.items():
        if key in stage and stage[key] not in allowed:
            tally.fail(f"{where}: {key} {stage[key]!r} is not one the format names")
    if not _TIME.match(str(stage.get("at"))) or _TIME.match(str(stage.get("at"))).group(8) is None:
        tally.fail(f"{where}: at is not a time with an offset")
    for key in ("trace_refs",):
        if key in stage and not (isinstance(stage[key], list) and all(_is_ref(x) for x in stage[key])):
            tally.fail(f"{where}: {key} is not a list of references")


def _check_content(content: Any, where: str, tally: Tally) -> None:
    reasons = ("withheld", "retention_disposition", "redaction_event", "other")
    if isinstance(content, dict) and content.get("availability") == "available":
        if (_check_members(content, {"availability", "bytes_b64"}, set(), where, tally)
                and _b64(content["bytes_b64"]) is None):
            tally.fail(f"{where}: bytes_b64 is not padded base64")
    elif isinstance(content, dict) and content.get("availability") == "unavailable":
        if (_check_members(content, {"availability", "reason"}, {"reason_ref"}, where, tally)
                and content["reason"] not in reasons):
            tally.fail(f"{where}: reason {content['reason']!r} is not one the format names")
    else:
        tally.fail(f"{where}: content is neither available nor unavailable")


def _check_specification(spec: Any, where: str, tally: Tally) -> None:
    if not _check_members(spec, {"spec_digest", "representation", "content", "summary"}, set(),
                          where, tally):
        return
    if not (isinstance(spec["spec_digest"], str) and _DIGEST.match(spec["spec_digest"])):
        tally.fail(f"{where}: spec_digest is not a SHA-256 in lowercase hex")
    rep = spec["representation"]
    if isinstance(rep, dict) and rep.get("kind") == "original_bytes":
        _check_members(rep, {"kind", "media_type"}, set(), f"{where}.representation", tally)
    elif isinstance(rep, dict) and rep.get("kind") == "canonical_form":
        _check_members(rep, {"kind", "media_type", "canonicalisation", "specification_ref"}, set(),
                       f"{where}.representation", tally)
    else:
        tally.fail(f"{where}: representation is neither original bytes nor a canonical form")
    _check_content(spec["content"], f"{where}.content", tally)
    summary = spec["summary"]
    if _check_members(summary, {"operation", "target", "policy_version", "input_version_refs"}, set(),
                      f"{where}.summary", tally):
        refs = summary["input_version_refs"]
        if not (isinstance(refs, list) and all(_is_ref(x) for x in refs)):
            tally.fail(f"{where}.summary: input_version_refs is not a list of references")


def _check_signature_shape(sig: Any, tally: Tally) -> None:
    if not _check_members(sig, {"algorithm", "key_ref", "signed_bytes_ref", "sealed_at", "value_b64"},
                          set(), "issuer_signature", tally):
        return
    if sig["algorithm"] != "Ed25519":
        tally.fail(f"issuer_signature: algorithm {sig['algorithm']!r} is not Ed25519")
    if sig["signed_bytes_ref"] != SIGNED_BYTES_REF:
        tally.fail("issuer_signature: signed_bytes_ref names other signed bytes")
    if not (isinstance(sig["key_ref"], str) and 1 <= len(sig["key_ref"]) <= 256):
        tally.fail("issuer_signature: key_ref is not a key reference")
    if not (isinstance(sig["sealed_at"], str) and _SEALED_AT.match(sig["sealed_at"])):
        tally.fail("issuer_signature: sealed_at is not written YYYY-MM-DDTHH:MM:SSZ")
    if _b64(sig["value_b64"]) is None:
        tally.fail("issuer_signature: value_b64 is not padded base64")


def structural_validity(doc: Any) -> dict[str, Any]:
    """The attachment against the shape its schema publishes, member by member."""
    tally = Tally()
    if not _check_members(doc, {"profile", "profile_version", "decision_id", "action_specifications",
                                "stages"}, {"issuer_signature"}, "attachment", tally):
        return tally.result()
    if doc["profile"] != PROFILE or doc["profile_version"] != PROFILE_VERSION:
        tally.fail(f"attachment: profile {doc['profile']!r} {doc['profile_version']!r} is not "
                   f"{PROFILE} {PROFILE_VERSION}")
    if not (isinstance(doc["decision_id"], str) and _DECISION_ID.match(doc["decision_id"])):
        tally.fail("attachment: decision_id is not a decision record id")
    specs = doc["action_specifications"]
    if not isinstance(specs, list) or not specs:
        tally.fail("attachment: action_specifications is not a non-empty list")
    else:
        for index, spec in enumerate(specs):
            _check_specification(spec, f"action_specifications[{index}]", tally)
    stages = doc["stages"]
    if not isinstance(stages, list):
        tally.fail("attachment: stages is not a list")
        return tally.result()
    kinds = [s.get("kind") for s in stages if isinstance(s, dict)]
    if "review" not in kinds or not {"outcome", "standing_approval"} & set(kinds):
        tally.fail("attachment: no review, or neither an outcome nor a standing approval")
    for index, stage in enumerate(stages):
        where = f"stages[{index}]"
        kind = stage.get("kind") if isinstance(stage, dict) else None
        if kind not in _STAGE_SHAPES:
            tally.fail(f"{where}: kind {kind!r} is not a stage the format names")
            continue
        required, optional = _STAGE_SHAPES[kind]
        if _check_members(stage, required, optional, where, tally):
            _check_values(stage, where, tally)
            _check_stage_kind(stage, where, tally)
    if "issuer_signature" in doc:
        _check_signature_shape(doc["issuer_signature"], tally)
    return tally.result()


# --- the attachment as read ----------------------------------------------------------------------

@dataclass
class Spec:
    index: int
    digest: str
    raw: bytes | None  # None: unavailable
    media_type: str
    summary: dict


@dataclass
class Attachment:
    """The parts of one attachment the binding checks read."""

    doc: dict
    specs: list[Spec]
    stages: list[dict]
    by_id: dict[str, dict] = field(default_factory=dict)
    position: dict[str, int] = field(default_factory=dict)
    duplicate_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_doc(cls, doc: dict) -> Attachment:
        specs = []
        for index, spec in enumerate(doc.get("action_specifications") or []):
            content = spec.get("content") or {}
            raw = _b64(content.get("bytes_b64")) if content.get("availability") == "available" else None
            rep = spec.get("representation") or {}
            specs.append(Spec(index, spec.get("spec_digest"), raw, rep.get("media_type", ""),
                              spec.get("summary") or {}))
        stages = [s for s in doc.get("stages") or [] if isinstance(s, dict)]
        out = cls(doc, specs, stages)
        for pos, stage in enumerate(stages):
            sid = stage.get("stage_id")
            if sid in out.by_id:
                out.duplicate_ids.append(sid)
                continue
            out.by_id[sid] = stage
            out.position[sid] = pos
        return out

    def of_kind(self, *kinds: str) -> list[dict]:
        return [s for s in self.stages if s.get("kind") in kinds]

    def spec(self, digest: str) -> Spec | None:
        return next((s for s in self.specs if s.digest == digest), None)

    def stage(self, ref: Any, *kinds: str) -> dict | None:
        found = self.by_id.get(ref) if isinstance(ref, str) else None
        if found is not None and kinds and found.get("kind") not in kinds:
            return None
        return found

    def at(self, stage: dict) -> Instant:
        return instant(stage.get("at"))

    def services(self) -> set[str]:
        """Every machine party the attachment names: the AI drafter, the requester, the executor."""
        named: set[str] = set()
        for stage in self.of_kind("proposal"):
            if stage.get("origin") == "ai":
                named |= {stage.get(k) for k in ("deployer_role_pointer", "system_name") if stage.get(k)}
        named |= {s["requested_by"] for s in self.of_kind("request") if s.get("requested_by")}
        named |= {s["executor_ref"] for s in self.of_kind("attempt") if s.get("executor_ref")}
        return named

    def proposers(self) -> set[str]:
        out: set[str] = set()
        for stage in self.of_kind("proposal"):
            out |= {stage.get(k) for k in ("deployer_role_pointer", "system_name", "actor_ref")
                    if stage.get(k)}
        return out

    def approvals(self) -> list[dict]:
        """Approved outcomes and standing approvals: every act that lets a request rest on it."""
        return [s for s in self.stages if s.get("kind") == "standing_approval"
                or (s.get("kind") == "outcome" and s.get("outcome") == "approved")]


def _before(earlier: Instant, later: Instant) -> bool | None:
    """Whether ``earlier`` is at or before ``later``; None when either names no instant."""
    if not earlier.ok or not later.ok:
        return None
    return earlier.seconds <= later.seconds


# --- specifications ------------------------------------------------------------------------------

def specification_dimensions(att: Attachment) -> tuple[dict, dict, list[dict]]:
    """Each specification's bytes against its digest, and its summary against its bytes."""
    digests, statements, per_spec = Tally(), Tally(), []
    for spec in att.specs:
        entry: dict[str, Any] = {"spec_index": spec.index, "spec_digest": spec.digest}
        if spec.raw is None:
            digests.gone(f"specification {spec.index}: bytes unavailable")
            statements.skip(f"specification {spec.index}: bytes unavailable, summary not checked")
            entry["digest"] = dim(UNAVAILABLE)
            entry["statements"] = dim(NOT_CHECKED)
            per_spec.append(entry)
            continue
        if sha256_hex(spec.raw) == spec.digest:
            entry["digest"] = dim(VERIFIED)
        else:
            digests.fail(f"specification {spec.index}: its bytes are not its digest's")
            entry["digest"] = dim(FAILED)
        entry["statements"] = _statements(spec, statements)
        per_spec.append(entry)
    return digests.result(), statements.result(), per_spec


def _statements(spec: Spec, tally: Tally) -> dict:
    if spec.media_type != "application/json":
        tally.skip(f"specification {spec.index}: media type {spec.media_type!r} is not read")
        return dim(NOT_CHECKED)
    try:
        body = read_document(spec.raw or b"")
    except NotRead as exc:
        tally.skip(f"specification {spec.index}: {exc}")
        return dim(NOT_CHECKED)
    if not isinstance(body, dict):
        tally.skip(f"specification {spec.index}: the bytes are not a JSON object")
        return dim(NOT_CHECKED)
    wrong = [k for k in ("operation", "target", "policy_version", "input_version_refs")
             if k not in body or not _same(body[k], spec.summary.get(k))]
    if wrong:
        tally.fail(f"specification {spec.index}: the summary's {', '.join(wrong)} is not the bytes'")
        return dim(FAILED)
    return dim(VERIFIED)


# --- record statements ---------------------------------------------------------------------------

def record_statements(att: Attachment, record: dict | None) -> dict:
    """The stages' statements about core fields, against the decision record when it is held."""
    if record is None:
        return dim(NOT_CHECKED, "the decision record is not supplied")
    tally = Tally()
    if record.get("decision_id") != att.doc.get("decision_id"):
        tally.fail(f"the attachment names {att.doc.get('decision_id')!r}, the record "
                   f"{record.get('decision_id')!r}")
    _proposer_against_record(att, record, tally)
    for stage in att.stages:
        if stage.get("kind") not in ("outcome", "standing_approval"):
            continue
        approval = stage.get("kind") == "standing_approval" or stage.get("outcome") == "approved"
        core = stage.get("core_ref")
        if core is None:
            if approval:
                tally.skip(f"{stage.get('stage_id')}: no core field backs this approval")
            continue
        _core_statement(stage, core, record, tally)
    return tally.result()


def _proposer_against_record(att: Attachment, record: dict, tally: Tally) -> None:
    authority = record.get("drafting_authority")
    for stage in att.of_kind("proposal"):
        if stage.get("origin") != "ai":
            continue
        if not isinstance(authority, dict):
            tally.fail(f"{stage.get('stage_id')}: an AI proposer, and the record has no drafting_authority")
            continue
        for key in ("deployer_role_pointer", "system_name", "version"):
            if stage.get(key) != authority.get(key):
                tally.fail(f"{stage.get('stage_id')}: {key} is not the record's drafting_authority's")


def _core_statement(stage: dict, core: dict, record: dict, tally: Tally) -> None:
    sid = stage.get("stage_id")
    word = "approved" if stage.get("kind") == "standing_approval" else stage.get("outcome")
    if core.get("field") == "affirmation_record":
        entry = record.get("affirmation_record")
        if not isinstance(entry, dict):
            tally.fail(f"{sid}: the record has no affirmation_record")
            return
        if word != "approved":
            tally.fail(f"{sid}: an affirmation backs an outcome that is not an approval")
        actor, when, method = entry.get("actor_identity"), entry.get("timestamp"), entry.get("method")
        if method != stage.get("method"):
            tally.fail(f"{sid}: method is not the affirmation_record's")
    else:
        index = core.get("index")
        if not _json_integer(index):
            tally.skip(f"{sid}: review_log index {index!r} is not written as an integer")
            return
        log = record.get("review_log")
        if not isinstance(log, list) or index >= len(log) or not isinstance(log[index], dict):
            tally.fail(f"{sid}: review_log has no entry {index}")
            return
        entry = log[index]
        actor, when = entry.get("reviewer"), entry.get("reviewed_at")
        if entry.get("outcome") not in OUTCOME_WORDS:
            tally.skip(f"{sid}: review_log outcome {entry.get('outcome')!r} is not a word this check knows")
        elif entry.get("outcome") != word:
            tally.fail(f"{sid}: the record's review_log says {entry.get('outcome')}, the stage {word}")
    if actor != stage.get("actor_ref"):
        tally.fail(f"{sid}: actor {stage.get('actor_ref')!r} is not the record's {actor!r}")
    core_time, stage_time = instant(when), instant(stage.get("at"))
    if not core_time.ok:
        tally.skip(f"{sid}: the record's time {when!r} cannot be compared ({core_time.why})")
    elif not stage_time.ok:
        tally.fail(f"{sid}: the stage's time {stage_time.text} names no instant")
    elif core_time.seconds != stage_time.seconds:
        tally.fail(f"{sid}: the stage's time is not the record's")


# --- action binding ------------------------------------------------------------------------------

class Binding:
    """The binding checks: one pass that also yields what the report carries beside the verdict."""

    def __init__(self, att: Attachment) -> None:
        self.att = att
        self.tally = Tally()
        self.reviews: list[list] = []
        self.standing: list[dict] = []
        self.request_stage_failed: set[str] = set()

    def run(self) -> dict:
        self._names_carried_specs()
        self._reviews()
        outcomes_by_review = self._outcomes()
        self._core_fields()
        self._changes()
        self._standing_approvals()
        self._requests(outcomes_by_review)
        self._attempts()
        return self.tally.result()

    # each stage that names a specification names one the attachment carries
    def _names_carried_specs(self) -> None:
        for stage in self.att.stages:
            for key in ("spec_digest", "shown_spec_digest", "approved_spec_digest"):
                if key in stage and self.att.spec(stage[key]) is None:
                    self.tally.fail(f"{stage.get('stage_id')}: {key} names a specification the "
                                    "attachment does not carry")

    def _reviews(self) -> None:
        for review in self.att.of_kind("review"):
            sid = review.get("stage_id")
            ref = review.get("proposal_ref")
            if "shown_bounds_digest" in review:
                if ref is not None:
                    self.tally.fail(f"{sid}: a review of bounds names a proposal")
                self.reviews.append([sid, "proposal_not_named", None])
                continue
            if ref is None:
                self.reviews.append([sid, "proposal_not_named", None])
                continue
            proposal = self.att.stage(ref, "proposal")
            if proposal is None:
                self.tally.fail(f"{sid}: proposal_ref {ref!r} names no proposal in the attachment")
                self.reviews.append([sid, "proposal_not_named", None])
            elif proposal.get("spec_digest") == review.get("shown_spec_digest"):
                self.reviews.append([sid, "as_proposed", None])
            else:
                editor = review.get("edited_by")
                if editor is None:
                    self.tally.fail(f"{sid}: shown other than its proposal, with no editor named")
                self.reviews.append([sid, "differs_from_proposal", editor])

    def _outcomes(self) -> dict[str, list[dict]]:
        by_review: dict[str, list[dict]] = {}
        for stage in self.att.of_kind("outcome", "standing_approval"):
            by_review.setdefault(stage.get("review_ref"), []).append(stage)
        for ref, answers in by_review.items():
            if len(answers) > 1:
                self.tally.fail(f"review {ref!r} has {len(answers)} outcomes")
        for outcome in self.att.of_kind("outcome"):
            sid = outcome.get("stage_id")
            review = self.att.stage(outcome.get("review_ref"), "review")
            if review is None:
                self.tally.fail(f"{sid}: answers no review in the attachment")
                continue
            if outcome.get("actor_ref") != review.get("reviewer_ref"):
                self.tally.fail(f"{sid}: given by {outcome.get('actor_ref')!r}, not by the person "
                                f"shown, {review.get('reviewer_ref')!r}")
            if outcome.get("outcome") != "approved":
                continue
            if "shown_bounds_digest" in review:
                self.tally.fail(f"{sid}: bounds approved as an outcome; an approval of bounds is a "
                                "standing approval")
            elif outcome.get("approved_spec_digest") != review.get("shown_spec_digest"):
                self.tally.fail(f"{sid}: approves a digest other than the one its review was shown")
        return by_review

    def _core_fields(self) -> None:
        seen: dict[tuple, str] = {}
        for stage in self.att.of_kind("outcome", "standing_approval"):
            core = stage.get("core_ref")
            if not isinstance(core, dict):
                continue
            key = (core.get("field"), repr(core.get("index")))
            if key in seen:
                self.tally.fail(f"{stage.get('stage_id')}: the core field {core.get('field')} "
                                f"already backs {seen[key]}")
            else:
                seen[key] = stage.get("stage_id")

    def _refused_digests(self) -> set[str]:
        """Specifications a reviewer in the attachment rejected or escalated."""
        out = set()
        for outcome in self.att.of_kind("outcome"):
            if outcome.get("outcome") in ("rejected", "escalated"):
                review = self.att.stage(outcome.get("review_ref"), "review")
                if review is not None and "shown_spec_digest" in review:
                    out.add(review["shown_spec_digest"])
        return out

    def _bound_digest(self, stage: dict | None) -> str | None:
        """The specification an approval or a change binds."""
        if stage is None:
            return None
        if stage.get("kind") == "outcome":
            return stage.get("approved_spec_digest")
        if stage.get("kind") == "change_authorisation":
            return stage.get("spec_digest")
        return None

    def _changes(self) -> None:
        parties = self.att.services() | self.att.proposers()
        refused = self._refused_digests()
        for change in self.att.of_kind("change_authorisation"):
            sid = change.get("stage_id")
            origin = self.att.stage(change.get("from_ref"))
            if origin is None or not (origin.get("kind") == "change_authorisation" or (
                    origin.get("kind") == "outcome" and origin.get("outcome") == "approved")):
                kind = None if origin is None else origin.get("kind")
                self.tally.fail(f"{sid}: a change starts from an approval or a change, not from {kind!r}"
                                if kind else f"{sid}: from_ref names no approval or change")
            elif self._bound_digest(origin) == change.get("spec_digest"):
                self.tally.fail(f"{sid}: names the specification it changes")
            if change.get("actor_ref") in parties:
                self.tally.fail(f"{sid}: authorised by {change.get('actor_ref')!r}, the proposer or a "
                                "service the attachment names")
            if change.get("spec_digest") in refused:
                self.tally.fail(f"{sid}: reaches a specification a reviewer rejected or escalated")

    # --- standing approvals ---

    def _standing_approvals(self) -> None:
        parties = self.att.services() | self.att.proposers()
        for approval in self.att.of_kind("standing_approval"):
            sid = approval.get("stage_id")
            review = self.att.stage(approval.get("review_ref"), "review")
            if review is None:
                self.tally.fail(f"{sid}: answers no review in the attachment")
            elif "shown_bounds_digest" not in review:
                self.tally.fail(f"{sid}: answers a review shown a specification, not bounds")
            elif review["shown_bounds_digest"] != approval.get("bounds_digest"):
                self.tally.fail(f"{sid}: the review was shown other bounds than those approved")
            if review is not None and approval.get("actor_ref") != review.get("reviewer_ref"):
                self.tally.fail(f"{sid}: given by someone other than the person shown the bounds")
            if approval.get("actor_ref") in parties:
                self.tally.fail(f"{sid}: given by {approval.get('actor_ref')!r}, the proposer or a "
                                "service the attachment names")
            self.standing.append(self._standing_entry(approval))
        for revocation in self.att.of_kind("standing_revocation"):
            target = self.att.stage(revocation.get("revokes_ref"))
            if target is None or target.get("kind") != "standing_approval":
                self.tally.fail(f"{revocation.get('stage_id')}: revokes no standing approval")

    def _standing_entry(self, approval: dict) -> dict:
        sid = approval.get("stage_id")
        requests = [r for r in self.att.of_kind("request") if r.get("authorised_by") == sid]
        revocations = [r for r in self.att.of_kind("standing_revocation") if r.get("revokes_ref") == sid]
        status, bounds, why = self._read_bounds(approval)
        entry: dict[str, Any] = {
            "standing_stage_id": sid, "status": status, "requests_recorded": len(requests),
            "max_requests": bounds.get("max_requests") if status == VERIFIED else None,
            "revocation": "recorded" if revocations else "none_recorded",
        }
        if why:
            entry["findings"] = [why]
        if status == FAILED:
            self.tally.fail(f"{sid}: {why}")
            for request in requests:
                self.request_stage_failed.add(request.get("stage_id"))
        elif status in (NOT_CHECKED, UNAVAILABLE):
            if requests:
                self.tally.skip(f"{sid}: {why}; the requests resting on it are not checked")
        else:
            self._requests_inside(approval, bounds, requests, revocations)
        return entry

    def _read_bounds(self, approval: dict) -> tuple[str, dict, str]:
        content = approval.get("bounds") or {}
        if content.get("availability") != "available":
            return UNAVAILABLE, {}, "the bounds' bytes are unavailable"
        raw = _b64(content.get("bytes_b64"))
        if raw is None:
            return NOT_CHECKED, {}, "the bounds' bytes cannot be decoded"
        if sha256_hex(raw) != approval.get("bounds_digest"):
            return FAILED, {}, "the bounds' bytes are not bounds_digest's"
        try:
            bounds = _read_bounds(raw)
        except IJSONError as exc:
            return NOT_CHECKED, {}, f"the bounds cannot be read ({exc.code})"
        problem = _bounds_problem(bounds)
        if problem:
            return FAILED, {}, f"not well-formed bounds: {problem}"
        return VERIFIED, bounds, ""

    def _requests_inside(self, approval: dict, bounds: dict, requests: list[dict],
                         revocations: list[dict]) -> None:
        sid = approval.get("stage_id")
        refused = self._refused_digests()
        if len(requests) > bounds["max_requests"]:
            self.tally.fail(f"{sid}: {len(requests)} requests rest on it, max_requests is "
                            f"{bounds['max_requests']}")
        start, end = instant(bounds["valid_from"]), instant(bounds["valid_until"])
        for request in requests:
            rid = request.get("stage_id")
            at = instant(request.get("at"))
            inside = _before(start, at), _before(at, end)
            if None in inside:
                self.tally.fail(f"{rid}: its time {at.text} cannot be placed in the period")
            elif not all(inside):
                self.tally.fail(f"{rid}: dated outside the bounds' period")
            if request.get("spec_digest") in refused:
                self.tally.fail(f"{rid}: reaches a specification a reviewer rejected or escalated")
            self._after_revocation(request, revocations)
            spec = self.att.spec(request.get("spec_digest"))
            if spec is None:
                continue  # reported by _names_carried_specs
            if spec.raw is None:
                self.tally.skip(f"{rid}: the specification's bytes are unavailable, not checked "
                                "against the bounds")
                continue
            problem = _outside_bounds(spec.raw, bounds)
            if problem:
                self.tally.fail(f"{rid}: outside the bounds: {problem}")

    def _after_revocation(self, request: dict, revocations: list[dict]) -> None:
        pos = self.att.position.get(request.get("stage_id"), -1)
        at = instant(request.get("at"))
        for revocation in revocations:
            if self.att.position.get(revocation.get("stage_id"), -1) < pos:
                self.tally.fail(f"{request.get('stage_id')}: listed after a recorded revocation")
                return
            order = _before(instant(revocation.get("at")), at)
            if order is None:
                self.tally.fail(f"{request.get('stage_id')}: whether it is dated after the revocation "
                                "cannot be checked")
                return
            if order and instant(revocation.get("at")).seconds != at.seconds:
                self.tally.fail(f"{request.get('stage_id')}: dated after a recorded revocation")
                return

    # --- requests ---

    def _requests(self, outcomes_by_review: dict[str, list[dict]]) -> None:
        ids: dict[str, str] = {}
        used: dict[str, int] = {}
        per_spec: dict[str, int] = {}
        for request in self.att.of_kind("request"):
            sid = request.get("stage_id")
            rid = request.get("request_id")
            if rid in ids:
                self.tally.fail(f"{sid}: request_id {rid!r} is already used by {ids[rid]}")
            else:
                ids[rid] = sid
            basis = self.att.stage(request.get("authorised_by"))
            kind = None if basis is None else basis.get("kind")
            if kind == "standing_approval":
                continue
            if kind == "change_authorisation" or (kind == "outcome" and basis.get("outcome") == "approved"):
                if self._bound_digest(basis) != request.get("spec_digest"):
                    self.tally.fail(f"{sid}: requests a specification other than the one "
                                    f"{basis.get('stage_id')} binds")
                used[basis["stage_id"]] = used.get(basis["stage_id"], 0) + 1
                per_spec[request.get("spec_digest")] = per_spec.get(request.get("spec_digest"), 0) + 1
            elif kind == "outcome":
                self.tally.fail(f"{sid}: rests on an outcome that is {basis.get('outcome')!r}, not an "
                                "approval")
            else:
                self.tally.fail(f"{sid}: authorised_by names no approval, change or standing approval")
        for change in self.att.of_kind("change_authorisation"):
            origin = change.get("from_ref")
            if isinstance(origin, str):
                used[origin] = used.get(origin, 0) + 1
        self._limits(used, per_spec)

    def _limits(self, used: dict[str, int], per_spec: dict[str, int]) -> None:
        largest: dict[str, int] = {}
        for stage in self.att.stages:
            digest = self._bound_digest(stage) if (
                stage.get("kind") == "change_authorisation"
                or (stage.get("kind") == "outcome" and stage.get("outcome") == "approved")) else None
            if digest is None:
                continue
            limit = stage.get("request_limit", 1)
            limit = limit if _json_integer(limit) else 1
            largest[digest] = max(largest.get(digest, 0), limit)
            count = used.get(stage.get("stage_id"), 0)
            if count > limit:
                self.tally.fail(f"{stage.get('stage_id')}: covers {limit} request(s) and {count} "
                                "rest on it, a change of it counting as one")
        for digest, count in per_spec.items():
            if digest in largest and count > largest[digest]:
                self.tally.fail(f"specification {digest[:12]}: requested {count} times, the largest "
                                f"request_limit binding it is {largest[digest]}")

    def _attempts(self) -> None:
        for attempt in self.att.of_kind("attempt"):
            sid = attempt.get("stage_id")
            request = self.att.stage(attempt.get("request_ref"), "request")
            if request is None:
                self.tally.fail(f"{sid}: names no request")
            elif attempt.get("spec_digest") != request.get("spec_digest"):
                self.tally.fail(f"{sid}: executes a specification other than the one requested")


def _bounds_problem(bounds: Any) -> str:
    """Why bounds are not well-formed, or the empty string."""
    if not isinstance(bounds, dict) or set(bounds) != set(BOUNDS_MEMBERS):
        names = sorted(set(bounds) ^ set(BOUNDS_MEMBERS)) if isinstance(bounds, dict) else []
        return f"members are not exactly the bounds' ({', '.join(names)})" if names else "not an object"
    for key in ("operation", "target", "policy_version"):
        if not isinstance(bounds[key], str):
            return f"{key} is not a string"
    refs = bounds["input_version_refs"]
    if not isinstance(refs, list) or not all(isinstance(x, str) for x in refs):
        return "input_version_refs is not a list of strings"
    if not (_json_integer(bounds["max_requests"]) and bounds["max_requests"] >= 1):
        return "max_requests is not a JSON integer from 1"
    start, end = instant(bounds["valid_from"]), instant(bounds["valid_until"])
    if not start.ok or not end.ok:
        return "the period's times name no instant"
    if start.seconds > end.seconds:
        return "valid_until is before valid_from"
    params = bounds["parameters"]
    if not isinstance(params, dict):
        return "parameters is not an object"
    for name, constraint in params.items():
        problem = _constraint_problem(constraint)
        if problem:
            return f"parameter {name!r}: {problem}"
    return ""


def _scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool)) or _json_integer(value)


def _constraint_problem(constraint: Any) -> str:
    if not isinstance(constraint, dict) or not constraint:
        return "a constraint is an object"
    keys = set(constraint)
    if keys == {"exact"}:
        return "" if _scalar(constraint["exact"]) else "exact is not a string, integer, boolean or null"
    if keys == {"one_of"}:
        values = constraint["one_of"]
        if not isinstance(values, list) or not values or not all(_scalar(v) for v in values):
            return "one_of is not a list of values"
        for i, value in enumerate(values):
            if any(_same(value, other) for other in values[i + 1:]):
                return "one_of names a value twice"
        return ""
    if keys == {"max_length"}:
        n = constraint["max_length"]
        return "" if _json_integer(n) and n >= 0 else "max_length is not a JSON integer from 0"
    if keys and keys <= {"min", "max"}:
        if not all(_json_integer(constraint[k]) for k in keys):
            return "min and max are JSON integers"
        if keys == {"min", "max"} and constraint["min"] > constraint["max"]:
            return "min is above max"
        return ""
    return f"a constraint of the kinds {sorted(keys)}"


def _outside_bounds(raw: bytes, bounds: dict) -> str:
    """Why a specification's bytes fall outside the bounds, or the empty string."""
    try:
        spec = _read_bounds(raw)
    except IJSONError as exc:
        return f"the specification cannot be read ({exc.code})"
    if not isinstance(spec, dict):
        return "the specification is not a JSON object"
    extra = sorted(set(spec) - set(SPEC_MEMBERS))
    if extra:
        return f"members the bounds do not name: {', '.join(extra)}"
    for key in ("operation", "target", "policy_version"):
        if key not in spec or not _same(spec[key], bounds[key]):
            return f"{key} is not the bounds'"
    refs = spec.get("input_version_refs", [])
    if not isinstance(refs, list) or any(not any(_same(r, a) for a in bounds["input_version_refs"])
                                         for r in refs):
        return "an input-version reference the bounds do not allow"
    params = spec.get("parameters", {})
    if not isinstance(params, dict):
        return "parameters is not an object"
    for name in sorted(set(params) | set(bounds["parameters"])):
        if name not in bounds["parameters"]:
            return f"parameter {name!r} is not named in the bounds"
        if name not in params:
            return f"parameter {name!r} is named in the bounds and missing"
        if not _satisfies(params[name], bounds["parameters"][name]):
            return f"parameter {name!r} is outside its constraint"
    return ""


def _satisfies(value: Any, constraint: dict) -> bool:
    if "exact" in constraint:
        return _same(value, constraint["exact"])
    if "one_of" in constraint:
        return any(_same(value, v) for v in constraint["one_of"])
    if "max_length" in constraint:
        return isinstance(value, str) and len(value) <= constraint["max_length"]
    if not _json_integer(value):
        return False
    return value >= constraint.get("min", value) and value <= constraint.get("max", value)


# --- order, rechecks, results, rationale ---------------------------------------------------------

_NAMES = ("proposal_ref", "review_ref", "revokes_ref", "from_ref", "authorised_by", "request_ref",
          "recheck_ref", "attempt_ref")


def stage_order(att: Attachment) -> dict:
    """Each stage comes after the stages it names, in the listing and in the issuer's time."""
    tally = Tally()
    for sid in att.duplicate_ids:
        tally.fail(f"stage id {sid!r} is used twice")
    for stage in att.stages:
        sid = stage.get("stage_id")
        for key in _NAMES:
            target = att.stage(stage.get(key))
            if target is None:
                continue
            if att.position[target["stage_id"]] > att.position.get(sid, -1):
                tally.fail(f"{sid}: listed before {target['stage_id']}, which it names")
            order = _before(att.at(target), att.at(stage))
            if order is None:
                bad = att.at(target) if not att.at(target).ok else att.at(stage)
                tally.fail(f"{sid}: its order against {target['stage_id']} cannot be checked: "
                           f"{bad.text} names no instant")
            elif not order:
                tally.fail(f"{sid}: dated before {target['stage_id']}, which it names")
    return tally.result(time_basis="issuer_assertion")


def authorisation_recheck(att: Attachment) -> dict:
    """Each attempt follows an authorising recheck of its own request, made for it alone."""
    attempts = att.of_kind("attempt")
    if not attempts and not att.of_kind("recheck"):
        return dim(NOT_CHECKED, "no recheck or attempt is recorded")
    tally = Tally()
    backed: dict[str, str] = {}
    for attempt in attempts:
        _one_attempt_recheck(att, attempt, backed, tally)
    _rechecks_after_revocation(att, tally)
    return tally.result()


def _one_attempt_recheck(att: Attachment, attempt: dict, backed: dict[str, str], tally: Tally) -> None:
    sid = attempt.get("stage_id")
    recheck = att.stage(attempt.get("recheck_ref"), "recheck")
    if recheck is None:
        tally.fail(f"{sid}: recheck_ref names no recheck")
        return
    if recheck.get("request_ref") != attempt.get("request_ref"):
        tally.fail(f"{sid}: its recheck is of another request")
    if recheck.get("result") != "authorised":
        tally.fail(f"{sid}: attempted after a recheck that did not authorise it")
    if recheck["stage_id"] in backed:
        tally.fail(f"{sid}: reuses the recheck of {backed[recheck['stage_id']]}")
    backed[recheck["stage_id"]] = sid
    order = _before(att.at(recheck), att.at(attempt))
    if order is None:
        tally.fail(f"{sid}: whether its recheck precedes it cannot be checked")
    elif not order:
        tally.fail(f"{sid}: its recheck is dated after it")
    for later in att.of_kind("recheck"):
        if later is recheck or later.get("request_ref") != attempt.get("request_ref"):
            continue
        listed = att.position[later["stage_id"]] < att.position.get(sid, -1)
        after = _before(att.at(recheck), att.at(later))
        before_attempt = _before(att.at(later), att.at(attempt))
        if listed and after and before_attempt and later.get("result") != "authorised":
            tally.fail(f"{sid}: the latest recheck before it, {later['stage_id']}, does not authorise it")


def _rechecks_after_revocation(att: Attachment, tally: Tally) -> None:
    for revocation in att.of_kind("standing_revocation"):
        approval = revocation.get("revokes_ref")
        requests = {r["stage_id"] for r in att.of_kind("request") if r.get("authorised_by") == approval}
        for recheck in att.of_kind("recheck"):
            if recheck.get("request_ref") not in requests or recheck.get("result") != "authorised":
                continue
            listed = att.position[recheck["stage_id"]] > att.position[revocation["stage_id"]]
            dated = _before(att.at(revocation), att.at(recheck))
            if dated is None:
                tally.fail(f"{recheck['stage_id']}: whether it follows the revocation cannot be checked")
            elif listed or (dated and att.at(revocation).seconds != att.at(recheck).seconds):
                tally.fail(f"{recheck['stage_id']}: authorised a request after a recorded revocation")


def observed_results(att: Attachment) -> dict:
    """Each attempt has exactly one result, carried through as recorded."""
    requests, attempts = att.of_kind("request"), att.of_kind("attempt")
    if not requests:
        return dim(NOT_CHECKED, "no execution attempt is recorded", execution_state="not_requested",
                   attempts=[])
    if not attempts:
        return dim(NOT_CHECKED, "no execution attempt is recorded",
                   execution_state="requested_not_attempted", attempts=[])
    tally = Tally()
    results: dict[str, list[dict]] = {}
    for result in att.of_kind("result"):
        if att.stage(result.get("attempt_ref"), "attempt") is None:
            tally.fail(f"{result.get('stage_id')}: a result naming a stage that is not an attempt")
            continue
        results.setdefault(result["attempt_ref"], []).append(result)
    rows = []
    for attempt in attempts:
        found = results.get(attempt.get("stage_id"), [])
        if not found:
            tally.fail(f"{attempt.get('stage_id')}: no result is recorded")
            rows.append({"attempt_stage_id": attempt.get("stage_id"), "observed": "missing",
                         "basis": None})
        elif len(found) > 1:
            tally.fail(f"{attempt.get('stage_id')}: {len(found)} results are recorded")
            rows.append({"attempt_stage_id": attempt.get("stage_id"), "observed": "multiple",
                         "basis": None})
        else:
            rows.append({"attempt_stage_id": attempt.get("stage_id"),
                         "observed": found[0].get("observed"), "basis": found[0].get("basis")})
    return tally.result(execution_state="attempted", attempts=rows)


def rationale_provenance(att: Attachment) -> dict:
    """The stated timing of each rationale against the issuer's times."""
    tally = Tally()
    for stage in att.stages:
        rationale = stage.get("rationale")
        if not isinstance(rationale, dict) or rationale.get("timing") == "not_recorded":
            continue
        sid = stage.get("stage_id")
        recorded, at = instant(rationale.get("recorded_at")), att.at(stage)
        if not recorded.ok or not at.ok:
            tally.fail(f"{sid}: the rationale's timing cannot be checked: a time names no instant")
        elif rationale.get("timing") == "contemporaneous" and recorded.seconds > at.seconds:
            tally.fail(f"{sid}: presented as contemporaneous, recorded after the stage")
        elif rationale.get("timing") == "later_supplemented" and recorded.seconds <= at.seconds:
            tally.fail(f"{sid}: said to be supplemented later, dated no later than the stage")
    return tally.result()


def executed_specifications(att: Attachment) -> list[dict]:
    """For each executed specification: shown to a reviewer, reached by a change, or by bounds."""
    paths: dict[str, set[str]] = {}
    order: list[str] = []
    for attempt in att.of_kind("attempt"):
        digest = attempt.get("spec_digest")
        if digest not in paths:
            paths[digest] = set()
            order.append(digest)
        request = att.stage(attempt.get("request_ref"), "request")
        basis = att.stage(request.get("authorised_by")) if request else None
        paths[digest].add(_reached_by(att, basis))
    out = []
    for digest in order:
        spec = att.spec(digest)
        if spec is None:
            continue
        for word in ("shown_to_reviewer", "via_change_only", "via_standing_approval", "unbound"):
            if word in paths[digest]:
                out.append({"spec_index": spec.index, "reached_by": word})
                break
    return out


def _reached_by(att: Attachment, basis: dict | None) -> str:
    if basis is None:
        return "unbound"
    if basis.get("kind") == "standing_approval":
        return "via_standing_approval"
    if basis.get("kind") == "change_authorisation":
        return "via_change_only"
    if basis.get("kind") == "outcome" and basis.get("outcome") == "approved":
        review = att.stage(basis.get("review_ref"), "review")
        if review is not None and "shown_spec_digest" in review:
            return "shown_to_reviewer"
    return "unbound"


# --- issuer signature ----------------------------------------------------------------------------

def _member_span(text: str, start: int, name: str) -> tuple[int, int] | None:
    """The span of member ``name``'s value in the object opening at ``text[start]``."""
    decoder = __import__("json").JSONDecoder()
    i = start + 1
    while True:
        while text[i] in " \t\r\n,":
            i += 1
        if text[i] == "}":
            return None
        key, i = decoder.raw_decode(text, i)
        while text[i] in " \t\r\n":
            i += 1
        i += 1  # the colon
        while text[i] in " \t\r\n":
            i += 1
        _, end = decoder.raw_decode(text, i)
        if key == name:
            return i, end
        i = end


def sealed_digest(data: bytes, value: str) -> str | None:
    """SHA-256 of the bytes as issued with every character of the signature value replaced by ``A``."""
    try:
        text = data.decode("utf-8")
        outer = _member_span(text, text.index("{"), "issuer_signature")
        if outer is None:
            return None
        inner = _member_span(text, outer[0], "value_b64")
    except (ValueError, IndexError):
        return None
    if inner is None:
        return None
    start, end = inner
    replaced = text[:start + 1] + "A" * len(value) + text[end - 1:]
    return sha256_hex(replaced.encode("utf-8"))


def _lp(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def seal_signed_bytes(key_ref: str, decision_id: str, digest_hex: str, sealed_at: str) -> bytes:
    """The organisation seal's signed bytes, kind ``attachment``, under the shared length-prefix rule."""
    fields = [b"dps-signatures", b"0.2.0", b"organisation_seal", key_ref.encode("utf-8"),
              b"attachment", decision_id.encode("utf-8"), bytes.fromhex(digest_hex),
              sealed_at.encode("utf-8")]
    return b"DPS-SIG\x00" + b"".join(_lp(f) for f in fields)


@dataclass
class TrustPolicy:
    """A trust policy configured by the relying party, read and judged once."""

    ref: str | None
    keys: dict[str, dict]
    refused: str = ""

    @classmethod
    def read(cls, policy: Any) -> TrustPolicy:
        if not isinstance(policy, dict):
            return cls(None, {}, "the trust policy is not an object")
        ref = policy.get("policy_ref")
        if policy.get("profile") != POLICY_PROFILE or policy.get("profile_version") != POLICY_VERSION:
            return cls(ref, {}, f"the trust policy is not {POLICY_PROFILE} {POLICY_VERSION}")
        keys: dict[str, dict] = {}
        seen_keys: dict[str, str] = {}
        refs: set[str] = set()
        for entry in policy.get("keys") or []:
            if not isinstance(entry, dict):
                return cls(ref, {}, "a key entry is not an object")
            key_ref, public = entry.get("key_ref"), entry.get("public_key_hex")
            if key_ref in refs:
                return cls(ref, {}, f"key reference {key_ref!r} names two entries")
            refs.add(key_ref)
            if isinstance(public, str):
                norm = public.lower()
                if norm in seen_keys:
                    return cls(ref, {}, f"one public key is listed under {seen_keys[norm]!r} and "
                                        f"{key_ref!r}")
                seen_keys[norm] = key_ref
            keys[key_ref] = entry
        for tsa in policy.get("tsas") or []:
            if isinstance(tsa, dict) and tsa.get("tsa_ref") in refs:
                return cls(ref, {}, f"reference {tsa.get('tsa_ref')!r} names two entries")
            if isinstance(tsa, dict):
                refs.add(tsa.get("tsa_ref"))
        return cls(ref, keys)

    def report(self) -> dict:
        if self.refused:
            return dim(FAILED, self.refused)
        return dim(VERIFIED)


def issuer_signature(data: bytes, doc: dict, policy: TrustPolicy | None,
                     latest_stage: Instant | None) -> dict:
    """The attachment's seal copy, checked with the relying party's own key for its reference."""
    sig = doc.get("issuer_signature")
    if sig is None:
        return dim(NOT_CHECKED, "the attachment carries no issuer signature")
    if policy is None:
        return dim(NOT_CHECKED, "no trust policy is configured, so no key is held for the signature")
    if not isinstance(sig, dict) or set(sig) != {"algorithm", "key_ref", "signed_bytes_ref",
                                                 "sealed_at", "value_b64"}:
        return dim(FAILED, "the copy does not have exactly the five members of a seal copy")
    key_ref = sig.get("key_ref")
    base = {"key_ref": key_ref, "algorithm": sig.get("algorithm"), "reference_source": "trust_policy",
            "attests": "issuer_recorded_claims_only"}
    if policy.refused:
        return dim(FAILED, f"not checked: the trust policy is refused ({policy.refused})", **base)
    if sig.get("algorithm") != "Ed25519" or sig.get("signed_bytes_ref") != SIGNED_BYTES_REF:
        return dim(FAILED, "the copy names another algorithm or other signed bytes", **base)
    entry = policy.keys.get(key_ref)
    if entry is None:
        return dim(FAILED, f"key {key_ref!r} is not in the trust policy", **base)
    base["holder"] = entry.get("holder")
    if entry.get("role") != "organisation" or entry.get("algorithm") != "Ed25519":
        return dim(FAILED, f"key {key_ref!r} is not an Ed25519 key in role organisation", **base)
    findings: list[str] = []
    signature_ok = _signature_verifies(data, doc, sig, entry, findings)
    base["certificate"] = _certificate(entry, findings)
    base["key_state"] = _key_state(entry, sig.get("sealed_at"), findings)
    sealed = instant(sig.get("sealed_at"))
    if latest_stage is not None and sealed.ok and latest_stage.ok and sealed.seconds < latest_stage.seconds:
        findings.append("sealed_at is earlier than the latest stage the attachment records; both are "
                        "the issuer's times")
    status = VERIFIED if (signature_ok and base["key_state"]["status"] == VERIFIED
                          and base["certificate"] != FAILED) else FAILED
    if signature_ok and base["key_state"]["status"] == UNAVAILABLE:
        status = UNAVAILABLE
    return dim(status, *findings, **base)


def _signature_verifies(data: bytes, doc: dict, sig: dict, entry: dict, findings: list[str]) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    digest = sealed_digest(data, sig["value_b64"])
    raw_sig = _b64(sig["value_b64"])
    try:
        public = bytes.fromhex(entry.get("public_key_hex", ""))
        key = Ed25519PublicKey.from_public_bytes(public)
    except ValueError:
        findings.append("the policy's public key for this reference cannot be read")
        return False
    if digest is None or raw_sig is None:
        findings.append("the sealed digest cannot be rebuilt from the attachment")
        return False
    try:
        signed = seal_signed_bytes(sig["key_ref"], doc.get("decision_id", ""), digest, sig["sealed_at"])
        key.verify(raw_sig, signed)
    except (InvalidSignature, ValueError, UnicodeEncodeError):
        findings.append("the signature does not verify over the signed bytes rebuilt from the attachment")
        return False
    return True


def _certificate(entry: dict, findings: list[str]) -> str:
    pinned = entry.get("certificate_b64")
    if pinned is None:
        return NOT_CHECKED
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(pinned, validate=True))
        held = cert.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except (ValueError, TypeError, binascii.Error):
        findings.append("the pinned certificate cannot be read")
        return FAILED
    if held.hex() != str(entry.get("public_key_hex", "")).lower():
        findings.append("the pinned certificate does not hold the key")
        return FAILED
    return VERIFIED


def _key_state(entry: dict, sealed_at: Any, findings: list[str]) -> dict:
    stated = instant(sealed_at)
    base = {"key_ref": entry.get("key_ref"), "time_basis": "stated_time", "time": sealed_at}
    if not stated.ok:
        return dim(FAILED, f"sealed_at {sealed_at!r} names no instant", **base)
    start, end = instant(entry.get("not_before")), instant(entry.get("not_after"))
    if not start.ok or not end.ok:
        return dim(FAILED, "the policy's validity for the key names no instant", **base)
    if not (start.seconds <= stated.seconds <= end.seconds):
        return dim(FAILED, "signed outside the key's validity", **base)
    if "revoked_at" in entry:
        revoked = instant(entry.get("revoked_at"))
        if not revoked.ok:
            return dim(FAILED, "the policy's revocation time names no instant", **base)
        if entry.get("revocation_reason") == "compromised":
            return dim(UNAVAILABLE, "the key was compromised: only an independent timestamp earlier "
                                    "than its revocation can establish when it signed, and none is "
                                    "read", **base)
        if stated.seconds >= revoked.seconds:
            return dim(FAILED, "signed after the key was superseded", **base)
    return dim(VERIFIED, **base)


# --- the strict profile --------------------------------------------------------------------------

def _approver_independence(att: Attachment) -> dict:
    approvals = att.approvals()
    if not approvals:
        return dim(NOT_CHECKED, "no approval is recorded")
    parties = att.services() | att.proposers()
    tally = Tally()
    for stage in approvals:
        if stage.get("actor_ref") in parties:
            tally.fail(f"{stage.get('stage_id')}: approved by {stage.get('actor_ref')!r}, which "
                       "proposed, requested or executes the action")
    return tally.result()


def _single_effect(att: Attachment, effects: dict) -> dict:
    attempts = att.of_kind("attempt")
    if not attempts:
        return dim(NOT_CHECKED, "no execution attempt is recorded")
    tally = Tally()
    observed = {r.get("attempt_ref"): r.get("observed") for r in att.of_kind("result")}
    for request in att.of_kind("request"):
        rid = request.get("request_id")
        mine = [a for a in attempts if a.get("request_ref") == request.get("stage_id")]
        words = [observed.get(a.get("stage_id")) for a in mine]
        if rid in effects:
            if not _json_integer(effects[rid]) or effects[rid] > 1:
                tally.fail(f"{request.get('stage_id')}: the target observed {effects[rid]!r} effects")
            continue
        if words.count("succeeded") > 1:
            tally.fail(f"{request.get('stage_id')}: attempts {', '.join(a.get('stage_id') for a in mine)}"
                       " were each observed to succeed; one request ran more than once")
        elif "indeterminate" in words[:-1]:
            tally.skip(f"{request.get('stage_id')}: retried after an indeterminate attempt; only an "
                       "observation at the target says whether it took effect twice")
    return tally.result()


def _named_actors(att: Attachment) -> list[tuple[str, Any]]:
    out = []
    for stage in att.stages:
        for key in ("reviewer_ref", "actor_ref"):
            if key in stage and stage.get("kind") != "proposal":
                out.append((stage.get("stage_id"), stage[key]))
    return out


def _identity_independent(att: Attachment, identities: dict | None) -> dict:
    if identities is None:
        return dim(NOT_CHECKED, "the relying party supplied no identity source", basis="issuer_assertion")
    tally = Tally()
    for sid, actor in _named_actors(att):
        entry = identities.get(actor)
        if not isinstance(entry, dict):
            tally.fail(f"{sid}: {actor!r} is not in the relying party's identity source")
        elif entry.get("status") != VERIFIED:
            tally.fail(f"{sid}: the identity source gives {actor!r} as {entry.get('status')!r}")
    return tally.result(basis="independent_source")


def _authority_independent(att: Attachment, grants: list | None) -> dict:
    if grants is None:
        return dim(NOT_CHECKED, "the relying party supplied no authority source", basis="issuer_assertion")
    held = {(g.get("actor_ref"), g.get("authority_ref")) for g in grants if isinstance(g, dict)}
    tally = Tally()
    for stage in att.approvals() + att.of_kind("change_authorisation"):
        pair = (stage.get("actor_ref"), (stage.get("authority") or {}).get("authority_ref"))
        if pair not in held:
            tally.fail(f"{stage.get('stage_id')}: the relying party's authority source grants "
                       f"{pair[0]!r} no {pair[1]!r}")
    if not att.approvals():
        tally.skip("no approval is recorded")
    return tally.result(basis="independent_source")


def _time_independent(att: Attachment, clock: dict | None) -> dict:
    if clock is None:
        return dim(NOT_CHECKED, "the relying party supplied no independent observation of the stages' "
                                "times", basis="issuer_assertion")
    tolerance = clock.get("tolerance_seconds", 0)
    seen = clock.get("observed") or {}
    tally = Tally()
    targets = att.approvals() + att.of_kind("change_authorisation", "attempt")
    if not att.of_kind("attempt"):
        tally.skip("no execution attempt is recorded")
    for stage in targets:
        sid = stage.get("stage_id")
        mark = instant(seen.get(sid))
        if not mark.ok:
            tally.fail(f"{sid}: no independent observation of this stage")
            continue
        at = att.at(stage)
        if not at.ok or abs(at.seconds - mark.seconds) > tolerance:
            tally.fail(f"{sid}: the issuer dates it {at.text}, observed {mark.text}")
    for attempt in att.of_kind("attempt"):
        request = att.stage(attempt.get("request_ref"), "request") or {}
        basis = att.stage(request.get("authorised_by"))
        if basis is None:
            continue
        approved, ran = instant(seen.get(basis.get("stage_id"))), instant(seen.get(attempt.get("stage_id")))
        if approved.ok and ran.ok and approved.seconds > ran.seconds:
            tally.fail(f"{attempt.get('stage_id')}: observed before the approval it rests on")
    return tally.result(basis="independent_source")


def _latest(decision_id: str, digest: str, latest: dict | None) -> dict:
    if latest is None or decision_id not in latest:
        return dim(NOT_CHECKED, "the relying party holds no latest attachment for this decision")
    if latest[decision_id] == digest:
        return dim(VERIFIED)
    return dim(FAILED, "a later attachment of this decision is held; this one is not the latest")


def strict_dimensions(att: Attachment, digest: str, signature: dict, relying: dict) -> dict:
    """The checks the strict profile adds, each a dimension of its own."""
    return {
        "approver_independence": _approver_independence(att),
        "single_effect_per_request": _single_effect(att, relying.get("target_effects") or {}),
        "identity_independent": _identity_independent(att, relying.get("identities")),
        "authority_independent": _authority_independent(att, relying.get("authority_grants")),
        "time_independent": _time_independent(att, relying.get("independent_times")),
        "latest_attachment": _latest(str(att.doc.get("decision_id")), digest, relying.get("latest")),
        "signature_required": dim(VERIFIED) if signature["status"] == VERIFIED else dim(
            FAILED, "the relying party requires a verified issuer signature"),
    }


# --- the report ----------------------------------------------------------------------------------

SCOPE = {"covers": "supplied_attachments_only",
         "not_assessed": ["legal_requirements", "conformance_level", "events_not_in_attachment",
                          "truth_of_recorded_claims", "what_the_reviewer_saw"]}


def read(data: bytes, *, record: bytes | None = None, trust_policy: Any = None,
         timestamps_beside: bool = False, relying_party: dict | None = None) -> dict:
    """Read one attachment's exact bytes and report every dimension separately."""
    digest = sha256_hex(data)
    policy = TrustPolicy.read(trust_policy) if trust_policy is not None else None
    out: dict[str, Any] = {"profile": PROFILE, "profile_version": PROFILE_VERSION,
                           "attachment_digest": digest}
    try:
        doc = read_document(data)
    except NotRead as exc:
        out["structural_validity"] = dim(FAILED, str(exc))
        return _unread(out, "the attachment is not read")
    out["decision_id"] = doc.get("decision_id") if isinstance(doc, dict) else None
    out["structural_validity"] = structural_validity(doc)
    if out["structural_validity"]["status"] != VERIFIED:
        return _unread(out, "the attachment does not have the format's shape")
    record_doc = None
    if record is not None:
        try:
            record_doc = read_document(record)
        except NotRead as exc:
            out["record"] = dim(FAILED, str(exc))
    att = Attachment.from_doc(doc)
    spec_digests, spec_statements, per_spec = specification_dimensions(att)
    binding = Binding(att)
    action = binding.run()
    out.update({
        "specifications": per_spec,
        "reviews": [{"review_stage_id": r[0], "shown": r[1], **({"edited_by": r[2]} if r[2] else {})}
                    for r in binding.reviews],
        "executed_specifications": executed_specifications(att),
        "standing_approvals": binding.standing,
        "specification_digests": spec_digests,
        "specification_statements": spec_statements,
        "record_statements": record_statements(att, record_doc if isinstance(record_doc, dict) else None),
        "action_binding": action,
        "stage_order": stage_order(att),
        "authorisation_recheck": authorisation_recheck(att),
        "observed_results": observed_results(att),
        "rationale_provenance": rationale_provenance(att),
        "identity_assurance": dim(NOT_CHECKED, basis="issuer_assertion"),
        "authority_assurance": dim(NOT_CHECKED, basis="issuer_assertion"),
    })
    times = [att.at(s) for s in att.stages if att.at(s).ok]
    latest = max(times, key=lambda t: t.seconds) if times else None
    out["trust_policy"] = policy.report() if policy is not None else dim(
        NOT_CHECKED, "no trust policy is configured")
    out["issuer_signature"] = issuer_signature(data, doc, policy, latest)
    out["time_assurance"] = (dim(NOT_SUPPORTED, "timestamps beside the attachment are not read by this "
                                                "reader", basis="issuer_assertion")
                             if timestamps_beside else dim(NOT_CHECKED, basis="issuer_assertion"))
    out["legal_signature"] = _legal(att)
    out["strict"] = strict_dimensions(att, digest, out["issuer_signature"], relying_party or {})
    out["scope_of_conclusion"] = SCOPE
    return out


def _legal(att: Attachment) -> dict:
    if any("legal_signature_ref" in s for s in att.stages):
        return dim(NOT_CHECKED, "a legal signature is referenced; its effect is outside this format",
                   basis="issuer_assertion")
    return dim(NOT_CHECKED, "no legal signature is referenced", basis="issuer_assertion")


def _unread(out: dict, why: str) -> dict:
    for name in BINDING_DIMENSIONS + ("issuer_signature", "time_assurance", "identity_assurance",
                                      "authority_assurance", "legal_signature"):
        out[name] = dim(NOT_CHECKED, why)
    out["strict"] = {name: dim(NOT_CHECKED, why) for name in STRICT_DIMENSIONS}
    out["scope_of_conclusion"] = SCOPE
    return out


def verdict(report: dict, profile: str = "baseline") -> tuple[str, str | None]:
    """What one profile accepts: ``("accept", None)`` or ``("reject", "<dimension>:<status>")``.

    ``baseline`` refuses a report whose structure or any binding dimension failed. ``strict`` also
    requires the issuer signature and every strict dimension to be verified. Neither changes what
    the report says about any dimension.
    """
    if profile not in PROFILES:
        raise ValueError(f"profile {profile!r} is not one of {PROFILES}")
    names = ("structural_validity",) + BINDING_DIMENSIONS
    for name in names:
        if report[name]["status"] == FAILED:
            return "reject", f"{name}:{FAILED}"
    if profile == "baseline":
        return "accept", None
    for name in STRICT_DIMENSIONS:  # signature_required carries the issuer signature's verdict
        status = report["strict"][name]["status"]
        if status != VERIFIED:
            return "reject", f"{name}:{status}"
    for name in BINDING_DIMENSIONS:
        if report[name]["status"] != VERIFIED:
            return "reject", f"{name}:{report[name]['status']}"
    return "accept", None


# --- the published test cases' form --------------------------------------------------------------

def compact(value: Any) -> bytes:
    """A document's bytes as the published cases write them: JSON with no whitespace, in UTF-8."""
    import json

    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _pointer(doc: Any, pointer: str) -> tuple[Any, str]:
    parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]
    node = doc
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node, parts[-1]


def apply_patch(doc: Any, patch: list[dict]) -> Any:
    """Apply a published case's patch (``set``, ``insert``, ``remove``, ``move``) to ``doc`` in place."""
    for op in patch:
        if "set" in op or "insert" in op:
            node, key = _pointer(doc, op.get("set", op.get("insert")))
            if isinstance(node, list) and "insert" in op:
                node.insert(len(node) if key == "-" else int(key), op["value"])
            elif isinstance(node, list):
                node[int(key)] = op["value"]
            else:
                node[key] = op["value"]
        elif "remove" in op:
            node, key = _pointer(doc, op["remove"])
            del node[int(key) if isinstance(node, list) else key]
        elif "move" in op:
            node, key = _pointer(doc, op["move"])
            value = node.pop(int(key) if isinstance(node, list) else key)
            target, where = _pointer(doc, op["to"])
            if isinstance(target, list):
                target.insert(int(where), value)
            else:
                target[where] = value
        else:
            raise ValueError(f"a patch operation this reader does not apply: {sorted(op)}")
    return doc


def binding_summary(report: dict) -> dict:
    """A report in the published binding cases' terms, for comparing with their expected values."""
    return {
        **{name: report[name]["status"] for name in BINDING_DIMENSIONS},
        "execution_state": report["observed_results"].get("execution_state"),
        "observed": [[a["attempt_stage_id"], a["observed"], a["basis"]]
                     for a in report["observed_results"].get("attempts", [])],
        "executed": [[e["spec_index"], e["reached_by"]] for e in report["executed_specifications"]],
        "reviews": [[r["review_stage_id"], r["shown"], r.get("edited_by")] for r in report["reviews"]],
        "standing": [[s["standing_stage_id"], s["status"], s["requests_recorded"], s["max_requests"],
                      s["revocation"]] for s in report["standing_approvals"]],
    }


def expected_differences(case: dict, report: dict) -> list[str]:
    """Where a report differs from one published binding case's expected values (empty: agrees).

    The cases expect every binding dimension ``verified`` and ``execution_state`` ``attempted``
    unless they say otherwise, and compare the carried lists only where they name them.
    """
    got, want = binding_summary(report), case.get("expected", {})
    diffs = [f"{name}: expected {want.get(name, VERIFIED)}, read {got[name]}"
             for name in BINDING_DIMENSIONS if got[name] != want.get(name, VERIFIED)]
    if got["execution_state"] != want.get("execution_state", "attempted"):
        diffs.append(f"execution_state: expected {want.get('execution_state', 'attempted')}, read "
                     f"{got['execution_state']}")
    diffs += [f"{name}: expected {want[name]}, read {got[name]}"
              for name in ("observed", "executed", "reviews", "standing")
              if name in want and want[name] != got[name]]
    return diffs


# --- corpus members and the command line ---------------------------------------------------------

def read_member(member: dict) -> tuple[dict, str, str | None]:
    """Read one corpus member: the report, and the verdict of the profile the member names.

    A member carries ``attachment`` (the exact text), and optionally ``record`` (text),
    ``trust_policy``, ``relying_party``, ``timestamps_beside`` and ``profile``.
    """
    record = member.get("record")
    report = read(member["attachment"].encode("utf-8"),
                  record=record.encode("utf-8") if isinstance(record, str) else None,
                  trust_policy=member.get("trust_policy"),
                  timestamps_beside=bool(member.get("timestamps_beside", False)),
                  relying_party=member.get("relying_party"))
    decision, reason = verdict(report, member.get("profile", "baseline"))
    return report, decision, reason


def main(argv: list[str] | None = None) -> int:
    """``agent-evidence-verify decision-record``: print one attachment's report and a profile's verdict."""
    import argparse
    import json
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="agent-evidence-verify decision-record",
        description="report every dimension of one action-binding attachment (dps-action-binding 0.3.0)")
    parser.add_argument("attachment", type=Path, help="the attachment's exact bytes")
    parser.add_argument("--record", type=Path, help="the decision record it sits beside")
    parser.add_argument("--trust-policy", type=Path, help="the relying party's own trust policy")
    parser.add_argument("--relying-party", type=Path,
                        help="the relying party's independent sources, for the strict profile")
    parser.add_argument("--timestamps-beside", action="store_true",
                        help="timestamps travel beside the attachment (reported not_supported)")
    parser.add_argument("--profile", choices=PROFILES, default="baseline")
    args = parser.parse_args(argv)
    try:
        data = args.attachment.read_bytes()
        record = args.record.read_bytes() if args.record else None
        policy = read_document(args.trust_policy.read_bytes()) if args.trust_policy else None
        party = read_document(args.relying_party.read_bytes()) if args.relying_party else None
    except (OSError, NotRead) as exc:
        print(f"agent-evidence-verify decision-record: {exc}", file=sys.stderr)
        return 2
    report = read(data, record=record, trust_policy=policy, timestamps_beside=args.timestamps_beside,
                  relying_party=party if isinstance(party, dict) else None)
    out: dict[str, Any] = {"report": report, "profile": args.profile}
    try:
        read_document(data)
    except NotRead:
        sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
        print("agent-evidence-verify decision-record: the attachment is not read", file=sys.stderr)
        return 2
    out["verdict"], out["reason"] = verdict(report, args.profile)
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0
