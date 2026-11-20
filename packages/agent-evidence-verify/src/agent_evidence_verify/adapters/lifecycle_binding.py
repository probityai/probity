"""``lifecycle_binding/v1``: does the authenticated execution report name the action the authenticated control
authorized, for one decision and one instruction?

Runtime evidence formats commonly answer "was what was authorized what was executed" by matching one
authorization record with one execution record. Each of grouping, identity, authentication and revocation
is a way to get that answer wrong: an execution of a second instruction matched against the first
instruction's authorization, a receiving side that recorded a different action from the issuing side, two
records with one identity where the order of the array picks the winner, a record whose self-hash
recomputes but whose signature is absent or made by a key nobody bound, and a key whose binding was
revoked before the record was read.

This claim type reads a set of decision, control and execution records under the
``agent-evidence/lifecycle-binding/v1`` profile and answers one of five states per group, never reading
absent evidence as a match:

``satisfied``     every artifact in the group, and the decision it cites, is admitted, unique by identity,
                  authenticated under its producer's active key binding, and every authorized action digest
                  equals every executed action digest;
``failure``       the digests differ, two authorizing records disagree, or an artifact does not authenticate;
``missing``       the group lacks an authorizing record, an execution record or the decision it cites;
``not_evaluated`` an artifact is signed under a binding the revocation snapshot does not list as active, or an
                  execution cites an instruction no authorization in the set covers;
``indeterminate`` two artifacts share one identity: no winner is chosen and nothing is compared.

Records are grouped by (decision record id, instruction id). The rules run in one order per group:
identity, an execution no control covers, a missing record, authentication, an inactive binding, then the
digest comparison. Each record is one JSON object:

``lifecycle_version`` ``"v1"``; ``artifact_type`` ``decision``, ``control`` or ``execution``; ``record_id``;
``producer``; ``integrity`` ``{current: "sha256:<hex>", signature: {alg, value: <hex>}}``; a control and an
execution also carry ``decision_ref.record_id`` and ``instruction_id``; a control carries ``boundary_side``
(``issuer`` or ``receiver``) and ``authorized_action_digest``; an execution carries
``executed_action_digest``. Digests are ``sha256:<hex>``.

Pre-images are domain-separated by a closed registry of six ASCII tags,
``agent-evidence/lifecycle-binding/v1/{decision,control,execution}/{hash,signature}``: the tag bytes, one
byte 0x0A, then the canonical bytes, with nothing between and nothing after. The hash input is the RFC 8785
form of the record without ``integrity.current`` and ``integrity.signature``. The signature input is the RFC
8785 form of ``{"current": <integrity.current>, "suite": <the suite the key binding names>}``: the wire
``alg`` is informative only, and a signature over another suite id does not verify. The tag is derived from
the declared type and version, never searched for, and an unregistered type or version is refused.

The consumer supplies, as case artifacts it pins, the key bindings (``{producer: {public_key_hex, suite}}``)
and a revocation snapshot (``{producer: {state: active|revoked}}``), which is required. Optionally it names
the action bytes of a record (``actions``) and the hash convention of each action digest pointer
(``pointer_conventions``, ``jcs`` or ``raw``): a published action is recomputed and compared.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..common import CaseError, _string
from ..ijson import IJSONError, describe, parse_ijson
from ..key_authority import key_set_fingerprint, key_sha256
from . import jcs_canonical
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "lifecycle_binding/v1"
VERSION = "v1"
TYPES = ("decision", "control", "execution")
TAG = "agent-evidence/lifecycle-binding/{version}/{type}/{purpose}"
TAGS = frozenset(TAG.format(version=VERSION, type=t, purpose=p) for t in TYPES for p in ("hash", "signature"))
SUITES = ("ed25519",)
STATES = ("satisfied", "failure", "missing", "not_evaluated", "indeterminate")
#: The order in which a group's state decides the whole set's reason: a failure is a contradiction,
#: then an unknown that no further reading resolves, then evidence that could still arrive.
PRIORITY = ("failure", "indeterminate", "not_evaluated", "missing")
POINTERS = ("authorized_action_digest", "executed_action_digest")
DOES_NOT_ESTABLISH = ("that the executed bytes themselves were observed: the claim is about records, and an "
                      "execution record is the executor's own report")
LIMIT = ("Reads decision, control and execution records against the consumer's key bindings and revocation "
         "snapshot. It shows, per (decision, instruction) group, whether the authenticated execution report "
         "names the action the authenticated control authorized; it does not show that the action ran.")

_MEMBERS = {
    "decision": {"lifecycle_version", "artifact_type", "record_id", "producer", "integrity"},
    "control": {"lifecycle_version", "artifact_type", "record_id", "producer", "integrity", "decision_ref",
                "instruction_id", "boundary_side", "authorized_action_digest"},
    "execution": {"lifecycle_version", "artifact_type", "record_id", "producer", "integrity", "decision_ref",
                  "instruction_id", "executed_action_digest"},
}
_HEX = frozenset("0123456789abcdef")


class Refused(ValueError):
    """The record set is not admissible under the profile: (reason, detail)."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason, self.detail = reason, detail


def tag(artifact_type: str, purpose: str, version: str = VERSION) -> bytes:
    """A registered tag, or :class:`Refused`: the registry is closed and case-sensitive."""
    text = TAG.format(version=version, type=artifact_type, purpose=purpose)
    if text not in TAGS:
        raise Refused("unregistered_tag", f"{text!r} is not a registered tag")
    return text.encode("ascii")


def _sha(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and not set(value[7:]) - _HEX


def hash_preimage(artifact: dict) -> bytes:
    body = {k: v for k, v in artifact.items() if k != "integrity"}
    rest = {k: v for k, v in artifact["integrity"].items() if k not in ("current", "signature")}
    if rest:
        body["integrity"] = rest
    return tag(artifact["artifact_type"], "hash") + b"\n" + jcs_canonical._value(body).encode("utf-8")


def signature_preimage(artifact: dict, suite: str) -> bytes:
    body = {"current": artifact["integrity"]["current"], "suite": suite}
    return tag(artifact["artifact_type"], "signature") + b"\n" + jcs_canonical._value(body).encode("utf-8")


def _shape(artifact: Any, index: int) -> dict:
    label = f"records[{index}]"
    if not isinstance(artifact, dict):
        raise Refused("record_shape", f"{label}: expected an object")
    if artifact.get("lifecycle_version") != VERSION or artifact.get("artifact_type") not in TYPES:
        raise Refused("unregistered_tag", f"{label}: version {artifact.get('lifecycle_version')!r} and type "
                      f"{artifact.get('artifact_type')!r} name no registered tag")
    kind = artifact["artifact_type"]
    required = _MEMBERS[kind]
    if not required <= set(artifact):
        raise Refused("record_shape", f"{label}: a {kind} carries {sorted(required - set(artifact))}")
    for member in ("record_id", "producer") + (("instruction_id",) if kind != "decision" else ()):
        if not isinstance(artifact[member], str) or not artifact[member]:
            raise Refused("record_shape", f"{label}.{member}: expected a string")
    integrity = artifact["integrity"]
    if (not isinstance(integrity, dict) or not _sha(integrity.get("current"))
            or not isinstance(integrity.get("signature"), dict)
            or not isinstance(integrity["signature"].get("value"), str)):
        raise Refused("record_shape", f"{label}.integrity: expected current and signature.value")
    if kind != "decision":
        ref = artifact["decision_ref"]
        if not isinstance(ref, dict) or not isinstance(ref.get("record_id"), str):
            raise Refused("record_shape", f"{label}.decision_ref.record_id: expected a string")
    if kind == "control" and artifact["boundary_side"] not in ("issuer", "receiver"):
        raise Refused("record_shape", f"{label}.boundary_side: expected issuer or receiver")
    for pointer in POINTERS:
        if pointer in artifact and not _sha(artifact[pointer]):
            raise Refused("record_shape", f"{label}.{pointer}: expected sha256:<hex>")
    return artifact


def _bindings(raw: bytes, label: str, members: set[str]) -> dict:
    try:
        value = parse_ijson(raw)
    except IJSONError as exc:
        raise CaseError(f"{label}: {describe(exc)}") from exc
    if not isinstance(value, dict) or any(not isinstance(v, dict) or set(v) != members for v in value.values()):
        raise CaseError(f"{label}: expected an object of producer to {sorted(members)}")
    return value


def authenticate(artifact: dict, bindings: dict) -> str | None:
    """None when the artifact authenticates under its producer's binding, else why not."""
    binding = bindings.get(artifact["producer"])
    if binding is None:
        return f"{artifact['record_id']}: no key binding names producer {artifact['producer']!r}"
    if hashlib.sha256(hash_preimage(artifact)).hexdigest() != artifact["integrity"]["current"][7:]:
        return f"{artifact['record_id']}: the hash does not recompute under its declared tag"
    suite = binding["suite"]
    if suite not in SUITES:
        return f"{artifact['record_id']}: the binding names suite {suite!r}, which this verifier does not run"
    try:
        key = bytes.fromhex(binding["public_key_hex"])
        Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(artifact["integrity"]["signature"]["value"]),
                                                       signature_preimage(artifact, suite))
    except (InvalidSignature, ValueError):
        return f"{artifact['record_id']}: the signature does not verify under the producer's bound key"
    return None


def _action_digest(data: bytes, convention: str) -> str:
    if convention == "raw":
        return "sha256:" + hashlib.sha256(data).hexdigest()
    try:
        return "sha256:" + hashlib.sha256(jcs_canonical.canonical("rfc8785", data.decode("utf-8"))).hexdigest()
    except (jcs_canonical.Refusal, UnicodeDecodeError) as exc:
        return f"unreadable: {exc}"


def evaluate(records: list[Any], bindings: dict, revocation: dict,
             actions: dict[str, bytes | None] | None = None,
             conventions: dict[str, str] | None = None) -> tuple[list[dict], dict]:
    """(per-group states, counts) for one record set. Raises :class:`Refused` for an inadmissible set."""
    records = [_shape(a, i) for i, a in enumerate(records)]
    actions, conventions = actions or {}, conventions or {}
    counts: dict[str, int] = {}
    for artifact in records:
        counts[artifact["record_id"]] = counts.get(artifact["record_id"], 0) + 1
    duplicated = {rid for rid, n in counts.items() if n > 1}
    decisions = {a["record_id"]: a for a in records if a["artifact_type"] == "decision"}
    groups: dict[tuple[str, str], list[dict]] = {}
    for artifact in records:
        if artifact["artifact_type"] != "decision":
            groups.setdefault((artifact["decision_ref"]["record_id"], artifact["instruction_id"]), []).append(artifact)
    out = []
    for key in sorted(groups):
        members = groups[key]
        controls = [a for a in members if a["artifact_type"] == "control"]
        executions = [a for a in members if a["artifact_type"] == "execution"]
        cited = decisions.get(key[0])
        ids = {a["record_id"] for a in members} | {key[0]}

        def state(value: str, detail: str, key: tuple[str, str] = key, controls: list = controls,
                  executions: list = executions) -> dict:
            return {"id": "group", "decision": key[0], "instruction": key[1], "state": value,
                    "status": {"satisfied": "pass", "failure": "fail"}.get(value, "unavailable"),
                    "controls": len(controls), "executions": len(executions), "detail": detail}

        if ids & duplicated:
            out.append(state("indeterminate", f"identity {sorted(ids & duplicated)} appears more than once"))
            continue
        if executions and not controls:
            out.append(state("not_evaluated", "an execution cites an instruction no authorization covers"))
            continue
        if not controls or not executions or cited is None:
            lacking = [n for n, have in (("control", controls), ("execution", executions), ("decision", cited))
                       if not have]
            out.append(state("missing", f"the group lacks a {', '.join(lacking)} record"))
            continue
        everything = [cited, *controls, *executions]
        failed = next((why for why in (authenticate(a, bindings) for a in everything) if why), None)
        if failed:
            out.append(state("failure", failed))
            continue
        inactive = sorted({a["producer"] for a in everything
                           if revocation.get(a["producer"], {}).get("state") != "active"})
        if inactive:
            out.append(state("not_evaluated", f"no active binding in the revocation snapshot for {inactive}"))
            continue
        published = []
        for artifact in [*controls, *executions]:
            data = actions.get(artifact["record_id"])
            pointer = "authorized_action_digest" if artifact["artifact_type"] == "control" else "executed_action_digest"
            if data is not None:
                got = _action_digest(data, conventions.get(pointer, "jcs"))
                if got != artifact[pointer]:
                    published.append(f"{artifact['record_id']}: the action bytes do not hash to {pointer}")
        if published:
            out.append(state("failure", published[0]))
            continue
        authorized = {c["authorized_action_digest"] for c in controls}
        executed = {e["executed_action_digest"] for e in executions}
        if len(authorized) > 1:
            out.append(state("failure", "two authorizing records in the group disagree"))
        elif authorized != executed:
            out.append(state("failure", "the executed digest differs from the authorized digest"))
        else:
            out.append(state("satisfied", f"{len(controls)} authorizations and {len(executions)} executions agree"))
    tally = {s: sum(1 for g in out if g["state"] == s) for s in STATES}
    return out, tally


def overall(groups: list[dict], decision_count: int) -> tuple[str, str]:
    """The set's decision and reason from its groups' states."""
    if not groups:
        return "not_established", "missing" if decision_count else "empty_denominator"
    states = {g["state"] for g in groups}
    for value in PRIORITY:
        if value in states:
            return ("contradicted" if value == "failure" else "not_established"), value
    return "supported", "satisfied"


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Consumer claim adapter: the record set, the key bindings and the revocation snapshot."""
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"records", "bindings", "revocation"}, {"actions", "pointer_conventions"})
    raw_bindings, bindings_binding = bound(artifacts, artifact_root, assessment["bindings"], "assessment.bindings")
    raw_revocation, revocation_binding = bound(artifacts, artifact_root, assessment["revocation"],
                                               "assessment.revocation")
    conventions = assessment.get("pointer_conventions") or {}
    if not isinstance(conventions, dict) or set(conventions) - set(POINTERS) \
            or set(conventions.values()) - {"jcs", "raw"}:
        raise CaseError("assessment.pointer_conventions: expected {pointer: jcs|raw} for the two action pointers")
    names = assessment.get("actions") or {}
    if not isinstance(names, dict):
        raise CaseError("assessment.actions: expected an object of record id to case artifact name")
    actions = {_string(k, "assessment.actions key"): bound(artifacts, artifact_root, v, f"assessment.actions.{k}")[0]
               for k, v in names.items()}
    data, records_binding = bound(artifacts, artifact_root, assessment["records"], "assessment.records")
    scope: dict[str, Any] = {"records": records_binding, "bindings": bindings_binding,
                             "revocation": revocation_binding, "does_not_establish": DOES_NOT_ESTABLISH,
                             "limit": LIMIT}
    if raw_bindings is None or raw_revocation is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established",
                        "bindings_unavailable" if raw_bindings is None else "revocation_unavailable")
    bindings = _bindings(raw_bindings, "bindings", {"public_key_hex", "suite"})
    revocation = _bindings(raw_revocation, "revocation", {"state"})
    scope["key_set_sha256"] = key_set_fingerprint(
        key_sha256(bytes.fromhex(b["public_key_hex"])) for b in bindings.values()
        if isinstance(b["public_key_hex"], str) and len(b["public_key_hex"]) == 64 and not set(b["public_key_hex"]) - _HEX)
    if data is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "records_unavailable")
    try:
        records = parse_ijson(data)
        if not isinstance(records, list):
            raise Refused("record_shape", "the record set is a JSON array")
        groups, tally = evaluate(records, bindings, revocation, actions, conventions)
    except IJSONError as exc:
        reason = "no_duplicate_member" if exc.code == "duplicate-member" else "record_shape"
        check = {"id": reason, "status": "fail", "detail": describe(exc)}
        return {**decision(case_id, CLAIM_TYPE, scope, "contradicted", reason, [check]), "vantage": "independent"}
    except Refused as exc:
        check = {"id": exc.reason, "status": "fail", "detail": exc.detail}
        return {**decision(case_id, CLAIM_TYPE, scope, "contradicted", exc.reason, [check]), "vantage": "independent"}
    scope["evidence_states"] = tally
    scope["groups"] = len(groups)
    result, reason = overall(groups, sum(1 for r in records if r.get("artifact_type") == "decision"))
    return {**decision(case_id, CLAIM_TYPE, scope, result, reason, groups), "vantage": "independent"}
