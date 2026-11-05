"""The two done verdicts and the done receipt, from the records of one run.

The run directory holds the records under fixed names. Each record arrives as a DSSE
envelope and is opened under a pinned key before anything reads it (:func:`open_run`). The
checks then run in ``probity-verify`` on the pinned bytes (:func:`checks`), and the receipt
carries two verdicts derived separately, with probity-verify's own combination
(``done_receipt/v2``):

- ``outcome``, is the work done: ``acceptance_observed/v1`` alone, the sealed visible and
  held-out commands graded outside the agent on its final tree;
- ``integrity``, did the agent game the process: ``protected_paths/v1``,
  ``probe_observed/v1`` (the oracle-free probes and the grader's visible-test detectors),
  ``tool_claim_match/v1`` (with the contract pinned) and ``completion_claim/v1``. A
  contradiction carries its class, and the worst class wins: tamper, then gaming, then
  deception. A hygiene finding (a claim true when made and stale after a later edit), no tool
  claims and no probes are excused.

``accepted`` is both axes supported; ``completion_claimed`` is whether the agent asserted done
(the claims record's ``completion.asserted``). There is no other combined verdict:
:func:`summary` is only the one-line decision a consumer that reads one field sees, derived
from the two axes by probity-verify's rule. probity-verify's ``done_receipt/v2`` derives every
one of these again from the same records.

The receipt is the ``probity-done-receipt/v2`` predicate, signed by the harness key and
naming its verifier (``verifier.id``); its in-toto Statement is written unsigned (see
:mod:`.formats`).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from probity_verify.adapters import done_receipt as shared
from probity_verify.core import adjudicate

from .formats import RECEIPT_PREDICATE, VERIFIER_ID, DoneError, encode, open_record, sha256, sign_record, statement

RECEIPT_SCHEMA = shared.SCHEMA
ROLES = {"contract": "probity-done-contract/v1", "tree": "probity-tree/v2",
         "observation": "probity-observation/v3", "capability": "probity-capabilities/v1",
         "grade": "probity-acceptance-grade/v1", "claims": "probity-tool-claims/v2"}
# (claim type, file stem, records, axis), in probity-verify's check order on each axis.
CHECKS = (
    ("acceptance_observed/v1", "acceptance", ("contract", "tree", "grade"), "outcome"),
    ("protected_paths/v1", "protected-paths", ("contract", "capability", "observation", "tree"),
     "integrity"),
    ("probe_observed/v1", "probes", ("contract", "tree", "grade"), "integrity"),
    ("tool_claim_match/v1", "tool-claims", ("claims", "capability", "observation", "contract"),
     "integrity"),
    ("completion_claim/v1", "completion", ("claims", "capability", "observation", "contract"),
     "integrity"),
)
# The checks that read the grade, not the observation: they take no observation scope.
GRADED = {"acceptance_observed/v1", "probe_observed/v1"}
OBSERVED = {"tree", "observation", "grade"}
SOURCES = "sources"


@dataclass(frozen=True)
class Pins:
    """The consumer's pins: which key signs which record, and who produced it."""

    harness_key: str
    host_key: str
    grader_key: str
    observed_party: str = "agent"
    observer_producer: str = "host-observer"
    allow_no_heldout: bool = False
    grader_producer: str = "harness-verifier"
    scopes: dict[str, str] = field(default_factory=lambda: {"tree": "PEER", "observation": "PEER",
                                                            "grade": "PEER"})

    def key(self, role: str) -> str:
        if role in ("contract", "claims"):
            return self.harness_key
        if role == "grade":
            return self.grader_key
        return self.host_key


def open_run(run: Path, pins: Pins) -> dict[str, bytes]:
    """Verify every record envelope under its pinned key; return the payload bytes by role.

    ``<role>.dsse.json`` must open to exactly the bytes of ``<role>.json``.
    """
    opened = {}
    for role, schema in ROLES.items():
        envelope = (run / f"{role}.dsse.json").read_bytes()
        payload = open_record(envelope, pins.key(role), schema)
        if payload != (run / f"{role}.json").read_bytes():
            raise DoneError(f"{role}.json is not the payload its envelope signs")
        opened[role] = payload
    return opened


def write_sources(run: Path, sources: dict[str, bytes]) -> None:
    """Keep the grader's protected sources as ``sources/<sha256>`` in the run directory."""
    if not sources:
        return
    (run / SOURCES).mkdir(exist_ok=True)
    for digest, data in sources.items():
        if sha256(data) != digest:
            raise DoneError("a protected source does not match its digest")
        (run / SOURCES / digest).write_bytes(data)


def _source_artifacts(run: Path) -> dict[str, dict[str, Any]]:
    """``source:<sha256>`` case artifacts, each bound by its own digest."""
    folder = run / SOURCES
    if not folder.is_dir():
        return {}
    found = {}
    for path in sorted(folder.iterdir()):
        data = path.read_bytes()
        if sha256(data) == path.name:
            found[f"source:{path.name}"] = {"path": f"{SOURCES}/{path.name}",
                                             "sha256": path.name, "length": len(data)}
    return found


def _artifact(name: str, data: bytes) -> dict[str, Any]:
    return {"path": name, "sha256": sha256(data), "length": len(data)}


def _case(claim_id: str, roles: tuple[str, ...], records: dict[str, bytes],
          extra: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """The case: its id is the records' ``claim_id``, which every adapter checks."""
    artifacts = {role: _artifact(f"{role}.json", records[role]) for role in roles}
    artifacts.update(extra or {})
    return {"schema_version": "probity-case/v1", "case_id": claim_id, "artifacts": artifacts}


def _witnesses(roles: tuple[str, ...], records: dict[str, bytes], pins: Pins) -> dict[str, Any]:
    witnesses = {}
    for role in roles:
        pin: dict[str, Any] = {"artifact": role, "sha256": sha256(records[role]),
                               "authority": f"signed by {pins.key(role)}"}
        if role in OBSERVED:
            producer = pins.grader_producer if role == "grade" else pins.observer_producer
            pin.update(producer=producer, vantage="independent",
                       witness_scope=pins.scopes.get(role, "PEER"))
        witnesses[role] = pin
    return witnesses


def _policy(claim_type: str, claim_id: str, roles: tuple[str, ...], records: dict[str, bytes],
            pins: Pins) -> dict[str, Any]:
    observation = json.loads(records["observation"])
    assessment: dict[str, Any] = {"claim_type": claim_type, "observed_party": pins.observed_party,
                                  "invocation_id": observation["invocation_id"]}
    assessment.update({f"{role}_witness": role for role in roles})
    if claim_type not in GRADED:
        assessment["scope"] = observation["scope"]
    elif claim_type == "acceptance_observed/v1" and pins.allow_no_heldout:
        assessment["allow_no_heldout"] = True
    return {"schema_version": "probity-policy/v1", "witnesses": _witnesses(roles, records, pins),
            "assessments": {claim_id: assessment}}


def checks(run: Path, records: dict[str, bytes], pins: Pins,
           require_witness_scope: str = "PEER") -> dict[str, list[dict[str, Any]]]:
    """Run the five probity-verify checks on the signed record bytes and write their cases;
    return each axis's entries, as ``done_receipt/v2`` places them."""
    out = run / "verify"
    out.mkdir(exist_ok=True)
    found: dict[str, list[dict[str, Any]]] = {"outcome": [], "integrity": []}
    claim_id = json.loads(records["observation"])["claim_id"]
    sources = _source_artifacts(run)
    for claim_type, check_name, roles, axis in CHECKS:
        case = _case(claim_id, roles, records,
                     sources if claim_type == "protected_paths/v1" else None)
        policy = _policy(claim_type, claim_id, roles, records, pins)
        (out / f"{check_name}.case.json").write_bytes(encode(case))
        (out / f"{check_name}.policy.json").write_bytes(encode(policy))
        result = adjudicate(case, policy, run, require_witness_scope=require_witness_scope)
        (out / f"{check_name}.decision.json").write_bytes(encode(result))
        found[axis].append(shared.entry(result))
    return found


def axes(found: dict[str, list[dict[str, Any]]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The outcome and integrity verdicts, by probity-verify's own combination."""
    return shared.combine_outcome(found["outcome"]), shared.combine_integrity(found["integrity"])


def summary(predicate: dict[str, Any]) -> dict[str, Any]:
    """The one decision a consumer that reads one field sees: ``supported`` only when
    accepted, else the integrity contradiction, else the outcome's, else what is open."""
    outcome, integrity = predicate["outcome"], predicate["integrity"]
    decision, reason = shared.decision(outcome, integrity)
    if decision == "not_established":
        return {"decision": decision, "reason": reason, "vantage": "unestablished"}
    axis = integrity if (integrity["decision"], integrity["reason"]) == (decision, reason) \
        else outcome
    found = {"decision": decision, "reason": reason, "vantage": "independent",
             "witness_scope": axis.get("witness_scope", "PEER")}
    if decision == "supported":
        found["witness_scope"] = "EXTERNAL" if all(
            item.get("witness_scope") == "EXTERNAL" for item in (outcome, integrity)) else "PEER"
    if "class" in axis and axis is integrity and decision == "contradicted":
        found["class"] = axis["class"]
    return found


def done_receipt_case(run: Path, records: dict[str, bytes], statement_bytes: bytes, pins: Pins,
                      verifier_ids: list[str] | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """The case and policy for probity-verify's ``done_receipt/v2`` over one attempt."""
    observation = json.loads(records["observation"])
    claim_id = observation["claim_id"]
    roles = tuple(ROLES)
    every = {**records, "receipt": statement_bytes}
    case = _case(claim_id, roles, records, {"receipt": _artifact("done-receipt.statement.json",
                                                                 statement_bytes),
                                            **_source_artifacts(run)})
    assessment: dict[str, Any] = {"claim_type": shared.CLAIM_TYPE,
                                  "observed_party": pins.observed_party,
                                  "invocation_id": observation["invocation_id"],
                                  "scope": observation["scope"], "receipt_witness": "receipt"}
    assessment.update({f"{role}_witness": role for role in roles})
    if pins.allow_no_heldout:
        assessment["allow_no_heldout"] = True
    if verifier_ids is not None:
        assessment["verifier_ids"] = list(verifier_ids)
    witnesses = _witnesses(roles, records, pins)
    witnesses["receipt"] = {"artifact": "receipt", "sha256": sha256(every["receipt"]),
                            "authority": f"signed by {pins.harness_key}"}
    return case, {"schema_version": "probity-policy/v1", "witnesses": witnesses,
                  "assessments": {claim_id: assessment}}


def _optional(run: Path, name: str) -> tuple[bytes | None, dict[str, Any] | None]:
    path = run / name
    if not path.is_file():
        return None, None
    data = path.read_bytes()
    return data, json.loads(data)


def assemble(run: Path, pins: Pins, require_witness_scope: str = "PEER") -> dict[str, Any]:
    """Open the records, run the checks and derive both verdicts: the unsigned predicate.

    The caller adds the optional members (``policy``, ``stop_decision``,
    ``verifier_isolation``) and signs it with :func:`sign_receipt`.
    """
    records = open_run(run, pins)
    found = checks(run, records, pins, require_witness_scope)
    launch_bytes, _ = _optional(run, "launch.json")
    launch_receipt_bytes, _ = _optional(run, "receipt.json")
    observation = json.loads(records["observation"])
    digests = {role: {"sha256": sha256(data)} for role, data in records.items()}
    if launch_bytes is not None and launch_receipt_bytes is not None:
        digests["launch"] = {"sha256": sha256(launch_bytes)}
        digests["launch_receipt"] = {"sha256": sha256(launch_receipt_bytes)}
    outcome, integrity = axes(found)
    return {
        "schema_version": RECEIPT_SCHEMA, "verifier": {"id": VERIFIER_ID},
        "claim_id": observation["claim_id"],
        "invocation_id": observation["invocation_id"], "records": digests,
        "completion_claimed": json.loads(records["claims"])["completion"]["asserted"],
        "accepted": shared.accepted(outcome, integrity),
        "outcome": outcome, "integrity": integrity,
        "external_effects": observation.get("external_mutations", []),
    }


@dataclass(frozen=True)
class Receipt:
    predicate: dict[str, Any]
    data: bytes
    envelope: bytes


def sign_receipt(run: Path, predicate: dict[str, Any], key) -> Receipt:
    """Sign the receipt and write it with its unsigned in-toto Statement."""
    tree = json.loads((run / "tree.json").read_bytes())
    data, envelope = sign_record(predicate, key)
    (run / "done-receipt.json").write_bytes(data)
    (run / "done-receipt.dsse.json").write_bytes(envelope)
    (run / "done-receipt.statement.json").write_bytes(encode(statement(
        RECEIPT_PREDICATE, "workspace-tree", tree["tree_sha256"], predicate)))
    return Receipt(predicate, data, envelope)


def write_record(run: Path, role: str, record: dict[str, Any], key) -> bytes:
    """Write ``<role>.json`` and ``<role>.dsse.json`` for one record; return its bytes."""
    data, envelope = sign_record(record, key)
    (run / f"{role}.json").write_bytes(data)
    (run / f"{role}.dsse.json").write_bytes(envelope)
    return data


def sign_observer_records(run: Path, host_key) -> None:
    """Re-encode the launcher's observation, capability and tree records and sign them."""
    for role in ("observation", "capability", "tree"):
        write_record(run, role, json.loads((run / f"{role}.json").read_bytes()), host_key)


def verifier_id(predicate: dict[str, Any]) -> str:
    """The receipt's required ``verifier.id``: an absolute https URI naming the verifier that
    signed it. A receipt without one is refused."""
    verifier = predicate.get("verifier")
    found = verifier.get("id") if isinstance(verifier, dict) else None
    if not isinstance(found, str) or not found.startswith("https://") or len(found) <= 8:
        raise DoneError("the receipt carries no verifier.id (a required https URI)")
    return found


def decision_line(found: dict[str, Any]) -> str:
    """``Decision: <decision> / <reason> (class: ..., vantage: ..., witness_scope: ...)``."""
    parts = [f"class: {found['class']}"] if "class" in found else []
    parts.append(f"vantage: {found['vantage']}")
    if "witness_scope" in found:
        parts.append(f"witness_scope: {found['witness_scope']}")
    return f"Decision: {found['decision']} / {found['reason']} ({', '.join(parts)})"


def axis_line(name: str, axis: dict[str, Any]) -> str:
    """``Outcome: supported / ...`` or ``Integrity: contradicted / ... (class: ...)``."""
    found = {"decision": axis["decision"], "reason": axis["reason"], "vantage": axis["vantage"]}
    for key in ("class", "witness_scope"):
        if key in axis:
            found[key] = axis[key]
    return decision_line(found).replace("Decision:", f"{name}:", 1)
