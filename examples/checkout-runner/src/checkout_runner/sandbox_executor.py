"""Executor role for the bounded refund sandbox (contract review-2026-10-23, section 10).

The executor did not decide admission and did not sign the handoff. Before any
effecting dispatch it re-derives authorization from the bytes it was handed:

* the handoff envelope, verified against the full committed admission record
  and the locally selected issuance trust (``sandbox_signer.verify_envelope``);
* the locally selected evaluation trust (section 7): the issuance snapshot must
  be accepted, the key must not be rebound, and revocation is checked at the
  actual dispatch instant;
* the original evidence files, each hashed against the record, and the PIC
  result's ``args_digest`` against the stored arguments;
* the dispatch window (section 8): L is the ceiling of the latest lower bound,
  U the floor of the earliest upper bound, and dispatch needs L <= now < U on
  the unrounded clock.

It persists the scoped operation, stored arguments and idempotency key before
calling the simulator, and records four closed JSONL streams (attempts,
outcomes, effects, observations). An outcome is promoted to observed_success
only from a simulator observation whose effect binds to this operation, its
idempotency key, its exact arguments and its original dispatch attempt; any
mismatch stays unresolved with a ``local-effect-binding-mismatch`` diagnostic.

JCS comes from the pinned ``agent-evidence-vectors`` package. These streams are
local records, not a new signed receipt format; their integrity rests on the
runner's sealed bundle and their meaning on the simulator readback.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from agent_evidence_vectors.run_vectors import jcs_dumps

from . import sandbox_signer as sg
from .sandbox_sim import LostResponse, SandboxSimulator, fmt_exact, parse_exact

EVALUATION = "refund-sandbox-trust-evaluation/0.1"
ATTEMPT = "refund-sandbox-attempt/0.1"
OUTCOME = "refund-sandbox-outcome/0.1"
EFFECT = "refund-sandbox-effect/0.1"
OBSERVATION = "refund-sandbox-observation/0.1"
REPORT_CONTEXT = "refund-sandbox-report-context/0.1"
BINDING_MISMATCH = "local-effect-binding-mismatch"
SAFE_INT = 2**53 - 1

COMMON = frozenset({
    "schema", "contract_revision", "run_id", "workflow_id", "admission_issuer", "provider_namespace",
    "operation_id", "recorded_at", "admission_ref", "idempotency_key",
})
STREAM_FIELDS = {
    ATTEMPT: COMMON | {"attempt_id", "kind", "handoff_file_ref", "trust_evaluation_file_ref", "tool",
                       "arguments", "arguments_digest", "started_at"},
    OUTCOME: COMMON | {"attempt_id", "attempt_ref", "status", "effect_ref", "observation_ref"},
    EFFECT: COMMON | {"effect_id", "attempt_id", "attempt_ref", "arguments", "arguments_digest", "committed_at"},
    OBSERVATION: COMMON | {"observation_id", "observation_kind", "attempt_id", "attempt_ref", "source_file_ref",
                           "effect_refs", "observed_at"},
}
STREAM_FILES = {ATTEMPT: "attempts.jsonl", OUTCOME: "outcomes.jsonl", EFFECT: "effects.jsonl",
                OBSERVATION: "observations.jsonl"}
EVALUATION_FIELDS = frozenset({"schema", "contract_revision", "evaluation_id", "workflow_id", "selected_at",
                               "accepted_issuance_snapshots", "keys"})
REPORT_FIELDS = frozenset({"schema", "contract_revision", "run_id", "scenario_id", "workflow_id",
                           "admission_issuer", "provider_namespace", "report_cutoff"})
OPERATION_SCOPE = (*sg.SCOPE, "operation_id")

_MS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ExecutorRefusal(sg.SignerRefusal):
    """An input, delivery or record the executor refuses, with a code."""


def _require(cond: bool, code: str) -> None:
    if not cond:
        raise ExecutorRefusal(code)


def file_ref(data: bytes) -> str:
    """Return ``sha256:`` plus the SHA-256 of raw file bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def arguments_digest(arguments: Any) -> str:
    """Execution arguments_digest: ``sha256:`` plus SHA-256(JCS(arguments))."""
    return file_ref(jcs_dumps(arguments))


def ceil_s(value: datetime) -> datetime:
    """Round an instant up to a whole second."""
    whole = value.replace(microsecond=0)
    return whole + timedelta(seconds=1) if value.microsecond else whole


def floor_s(value: datetime) -> datetime:
    """Round an instant down to a whole second."""
    return value.replace(microsecond=0)


def parse_ms(value: Any) -> datetime:
    """Parse a millisecond UTC instant (YYYY-MM-DDTHH:MM:SS.sssZ)."""
    _require(isinstance(value, str) and bool(_MS.match(value)), "timestamp-ms-format")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


# Strict wrapper JSON: closed objects, no duplicate keys, floats, constants,
# unsafe integers or non-ASCII strings.

def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    _require(len({k for k, _ in pairs}) == len(pairs), "wrapper-duplicate-field")
    return dict(pairs)


def _no_float(_: str) -> Any:
    raise ExecutorRefusal("wrapper-float")


def _no_constant(_: str) -> Any:
    raise ExecutorRefusal("wrapper-constant")


def check_wrapper_value(value: Any) -> None:
    """Refuse values the wrapper hashing rules exclude."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        _require(-SAFE_INT <= value <= SAFE_INT, "wrapper-unsafe-integer")
    elif isinstance(value, str):
        _require(value.isascii(), "wrapper-non-ascii")
    elif isinstance(value, list):
        for item in value:
            check_wrapper_value(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _require(isinstance(key, str) and key.isascii(), "wrapper-non-ascii")
            check_wrapper_value(item)
    else:
        raise ExecutorRefusal("wrapper-float" if isinstance(value, float) else "wrapper-type")


def strict_loads(data: bytes) -> Any:
    """Parse one wrapper JSON document strictly."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ExecutorRefusal("wrapper-non-ascii") from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_constant)
    except json.JSONDecodeError:
        raise ExecutorRefusal("wrapper-json") from None
    check_wrapper_value(value)
    return value


def typed_equal(a: Any, b: Any) -> bool:
    """Typed canonical equality: same JSON types throughout, then identical JCS bytes."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(typed_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(typed_equal(x, y) for x, y in zip(a, b))
    return jcs_dumps(a) == jcs_dumps(b)


# Section 7: evaluation trust.

def check_evaluation(evaluation: Any, issuance: dict[str, Any]) -> None:
    """Check an evaluation-trust file's closed shape and that no key is rebound."""
    _require(isinstance(evaluation, dict) and set(evaluation) == EVALUATION_FIELDS, "evaluation-fields")
    _require(evaluation["schema"] == EVALUATION, "evaluation-schema")
    _require(evaluation["contract_revision"] == sg.CONTRACT_REVISION, "evaluation-revision")
    _require(evaluation["workflow_id"] == issuance["workflow_id"], "evaluation-workflow")
    sg.parse_ts(evaluation["selected_at"])
    accepted = evaluation["accepted_issuance_snapshots"]
    _require(isinstance(accepted, list) and len(set(accepted)) == len(accepted), "evaluation-accepted")
    _require(all(isinstance(r, str) and r.startswith("sha256:") and bool(_HEX64.match(r[7:])) for r in accepted),
             "evaluation-accepted")
    keys = evaluation["keys"]
    _require(isinstance(keys, list), "evaluation-keys")
    seen: set[str] = set()
    issued = {k["key_id"]: k for k in issuance["keys"]}
    for key in keys:
        _require(isinstance(key, dict) and set(key) == sg.KEY_FIELDS, "evaluation-key-fields")
        _require(isinstance(key["public_key_hex"], str) and bool(_HEX64.match(key["public_key_hex"])),
                 "evaluation-key-hex")
        _require(key["key_id"] not in seen, "evaluation-key-duplicate")
        seen.add(key["key_id"])
        old = issued.get(key["key_id"])
        if old is not None:
            same = all(old[f] == key[f] for f in ("public_key_hex", "issuer", "role"))
            _require(same, "key-rebound")
        for name in ("not_before", "not_after"):
            sg.parse_ts(key[name])
        if key["revoked_at"] is not None:
            sg.parse_ts(key["revoked_at"])


@dataclass(frozen=True)
class Delivery:
    """Everything an executor is handed for one operation, as bytes or locally selected config."""

    handoff_file: bytes
    record: dict[str, Any]
    issuance: dict[str, Any]
    evaluation_file: bytes
    evidence: dict[str, bytes]
    native_bounds: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Authorization:
    """The result of a successful pre-dispatch check."""

    payload: dict[str, Any]
    lower: datetime
    upper: datetime
    pic_args_digest: str
    handoff_file_ref: str
    evaluation_file_ref: str


def check_evidence(record: dict[str, Any], evidence: dict[str, bytes]) -> str:
    """Hash every original evidence file against the record; return the PIC args_digest."""
    _require(isinstance(evidence, dict) and set(evidence) == set(sg.INPUT_REFS), "evidence-fields")
    for name in sg.INPUT_REFS:
        _require(file_ref(evidence[name]) == record[name], f"evidence-{name}")
    pic = strict_loads(evidence["pic_verification_ref"])
    _require(isinstance(pic, dict) and isinstance(pic.get("args_digest"), str), "pic-result-shape")
    _require(bool(_HEX64.match(pic["args_digest"])), "pic-result-shape")
    _require(typed_equal(pic.get("arguments"), record["arguments"]), "pic-arguments")
    _require(arguments_digest(record["arguments"]) == "sha256:" + pic["args_digest"], "pic-args-digest")
    return pic["args_digest"]


def _keys(payload: dict[str, Any], issuance: dict[str, Any], evaluation: dict[str, Any]) -> tuple[dict, dict]:
    issued = [k for k in issuance["keys"] if k["key_id"] == payload["key_id"]]
    current = [k for k in evaluation["keys"] if k["key_id"] == payload["key_id"]]
    _require(len(issued) == 1, "key-unknown")
    _require(len(current) == 1, "evaluation-key-unknown")
    return issued[0], current[0]


def dispatch_window(payload: dict[str, Any], record: dict[str, Any], keys: tuple[dict, ...],
                    native_bounds: tuple[tuple[str, str], ...]) -> tuple[datetime, datetime]:
    """Return (L, U): inward whole-second conversion of every applicable bound (section 8)."""
    lowers = [sg.parse_ts(payload["not_before"]), sg.parse_ts(record["committed_at"])]
    uppers = [sg.parse_ts(payload["valid_until"]), sg.parse_ts(record["valid_until"])]
    for key in keys:
        lowers.append(sg.parse_ts(key["not_before"]))
        uppers.append(sg.parse_ts(key["not_after"]))
    for low, high in native_bounds:
        lowers.append(ceil_s(parse_ms(low)))
        uppers.append(floor_s(parse_ms(high)))
    lower, upper = max(lowers), min(uppers)
    _require(lower < upper, "dispatch-window-empty")
    return lower, upper


def _revocation(keys: tuple[dict, ...], now: datetime) -> None:
    for key in keys:
        if key["revoked_at"] is not None:
            _require(now < floor_s(sg.parse_ts(key["revoked_at"])), "key-revoked-at-dispatch")


def authorize(delivery: Delivery, now: datetime) -> Authorization:
    """Every check section 10 requires before an effecting dispatch, at the unrounded instant ``now``."""
    envelope = strict_loads(delivery.handoff_file)
    payload = sg.verify_envelope(sg.HANDOFF, envelope, delivery.record, delivery.issuance)
    evaluation = strict_loads(delivery.evaluation_file)
    check_evaluation(evaluation, delivery.issuance)
    _require(payload["trust_snapshot_ref"] in evaluation["accepted_issuance_snapshots"],
             "issuance-snapshot-not-accepted")
    keys = _keys(payload, delivery.issuance, evaluation)
    _require(keys[1]["role"] == sg.SIGNER_ROLE, "key-role")
    pic_digest = check_evidence(delivery.record, delivery.evidence)
    _revocation(keys, now)
    lower, upper = dispatch_window(payload, delivery.record, keys, delivery.native_bounds)
    _require(lower <= now, "dispatch-before-window")
    _require(now < upper, "dispatch-after-window")
    return Authorization(payload, lower, upper, pic_digest, file_ref(delivery.handoff_file),
                         file_ref(delivery.evaluation_file))


def evaluate_history(delivery: Delivery, exact_dispatch: datetime | None, evaluation_time: datetime) -> dict[str, str]:
    """Historical reader split (section 8): integrity, recorded-attempt authorization, new dispatch."""
    out: dict[str, str] = {}
    try:
        sg.verify_envelope(sg.HANDOFF, strict_loads(delivery.handoff_file), delivery.record, delivery.issuance)
        out["integrity"] = "ESTABLISHED"
    except sg.SignerRefusal as exc:
        out["integrity"] = f"CONTRADICTED:{exc.code}"
    if exact_dispatch is None:
        out["recorded_attempt"] = "NOT_ESTABLISHED"
    else:
        out["recorded_attempt"] = _try_authorize(delivery, exact_dispatch, "ESTABLISHED", "CONTRADICTED")
    out["new_dispatch"] = _try_authorize(delivery, evaluation_time, "allowed", "forbidden")
    return out


def _try_authorize(delivery: Delivery, at: datetime, yes: str, no: str) -> str:
    try:
        authorize(delivery, at)
        return yes
    except sg.SignerRefusal as exc:
        return f"{no}:{exc.code}"


def check_stream_record(schema: str, record: Any) -> None:
    """Closed-object check for one execution-stream record."""
    _require(isinstance(record, dict) and set(record) == STREAM_FIELDS[schema], f"stream-fields:{schema}")
    _require(record["schema"] == schema and record["contract_revision"] == sg.CONTRACT_REVISION,
             f"stream-schema:{schema}")
    check_wrapper_value(record)
    sg.parse_ts(record["recorded_at"])


def load_stream(store: Path, schema: str) -> list[dict[str, Any]]:
    """Read one stream strictly; every line is a closed record."""
    path = Path(store) / STREAM_FILES[schema]
    if not path.exists():
        return []
    records = []
    for line in path.read_bytes().splitlines():
        record = strict_loads(line)
        check_stream_record(schema, record)
        records.append(record)
    return records


def binding_problems(op: dict[str, Any], effect: dict[str, Any], attempts: dict[str, dict[str, Any]]) -> list[str]:
    """Everything that must hold before an effect can promote an outcome to observed_success."""
    problems = [f"effect-{name}" for name in (*OPERATION_SCOPE, "idempotency_key", "admission_ref")
                if effect[name] != op[name]]
    if not typed_equal(effect["arguments"], op["arguments"]):
        problems.append("effect-arguments")
    digest = arguments_digest(effect["arguments"])
    if effect["arguments_digest"] != digest or digest != "sha256:" + op["pic_args_digest"]:
        problems.append("effect-arguments-digest")
    origin = attempts.get(effect["attempt_id"])
    if origin is None or origin["kind"] != "dispatch" or sg.ref_of(origin) != effect["attempt_ref"]:
        problems.append("effect-attempt")
    return problems


class SandboxExecutor:
    """Section 10 executor over a synthetic simulator. One store directory per run."""

    def __init__(self, store: Path, run_id: str, simulator: SandboxSimulator, clock: Callable[[], datetime]) -> None:
        self.store = Path(store)
        self.run_id = run_id
        self.sim = simulator
        self.clock = clock
        (self.store / "raw").mkdir(parents=True, exist_ok=True)

    # Persistence.

    def _write_atomic(self, path: Path, data: bytes) -> None:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def operations(self) -> dict[str, dict[str, Any]]:
        """Persisted operations keyed by idempotency key."""
        path = self.store / "operations.json"
        return json.loads(path.read_bytes()) if path.exists() else {}

    def _save_op(self, op: dict[str, Any]) -> None:
        ops = self.operations()
        ops[op["idempotency_key"]] = op
        self._write_atomic(self.store / "operations.json", jcs_dumps(ops))

    def _append(self, schema: str, body: dict[str, Any], op: dict[str, Any]) -> dict[str, Any]:
        record = {"schema": schema, "contract_revision": sg.CONTRACT_REVISION, "run_id": self.run_id,
                  **{k: op[k] for k in OPERATION_SCOPE}, "admission_ref": op["admission_ref"],
                  "idempotency_key": op["idempotency_key"], **body, "recorded_at": sg.fmt_ts(self.clock())}
        check_stream_record(schema, record)
        with open(self.store / STREAM_FILES[schema], "ab") as fh:
            fh.write(jcs_dumps(record) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        return record

    def _raw(self, name: str, entry: dict[str, Any]) -> None:
        with open(self.store / "raw" / name, "ab") as fh:
            fh.write(json.dumps(entry, sort_keys=True).encode("ascii") + b"\n")

    def exact_dispatch_time(self, attempt_id: str) -> datetime | None:
        """The retained exact producer dispatch time for an attempt, if any."""
        path = self.store / "raw" / "dispatch-times.jsonl"
        if not path.exists():
            return None
        for line in path.read_bytes().splitlines():
            entry = json.loads(line)
            if entry["attempt_id"] == attempt_id:
                return parse_exact(entry["at"])
        return None

    def diagnostics(self) -> list[dict[str, Any]]:
        """Executor diagnostics, such as local-effect-binding-mismatch."""
        path = self.store / "raw" / "diagnostics.jsonl"
        return [json.loads(x) for x in path.read_bytes().splitlines()] if path.exists() else []

    # Delivery and dispatch.

    def deliver(self, delivery: Delivery, arguments: Any = None, fail_before_send: bool = False,
                fault: str = "none") -> dict[str, Any]:
        """Authorize, persist and dispatch once; an identical delivery recovers the existing operation."""
        now = self.clock()
        auth = authorize(delivery, now)
        record = delivery.record
        stored = copy.deepcopy(record["arguments"])
        if arguments is not None:
            check_wrapper_value(arguments)
            _require(typed_equal(arguments, stored), "alternate-arguments")
        scope = {k: record[k] for k in OPERATION_SCOPE}
        key = sg.idempotency_key(scope)
        existing = self.operations().get(key)
        if existing is not None:
            same = existing["admission_ref"] == auth.payload["admission_ref"] and typed_equal(existing["arguments"], stored)
            _require(same, "operation-conflict")
            return existing
        op = {**scope, "admission_ref": auth.payload["admission_ref"], "idempotency_key": key, "arguments": stored,
              "pic_args_digest": auth.pic_args_digest, "handoff_file_ref": auth.handoff_file_ref,
              "trust_evaluation_file_ref": auth.evaluation_file_ref, "attempts": 0, "state": "persisted"}
        self._save_op(op)
        return self._dispatch(op, now, fail_before_send, fault)

    def _attempt(self, op: dict[str, Any], kind: str, at: datetime) -> dict[str, Any]:
        op["attempts"] += 1
        attempt_id = f"{op['operation_id']}-a{op['attempts']}"
        self._save_op(op)
        args = copy.deepcopy(op["arguments"])
        return self._append(ATTEMPT, {
            "attempt_id": attempt_id, "kind": kind, "handoff_file_ref": op["handoff_file_ref"],
            "trust_evaluation_file_ref": op["trust_evaluation_file_ref"], "tool": "refund",
            "arguments": args, "arguments_digest": arguments_digest(args), "started_at": sg.fmt_ts(at)}, op)

    def _outcome(self, op: dict[str, Any], attempt: dict[str, Any], status: str,
                 effect: dict[str, Any] | None, observation: dict[str, Any] | None) -> dict[str, Any]:
        op["state"] = status
        self._save_op(op)
        return self._append(OUTCOME, {
            "attempt_id": attempt["attempt_id"], "attempt_ref": sg.ref_of(attempt), "status": status,
            "effect_ref": sg.ref_of(effect) if effect else None,
            "observation_ref": sg.ref_of(observation) if observation else None}, op)

    def _dispatch(self, op: dict[str, Any], now: datetime, fail_before_send: bool, fault: str) -> dict[str, Any]:
        attempt = self._attempt(op, "dispatch", now)
        self._raw("dispatch-times.jsonl", {"attempt_id": attempt["attempt_id"], "at": fmt_exact(now)})
        if fail_before_send:
            self._outcome(op, attempt, "unresolved", None, None)
            return op
        request = {"idempotency_key": op["idempotency_key"], "operation_id": op["operation_id"],
                   "attempt_id": attempt["attempt_id"], "arguments": copy.deepcopy(op["arguments"])}
        try:
            self.sim.apply(request, fault)
        except LostResponse:
            self._outcome(op, attempt, "unresolved", None, None)
            return op
        return self._observe(op, attempt)

    def reconcile(self, idempotency_key: str) -> dict[str, Any]:
        """Non-effecting lookup, allowed after expiry or revocation; a new attempt_id of kind reconcile_lookup."""
        op = self.operations().get(idempotency_key)
        _require(op is not None, "operation-unknown")
        attempt = self._attempt(op, "reconcile_lookup", self.clock())
        return self._observe(op, attempt)

    # Observation and promotion.

    def _effect_record(self, op: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
        attempts = {a["attempt_id"]: a for a in load_stream(self.store, ATTEMPT)}
        origin = attempts.get(row["attempt_id"])
        body = {"effect_id": row["effect_id"], "attempt_id": row["attempt_id"],
                "attempt_ref": sg.ref_of(origin) if origin else "sha256:" + "0" * 64,
                "arguments": row["arguments"], "arguments_digest": arguments_digest(row["arguments"]),
                "committed_at": sg.fmt_ts(parse_exact(row["committed_at"]))}
        provider_op = {**op, "operation_id": row["operation_id"], "idempotency_key": row["idempotency_key"]}
        for prior in load_stream(self.store, EFFECT):
            if all(prior[k] == v for k, v in body.items() if k != "committed_at") and \
                    prior["operation_id"] == row["operation_id"]:
                return prior
        return self._append(EFFECT, body, provider_op)

    def _observe(self, op: dict[str, Any], attempt: dict[str, Any]) -> dict[str, Any]:
        observed = self.clock()
        raw, row, received = self.sim.query(op["idempotency_key"])
        observation_id = f"{attempt['attempt_id']}-o"
        (self.store / "raw" / f"{observation_id}.json").write_bytes(raw)
        effect = self._effect_record(op, row) if row is not None else None
        if effect is not None:
            kind = "effect_present"
        elif received:
            kind = "unresolved"
        else:
            kind = "no_effect_pre_dispatch"
        observation = self._append(OBSERVATION, {
            "observation_id": observation_id, "observation_kind": kind, "attempt_id": attempt["attempt_id"],
            "attempt_ref": sg.ref_of(attempt), "source_file_ref": file_ref(raw),
            "effect_refs": [sg.ref_of(effect)] if effect else [], "observed_at": sg.fmt_ts(observed)}, op)
        if kind == "no_effect_pre_dispatch":
            self._outcome(op, attempt, "observed_failure", None, observation)
        elif kind == "unresolved":
            self._outcome(op, attempt, "unresolved", None, observation)
        else:
            self._promote(op, attempt, effect, observation)
        return op

    def _promote(self, op: dict[str, Any], attempt: dict[str, Any], effect: dict[str, Any],
                 observation: dict[str, Any]) -> None:
        attempts = {a["attempt_id"]: a for a in load_stream(self.store, ATTEMPT)}
        problems = binding_problems(op, effect, attempts)
        if problems:
            self._raw("diagnostics.jsonl", {"code": BINDING_MISMATCH, "attempt_id": attempt["attempt_id"],
                                            "effect_id": effect["effect_id"], "problems": problems})
            self._outcome(op, attempt, "unresolved", None, observation)
            return
        self._outcome(op, attempt, "observed_success", effect, observation)


def result_at_cutoff(store: Path, context: Any) -> dict[str, Any]:
    """Result and selected-scope effect count supported by observations at or before report_cutoff."""
    _require(isinstance(context, dict) and set(context) == REPORT_FIELDS, "report-context-fields")
    _require(context["schema"] == REPORT_CONTEXT and context["contract_revision"] == sg.CONTRACT_REVISION,
             "report-context-schema")
    cutoff = parse_ms(context["report_cutoff"])
    scope = {k: context[k] for k in ("run_id", *sg.SCOPE)}

    def in_scope(r: dict[str, Any]) -> bool:
        return all(r[k] == v for k, v in scope.items())

    def available(r: dict[str, Any], *fields: str) -> bool:
        return in_scope(r) and all(sg.parse_ts(r[f]) <= cutoff for f in fields)

    observations = {sg.ref_of(o): o for o in load_stream(store, OBSERVATION) if available(o, "observed_at", "recorded_at")}
    effects = {sg.ref_of(e) for e in load_stream(store, EFFECT) if in_scope(e)}
    supported = {ref for o in observations.values() if o["observation_kind"] == "effect_present"
                 for ref in o["effect_refs"] if ref in effects}
    success = [o for o in load_stream(store, OUTCOME)
               if available(o, "recorded_at") and o["status"] == "observed_success"
               and o["observation_ref"] in observations and o["effect_ref"] in supported]
    return {"result": "observed_success" if success else "NOT_ESTABLISHED", "effect_count": len(supported)}
