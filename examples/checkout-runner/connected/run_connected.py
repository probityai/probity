"""Connected refund run for aeoess/agent-governance-vocabulary#193 (contract review-2026-10-23).

One process drives every pinned component's own code in order, handing each the
bytes the previous one wrote:

1. APS inputs: ``aps_inputs.mjs`` calls the APS SDK 8.0.1 functions, loaded
   through the Horizon Shield adapter's tree-pinned ``pinnedSdk()``.
2. PIC proposal: ``make_fixture.py`` of pic-standard ``examples/refund-sandbox``
   signs a proposal naming the actual APS ``receipt_id`` and ``decision_id``.
3. PIC verification: ``pic_result.py`` of the same example writes the closed
   section 4 result for this run id.
4. Admission input checks: Horizon Shield ``adapter_aps_receipt.mjs`` over the
   eleven section 3 files at the consumption instant.
5. Admission state: a runner-held stand-in for the admission door (not built
   yet): decision to operation mapping, single-use consumption, replay and
   reissue verdicts, the committed section 5 record.
6. Handoff and resolution signing: ``checkout_runner.sandbox_signer``.
7. Execution, observation and reconciliation: ``checkout_runner.sandbox_executor``
   over the synthetic provider ``checkout_runner.sandbox_sim``.

Every subprocess's argv, exit status, stdout and stderr are kept under
``transcript/``; every file the run wrote is listed with its size and SHA-256 in
``MANIFEST.json``. All keys are public test keys and the provider is a local
simulator: nothing here is merchant authority or a provider effect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent_evidence_vectors.run_vectors import ed25519_public_key, jcs_dumps
from checkout_runner import sandbox_executor as ex
from checkout_runner import sandbox_signer as sg
from checkout_runner.sandbox_sim import SandboxSimulator

WORKFLOW = "wf-refund-193"
ISSUER = "runner-admission-standin"
NAMESPACE = "sim-local"
SIGNER_KEY_ID = "runner-handoff-signer-1"
SIGNER_SEED = hashlib.sha256(b"refund-j01-connected test-only handoff signer").digest()
CASE_FILES = ("inputs/pic-proposal.json", "inputs/aps-approval.json", "inputs/aps-intent.json",
              "inputs/aps-action.json", "inputs/aps-payload.json", "inputs/decision-evidence.json",
              "inputs/pic-verification.json", "trust/pic-keys.json", "trust/aps-consumption.json",
              "trust/handoff-issuance.json", "trust/handoff-evaluation.json")
REF_FILES = {
    "pic_evidence_ref": "inputs/pic-proposal.json", "pic_verification_ref": "inputs/pic-verification.json",
    "pic_trust_file_ref": "trust/pic-keys.json", "aps_evidence_ref": "inputs/aps-approval.json",
    "aps_intent_file_ref": "inputs/aps-intent.json", "aps_action_file_ref": "inputs/aps-action.json",
    "aps_payload_file_ref": "inputs/aps-payload.json", "decision_evidence_ref": "inputs/decision-evidence.json",
    "aps_consumption_trust_ref": "trust/aps-consumption.json",
}


def now() -> datetime:
    return datetime.now(timezone.utc)


def ms(t: datetime) -> str:
    """UTC millisecond instant, rounded up (an event time is never moved earlier)."""
    whole_ms = t.replace(microsecond=(t.microsecond // 1000) * 1000)
    if t.microsecond % 1000:
        whole_ms += timedelta(milliseconds=1)
    return whole_ms.strftime("%Y-%m-%dT%H:%M:%S.") + f"{whole_ms.microsecond // 1000:03d}Z"


def ms_floor(t: datetime) -> str:
    """UTC millisecond instant, rounded down (a report cutoff is never moved later)."""
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def sha_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Tools:
    node: str
    pic_python: str
    pic_example: Path
    horizon_adapter: Path
    aps_inputs: Path


@dataclass
class Run:
    root: Path
    run_id: str
    tools: Tools
    seq: int = 0
    steps: list[dict[str, Any]] = field(default_factory=list)

    def call(self, name: str, argv: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
        """Run one producer command and keep its argv, exit status and output."""
        self.seq += 1
        tag = f"{self.seq:02d}-{name}"
        started = now()
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=300, check=False)
        ended = now()
        tdir = self.root / "transcript"
        tdir.mkdir(parents=True, exist_ok=True)
        (tdir / f"{tag}.out").write_bytes(proc.stdout)
        (tdir / f"{tag}.err").write_bytes(proc.stderr)
        entry = {"seq": self.seq, "name": name, "argv": [self.rel(a) for a in argv], "cwd": self.rel(str(cwd)),
                 "exit": proc.returncode, "started_at": ms(started), "ended_at": ms(ended),
                 "stdout_ref": sha_ref(proc.stdout), "stderr_ref": sha_ref(proc.stderr)}
        with open(tdir / "commands.jsonl", "ab") as fh:
            fh.write(json.dumps(entry, sort_keys=True).encode() + b"\n")
        return proc

    def rel(self, value: str) -> str:
        """Show paths inside the run directory or the component checkouts relative to them."""
        for base, label in ((self.root, "$RUN"), (self.tools.pic_example, "$PIC_EXAMPLE"),
                            (self.tools.horizon_adapter, "$HORIZON_ADAPTER"), (self.tools.aps_inputs.parent, "$CONNECTED")):
            text = str(base)
            if value.startswith(text):
                return label + value[len(text):]
        return value


# Trust selections the runner supplies independently of the evidence bundle.

def issuance_snapshot() -> dict[str, Any]:
    return {"schema": sg.TRUST, "workflow_id": WORKFLOW, "version": "1", "provider_namespaces": [NAMESPACE],
            "keys": [{"key_id": SIGNER_KEY_ID, "issuer": ISSUER, "role": sg.SIGNER_ROLE,
                      "public_key_hex": ed25519_public_key(SIGNER_SEED).hex(), "not_before": "2026-10-01T00:00:00Z",
                      "not_after": "2026-12-01T00:00:00Z", "revoked_at": None}]}


def evaluation_selection(issuance: dict[str, Any], at: datetime) -> dict[str, Any]:
    return {"schema": ex.EVALUATION, "contract_revision": sg.CONTRACT_REVISION, "evaluation_id": "eval-connected-1",
            "workflow_id": WORKFLOW, "selected_at": sg.fmt_ts(at), "accepted_issuance_snapshots": [sg.ref_of(issuance)],
            "keys": [dict(k) for k in issuance["keys"]]}


# Producer steps.

def make_aps(run: Run, case: Path, *, decision_id: str, payment_id: str, amount: int, intent_at: str,
             approval_at: str, valid_until: str, nonce: str, label: str) -> dict[str, Any]:
    proc = run.call("aps-inputs", [run.tools.node, str(run.tools.aps_inputs), "--adapter", str(run.tools.horizon_adapter),
                                   "--out", str(case), "--seed-label", label, "--decision-id", decision_id,
                                   "--payment-id", payment_id, "--amount-minor", str(amount), "--currency", "EUR",
                                   "--intent-issued-at", intent_at, "--approval-issued-at", approval_at,
                                   "--valid-until", valid_until, "--nonce", nonce], run.tools.aps_inputs.parent)
    if proc.returncode != 0:
        raise SystemExit(f"aps_inputs failed: {proc.stderr.decode(errors='replace')}")
    return json.loads(proc.stdout)


def make_pic(run: Run, case: Path, *, decision_id: str, approval_ref: str, payment_id: str, amount: int) -> int:
    out = case / "inputs" / "pic-proposal.json"
    proc = run.call("pic-make-fixture", [run.tools.pic_python, "make_fixture.py", "--decision-id", decision_id,
                                         "--approval-ref", approval_ref, "--approval-ref-source", "aps-receipt-id",
                                         "--payment-id", payment_id, "--amount-minor", str(amount), "--currency", "EUR",
                                         "--ttl-seconds", "1800", "--out", str(out)], run.tools.pic_example)
    return proc.returncode


def verify_pic(run: Run, case: Path, out_name: str = "pic-verification.json") -> tuple[int, dict[str, Any] | None]:
    out = case / "inputs" / out_name
    proc = run.call("pic-result", [run.tools.pic_python, "pic_result.py", "--proposal", str(case / "inputs" / "pic-proposal.json"),
                                   "--keyring", str(case / "trust" / "pic-keys.json"), "--run-id", run.run_id,
                                   "--contract-revision", sg.CONTRACT_REVISION, "--out", str(out)], run.tools.pic_example)
    result = json.loads(out.read_bytes()) if out.exists() else None
    return proc.returncode, result


def horizon_check(run: Run, case: Path) -> tuple[int, dict[str, Any], str]:
    consumed = ms(now())
    proc = run.call("horizon-aps-receipt", [run.tools.node, str(run.tools.horizon_adapter / "adapter_aps_receipt.mjs"),
                                            "--case", str(case), "--run-id", run.run_id, "--consumed-at", consumed],
                    run.tools.horizon_adapter)
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        out = {"verified": False, "code": "ADAPTER_OUTPUT_UNREADABLE"}
    return proc.returncode, out, consumed


def seed_trust(run: Run, case: Path, issuance: dict[str, Any], evaluation: dict[str, Any]) -> None:
    (case / "trust").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(run.tools.pic_example / "keys" / "pic_keys.example.json", case / "trust" / "pic-keys.json")
    (case / "trust" / "handoff-issuance.json").write_bytes(jcs_dumps(issuance))
    (case / "trust" / "handoff-evaluation.json").write_bytes(jcs_dumps(evaluation))


def case_bytes(case: Path) -> dict[str, bytes]:
    return {rel: (case / rel).read_bytes() for rel in CASE_FILES}


# Admission stand-in.

class Admission:
    """Runner-held stand-in for the admission door: in-memory state, persisted for the record only."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.consumed: dict[str, str] = {}
        self.decisions: dict[str, dict[str, Any]] = {}

    def _save(self) -> None:
        self.path.write_bytes(jcs_dumps({"consumed": self.consumed, "decisions": self.decisions}))

    def admit(self, case: Path, adapter_out: dict[str, Any], at: datetime) -> dict[str, Any]:
        """Return a verdict: committed, existing, resolved_existing or refused, with the record it rests on."""
        if adapter_out.get("verified") is not True:
            return {"verdict": "refused", "code": "input-checks-failed"}
        files = case_bytes(case)
        approval = json.loads(files["inputs/aps-approval.json"])
        payload = json.loads(files["inputs/aps-payload.json"])
        decision_id = adapter_out["decision_id"]
        proposal = json.loads(files["inputs/pic-proposal.json"])
        expires = datetime.strptime(json.loads(proposal["evidence"][0]["payload"])["expires_at"],
                                    "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        aps_until = datetime.strptime(approval["result"]["valid_until"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        key = "\n".join((WORKFLOW, ISSUER, NAMESPACE, decision_id))
        refs = {name: sha_ref(files[rel]) for name, rel in REF_FILES.items()}
        receipt = approval["receipt_id"]
        known = self.decisions.get(key)
        if known is not None:
            if not ex.typed_equal(known["record"]["arguments"], payload):
                return {"verdict": "refused", "code": "same-decision-changed-content"}
            if receipt == known["record"]["approval_ref"]:
                return {"verdict": "existing", "record": known["record"]}
            return {"verdict": "resolved_existing", "record": known["record"], "presented_approval_ref": receipt,
                    "presented_inputs": refs}
        if receipt in self.consumed:
            return {"verdict": "refused", "code": "approval-already-consumed"}
        committed = datetime.strptime(sg.fmt_ts(at), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        until = min(committed + timedelta(seconds=sg.HANDOFF_LIFETIME_CEILING), ex.floor_s(aps_until), ex.floor_s(expires))
        if until <= committed:
            return {"verdict": "refused", "code": "admission-window-empty"}
        operation_id = "op-" + hashlib.sha256((key + "\n" + receipt).encode()).hexdigest()[:16]
        record = {"schema": sg.ADMISSION, "contract_revision": sg.CONTRACT_REVISION, "workflow_id": WORKFLOW,
                  "admission_issuer": ISSUER, "provider_namespace": NAMESPACE, "decision_id": decision_id,
                  "operation_id": operation_id, "approval_ref": receipt, **refs, "tool": "refund",
                  "arguments": payload, "state": "committed", "committed_at": sg.fmt_ts(committed),
                  "valid_until": sg.fmt_ts(until)}
        sg.check_admission_record(record)
        self.consumed[receipt] = operation_id
        self.decisions[key] = {"record": record}
        self._save()
        return {"verdict": "committed", "record": record}


# Execution helpers.

def native_bounds(case: Path) -> tuple[tuple[str, str], ...]:
    approval = json.loads((case / "inputs" / "aps-approval.json").read_bytes())
    proposal = json.loads((case / "inputs" / "pic-proposal.json").read_bytes())
    expires = json.loads(proposal["evidence"][0]["payload"])["expires_at"].replace("Z", ".000Z")
    return ((approval["issued_at"], approval["result"]["valid_until"]), (approval["issued_at"], expires))


def delivery_for(case: Path, record: dict[str, Any], handoff: bytes, issuance: dict[str, Any],
                 evaluation_file: bytes) -> ex.Delivery:
    files = case_bytes(case)
    evidence = {name: files[rel] for name, rel in REF_FILES.items()}
    return ex.Delivery(handoff, record, issuance, evaluation_file, evidence, native_bounds(case))


def wait_for_window(payload: dict[str, Any], record: dict[str, Any]) -> float:
    """Sleep until the whole-second lower bounds have passed; return the seconds waited."""
    lower = max(sg.parse_ts(payload["not_before"]), sg.parse_ts(record["committed_at"]))
    wait = (lower - now()).total_seconds()
    if wait > 0:
        time.sleep(wait + 0.05)
        return wait + 0.05
    return 0.0


def apply_count(sim: SandboxSimulator, key: str) -> int:
    return sum(1 for r in json.loads(sim.path.read_bytes())["requests"] if r["kind"] == "apply" and r["idempotency_key"] == key)


def report_context(run_id: str, scenario: str) -> dict[str, Any]:
    """Report context with a cutoff taken after the whole-second ceiling of the last recorded_at."""
    time.sleep(1.1)
    return {"schema": ex.REPORT_CONTEXT, "contract_revision": sg.CONTRACT_REVISION, "run_id": run_id,
            "scenario_id": scenario, "workflow_id": WORKFLOW, "admission_issuer": ISSUER,
            "provider_namespace": NAMESPACE, "report_cutoff": ms_floor(now())}


def refusal(fn: Any) -> str | None:
    try:
        fn()
    except sg.SignerRefusal as exc:
        return exc.code
    return None


# Scenarios.

def stage(run: Run, case_id: str, issuance: dict[str, Any], evaluation: dict[str, Any], *, decision_id: str,
          payment_id: str, amount: int, nonce: str, label: str, intent_at: str | None = None,
          pic_amount: int | None = None) -> tuple[Path, dict[str, Any]]:
    """Write one case's eleven section 3 files from the producers.

    ``intent_at`` reuses an earlier intent and action (a reissue of the same
    decision): the deterministic signatures then reproduce the same intent
    receipt, and only the approval is new.
    """
    case = run.root / "cases" / case_id
    case.mkdir(parents=True)
    t0 = now()
    intent_at = intent_at or ms(t0)
    approval_at = ms(t0 + timedelta(milliseconds=1))
    valid_until = ms(t0 + timedelta(minutes=30))
    aps = make_aps(run, case, decision_id=decision_id, payment_id=payment_id, amount=amount, intent_at=intent_at,
                   approval_at=approval_at, valid_until=valid_until, nonce=nonce, label=label)
    seed_trust(run, case, issuance, evaluation)
    rc = make_pic(run, case, decision_id=decision_id, approval_ref=aps["receipt_id"], payment_id=payment_id,
                  amount=pic_amount if pic_amount is not None else amount)
    if rc != 0:
        raise SystemExit(f"make_fixture failed in {case_id}")
    aps["intent_issued_at"] = intent_at
    return case, aps


def run_scenarios(run: Run) -> dict[str, Any]:
    issuance = issuance_snapshot()
    evaluation = evaluation_selection(issuance, now())
    evaluation_file = jcs_dumps(evaluation)
    (run.root / "trust").mkdir(parents=True, exist_ok=True)
    (run.root / "trust" / "handoff-issuance.json").write_bytes(jcs_dumps(issuance))
    (run.root / "trust" / "handoff-evaluation.json").write_bytes(evaluation_file)
    (run.root / "admission").mkdir()
    (run.root / "signer").mkdir()
    (run.root / "sim").mkdir()
    sim = SandboxSimulator(run.root / "sim" / "sim.json", now)
    executor = ex.SandboxExecutor(run.root / "executor", run.run_id, sim, now)
    admission = Admission(run.root / "admission" / "state.json")
    results: dict[str, Any] = {}

    def sign(name: str, record: dict[str, Any]) -> bytes:
        env = sg.sign_handoff(record, issuance, SIGNER_KEY_ID, SIGNER_SEED, now())
        data = jcs_dumps(env)
        (run.root / "signer" / f"{name}.handoff.json").write_bytes(data)
        return data

    # J01: the exact original approval, end to end.
    case, aps = stage(run, "j01", issuance, evaluation, decision_id="decision-j01", payment_id="pay_A", amount=4000,
                      nonce="0" * 31 + "1", label="j01")
    pic_rc, pic = verify_pic(run, case)
    h_rc, h_out, consumed = horizon_check(run, case)
    adm = admission.admit(case, h_out, now()) if h_rc == 0 else {"verdict": "refused", "code": "input-checks-failed"}
    j01: dict[str, Any] = {"aps": aps, "pic_exit": pic_rc, "pic_result": pic, "horizon_exit": h_rc, "horizon": h_out,
                           "consumed_at": consumed, "admission": {k: v for k, v in adm.items() if k != "record"}}
    j01_record = adm.get("record")
    j01_handoff = b""
    if adm["verdict"] == "committed":
        j01_handoff = sign("j01", j01_record)
        j01["handoff_verifies"] = refusal(lambda: sg.verify_envelope(sg.HANDOFF, json.loads(j01_handoff), j01_record,
                                                                     issuance)) is None
        payload = json.loads(j01_handoff)["payload"]
        j01["waited_for_window_s"] = round(wait_for_window(payload, j01_record), 3)
        d = delivery_for(case, j01_record, j01_handoff, issuance, evaluation_file)
        try:
            op = executor.deliver(d)
            j01["executor"] = {"state": op["state"], "operation_id": op["operation_id"], "idempotency_key": op["idempotency_key"]}
            j01["applies_for_key"] = apply_count(sim, op["idempotency_key"])
        except sg.SignerRefusal as exc:
            j01["executor"] = {"refused": exc.code}
        ctx = report_context(run.run_id, "j01")
        (run.root / "executor" / "report-context-j01.json").write_bytes(jcs_dumps(ctx))
        j01["result_at_cutoff"] = ex.result_at_cutoff(run.root / "executor", ctx)
    results["J01"] = j01

    # N1a: arguments changed in the signed PIC proposal after approval.
    case, _ = stage(run, "n1a-pic-args", issuance, evaluation, decision_id="decision-n1a", payment_id="pay_C",
                    amount=4000, nonce="0" * 31 + "2", label="n1a")
    prop = json.loads((case / "inputs" / "pic-proposal.json").read_bytes())
    prop["action"]["args"]["amount_minor"] = 4100
    (case / "inputs" / "pic-proposal.json").write_bytes((json.dumps(prop, indent=2, sort_keys=True) + "\n").encode())
    pic_rc, pic = verify_pic(run, case)
    results["N1a"] = {"pic_exit": pic_rc, "pic_error": pic and pic.get("error_code"), "pic_result": pic and pic.get("result")}

    # N1b: arguments changed in the APS payload after the approval was signed.
    case, _ = stage(run, "n1b-aps-payload", issuance, evaluation, decision_id="decision-n1b", payment_id="pay_D",
                    amount=4000, nonce="0" * 31 + "3", label="n1b")
    payload_file = case / "inputs" / "aps-payload.json"
    body = json.loads(payload_file.read_bytes())
    body["amount_minor"] = 4100
    payload_file.write_bytes((json.dumps(body, indent=2) + "\n").encode())
    pic_rc, _ = verify_pic(run, case)
    h_rc, h_out, _ = horizon_check(run, case)
    results["N1b"] = {"pic_exit": pic_rc, "horizon_exit": h_rc, "horizon": h_out}

    if j01_record is not None and j01_handoff:
        j01_case = run.root / "cases" / "j01"
        j01_delivery = delivery_for(j01_case, j01_record, j01_handoff, issuance, evaluation_file)
        key = sg.idempotency_key(j01_record)

        # N1c: alternate arguments at dispatch for the admitted operation.
        code = refusal(lambda: executor.deliver(j01_delivery, arguments={"payment_id": "pay_A", "amount_minor": 4100,
                                                                         "currency": "EUR"}))
        results["N1c"] = {"executor_refused": code, "applies_for_key": apply_count(sim, key)}

        # N2: replayed admission of the same approval, then the duplicate handoff and a re-signed one.
        h_rc, h_out, _ = horizon_check(run, j01_case)
        replay = admission.admit(j01_case, h_out, now()) if h_rc == 0 else {"verdict": "refused", "code": "input-checks-failed"}
        n2: dict[str, Any] = {"horizon_exit": h_rc, "admission": replay["verdict"],
                              "same_admission_ref": replay.get("record") is not None and sg.ref_of(replay["record"]) == sg.ref_of(j01_record)}
        if executor_ok(results):
            dup = executor.deliver(j01_delivery)
            resigned = sign("n2-resigned", replay["record"]) if replay["verdict"] == "existing" else None
            n2["duplicate_delivery_state"] = dup["state"]
            if resigned is not None:
                again = executor.deliver(delivery_for(j01_case, replay["record"], resigned, issuance, evaluation_file))
                n2["resigned_delivery_state"] = again["state"]
                n2["resigned_valid_until"] = json.loads(resigned)["payload"]["valid_until"]
                n2["original_valid_until"] = json.loads(j01_handoff)["payload"]["valid_until"]
        n2["applies_for_key"] = apply_count(sim, key)
        results["N2"] = n2

        # N3: reissue with new matching PIC evidence resolves to the existing operation and never dispatches.
        case, aps3 = stage(run, "n3-reissue", issuance, evaluation, decision_id="decision-j01", payment_id="pay_A",
                           amount=4000, nonce="0" * 31 + "1", label="j01", intent_at=aps["intent_issued_at"])
        pic_rc, _ = verify_pic(run, case)
        h_rc, h_out, _ = horizon_check(run, case)
        res = admission.admit(case, h_out, now()) if h_rc == 0 else {"verdict": "refused", "code": "input-checks-failed"}
        n3: dict[str, Any] = {"new_receipt_id": aps3["receipt_id"], "original_receipt_id": j01_record["approval_ref"],
                              "pic_exit": pic_rc, "horizon_exit": h_rc, "admission": res["verdict"]}
        if res["verdict"] == "resolved_existing":
            env = sg.sign_resolution(res["record"], res["presented_approval_ref"], res["presented_inputs"], issuance,
                                     SIGNER_KEY_ID, SIGNER_SEED, now())
            data = jcs_dumps(env)
            (run.root / "signer" / "n3.resolution.json").write_bytes(data)
            n3["resolution_verifies"] = refusal(lambda: sg.verify_envelope(sg.RESOLUTION, env, res["record"], issuance)) is None
            n3["dispatch_authorized"] = env["payload"]["dispatch_authorized"]
            n3["executor_refused_resolution_as_handoff"] = refusal(
                lambda: executor.deliver(delivery_for(j01_case, res["record"], data, issuance, evaluation_file)))
        n3["applies_for_key"] = apply_count(sim, key)
        results["N3"] = n3

        # N3b: a new APS receipt presented with the old J01 PIC proposal.
        case_b = run.root / "cases" / "n3b-old-pic"
        shutil.copytree(case, case_b)
        shutil.copyfile(j01_case / "inputs" / "pic-proposal.json", case_b / "inputs" / "pic-proposal.json")
        (case_b / "inputs" / "pic-verification.json").unlink()
        pic_rc, _ = verify_pic(run, case_b)
        h_rc, h_out, _ = horizon_check(run, case_b)
        results["N3b"] = {"pic_exit": pic_rc, "horizon_exit": h_rc, "horizon": h_out}

    # N4: provider commits the effect, the response is lost; retry, then reconcile.
    case, _ = stage(run, "n4-lost-ack", issuance, evaluation, decision_id="decision-n4", payment_id="pay_B",
                    amount=2500, nonce="0" * 31 + "4", label="n4")
    pic_rc, _ = verify_pic(run, case)
    h_rc, h_out, _ = horizon_check(run, case)
    adm4 = admission.admit(case, h_out, now()) if h_rc == 0 else {"verdict": "refused", "code": "input-checks-failed"}
    n4: dict[str, Any] = {"pic_exit": pic_rc, "horizon_exit": h_rc, "admission": adm4["verdict"]}
    if adm4["verdict"] == "committed":
        rec4 = adm4["record"]
        handoff4 = sign("n4", rec4)
        wait_for_window(json.loads(handoff4)["payload"], rec4)
        d4 = delivery_for(case, rec4, handoff4, issuance, evaluation_file)
        key4 = sg.idempotency_key(rec4)
        try:
            n4["first_delivery_state"] = executor.deliver(d4, fault="lose_response")["state"]
            n4["retry_delivery_state"] = executor.deliver(d4)["state"]
            n4["applies_before_reconcile"] = apply_count(sim, key4)
            n4["reconcile_state"] = executor.reconcile(key4)["state"]
        except sg.SignerRefusal as exc:
            n4["executor_refused"] = exc.code
        n4["applies_for_key"] = apply_count(sim, key4)
        ctx = report_context(run.run_id, "n4")
        (run.root / "executor" / "report-context-n4.json").write_bytes(jcs_dumps(ctx))
        n4["result_at_cutoff"] = ex.result_at_cutoff(run.root / "executor", ctx)
    results["N4"] = n4

    results["simulator"] = {"effect_count": sim.effect_count(),
                            "ledger": [{k: r[k] for k in ("effect_id", "operation_id", "arguments")}
                                       for r in json.loads(sim.path.read_bytes())["ledger"]]}
    results["diagnostics"] = executor.diagnostics()
    return results


# Scoring: one row per step, the party whose code ran it, and who operated it in this run.

RUNNER = "probity runner (this run's operator)"
STEPS = [
    ("J01", "1 input: PIC native verification", "pic-standard examples/refund-sandbox (PIC)",
     lambda r: r["pic_exit"] == 0 and (r["pic_result"] or {}).get("result") == "allow", "exit 0, result allow"),
    ("J01", "1 input: APS receipt, decision, action, payload and PIC binding checks",
     "horizon-shield aps-receipt adapter over APS SDK 8.0.1 (Horizon Shield, APS)",
     lambda r: r["horizon_exit"] == 0 and r["horizon"].get("verified") is True, "verified, steps 0 to 8"),
    ("J01", "2 single-use admission: one committed record", "admission stand-in in this harness (door not built)",
     lambda r: r["admission"]["verdict"] == "committed", "committed"),
    ("J01", "3 signature and trust: handoff signed and verified", "checkout-runner sandbox_signer (Probity)",
     lambda r: r.get("handoff_verifies") is True, "verifies under the issuance snapshot"),
    ("J01", "3 signature and trust: executor pre-dispatch authorization", "checkout-runner sandbox_executor (Probity)",
     lambda r: "state" in r.get("executor", {}), "authorized"),
    ("J01", "4 execution: one dispatch to the provider", "checkout-runner sandbox_executor (Probity)",
     lambda r: r.get("applies_for_key") == 1, "1 apply request"),
    ("J01", "5 observed effect: bound effect at the report cutoff", "checkout-runner sandbox_executor and sandbox_sim (Probity)",
     lambda r: r.get("result_at_cutoff") == {"result": "observed_success", "effect_count": 1}, "observed_success, 1 effect"),
    ("N1a", "changed amount in the signed PIC proposal", "pic-standard (PIC)",
     lambda r: r["pic_exit"] == 1 and r["pic_result"] == "block", "PIC blocks"),
    ("N1b", "changed amount in the APS payload", "horizon-shield adapter (Horizon Shield, APS)",
     lambda r: r["horizon"].get("code") == "PAYLOAD_REF", "refused at step 5"),
    ("N1c", "changed amount at dispatch", "checkout-runner sandbox_executor (Probity)",
     lambda r: r["executor_refused"] == "alternate-arguments" and r["applies_for_key"] == 1, "alternate-arguments, no new apply"),
    ("N2", "replayed admission of the consumed approval", "admission stand-in, executor (Probity)",
     lambda r: r["admission"] == "existing" and r["same_admission_ref"] and r.get("duplicate_delivery_state") == "observed_success"
     and r.get("resigned_delivery_state") == "observed_success" and r["applies_for_key"] == 1,
     "existing operation, no second dispatch"),
    ("N3", "reissued approval with new matching PIC evidence", "PIC, Horizon adapter, admission stand-in, signer, executor",
     lambda r: r["admission"] == "resolved_existing" and r.get("resolution_verifies") is True and r.get("dispatch_authorized") is False
     and r.get("executor_refused_resolution_as_handoff") == "payload-fields" and r["applies_for_key"] == 1,
     "resolved_existing, signed resolution, never dispatches"),
    ("N3b", "new APS receipt with the old PIC proposal", "horizon-shield adapter (Horizon Shield)",
     lambda r: r["horizon"].get("code") == "PIC_APPROVAL_REF", "refused at step 7"),
    ("N4", "provider commits, response lost, then retry and reconcile", "checkout-runner sandbox_executor and sandbox_sim (Probity)",
     lambda r: r.get("first_delivery_state") == "unresolved" and r.get("retry_delivery_state") == "unresolved"
     and r.get("applies_before_reconcile") == 1 and r.get("reconcile_state") == "observed_success" and r["applies_for_key"] == 1,
     "unresolved until lookup, then observed_success, 1 apply"),
]


def score(results: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-step verdicts: ESTABLISHED, CONTRADICTED, or NOT_ESTABLISHED when the step never ran."""
    rows = []
    for scenario, step, code_owner, check, expected in STEPS:
        r = results.get(scenario)
        if r is None:
            verdict = "NOT_ESTABLISHED"
        else:
            try:
                verdict = "ESTABLISHED" if check(r) else "CONTRADICTED"
            except (KeyError, TypeError, AttributeError):
                verdict = "NOT_ESTABLISHED"
        rows.append({"scenario": scenario, "step": step, "code": code_owner, "operated_by": RUNNER,
                     "expected": expected, "verdict": verdict})
    sim = results["simulator"]
    rows.append({"scenario": "all", "step": "effect count across the run", "code": "sandbox_sim (Probity)",
                 "operated_by": RUNNER, "expected": "2 effects (J01, N4); 0 from every negative",
                 "verdict": "ESTABLISHED" if sim["effect_count"] == 2 else "CONTRADICTED"})
    return rows


def executor_ok(results: dict[str, Any]) -> bool:
    return results.get("J01", {}).get("executor", {}).get("state") == "observed_success"


def git_head(path: Path) -> str:
    proc = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, check=False)
    return proc.stdout.decode().strip() if proc.returncode == 0 else "unknown"


def manifest(run: Run, extra: dict[str, Any]) -> None:
    entries = []
    for path in sorted(p for p in run.root.rglob("*") if p.is_file() and p.name != "MANIFEST.json"):
        data = path.read_bytes()
        entries.append({"path": str(path.relative_to(run.root)), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    body = {"format": "refund-connected-run-manifest/0.1", "run_id": run.run_id, **extra, "files": entries}
    (run.root / "MANIFEST.json").write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--node", required=True)
    ap.add_argument("--pic-python", required=True)
    ap.add_argument("--pic-checkout", required=True, type=Path)
    ap.add_argument("--horizon-checkout", required=True, type=Path)
    ap.add_argument("--runner-checkout", required=True, type=Path,
                    help="the probity checkout whose checkout_runner package this run imports")
    args = ap.parse_args()
    if args.out.exists():
        print(f"refusing to reuse {args.out}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True)
    here = Path(__file__).resolve().parent
    tools = Tools(node=args.node, pic_python=args.pic_python,
                  pic_example=args.pic_checkout / "examples" / "refund-sandbox",
                  horizon_adapter=args.horizon_checkout / "workers/hs-ledger/nenrin/musubi-v0/adapters/aps_receipt",
                  aps_inputs=here / "aps_inputs.mjs")
    run = Run(args.out.resolve(), args.run_id, tools)
    started = now()
    results = run_scenarios(run)
    (run.root / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    rows = score(results)
    (run.root / "verdicts.json").write_text(json.dumps(rows, indent=2) + "\n")
    table = ["| Case | Step | Code that ran it | Expected | Verdict |", "|---|---|---|---|---|"]
    table += [f"| {r['scenario']} | {r['step']} | {r['code']} | {r['expected']} | {r['verdict']} |" for r in rows]
    (run.root / "VERDICTS.md").write_text("\n".join(table) + "\n")
    node_v = subprocess.run([args.node, "--version"], capture_output=True, check=False).stdout.decode().strip()
    pic_v = subprocess.run([args.pic_python, "--version"], capture_output=True, check=False).stdout.decode().strip()
    manifest(run, {"started_at": ms(started), "ended_at": ms(now()), "pins": {
        "pic-standard": git_head(args.pic_checkout), "horizon-shield": git_head(args.horizon_checkout),
        "probity harness": git_head(here), "probity checkout_runner (signer, executor, simulator)": git_head(args.runner_checkout),
        "checkout_runner imported from": str(Path(sg.__file__).resolve().parent), "node": node_v, "pic_python": pic_v,
        "runner_python": platform.python_version(), "host": platform.node()}})
    print("\n".join(table))
    return 0 if all(r["verdict"] == "ESTABLISHED" for r in rows) else 1


if __name__ == "__main__":
    os.umask(0o022)
    sys.exit(main())
