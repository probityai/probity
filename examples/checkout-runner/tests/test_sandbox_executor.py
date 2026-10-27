"""Executor role (contract review-2026-10-23, section 10): the J12 to J24 cases and their controls.

Each J case has its own fixture id in the test name. Every refusal test also
checks the simulator: a refusal that still produced an effect is a failure.
Bad keys and signatures come from ``forge_handoff``, a test-only helper; the
production signer refuses to make them. All keys are synthetic.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_evidence_vectors.run_vectors import ed25519_public_key, ed25519_sign, jcs_dumps
from checkout_runner import sandbox_executor as ex
from checkout_runner import sandbox_signer as sg
from checkout_runner.sandbox_sim import SandboxSimulator

SEED = hashlib.sha256(b"refund-sandbox test-only admission signer").digest()
ROTATED = hashlib.sha256(b"refund-sandbox test-only rotated signer").digest()
OTHER = hashlib.sha256(b"refund-sandbox test-only other key").digest()
ARGS = {"payment_id": "pay_A", "amount_minor": 4000, "currency": "EUR"}


def at(hms: str) -> datetime:
    """An exact instant on the fixture day; ``hms`` is HH:MM:SS.ffffff or HH:MM:SS."""
    fmt = "%H:%M:%S.%f" if "." in hms else "%H:%M:%S"
    t = datetime.strptime(hms, fmt)
    return datetime(2026, 10, 27, t.hour, t.minute, t.second, t.microsecond, tzinfo=timezone.utc)


class Clock:
    def __init__(self, t: datetime) -> None:
        self.t = t

    def __call__(self) -> datetime:
        return self.t


def key(seed: bytes = SEED, key_id: str = "k1", role: str = sg.SIGNER_ROLE, revoked_at=None) -> dict:
    return {"key_id": key_id, "issuer": "admission-door", "role": role,
            "public_key_hex": ed25519_public_key(seed).hex(), "not_before": "2026-10-01T00:00:00Z",
            "not_after": "2026-11-01T00:00:00Z", "revoked_at": revoked_at}


def snapshot(*keys: dict) -> dict:
    return {"schema": sg.TRUST, "workflow_id": "wf-refund-1", "version": 1,
            "provider_namespaces": ["sim"], "keys": list(keys) or [key(), key(ROTATED, "k2")]}


def evidence(args: dict = ARGS) -> dict[str, bytes]:
    files = {name: f"synthetic {name} bytes".encode() for name in sg.INPUT_REFS}
    pic = {"arguments": args, "args_digest": hashlib.sha256(jcs_dumps(args)).hexdigest()}
    files["pic_verification_ref"] = json.dumps(pic).encode()
    return files


def record(files: dict[str, bytes], args: dict = ARGS, operation_id: str = "op-1") -> dict:
    return {
        "schema": sg.ADMISSION, "contract_revision": sg.CONTRACT_REVISION,
        "workflow_id": "wf-refund-1", "admission_issuer": "admission-door", "provider_namespace": "sim",
        "decision_id": "dec-1", "operation_id": operation_id, "approval_ref": "rcpt-1",
        **{name: ex.file_ref(files[name]) for name in sg.INPUT_REFS},
        "tool": "refund", "arguments": dict(args), "state": "committed",
        "committed_at": "2026-10-27T11:59:00Z", "valid_until": "2026-10-27T12:30:00Z",
    }


def evaluation(issuance: dict, keys: list | None = None, accepted: list | None = None) -> bytes:
    body = {"schema": ex.EVALUATION, "contract_revision": sg.CONTRACT_REVISION, "evaluation_id": "eval-1",
            "workflow_id": "wf-refund-1", "selected_at": "2026-10-27T12:00:00Z",
            "accepted_issuance_snapshots": accepted if accepted is not None else [sg.ref_of(issuance)],
            "keys": keys if keys is not None else copy.deepcopy(issuance["keys"])}
    return jcs_dumps(body)


def delivery(rec: dict | None = None, files: dict | None = None, seed: bytes = SEED, key_id: str = "k1",
             issuance: dict | None = None, eval_file: bytes | None = None, native=()) -> ex.Delivery:
    files = files or evidence()
    rec = rec or record(files)
    issuance = issuance or snapshot()
    env = sg.sign_handoff(rec, issuance, key_id, seed, at("12:00:00.250"))
    return ex.Delivery(jcs_dumps(env), rec, issuance, eval_file or evaluation(issuance), files, tuple(native))


def forge_handoff(d: ex.Delivery, seed: bytes, key_id: str) -> ex.Delivery:
    """Test-only: sign a handoff the production signer would refuse to sign."""
    payload = dict(json.loads(d.handoff_file)["payload"], key_id=key_id)
    sig = ed25519_sign(seed, sg.signing_bytes(sg.HANDOFF, payload))
    env = {"payload": payload, "alg": "ed25519", "signature": base64.b64encode(sig).decode()}
    return ex.Delivery(jcs_dumps(env), d.record, d.issuance, d.evaluation_file, d.evidence, d.native_bounds)


@pytest.fixture
def clock() -> Clock:
    return Clock(at("12:00:05"))


@pytest.fixture
def sim(tmp_path: Path, clock: Clock) -> SandboxSimulator:
    return SandboxSimulator(tmp_path / "sim.json", clock)


@pytest.fixture
def executor(tmp_path: Path, sim: SandboxSimulator, clock: Clock) -> ex.SandboxExecutor:
    return ex.SandboxExecutor(tmp_path / "run", "run-1", sim, clock)


def refused(executor: ex.SandboxExecutor, sim: SandboxSimulator, d: ex.Delivery, code: str, **kw) -> None:
    with pytest.raises(sg.SignerRefusal) as err:
        executor.deliver(d, **kw)
    assert err.value.code == code
    assert sim.effect_count() == 0 and apply_requests(sim) == 0


def apply_requests(sim: SandboxSimulator) -> int:
    return sum(1 for r in json.loads(sim.path.read_bytes())["requests"] if r["kind"] == "apply")


def tamper_row(sim: SandboxSimulator, **fields) -> None:
    state = json.loads(sim.path.read_bytes())
    state["ledger"][0].update(fields)
    sim.path.write_text(json.dumps(state))


def context(cutoff: str) -> dict:
    return {"schema": ex.REPORT_CONTEXT, "contract_revision": sg.CONTRACT_REVISION, "run_id": "run-1",
            "scenario_id": "s1", "workflow_id": "wf-refund-1", "admission_issuer": "admission-door",
            "provider_namespace": "sim", "report_cutoff": cutoff}


def outcomes(executor: ex.SandboxExecutor) -> list[str]:
    return [o["status"] for o in ex.load_stream(executor.store, ex.OUTCOME)]


# Positive control for every refusal below.

def test_control_valid_delivery_dispatches_once_and_is_observed(executor, sim) -> None:
    op = executor.deliver(delivery())
    assert op["state"] == "observed_success" and sim.effect_count() == 1
    attempt = ex.load_stream(executor.store, ex.ATTEMPT)[0]
    assert attempt["arguments_digest"] == "sha256:" + hashlib.sha256(jcs_dumps(ARGS)).hexdigest()
    effect = ex.load_stream(executor.store, ex.EFFECT)[0]
    assert effect["attempt_id"] == attempt["attempt_id"] and effect["attempt_ref"] == sg.ref_of(attempt)
    assert ex.result_at_cutoff(executor.store, context("2026-10-27T12:00:05.000Z")) == {
        "result": "observed_success", "effect_count": 1}


# J12: changed record, forged, unknown or wrong-role handoff key.

def test_j12a_changed_record_is_not_dispatched(executor, sim) -> None:
    d = delivery()
    changed = dict(d.record, arguments=dict(ARGS, amount_minor=4001))
    refused(executor, sim, ex.Delivery(d.handoff_file, changed, d.issuance, d.evaluation_file, d.evidence),
            "admission-ref")


def test_j12b_forged_signature_is_not_dispatched(executor, sim) -> None:
    d = delivery()
    env = json.loads(d.handoff_file)
    sig = bytearray(base64.b64decode(env["signature"]))
    sig[0] ^= 1
    env["signature"] = base64.b64encode(bytes(sig)).decode()
    refused(executor, sim, ex.Delivery(jcs_dumps(env), d.record, d.issuance, d.evaluation_file, d.evidence),
            "signature-invalid")


def test_j12c_unknown_key_is_not_dispatched(executor, sim) -> None:
    refused(executor, sim, forge_handoff(delivery(), OTHER, "k9"), "key-unknown")


def test_j12d_wrong_role_key_is_not_dispatched(executor, sim) -> None:
    issuance = snapshot(key(), key(OTHER, "k3", role="pic-merchant"))
    refused(executor, sim, forge_handoff(delivery(issuance=issuance), OTHER, "k3"), "key-role")


def test_j12e_key_rebound_in_evaluation_trust_is_refused(executor, sim) -> None:
    issuance = snapshot()
    rebound = [dict(issuance["keys"][0], public_key_hex=ed25519_public_key(OTHER).hex()), issuance["keys"][1]]
    refused(executor, sim, delivery(issuance=issuance, eval_file=evaluation(issuance, rebound)), "key-rebound")


# J13: valid old signature, signer revoked before dispatch.

def test_j13_revoked_before_dispatch_keeps_history_and_forbids_new_dispatch(executor, sim) -> None:
    issuance = snapshot()
    keys = copy.deepcopy(issuance["keys"])
    keys[0]["revoked_at"] = "2026-10-27T12:00:03Z"
    d = delivery(issuance=issuance, eval_file=evaluation(issuance, keys))
    refused(executor, sim, d, "key-revoked-at-dispatch")
    history = ex.evaluate_history(d, at("12:00:02.500"), at("12:00:05"))
    assert history == {"integrity": "ESTABLISHED", "recorded_attempt": "ESTABLISHED",
                       "new_dispatch": "forbidden:key-revoked-at-dispatch"}
    assert ex.evaluate_history(d, None, at("12:00:05"))["recorded_attempt"] == "NOT_ESTABLISHED"


# J15: later trust differs without an applicable revocation.

def test_j15_later_trust_without_revocation_still_dispatches(executor, sim) -> None:
    issuance = snapshot()
    later = snapshot(*issuance["keys"], key(OTHER, "k4"))
    keys = copy.deepcopy(later["keys"])
    d = delivery(issuance=issuance, eval_file=evaluation(issuance, keys, [sg.ref_of(issuance), sg.ref_of(later)]))
    assert executor.deliver(d)["state"] == "observed_success"


def test_j15_control_unaccepted_issuance_snapshot_is_refused(executor, sim) -> None:
    issuance = snapshot()
    other = snapshot(*issuance["keys"], key(OTHER, "k4"))
    refused(executor, sim, delivery(issuance=issuance, eval_file=evaluation(issuance, accepted=[sg.ref_of(other)])),
            "issuance-snapshot-not-accepted")


# J16: alternate dispatch arguments or conflicting operation reuse.

@pytest.mark.parametrize("args,code", [
    (dict(ARGS, amount_minor=4001), "alternate-arguments"),
    (dict(ARGS, amount_minor="4000"), "alternate-arguments"),
    (dict(ARGS, amount_minor=True), "alternate-arguments"),
    (dict(ARGS, amount_minor=4000.0), "wrapper-float"),
    ({"payment_id": "pay_A", "amount_minor": 4000}, "alternate-arguments"),
])
def test_j16a_alternate_arguments_are_refused(executor, sim, args, code) -> None:
    refused(executor, sim, delivery(), code, arguments=args)


def test_j16a_control_key_order_only_arguments_dispatch(executor, sim) -> None:
    reordered = {"currency": "EUR", "amount_minor": 4000, "payment_id": "pay_A"}
    assert executor.deliver(delivery(), arguments=reordered)["state"] == "observed_success"


def test_j16b_conflicting_operation_reuse_adds_no_effect(executor, sim) -> None:
    executor.deliver(delivery())
    files = evidence(dict(ARGS, amount_minor=5000))
    with pytest.raises(sg.SignerRefusal) as err:
        executor.deliver(delivery(record(files, dict(ARGS, amount_minor=5000)), files))
    assert err.value.code == "operation-conflict" and sim.effect_count() == 1 and apply_requests(sim) == 1


# J17: duplicate delivery.

def test_j17_duplicate_delivery_recovers_the_same_operation(executor, sim) -> None:
    d = delivery()
    first = executor.deliver(d)
    second = executor.deliver(d)
    rotated = executor.deliver(delivery(seed=ROTATED, key_id="k2"))
    scope = {k: d.record[k] for k in ex.OPERATION_SCOPE}
    assert first["idempotency_key"] == second["idempotency_key"] == rotated["idempotency_key"] == sg.idempotency_key(scope)
    assert sim.effect_count() == 1 and apply_requests(sim) == 1
    assert [a["kind"] for a in ex.load_stream(executor.store, ex.ATTEMPT)] == ["dispatch"]


# J18: provider commits, response lost.

def test_j18_lost_response_is_unresolved_until_lookup_binds_the_same_effect(executor, sim) -> None:
    op = executor.deliver(delivery(), fault="lose_response")
    assert op["state"] == "unresolved" and outcomes(executor) == ["unresolved"] and sim.effect_count() == 1
    executor.reconcile(op["idempotency_key"])
    attempts = ex.load_stream(executor.store, ex.ATTEMPT)
    assert [a["kind"] for a in attempts] == ["dispatch", "reconcile_lookup"]
    assert attempts[0]["attempt_id"] != attempts[1]["attempt_id"]
    effect = ex.load_stream(executor.store, ex.EFFECT)[0]
    assert effect["attempt_id"] == attempts[0]["attempt_id"]  # the effect keeps its original dispatch
    obs = ex.load_stream(executor.store, ex.OBSERVATION)[-1]
    assert obs["attempt_id"] == attempts[1]["attempt_id"] and obs["effect_refs"] == [sg.ref_of(effect)]
    raw = (executor.store / "raw" / f"{obs['observation_id']}.json").read_bytes()
    assert obs["source_file_ref"] == ex.file_ref(raw)
    assert outcomes(executor) == ["unresolved", "observed_success"] and sim.effect_count() == 1


# J19: pre-dispatch failure.

def test_j19_pre_dispatch_failure_shows_no_dispatch_and_no_effect(executor, sim) -> None:
    op = executor.deliver(delivery(), fail_before_send=True)
    executor.reconcile(op["idempotency_key"])
    obs = ex.load_stream(executor.store, ex.OBSERVATION)[-1]
    assert obs["observation_kind"] == "no_effect_pre_dispatch" and obs["effect_refs"] == []
    assert outcomes(executor) == ["unresolved", "observed_failure"]
    assert sim.effect_count() == 0 and apply_requests(sim) == 0


def test_j19_control_received_request_is_not_no_effect_pre_dispatch(executor, sim) -> None:
    op = executor.deliver(delivery(), fault="receive_then_fail")
    executor.reconcile(op["idempotency_key"])
    assert ex.load_stream(executor.store, ex.OBSERVATION)[-1]["observation_kind"] == "unresolved"
    assert outcomes(executor) == ["unresolved", "unresolved"] and apply_requests(sim) == 1


# J20: expiry while unresolved.

def test_j20_expiry_allows_lookup_only(executor, sim, clock) -> None:
    d = delivery()
    op = executor.deliver(d, fault="receive_then_fail")
    clock.t = at("12:10:01")  # handoff valid_until; equality is outside the window
    with pytest.raises(sg.SignerRefusal) as err:
        executor.deliver(d)
    assert err.value.code == "dispatch-after-window" and apply_requests(sim) == 1
    executor.reconcile(op["idempotency_key"])
    assert outcomes(executor)[-1] == "unresolved" and sim.effect_count() == 0 and apply_requests(sim) == 1


def test_j20_lookup_after_expiry_can_confirm_an_earlier_effect(executor, sim, clock) -> None:
    op = executor.deliver(delivery(), fault="lose_response")
    clock.t = at("12:20:00")
    executor.reconcile(op["idempotency_key"])
    assert outcomes(executor) == ["unresolved", "observed_success"] and apply_requests(sim) == 1


# J21: observation or recording after the report cutoff.

def test_j21a_observation_at_900ms_cannot_support_a_500ms_cutoff(executor, sim, clock) -> None:
    clock.t = at("12:00:05.900")
    executor.deliver(delivery())
    obs = ex.load_stream(executor.store, ex.OBSERVATION)[0]
    assert obs["observed_at"] == "2026-10-27T12:00:06Z"
    assert ex.result_at_cutoff(executor.store, context("2026-10-27T12:00:05.500Z")) == {
        "result": "NOT_ESTABLISHED", "effect_count": 0}
    assert ex.result_at_cutoff(executor.store, context("2026-10-27T12:00:06.000Z"))["result"] == "observed_success"


def test_j21b_earlier_observation_recorded_after_cutoff_does_not_count(tmp_path, clock) -> None:
    class SlowRecording(SandboxSimulator):
        def query(self, key):
            out = super().query(key)
            clock.t = at("12:00:07")
            return out

    sim = SlowRecording(tmp_path / "sim.json", clock)
    executor = ex.SandboxExecutor(tmp_path / "run", "run-1", sim, clock)
    executor.deliver(delivery())
    obs = ex.load_stream(executor.store, ex.OBSERVATION)[0]
    assert (obs["observed_at"], obs["recorded_at"]) == ("2026-10-27T12:00:05Z", "2026-10-27T12:00:07Z")
    assert ex.result_at_cutoff(executor.store, context("2026-10-27T12:00:06.000Z")) == {
        "result": "NOT_ESTABLISHED", "effect_count": 0}
    assert ex.result_at_cutoff(executor.store, context("2026-10-27T12:00:07.000Z"))["result"] == "observed_success"


# J22 and J23: same argument digest, wrong effect.operation_id; unchanged and key-order controls.

def test_j22_wrong_effect_operation_id_is_a_binding_contradiction(executor, sim) -> None:
    op = executor.deliver(delivery(), fault="lose_response")
    tamper_row(sim, operation_id="op-other")
    executor.reconcile(op["idempotency_key"])
    effect = ex.load_stream(executor.store, ex.EFFECT)[0]
    assert effect["arguments_digest"] == ex.arguments_digest(ARGS)  # same digest, wrong operation
    assert "observed_success" not in outcomes(executor) and executor.operations()[op["idempotency_key"]]["state"] == "unresolved"
    assert executor.diagnostics() == [{"code": ex.BINDING_MISMATCH, "attempt_id": "op-1-a2",
                                       "effect_id": "eff-1", "problems": ["effect-operation_id"]}]
    assert ex.result_at_cutoff(executor.store, context("2026-10-27T12:00:05.000Z"))["result"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("fields", [{}, {"arguments": {"currency": "EUR", "amount_minor": 4000, "payment_id": "pay_A"}}],
                         ids=["j23a-unchanged", "j23b-key-order-only"])
def test_j23_controls_reconcile_successfully(executor, sim, fields) -> None:
    op = executor.deliver(delivery(), fault="lose_response")
    if fields:
        tamper_row(sim, **fields)
    executor.reconcile(op["idempotency_key"])
    assert outcomes(executor) == ["unresolved", "observed_success"] and executor.diagnostics() == []


def test_j22_control_changed_arguments_or_attempt_also_refuse_promotion(executor, sim) -> None:
    op = executor.deliver(delivery(), fault="lose_response")
    tamper_row(sim, arguments=dict(ARGS, amount_minor=4001), attempt_id="op-1-a9")
    executor.reconcile(op["idempotency_key"])
    problems = executor.diagnostics()[0]["problems"]
    assert problems == ["effect-arguments", "effect-arguments-digest", "effect-attempt"]


# J24: precision and exact upper-bound cases.

NATIVE = (("2026-10-27T12:00:02.250Z", "2026-10-27T12:00:09.900Z"),)


@pytest.mark.parametrize("now,ok,code", [
    ("12:00:02.900", False, "dispatch-before-window"),  # .250 lower bound rounds up to :03
    ("12:00:03", True, None),
    ("12:00:08.999", True, None),
    ("12:00:09", False, "dispatch-after-window"),  # .900 upper bound rounds down to :09; equality refused
    ("12:00:09.500", False, "dispatch-after-window"),  # native would accept; the wrapper bound does not
])
def test_j24a_inward_conversion_of_native_bounds(executor, sim, clock, now, ok, code) -> None:
    clock.t = at(now)
    d = delivery(native=NATIVE)
    if ok:
        assert executor.deliver(d)["state"] == "observed_success"
    else:
        refused(executor, sim, d, code)


def test_j24b_empty_converted_window_is_refused(executor, sim) -> None:
    refused(executor, sim, delivery(native=(("2026-10-27T12:00:05.250Z", "2026-10-27T12:00:05.900Z"),)),
            "dispatch-window-empty")


def test_j24c_no_extension_past_the_handoff_and_exact_upper_bound(executor, sim, clock) -> None:
    clock.t = at("12:10:00.999")
    assert executor.deliver(delivery())["state"] == "observed_success"
    clock.t = at("12:10:01")
    refused_sim = SandboxSimulator(executor.store.parent / "sim2.json", clock)
    fresh = ex.SandboxExecutor(executor.store.parent / "run2", "run-1", refused_sim, clock)
    refused(fresh, refused_sim, delivery(), "dispatch-after-window")


def test_j24d_section8_example_recorded_attempt_at_9500ms_within_u(executor, sim) -> None:
    d = delivery(native=(("2026-10-27T12:00:00.000Z", "2026-10-27T12:00:10.000Z"),))
    history = ex.evaluate_history(d, at("12:00:09.500"), at("12:00:11"))
    assert history == {"integrity": "ESTABLISHED", "recorded_attempt": "ESTABLISHED",
                       "new_dispatch": "forbidden:dispatch-after-window"}


# Strict wrapper parsing and evidence binding.

def test_wrapper_files_are_parsed_strictly(executor, sim) -> None:
    d = delivery()
    dup = d.handoff_file[:-1] + b',"alg":"ed25519"}'
    refused(executor, sim, ex.Delivery(dup, d.record, d.issuance, d.evaluation_file, d.evidence),
            "wrapper-duplicate-field")
    floaty = d.evaluation_file.replace(b'"keys":', b'"x":1.5,"keys":')
    refused(executor, sim, ex.Delivery(d.handoff_file, d.record, d.issuance, floaty, d.evidence), "wrapper-float")
    nonascii = d.evaluation_file.replace(b'"eval-1"', b'"eval-\\u00e9"')
    refused(executor, sim, ex.Delivery(d.handoff_file, d.record, d.issuance, nonascii, d.evidence), "wrapper-non-ascii")
    big = d.evaluation_file.replace(b'"keys":', b'"x":9007199254740992,"keys":')
    refused(executor, sim, ex.Delivery(d.handoff_file, d.record, d.issuance, big, d.evidence), "wrapper-unsafe-integer")


def test_evidence_files_must_hash_to_the_record(executor, sim) -> None:
    d = delivery()
    files = dict(d.evidence, aps_payload_file_ref=b"swapped")
    refused(executor, sim, ex.Delivery(d.handoff_file, d.record, d.issuance, d.evaluation_file, files),
            "evidence-aps_payload_file_ref")


def test_pic_args_digest_must_match_the_stored_arguments(executor, sim) -> None:
    files = evidence()
    pic = {"arguments": ARGS, "args_digest": "0" * 64}
    files["pic_verification_ref"] = json.dumps(pic).encode()
    refused(executor, sim, delivery(record(files), files), "pic-args-digest")


def test_streams_are_closed_records(executor, sim) -> None:
    executor.deliver(delivery(), fault="lose_response")
    executor.reconcile(next(iter(executor.operations())))
    for schema in ex.STREAM_FILES:
        for rec in ex.load_stream(executor.store, schema):
            assert set(rec) == ex.STREAM_FIELDS[schema]
    path = executor.store / ex.STREAM_FILES[ex.OUTCOME]
    path.write_bytes(path.read_bytes().replace(b'"status"', b'"extra":1,"status"', 1))
    with pytest.raises(sg.SignerRefusal):
        ex.load_stream(executor.store, ex.OUTCOME)
