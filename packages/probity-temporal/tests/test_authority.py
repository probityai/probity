"""The authority without a Temporal server: check order, M of N, revocation, approval source, content
guard, shadow mode, crash recovery of the index, key resolvers, and the per-call cost budget."""

from __future__ import annotations

import dataclasses
import io
import json
import statistics
import time
from pathlib import Path

import pytest

from probity_records import Signer, args_sha256, sign_approval, verify_journal, verify_permit
from probity_temporal import (ApprovalPolicy, AwsSecretsManagerKey, EnvKey, FileKey, FirstOf,
                              GcpSecretManagerKey, LocalAuthority, NotAdmissible, Request, Revocations,
                              VaultKey, admit, errors, sign_revocations)
from probity_temporal.authority import EVENT, PHASE

TOOL = "refund_payment"
REQ = {"customer_id": "alice", "amount_cents": 4000, "payee_account": "acct-alice"}
DIGEST = args_sha256([REQ])


def _nest(n: int) -> list:
    v: list = [1]
    for _ in range(n):
        v = [v]
    return v


def _approval(signer: Signer, name: str, pid: str = "p" * 64, digest: str = DIGEST) -> dict:
    return sign_approval(signer, {
        "approvalId": pid, "approver": name, "event": EVENT, "expiresAt": "2999-01-01T00:00:00Z",
        "issuedAt": "2000-01-01T00:00:00Z", "keyId": signer.key_id, "payloadSha256": digest, "phase": PHASE,
        "principal": "customer:alice", "target": "wf", "tool": TOOL})


def _req(approvals, activity_id="1", **kw) -> Request:
    return Request("wf", "run", activity_id, TOOL, 1, [REQ], DIGEST, "call", "customer:alice", approvals, **kw)


def _verify(path: Path, authority: LocalAuthority) -> dict:
    return verify_journal(path, [authority.public_pem()], authority.checkpoint())


def test_every_code_is_stable_and_retry_split_is_stated() -> None:
    assert len(set(errors.CHECK_ORDER)) == len(errors.CHECK_ORDER)
    for code in errors.ALL:
        assert errors.code_for(errors.reason_for(code)) == code
        exc = errors.refusal(code, "x")
        assert exc.type == code and exc.non_retryable == (code not in errors.RETRYABLE)
    assert errors.RETRYABLE == {errors.APPROVAL_PENDING, errors.REVOCATION_STATE_STALE, errors.AUTHORITY_UNAVAILABLE}
    with pytest.raises(ValueError):
        errors.code_for("made_up")


@pytest.mark.parametrize("value,reason", [
    (b"x", "bytes_form_depends_on_converter"), ({1, 2}, "set_has_no_stable_order"),
    (2**63, "int_out_of_64_bit_range"), (float("nan"), "float_not_finite"), ({1: "a"}, "key_not_a_string"),
    (object(), "unsupported_type_object"), (_nest(40), "too_deep"),
])
def test_admission_refuses_values_that_cannot_be_signed_faithfully(value, reason) -> None:
    with pytest.raises(NotAdmissible) as exc:
        admit([value])
    assert exc.value.reason == reason
    admit([REQ, [1, 2.5, None, True, "s"], {"nested": {"ok": [1]}}])


def test_admission_refuses_pydantic_models_that_hide_a_value() -> None:
    from pydantic import BaseModel, Field, SecretStr, computed_field, field_serializer

    class Plain(BaseModel):
        amount: int

    class Excluded(BaseModel):
        amount: int
        note: str = Field(default="x", exclude=True)

    class Secret(BaseModel):
        token: SecretStr

    class Serialized(BaseModel):
        amount: int

        @field_serializer("amount")
        def _s(self, v: int) -> int:
            return v // 100

    class Computed(BaseModel):
        amount: int

        @computed_field
        @property
        def doubled(self) -> int:
            return self.amount * 2

    class Aliased(BaseModel):
        a: int = Field(serialization_alias="b")
        b: int

    admit([Plain(amount=1)])
    for model, reason in [(Excluded(amount=1), "excluded_field"), (Secret(token="t"), "secret_value_hidden"),
                          (Serialized(amount=1), "custom_serializer"), (Computed(amount=1), "computed_field"),
                          (Aliased(a=1, b=2), "serialized_names_collide")]:
        with pytest.raises(NotAdmissible) as exc:
            admit([model])
        assert exc.value.reason == reason


def test_m_of_n_needs_distinct_approvers(tmp_path) -> None:
    a, b, c = Signer.generate(), Signer.generate(), Signer.generate()
    policy = ApprovalPolicy({"human:a": a.public_pem(), "human:b": b.public_pem(), "human:c": c.public_pem()}, 2)
    authority = LocalAuthority(tmp_path, tool_policies={TOOL: policy})
    one = authority.authorize(_req([_approval(a, "human:a")], "1"))
    assert (one.ok, one.code) == (False, errors.APPROVAL_THRESHOLD_NOT_MET)
    twice = authority.authorize(_req([_approval(a, "human:a"), _approval(a, "human:a")], "2"))
    assert twice.code == errors.APPROVAL_THRESHOLD_NOT_MET
    two = authority.authorize(_req([_approval(a, "human:a"), _approval(c, "human:c")], "3"))
    assert two.ok, two.reason
    claims = verify_permit(two.permit, authority.public_pem())
    assert claims["idempotencyKey"] == claims["permitId"] == "p" * 64
    report = _verify(tmp_path, authority)
    assert report["verdict"] == "PASS", report["failures"]
    allow = [s["predicate"] for s in report["statements"] if s["predicate"]["decision"] == "allow"][0]
    assert allow["threshold"] == 2 and len(allow["approvalBindings"]) == 2


def test_revocation_refuses_keys_and_permits_rejects_rollback_and_goes_stale(tmp_path) -> None:
    approver, revoker = Signer.generate(), Signer.generate()
    clock = [0.0]
    lists = [sign_revocations(revoker, 1, [], [], "2026-11-08T00:00:00Z")]
    revs = Revocations(lambda: lists[-1], revoker.public_pem(), refresh_seconds=10, max_staleness=60,
                       monotonic=lambda: clock[0])
    authority = LocalAuthority(tmp_path, {"human:a": approver.public_pem()}, revocations=revs)
    assert authority.authorize(_req([_approval(approver, "human:a", "1" * 64)], "1")).ok
    lists.append(sign_revocations(revoker, 2, [], ["2" * 64], "t"))
    clock[0] = 11
    assert authority.authorize(_req([_approval(approver, "human:a", "2" * 64)], "2")).code == errors.PERMIT_REVOKED
    lists.append(sign_revocations(revoker, 3, [approver.key_id], [], "t"))
    clock[0] = 22
    assert authority.authorize(_req([_approval(approver, "human:a", "3" * 64)], "3")).code == errors.APPROVER_REVOKED
    lists.append(sign_revocations(revoker, 2, [], [], "t"))  # a rollback is refused; version 3 stays
    clock[0] = 33
    assert authority.authorize(_req([_approval(approver, "human:a", "4" * 64)], "4")).code == errors.APPROVER_REVOKED
    assert any(r.startswith("rollback_2_below_3") for r in revs.rejected)
    lists.append(sign_revocations(Signer.generate(), 9, [], [], "t"))  # wrong key: refused, and time passes
    clock[0] = 200
    stale = authority.authorize(_req([_approval(approver, "human:a", "5" * 64)], "5"))
    assert stale.code == errors.REVOCATION_STATE_STALE and errors.REVOCATION_STATE_STALE in errors.RETRYABLE
    assert _verify(tmp_path, authority)["verdict"] == "PASS"


def test_approval_source_pending_is_retryable_and_missing_is_final(tmp_path) -> None:
    approver = Signer.generate()
    answers: list = [None]
    authority = LocalAuthority(tmp_path, {"human:a": approver.public_pem()}, approval_source=lambda r: answers[-1])
    assert authority.authorize(_req([])).code == errors.APPROVAL_PENDING
    answers.append([])
    assert authority.authorize(_req([])).code == errors.APPROVAL_MISSING
    answers.append([_approval(approver, "human:a")])
    assert authority.authorize(_req([])).ok


def test_content_guard_blocks_and_fails_closed(tmp_path) -> None:
    approver = Signer.generate()

    def guard(tool: str, data: bytes) -> dict:
        if b"boom" in data:
            raise RuntimeError("classifier down")
        return {"action": "block" if b"AKIA" in data else "allow"}

    authority = LocalAuthority(tmp_path, {"human:a": approver.public_pem()}, content_guard=guard)
    for n, note in enumerate(["AKIAABCDEFGHIJKLMNOP", "boom"]):
        args = [{**REQ, "note": note}]
        req = dataclasses.replace(_req([_approval(approver, "human:a", str(n) * 64, args_sha256(args))], str(n)),
                                  args=args, args_sha256=args_sha256(args))
        assert authority.authorize(req).code == errors.CONTENT_BLOCKED
    statements = _verify(tmp_path, authority)["statements"]
    assert statements[1]["predicate"]["context"]["contentGuard"]["reason"] == "classifier_error"


def test_shadow_mode_records_the_refusal_and_lets_the_call_through(tmp_path) -> None:
    authority = LocalAuthority(tmp_path, {"human:a": Signer.generate().public_pem()}, mode="shadow")
    decision = authority.authorize(_req([]))
    assert (decision.ok, decision.shadow, decision.permit, decision.code) == (True, True, None, errors.APPROVAL_MISSING)
    pred = _verify(tmp_path, authority)["statements"][0]["predicate"]
    assert (pred["decision"], pred["context"]["shadow"]) == ("deny", True)


def test_index_lost_after_a_crash_is_rebuilt_from_the_journal(tmp_path) -> None:
    approver = Signer.generate()
    signed = _approval(approver, "human:a")
    first = LocalAuthority(tmp_path, {"human:a": approver.public_pem()})
    assert first.authorize(_req([signed], "1")).ok
    for name in ("authority.db", "authority.db-wal", "authority.db-shm"):
        (tmp_path / name).unlink(missing_ok=True)
    second = LocalAuthority(tmp_path, {"human:a": approver.public_pem()})
    assert second.authorize(_req([signed], "2")).code == errors.code_for("approval_replayed")


def test_key_resolvers(tmp_path, monkeypatch) -> None:
    pem = Signer.generate().private_pem()
    path = tmp_path / "k.pem"
    path.write_bytes(pem)
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        FileKey(path).resolve()
    path.chmod(0o600)
    assert FileKey(path).resolve() == pem
    monkeypatch.setenv("PROBITY_AUTHORITY_KEY_PEM", pem.decode())
    assert EnvKey().resolve() == pem

    seen = {}

    def opener(req, timeout):
        seen["url"], seen["token"] = req.full_url, req.headers["X-vault-token"]
        return io.BytesIO(json.dumps({"data": {"data": {"pem": pem.decode()}}}).encode())

    assert VaultKey("https://vault:8200", "probity/authority", token="t", opener=opener).resolve() == pem
    assert seen == {"url": "https://vault:8200/v1/secret/data/probity/authority", "token": "t"}

    class Aws:
        def get_secret_value(self, SecretId):  # noqa: N803
            return {"SecretString": json.dumps({"pem": pem.decode()})}

    assert AwsSecretsManagerKey("arn", field="pem", client=Aws()).resolve() == pem

    class Gcp:
        def access_secret_version(self, request):
            return type("R", (), {"payload": type("P", (), {"data": pem})()})()

    assert GcpSecretManagerKey("projects/p/secrets/s/versions/1", client=Gcp()).resolve() == pem
    monkeypatch.delenv("PROBITY_AUTHORITY_KEY_PEM")
    assert FirstOf([EnvKey(), FileKey(path)]).resolve() == pem
    authority = LocalAuthority(tmp_path / "a", {"human:a": Signer.generate().public_pem()}, key=FileKey(path))
    assert authority.signer.private_pem() == pem and not (tmp_path / "a" / "authority.pem").exists()


def test_per_call_cost_stays_flat_and_under_budget(tmp_path) -> None:
    """2,000 gated decisions on one host: p95 under 5 ms, and the last 500 no slower than the first 500."""
    approver = Signer.generate()
    authority = LocalAuthority(tmp_path, {"human:a": approver.public_pem()})
    calls = [_req([_approval(approver, "human:a", f"{n:064x}")], str(n)) for n in range(2000)]
    times = []
    for req in calls:
        t0 = time.perf_counter()
        assert authority.authorize(req).ok
        times.append(time.perf_counter() - t0)
    p50, p95 = statistics.median(times), statistics.quantiles(times, n=20)[18]
    early, late = statistics.median(times[:500]), statistics.median(times[-500:])
    (tmp_path.parent / "perf.json").write_text(json.dumps({"p50_ms": p50 * 1e3, "p95_ms": p95 * 1e3,
                                                          "early_p50_ms": early * 1e3, "late_p50_ms": late * 1e3}))
    print(f"PERF p50={p50 * 1e3:.3f}ms p95={p95 * 1e3:.3f}ms early={early * 1e3:.3f}ms late={late * 1e3:.3f}ms")
    assert p95 < 0.005, f"p95 {p95 * 1e3:.2f} ms"
    assert late < early * 1.5 + 0.0005, f"cost rises with the run: {early * 1e3:.2f} -> {late * 1e3:.2f} ms"
