"""An observed effect resolves a committed reservation only when it is that operation's own row."""
from synth import attempt, case_dir, decision, permit
from checkout_runner.report import C, E, derive

T = 1_791_900_000_000
P = permit()
RID = P["receipt"]["receipt_id"]
OP = {"receipt_id": RID, "idempotency_key": "k1", "request_digest": P["receipt"]["action_ref"],
      "reservation_id": "res_1", "valid_until": "2026-10-13T14:15:00.000Z", "state": "response_ok", "provider_ref": "p1"}


def _verdict(tmp_path, observed):
    ev = {"reservation_id": "res_1", "from_state": "reserved", "to_state": "committed", "cause": "t",
          "evidence": '{"platform_ref":"p1"}', "at": "2026-10-13T14:00:02.000Z"}
    effect = {"idempotency_key": "k1", "provider_ref": "p1", "kind": "effect", "request_digest": "x", "at_ms": T + 1000}
    d = case_dir(tmp_path, dict(decisions=[decision(P)], attempts=[attempt(1, P, T + 1000)], operations=[OP],
                                effects=[effect], gate_events=[ev],
                                observations=[{"at_ms": T + 3000, "receipt_id": RID, "row": observed}]),
                 expected_decisions=[["permit", "permitted"]], expected_attempts=["response_ok"])
    return derive(d)["outcome.resolved_at_cutoff"]["verdict"]


def test_own_effect_row_resolves(tmp_path):
    own = {"idempotency_key": "k1", "provider_ref": "p1", "kind": "effect", "request_digest": "x", "at_ms": T + 1000}
    assert _verdict(tmp_path, own) == E


def test_same_arguments_under_another_occurrence_contradicts(tmp_path):
    other = {"idempotency_key": "k9", "provider_ref": "p9", "kind": "effect", "request_digest": "x", "at_ms": T + 1000}
    assert _verdict(tmp_path, other) == C


def test_lost_response_own_key_resolves_without_provider_ref(tmp_path):
    """After a lost response the operation has no provider reference; its own row by key still resolves it."""
    global OP
    saved, OP = OP, {**OP, "provider_ref": None}
    try:
        own = {"idempotency_key": "k1", "provider_ref": "p1", "kind": "effect", "request_digest": "x", "at_ms": T + 1000}
        assert _verdict(tmp_path, own) == E
        other = {"idempotency_key": "k9", "provider_ref": "p9", "kind": "effect", "request_digest": "x", "at_ms": T + 1000}
        assert _verdict(tmp_path, other) == C
    finally:
        OP = saved
