import copy
import hashlib
import json
from pathlib import Path

import pytest

from probity_verify import CaseError, adjudicate
from probity_verify.cli import main


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def packet(tmp_path):
    prices = [{"provider": "fixture", "model": "loop", "target": "tool",
               "unit": "microUSD", "valid_from": 100, "expires_at": 400,
               "input_rate": 2, "output_rate": 3, "fixed_cost": 1}]
    budget = {"schema_version": "probity-spend-policy/v1", "budget_id": "budget-1",
              "unit": "microUSD", "limit": 100, "valid_from": 100,
              "expires_at": 500, "prices_sha256": digest(prices)}
    call = {"call_id": "call-1", "attempt": 1, "provider": "fixture", "model": "loop",
            "target": "tool", "args_sha256": "a" * 64, "input_limit": 10,
            "output_limit": 2, "price_sha256": digest(prices[0])}
    reservation = digest({"budget_id": "budget-1", "call_id": "call-1", "attempt": 1})
    trace = {"schema_version": "probity-spend-trace/v1", "budget_id": "budget-1",
             "policy_sha256": digest(budget), "events": [
                 {"sequence": 1, "kind": "reserve", "at": 101, "reservation": reservation,
                  "call": copy.deepcopy(call), "maximum": 27, "remaining_before": 100,
                  "remaining_after": 73},
                 {"sequence": 2, "kind": "dispatch", "at": 102, "reservation": reservation,
                  "call": copy.deepcopy(call), "maximum": 27, "remaining_after": 73},
                 {"sequence": 3, "kind": "settle", "at": 103, "reservation": reservation,
                  "actual": 12, "bound_exceeded": False, "remaining_after": 88},
                 {"sequence": 4, "kind": "refund", "at": 103, "reservation": reservation,
                  "amount": 15, "reason": "unused-reservation", "remaining_after": 88}]}
    case = {"schema_version": "probity-case/v1", "case_id": "spend-1", "artifacts": {}}
    policy = {"schema_version": "probity-policy/v1", "witnesses": {},
              "assessments": {"spend-1": {"claim_type": "spend_reservation/v1",
                  "budget_id": "budget-1", "budget_policy_witness": "budget",
                  "price_table_witness": "prices", "trace_witness": "trace"}}}

    def put(role, value, *, raw=None, pin=True):
        data = raw if raw is not None else (json.dumps(value, indent=2) + "\n").encode()
        (tmp_path / f"{role}.json").write_bytes(data)
        sha = hashlib.sha256(data).hexdigest()
        case["artifacts"][role] = {"path": f"{role}.json", "sha256": sha, "length": len(data)}
        if pin:
            policy["witnesses"][role] = {"artifact": role, "sha256": sha,
                                         "authority": "consumer-selected synthetic record"}

    def evaluate():
        put("budget", budget)
        put("prices", prices)
        put("trace", trace)
        return adjudicate(case, policy, tmp_path)

    evaluate()
    return tmp_path, case, policy, budget, prices, call, trace, put, evaluate


def outcome(packet):
    report = packet[8]()
    return report["decision"], report["reason"]


def test_settlement_releases_only_unused_maximum(packet):
    report = packet[8]()
    assert (report["decision"], report["reason"]) == (
        "supported", "spend_reservations_match_consumer_policy")
    assert report["scope"]["accounting"] == {
        "limit": 100, "unit": "microUSD", "held_maximum": 0,
        "recorded_settled_cost": 12, "conservative_remaining": 88,
        "pending_dispatch_receipts": 0, "execution_outcome": "not_established"}


def test_missing_dispatch_receipt_keeps_maximum_held(packet):
    packet[6]["events"] = packet[6]["events"][:2]
    report = packet[8]()
    assert report["decision"] == "supported"
    assert report["scope"]["accounting"]["held_maximum"] == 27
    assert report["scope"]["accounting"]["conservative_remaining"] == 73
    assert report["scope"]["accounting"]["pending_dispatch_receipts"] == 1
    assert report["scope"]["accounting"]["execution_outcome"] == "not_established"


def test_missing_refund_record_is_not_a_free_reservation(packet):
    packet[6]["events"].pop()
    report = packet[8]()
    assert (report["decision"], report["reason"]) == ("not_established", "settlement_refund_missing")
    assert report["scope"]["accounting"]["held_maximum"] == 27
    assert report["scope"]["accounting"]["conservative_remaining"] == 73


@pytest.mark.parametrize("change,reason", [
    (lambda t: t["events"].pop(0), "trace_sequence_mismatch"),
    (lambda t: t["events"][1]["call"].update(args_sha256="b" * 64), "dispatch_call_mismatch"),
    (lambda t: t["events"][1]["call"].update(attempt=2), "dispatch_call_mismatch"),
    (lambda t: t["events"][1]["call"].update(target="other"), "unknown_price"),
    (lambda t: t["events"][1].update(at=400), "stale_price"),
    (lambda t: t["events"][0]["call"].update(price_sha256="b" * 64), "price_version_mismatch"),
    (lambda t: t["events"][0].update(reservation="b" * 64), "reservation_id_mismatch"),
    (lambda t: t["events"][0].update(maximum=26), "reservation_maximum_mismatch"),
    (lambda t: t["events"][0].update(remaining_before=101), "reserve_balance_mismatch"),
    (lambda t: t["events"][0].update(remaining_after=74), "event_balance_mismatch"),
    (lambda t: t["events"][1].update(at=100), "trace_clock_rollback"),
    (lambda t: t["events"][2].update(actual=28, bound_exceeded=True, remaining_after=72), "settlement_bound_exceeded"),
    (lambda t: t["events"][2].update(bound_exceeded=True), "settlement_bound_flag_mismatch"),
    (lambda t: t["events"][3].update(amount=16), "refund_amount_mismatch"),
    (lambda t: t["events"][3].update(reason="cancel-before-dispatch"), "refund_after_dispatch_or_used"),
    (lambda t: t.update(budget_id="other"), "budget_scope_mismatch"),
    (lambda t: t.update(policy_sha256="b" * 64), "trace_policy_selection_mismatch"),
])
def test_trace_cannot_rebind_or_free_an_executing_call(packet, change, reason):
    change(packet[6])
    assert outcome(packet) == ("contradicted", reason)


def test_dispatch_without_reservation_even_with_contiguous_sequence(packet):
    packet[6]["events"] = [packet[6]["events"][1]]
    packet[6]["events"][0]["sequence"] = 1
    assert outcome(packet) == ("contradicted", "dispatch_without_unused_reservation")


def test_duplicate_dispatch_is_not_a_retry(packet):
    events = packet[6]["events"]
    events[2] = copy.deepcopy(events[1])
    events[2]["sequence"] = 3
    assert outcome(packet) == ("contradicted", "dispatch_without_unused_reservation")


def test_reserved_maxima_compete_for_same_budget(packet):
    events = packet[6]["events"]
    events[:] = events[:1]
    second = copy.deepcopy(events[0])
    second.update(sequence=2, remaining_before=73, remaining_after=46)
    second["call"]["call_id"] = "call-2"
    second["reservation"] = digest({"budget_id": "budget-1", "call_id": "call-2", "attempt": 1})
    events.append(second)
    packet[3]["limit"] = 40
    packet[6]["policy_sha256"] = digest(packet[3])
    events[0].update(remaining_before=40, remaining_after=13)
    second.update(remaining_before=13, remaining_after=-14)
    assert outcome(packet) == ("contradicted", "over_budget_reservation")


def test_negative_debt_still_reports_over_bound_settlement(packet):
    packet[6]["events"][2].update(actual=101, bound_exceeded=True, remaining_after=-1)
    assert outcome(packet) == ("contradicted", "settlement_bound_exceeded")


def test_cancellation_requires_no_dispatch(packet):
    events = packet[6]["events"]
    cancellation = copy.deepcopy(events[-1])
    cancellation.update(sequence=2, amount=27, reason="cancel-before-dispatch", remaining_after=100)
    events[:] = [events[0], cancellation]
    report = packet[8]()
    assert report["decision"] == "supported"
    assert report["scope"]["accounting"]["conservative_remaining"] == 100


def test_unknown_price_is_valid_as_a_refusal_not_a_dispatch(packet):
    call = copy.deepcopy(packet[5])
    call["model"] = "unpriced"
    packet[6]["events"] = [{"sequence": 1, "kind": "deny", "at": 101,
                            "call": call, "reason": "unknown-price", "remaining_after": 100}]
    assert packet[8]()["decision"] == "supported"
    packet[6]["events"][0]["reason"] = "insufficient-budget"
    assert outcome(packet) == ("contradicted", "deny_reason_mismatch")


def test_denied_malformed_call_is_retained_as_refused_input(packet):
    packet[6]["events"] = [{"sequence": 1, "kind": "deny", "at": 101,
                            "call": {"attempt": True}, "reason": "invalid-call", "remaining_after": 100}]
    assert packet[8]()["decision"] == "supported"


def test_price_table_selection_is_not_case_owned(packet):
    packet[4][0]["input_rate"] = 0
    assert outcome(packet) == ("contradicted", "price_table_selection_mismatch")


@pytest.mark.parametrize("role", ["budget", "prices", "trace"])
def test_missing_or_unpinned_artifact_is_unestablished(packet, role):
    packet[0].joinpath(role + ".json").unlink()
    report = adjudicate(packet[1], packet[2], packet[0])
    assert report["decision"] == "not_established"
    packet[7](role, {}, pin=False)
    assert adjudicate(packet[1], packet[2], packet[0])["decision"] == "not_established"


@pytest.mark.parametrize("change", [
    lambda t: t["events"][0].update(kind=[]),
    lambda t: t["events"][0].update(at=True),
    lambda t: t["events"][0]["call"].update(input_limit=1.5),
    lambda t: t["events"][2].update(actual=-1),
    lambda t: t["events"][2].update(bound_exceeded=1),
    lambda t: t["events"][0]["call"].update(output_limit=1 << 53),
    lambda t: t["events"][0].update(extra="unrecognized"),
])
def test_malformed_record_has_no_verdict(packet, change):
    change(packet[6])
    with pytest.raises(CaseError):
        packet[8]()


def test_malformed_late_record_cannot_hide_behind_earlier_contradiction(packet):
    packet[6]["events"][0]["call"]["model"] = "unpriced"
    packet[6]["events"][2]["actual"] = False
    with pytest.raises(CaseError):
        packet[8]()


def test_raw_duplicate_member_and_nonfinite_value_are_not_parsed_away(packet):
    raw = b'{"schema_version":"probity-spend-trace/v1","budget_id":"budget-1","budget_id":"other"}'
    packet[7]("trace", None, raw=raw)
    with pytest.raises(CaseError, match="duplicate JSON key"):
        adjudicate(packet[1], packet[2], packet[0])
    packet[7]("trace", None, raw=b'{"events":NaN}')
    with pytest.raises(CaseError, match="non-JSON number"):
        adjudicate(packet[1], packet[2], packet[0])


def test_cli_malformed_trace_exits_two_without_verdict(packet, capsys):
    packet[7]("trace", None, raw=b'{"events":NaN}')
    case_path = packet[0] / "case.json"
    policy_path = packet[0] / "consumer-policy.json"
    case_path.write_text(json.dumps(packet[1]))
    policy_path.write_text(json.dumps(packet[2]))
    assert main([str(case_path), "--policy", str(policy_path), "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "non-JSON number" in captured.err


def test_empty_trace_does_not_establish_a_spend_run(packet):
    packet[6]["events"] = []
    assert outcome(packet) == ("not_established", "spend_trace_empty")


def test_final_amount_equal_to_bound_requires_zero_refund_record(packet):
    packet[6]["events"][2].update(actual=27, remaining_after=73)
    packet[6]["events"][3].update(amount=0, remaining_after=73)
    assert packet[8]()["decision"] == "supported"


def test_settle_without_dispatch_cannot_unlock_funds(packet):
    events = packet[6]["events"]
    events.pop(1)
    events[1]["sequence"] = 2
    assert outcome(packet) == ("contradicted", "settlement_without_dispatch")


@pytest.mark.parametrize("name,held", [("accepted", 0), ("pending", 27), ("refused-overshoot", 0)])
def test_generated_examples_replay_through_public_api(name, held):
    root = Path(__file__).resolve().parents[1] / "examples/spend-reservation" / name
    case = json.loads((root / "case.json").read_bytes())
    policy = json.loads((root / "policy.json").read_bytes())
    report = adjudicate(case, policy, root)
    assert report["decision"] == "supported"
    assert report["scope"]["accounting"]["held_maximum"] == held
