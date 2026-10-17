"""A record cannot declare its own EXTERNAL witness scope.

These tests need no witness verifier: they cover the consumer pin's shape, a
record that claims EXTERNAL with no bundle, and the outcome when the verifier
is not installed. The co-signature checks themselves are in
witness_bundles.py, which runs in the witness environment.
"""

import pytest
from done_run import decide, honest_records
from probity_verify import CaseError, adjudicate
from probity_verify.adapters import witnessed
from probity_verify.cli import main
from test_done_receipt import build as build_receipt
from witness_run import external, pin, written

HOST_KEY = "aa" * 32
WITNESS_KEY = "bb" * 32
CLAIM = "protected_paths/v1"


def test_self_declared_external_scope_is_refused(tmp_path):
    """The exploit: a host writes EXTERNAL into its records and the pin agrees."""
    records = external(honest_records(), "observation", "tree")
    with pytest.raises(CaseError, match="must name the witness bundle"):
        decide(tmp_path, records, CLAIM, require_witness_scope="EXTERNAL")


def peer_pinned(tmp_path, records, claim=CLAIM):
    """A case whose pins all say PEER, whatever the records claim."""
    _files, case, policy = written(tmp_path, records, claim)
    for witness in policy["witnesses"].values():
        if "witness_scope" in witness:
            witness["witness_scope"] = "PEER"
    return case, policy


@pytest.mark.parametrize("claim", ["protected_paths/v1", "acceptance_observed/v1",
                                   "tool_claim_match/v1"])
def test_record_claiming_external_under_a_peer_pin_is_unwitnessed(tmp_path, claim):
    """The record says EXTERNAL; nothing proves it, so it earns PEER and says why."""
    records = external(honest_records(), "observation", "tree", "grade")
    case, policy = peer_pinned(tmp_path, records, claim)
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["witness_scope"]) == ("supported", "PEER")
    claims = result["unwitnessed_scope_claims"]
    assert claims and all(item["reason"] == "no witness bundle is pinned for this record"
                          for item in claims)
    held = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (held["decision"], held["reason"]) == ("not_established",
                                                  "witness_scope_unwitnessed")
    assert held["checks"][-1]["unwitnessed_claims"] == claims


def test_record_claiming_peer_has_no_unwitnessed_claim(tmp_path):
    case, policy = peer_pinned(tmp_path, honest_records())
    held = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert held["reason"] == "witness_scope_below_required"
    assert "unwitnessed_claims" not in held["checks"][-1]


def test_contradiction_with_an_unwitnessed_claim_stands(tmp_path):
    records = external(honest_records(), "tree", "grade")
    records["grade"]["results"][0]["exit"] = 1
    case, policy = peer_pinned(tmp_path, records, "acceptance_observed/v1")
    result = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (result["decision"], result["witness_scope"]) == ("contradicted", "PEER")
    assert all(check["id"] != "witness_scope" for check in result["checks"])


def test_cli_holds_an_unwitnessed_external_claim(tmp_path, capsys):
    import json
    case, policy = peer_pinned(tmp_path, external(honest_records(), "observation", "tree"))
    (tmp_path / "case.json").write_text(json.dumps(case))
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    assert main([str(tmp_path / "case.json"), "--policy", str(tmp_path / "policy.json"),
                 "--require-witness-scope", "EXTERNAL", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert (result["decision"], result["reason"]) == ("not_established",
                                                      "witness_scope_unwitnessed")


def test_done_receipt_carries_unwitnessed_claims_from_its_checks(tmp_path):
    def peer(raw, case, policy):
        policy["witnesses"]["grade"]["witness_scope"] = "PEER"

    records = external(honest_records(), "grade")
    with pytest.raises(CaseError, match="must name the witness bundle"):
        build_receipt(tmp_path, records)
    result = build_receipt(tmp_path, records, pins=peer, require="EXTERNAL")
    assert (result["decision"], result["reason"]) == ("not_established",
                                                      "witness_scope_unwitnessed")
    [claim] = result["unwitnessed_scope_claims"]
    assert (claim["witness"], claim["reason"]) == (
        "grade", "no witness bundle is pinned for this record")


def test_peer_pin_cannot_name_a_witness(tmp_path):
    _files, case, policy = written(tmp_path, honest_records(), CLAIM)
    pin(tmp_path, case, policy, "tree", b"{}", HOST_KEY, WITNESS_KEY, scope="PEER")
    with pytest.raises(CaseError, match="only an EXTERNAL scope pin names a witness"):
        adjudicate(case, policy, tmp_path)


def configured(tmp_path, change):
    _files, case, policy = written(tmp_path, honest_records(), CLAIM)
    for role in ("observation", "tree"):
        pin(tmp_path, case, policy, role, b"{}", HOST_KEY, WITNESS_KEY)
    change(policy["witnesses"]["tree"]["witnessed"])
    return case, policy


@pytest.mark.parametrize("change, message", [
    (lambda c: c["host"].update(public_key="AA" * 32), "lowercase hex Ed25519"),
    (lambda c: c["witness"].update(public_key=7), "lowercase hex Ed25519"),
    (lambda c: c["witness"].update(operator=" "), "nonempty operator name"),
    (lambda c: c["witness"].update(public_key=HOST_KEY), "name one key"),
    (lambda c: c.update(consistency="tree.json"), "needs a retained_checkpoint"),
    (lambda c: c.update(bundle="missing"), "unknown artifact: missing"),
    (lambda c: c.update(bundle=""), "expected nonempty string"),
    (lambda c: c.update(extra="x"), "expected fields"),
    (lambda c: c["host"].pop("operator"), "expected fields"),
])
def test_malformed_witness_pin_refuses(tmp_path, change, message):
    case, policy = configured(tmp_path, change)
    with pytest.raises(CaseError, match=message):
        adjudicate(case, policy, tmp_path)


def test_without_the_verifier_no_record_reaches_external(tmp_path, monkeypatch):
    monkeypatch.setattr(witnessed, "observer_scope", None)
    case, policy = configured(tmp_path, lambda config: None)
    result = adjudicate(case, policy, tmp_path)
    assert (result["decision"], result["witness_scope"]) == ("supported", "PEER")
    outcome = result["scope"]["witnesses"]["tree"]["witnessed"]
    assert (outcome["status"], outcome["witness_scope"]) == ("unavailable", "PEER")
    assert "agent-evidence-observer[witness]" in outcome["reason"]
    held = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (held["decision"], held["reason"]) == ("not_established",
                                                  "witness_scope_below_required")


def test_scope_of_needs_records():
    from probity_verify.adapters.done_records import scope_of
    earned = {"witness_scope": "EXTERNAL", "witnessed": {"witness_scope": "EXTERNAL"}}
    assert scope_of() == "PEER"
    assert scope_of((None, earned)) == "PEER"
    assert scope_of(({"witness_scope": "PEER"}, earned)) == "EXTERNAL"
    assert scope_of(({"witness_scope": "EXTERNAL"}, {"witness_scope": "EXTERNAL"})) == "PEER"
