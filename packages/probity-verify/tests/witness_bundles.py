"""EXTERNAL scope is earned only from a verified 2-of-2 witness co-signature.

The records say ``PEER``, as a launcher writes them: its receipt requires every
record to match its own ``PEER`` scope. The scope comes from the bundles alone.
The bundles come from agent-evidence-observer's own witness log, run in
process, so these tests need the witness environment (Python 3.12 or later,
``requirements-witness.txt``). The file name keeps it out of the default test
run; name it explicitly: ``pytest tests/witness_bundles.py``.
"""

from __future__ import annotations

import json

import pytest
from done_run import honest_records
from probity_observer.witness.checkpoint import signer
from probity_observer.witness.server import WitnessLog, init_witness
from probity_verify import adjudicate
from probity_verify.cli import main
from probityai import dsse
from test_done_receipt import build as build_receipt
from witness_run import HOST_OPERATOR, external, pin, written

HOST = signer(bytes(range(32)))
WITNESS = signer(bytes(range(32, 64)))
FOREIGN = signer(bytes(range(64, 96)))
HOST_KEY = HOST.public_key.hex()
WITNESS_KEY = WITNESS.public_key.hex()
PAYLOAD_TYPE = "application/json"
ORIGIN = "example.org/witness"
CLAIMS = {"protected_paths/v1": ("observation", "tree"),
          "acceptance_observed/v1": ("tree", "grade"),
          "tool_claim_match/v1": ("observation",)}


@pytest.fixture
def make_log(tmp_path):
    opened: list[WitnessLog] = []

    def make(name="witness", seed=bytes(range(32, 64)), producers=(HOST_KEY,)):
        directory = tmp_path / "logs" / name
        init_witness(directory, ORIGIN, list(producers), seed=seed)
        opened.append(WitnessLog(directory))
        return opened[-1]

    yield make
    for log in opened:
        log.close()


def witness(log, raw, role):
    """The bundle the witness returns for one host-signed record."""
    return log.add(dsse.sign(PAYLOAD_TYPE, raw, HOST), f"case-1/{role}", HOST_KEY)


def encode(bundle):
    return json.dumps(bundle).encode()


def setup(tmp_path, log, claim_type="protected_paths/v1", records=None, **options):
    """Build a case whose observed records say PEER and whose pins carry witness bundles."""
    roles = CLAIMS[claim_type]
    files, case, policy = written(tmp_path, records or honest_records(), claim_type)
    for role in roles:
        pin(tmp_path, case, policy, role, encode(witness(log, files[f"{role}.json"], role)),
            HOST_KEY, WITNESS_KEY, **options)
    return files, case, policy


def outcome(result, role):
    return result["scope"]["witnesses"][role]["witnessed"]


@pytest.mark.parametrize("claim_type", sorted(CLAIMS))
def test_valid_two_of_two_from_different_operators_is_external(tmp_path, make_log, claim_type):
    _, case, policy = setup(tmp_path, make_log(), claim_type)
    result = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (result["decision"], result["witness_scope"]) == ("supported", "EXTERNAL")
    for role in CLAIMS[claim_type]:
        verified = outcome(result, role)
        assert (verified["status"], verified["witness_scope"]) == ("verified", "EXTERNAL")
        assert verified["claim_id"] == f"case-1/{role}"


def rebundle(tmp_path, case, policy, role, change):
    """Replace one role's stored bundle with a changed copy."""
    path = tmp_path / policy["witnesses"][role]["witnessed"]["bundle"]
    bundle = json.loads(path.read_bytes())
    change(bundle)
    pin(tmp_path, case, policy, role, encode(bundle), HOST_KEY, WITNESS_KEY)


def held(tmp_path, case, policy, role="tree"):
    result = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (result["decision"], result["reason"]) == ("not_established",
                                                      "witness_scope_below_required")
    assert result["checks"][-1]["observed"] == "PEER"
    return outcome(result, role)


def test_record_with_no_witness_signature_is_peer(tmp_path, make_log):
    files, case, policy = setup(tmp_path, make_log())
    host_only = dsse.sign(PAYLOAD_TYPE, files["tree.json"], HOST).decode()
    rebundle(tmp_path, case, policy, "tree", lambda bundle: bundle.update(envelope=host_only))
    refused = held(tmp_path, case, policy)
    assert (refused["status"], refused["witness_scope"]) == ("refused", "PEER")
    assert "not signed by both" in refused["reason"]


@pytest.mark.parametrize("keys", [(WITNESS,), (HOST, FOREIGN), (WITNESS, FOREIGN)])
def test_one_of_two_pinned_signatures_is_peer(tmp_path, make_log, keys):
    files, case, policy = setup(tmp_path, make_log())
    envelope = dsse.sign(PAYLOAD_TYPE, files["tree.json"], list(keys)).decode()
    rebundle(tmp_path, case, policy, "tree", lambda bundle: bundle.update(envelope=envelope))
    refused = held(tmp_path, case, policy)
    assert refused["status"] == "refused" and "not signed by both" in refused["reason"]


def test_same_operator_for_host_and_witness_is_peer(tmp_path, make_log):
    _, case, policy = setup(tmp_path, make_log(), witness_operator=HOST_OPERATOR)
    verified = held(tmp_path, case, policy)
    assert (verified["status"], verified["witness_scope"]) == ("verified", "PEER")
    assert verified["reason"] == "one operator holds the host and witness keys"


def test_bundle_from_a_foreign_witness_key_is_peer(tmp_path, make_log):
    foreign = make_log("foreign", seed=bytes(range(64, 96)))
    _, case, policy = setup(tmp_path, foreign)
    refused = held(tmp_path, case, policy)
    assert (refused["status"], refused["witness_scope"]) == ("refused", "PEER")


def test_pin_naming_a_foreign_host_key_is_peer(tmp_path, make_log):
    _files, case, policy = setup(tmp_path, make_log())
    bundle = json.loads((tmp_path / "tree.witness.json").read_bytes())
    pin(tmp_path, case, policy, "tree", encode(bundle), FOREIGN.public_key.hex(), WITNESS_KEY)
    refused = held(tmp_path, case, policy)
    assert "different producer key" in refused["reason"]


def test_bundle_for_another_record_is_peer(tmp_path, make_log):
    log = make_log()
    files, case, policy = setup(tmp_path, log)
    other = witness(log, files["observation.json"], "tree-other")
    pin(tmp_path, case, policy, "tree", encode(other), HOST_KEY, WITNESS_KEY)
    refused = held(tmp_path, case, policy)
    assert refused["reason"] == "the witnessed payload is not the pinned record"


def test_launcher_records_that_say_peer_earn_external_from_their_bundles(tmp_path, make_log):
    files, case, policy = setup(tmp_path, make_log())
    assert {files[f"{role}.json"].count(b'"witness_scope": "PEER"')
            for role in ("observation", "tree")} == {1}
    result = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (result["decision"], result["witness_scope"]) == ("supported", "EXTERNAL")
    assert "unwitnessed_scope_claims" not in result


def test_record_claiming_external_with_a_verified_bundle_is_external(tmp_path, make_log):
    log = make_log()
    records = external(honest_records(), "observation", "tree")
    _, case, policy = setup(tmp_path, log, records=records)
    result = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (result["decision"], result["witness_scope"]) == ("supported", "EXTERNAL")
    assert "unwitnessed_scope_claims" not in result


def test_record_claiming_external_with_a_refused_bundle_is_unwitnessed(tmp_path, make_log):
    records = external(honest_records(), "tree")
    files, case, policy = setup(tmp_path, make_log(), records=records)
    host_only = dsse.sign(PAYLOAD_TYPE, files["tree.json"], HOST).decode()
    rebundle(tmp_path, case, policy, "tree", lambda bundle: bundle.update(envelope=host_only))
    result = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (result["decision"], result["reason"]) == ("not_established",
                                                      "witness_scope_unwitnessed")
    [claim] = result["checks"][-1]["unwitnessed_claims"]
    assert (claim["witness"], claim["claimed"], claim["earned"]) == ("tree", "EXTERNAL", "PEER")
    assert "not signed by both" in claim["reason"]


def test_cli_decides_external_from_the_bundles(tmp_path, make_log, capsys):
    _, case, policy = setup(tmp_path, make_log())
    (tmp_path / "case.json").write_text(json.dumps(case))
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    assert main([str(tmp_path / "case.json"), "--policy", str(tmp_path / "policy.json"),
                 "--require-witness-scope", "EXTERNAL", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert (result["decision"], result["witness_scope"]) == ("supported", "EXTERNAL")


def test_done_receipt_is_external_only_when_every_record_is_witnessed(tmp_path, make_log):
    log = make_log()

    def pins(raw, case, policy, refuse=()):
        for role in ("observation", "tree", "grade"):
            bundle = witness(log, raw[role], role)
            if role in refuse:
                bundle["envelope"] = dsse.sign(PAYLOAD_TYPE, raw[role], HOST).decode()
            pin(tmp_path, case, policy, role, encode(bundle), HOST_KEY, WITNESS_KEY)

    result = build_receipt(tmp_path, honest_records(), pins=pins, require="EXTERNAL")
    assert (result["decision"], result["witness_scope"]) == ("supported", "EXTERNAL")
    held = build_receipt(tmp_path, honest_records(),
                         pins=lambda *args: pins(*args, refuse=("grade",)), require="EXTERNAL")
    assert (held["decision"], held["reason"]) == ("not_established",
                                                  "witness_scope_below_required")


@pytest.mark.parametrize("raw, status", [(b"not json", "refused"), (b"\xff", "refused"),
                                         (b"[]", "refused")])
def test_unreadable_bundle_is_peer(tmp_path, make_log, raw, status):
    _, case, policy = setup(tmp_path, make_log())
    pin(tmp_path, case, policy, "tree", raw, HOST_KEY, WITNESS_KEY)
    assert held(tmp_path, case, policy)["status"] == status


def test_missing_bundle_file_is_peer(tmp_path, make_log):
    _, case, policy = setup(tmp_path, make_log())
    (tmp_path / "tree.witness.json").unlink()
    refused = held(tmp_path, case, policy)
    assert (refused["status"], refused["reason"]) == ("unavailable",
                                                      "a witness artifact is unavailable")


def test_unbound_record_is_peer(tmp_path, make_log):
    _, case, policy = setup(tmp_path, make_log())
    policy["witnesses"]["tree"]["sha256"] = "0" * 64
    result = adjudicate(case, policy, tmp_path)
    assert outcome(result, "tree")["reason"] == "the witnessed record is unbound"


def grown(tmp_path, make_log):
    """A log that holds an earlier record, so the bundle's checkpoint is at size 2."""
    log = make_log()
    log.add(dsse.sign(PAYLOAD_TYPE, b"{}", HOST), "earlier", HOST_KEY)
    retained = log.checkpoint(1)
    return log, retained


def test_retained_checkpoint_with_a_consistency_proof_is_external(tmp_path, make_log):
    log, retained = grown(tmp_path, make_log)
    files, case, policy = written(tmp_path, external(honest_records(), "observation", "tree"),
                                  "protected_paths/v1")
    for role in ("observation", "tree"):
        bundle = witness(log, files[f"{role}.json"], role)
        proof = log.consistency(1, log.size)
        pin(tmp_path, case, policy, role, encode(bundle), HOST_KEY, WITNESS_KEY,
            retained_checkpoint=retained, consistency=encode(proof))
    result = adjudicate(case, policy, tmp_path, require_witness_scope="EXTERNAL")
    assert (result["decision"], result["witness_scope"]) == ("supported", "EXTERNAL")


def test_retained_checkpoint_without_a_proof_is_unproven(tmp_path, make_log):
    log, retained = grown(tmp_path, make_log)
    _, case, policy = setup(tmp_path, log, retained_checkpoint=retained)
    unproven = held(tmp_path, case, policy)
    assert unproven["status"] == "equivocation"
    assert "not proven consistent" in unproven["reason"]


def test_forked_log_is_an_equivocation(tmp_path, make_log):
    fork = make_log("fork")
    fork.add(dsse.sign(PAYLOAD_TYPE, b'{"other":1}', HOST), "earlier", HOST_KEY)
    retained = fork.checkpoint(1)
    _, case, policy = setup(tmp_path, make_log(), retained_checkpoint=retained)
    fork_proof = held(tmp_path, case, policy, role="observation")
    assert (fork_proof["status"], fork_proof["witness_scope"]) == ("equivocation", "PEER")
    assert "two roots for one size" in fork_proof["reason"]


def test_unreadable_consistency_proof_is_peer(tmp_path, make_log):
    log, retained = grown(tmp_path, make_log)
    _, case, policy = setup(tmp_path, log, retained_checkpoint=retained,
                            consistency=b"not json")
    assert held(tmp_path, case, policy)["status"] == "refused"
