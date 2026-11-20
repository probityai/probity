"""The OCSF decision-record reader against the format's published samples and the ways a stream breaks.

The published samples (``tests/data/ocsf-decision/``, pinned by SHA-256 in ``SOURCE.json``) carry two
chained records signed with the format's demo key and nine unchained decision records with stream
stamps. Every break below is built from those records: a duplicate member that rides a valid seal,
a swapped or unknown key id, a record re-signed under a retired key, a dropped tail, a deleted
record, a fork, a substituted uid, a stream gap, a ruling that reads two ways, an integer a double
cannot hold and an unsigned chain rewritten end to end.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from agent_evidence_verify import corpus
from agent_evidence_verify import ocsf_decision as o

DATA = Path(__file__).parent / "data" / "ocsf-decision"
AUTHORITY = "org-f3576cf6"
DEMO = ec.derive_private_key(int.from_bytes(b"\x42" * 32, "big"), ec.SECP256R1())
TEST = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"ocsf-decision test key 1").digest(), "big"),
                             ec.SECP256R1())
RETIRED = ec.derive_private_key(int.from_bytes(hashlib.sha256(b"ocsf-decision test key 0").digest(), "big"),
                                ec.SECP256R1())


def published(name: str) -> list[dict]:
    """The records of one published sample file, in order, after checking the file's pin."""
    pins = json.loads((DATA / "SOURCE.json").read_text(encoding="utf-8"))["files"]
    raw = (DATA / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == pins[name]["sha256"]
    out = []
    for block in re.findall(r"```(?:jsonc|text)\n(.*?)```", raw.decode("utf-8"), re.S):
        for part in re.split(r"^// =====.*$", block, flags=re.M):
            body = "\n".join(line for line in part.splitlines() if not line.startswith("//")).strip()
            if body.startswith("{"):
                out.append(json.loads(body))
    return out


def text(records: list[dict]) -> bytes:
    return "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in records).encode()


def policy(*entries: tuple) -> dict:
    return {"keys": [o.jwk(k.public_key(), kid, auth, **window) for k, kid, auth, window in entries]}


DEMO_POLICY = policy((DEMO, "demo-key-2026-07", AUTHORITY, {}))
TEST_POLICY = policy((TEST, "test-key-1", AUTHORITY, {"not_before": "2026-01-01T00:00:00Z"}),
                     (RETIRED, "test-key-0", AUTHORITY, {"not_before": "2025-01-01T00:00:00Z",
                                                         "not_after": "2025-12-31T23:59:59Z"}))
FP = {"algorithm": "SHA-256", "algorithm_id": 3, "encoding": "Hex", "encoding_id": 1,
      "serialization": "JCS", "serialization_id": 2}
SIG = [{"algorithm": "ECDSA", "algorithm_id": 3, "serialization": "DSSE", "serialization_id": 5}]


def seal(event: dict, key, kid: str | None) -> dict:
    """Fingerprint and, with a key, sign one record by the published rule."""
    att = event["attestation_list"][0]
    for member in ("fingerprint", "signatures"):
        att.pop(member, None)
    un = event.setdefault("unmapped", {})
    un.pop("signature_b64", None)
    un.pop("signature_key_id", None)
    data = o.signing_input(event)
    att["fingerprint"] = {**FP, "value": hashlib.sha256(data).hexdigest()}
    if key is not None:
        att["signatures"] = copy.deepcopy(SIG)
        sig = key.sign(o.pae(data), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        un["signature_b64"] = base64.b64encode(sig).decode("ascii")
        if kid is not None:
            un["signature_key_id"] = kid
    if not un:
        del event["unmapped"]
    return event


def emit(bodies: list[dict], key=TEST, kid: str | None = "test-key-1", chain_uid: str = "gw-1-test") -> list[dict]:
    """A chain over ``bodies``, as the format's text describes one."""
    out: list[dict] = []
    for i, body in enumerate(bodies):
        event = copy.deepcopy(body)
        event.pop("attestation_list", None)
        event.setdefault("metadata", {})["uid"] = f"{chain_uid}-{i:06d}"
        att = {"uid": f"{chain_uid}-att-{i:06d}", "chain_uid": chain_uid, "authority_uid": AUTHORITY}
        if out:
            att["prev_event"] = {"uid": out[-1]["metadata"]["uid"], "type_uid": out[-1]["type_uid"],
                                 "fingerprint": copy.deepcopy(out[-1]["attestation_list"][0]["fingerprint"])}
        event["attestation_list"] = [att]
        out.append(seal(event, key, kid))
    return out


def head(record: dict) -> dict:
    return {"chain_uid": record["attestation_list"][0]["chain_uid"], "uid": record["metadata"]["uid"],
            "fingerprint": record["attestation_list"][0]["fingerprint"]["value"]}


DECISIONS = published("SAMPLE-OUTPUT-DECISIONS.md") + published("SAMPLE-OUTPUT-PROVENANCE.md")
CHAIN = emit(DECISIONS)


def judge(records, *, trust=TEST_POLICY, heads=None, profile="baseline", raw: bytes | None = None):
    report = o.read(raw if raw is not None else text(records), trust_policy=trust,
                    relying_party={"heads": heads} if heads is not None else None)
    return report, o.verdict(report, profile)


# --- the published samples -------------------------------------------------------------------------

def test_published_signed_pair_verifies_with_the_demo_key():
    pair = published("SAMPLE-OUTPUT.md")
    report, decision = judge(pair, trust=DEMO_POLICY)
    for name in o.RECORD_DIMENSIONS + ("chain_links", "chain_gaps", "chain_head", "record_uniqueness"):
        assert report[name]["status"] == o.VERIFIED, (name, report[name])
    assert [r["fingerprint"]["recomputed"] for r in report["records"]] == [
        r["attestation_list"][0]["fingerprint"]["value"] for r in pair]
    assert report["tail"]["status"] == o.NOT_CHECKED
    assert decision == ("accept", None)
    assert o.verdict(report, "strict") == ("reject", "tail_anchored:not_checked")
    anchored, _ = judge(pair, trust=DEMO_POLICY, heads=[head(pair[-1])])
    assert o.verdict(anchored, "strict") == ("accept", None)


def test_published_decisions_read_dense_and_unsigned():
    report, decision = judge(DECISIONS)
    assert len(report["records"]) == 9
    assert report["decision_consistency"]["status"] == o.VERIFIED
    assert report["stream_sequence"]["status"] == o.VERIFIED
    assert report["stream_head"]["status"] == o.UNAVAILABLE
    assert report["signature"]["status"] == o.UNAVAILABLE
    assert decision == ("accept", None)
    assert o.verdict(report, "strict") == ("reject", "signature_required:unavailable")


def test_our_chain_over_the_published_decisions_passes_strict_with_a_head():
    report, decision = judge(CHAIN, heads=[head(CHAIN[-1])], profile="strict")
    assert decision == ("reject", "opening_supplied:unavailable")  # the stream opens at 41, not 0
    stream = DECISIONS[0]["unmapped"]["aid.stream"]
    bodies = copy.deepcopy(DECISIONS)
    for i, body in enumerate(bodies):
        body["unmapped"]["aid.stream"].update(stream_seq=i, emission_seq=i)
    chain = emit(bodies)
    report, decision = judge(chain, heads=[head(chain[-1])], profile="strict")
    assert decision == ("accept", None), report["strict"]
    assert stream["stream_seq"] == 41


# --- members named twice --------------------------------------------------------------------------

def test_duplicate_member_rides_a_valid_seal_and_is_refused():
    event = published("SAMPLE-OUTPUT.md")[0]
    raw = json.dumps(event, separators=(",", ":"))
    forged = raw.replace('"disposition":"Logged"', '"disposition":"Blocked","disposition_id":2,'
                         '"disposition":"Logged"', 1)
    last_wins = json.loads(forged)  # what a last-wins reader keeps: the sealed bytes, unchanged
    assert hashlib.sha256(o.signing_input(last_wins)).hexdigest() == \
        event["attestation_list"][0]["fingerprint"]["value"]
    report, decision = judge(None, trust=DEMO_POLICY, raw=(forged + "\n").encode())
    assert decision == ("reject", "structural_validity:failed")
    assert "duplicate-member" in report["records"][0]["structural_validity"]["findings"][0]


def test_duplicate_member_spelled_with_an_escape_is_refused():
    event = json.dumps(published("SAMPLE-OUTPUT.md")[0], separators=(",", ":"))
    forged = event.replace('"action":"Observed"', '"\\u0061ction":"Denied","action":"Observed"', 1)
    _, decision = judge(None, trust=DEMO_POLICY, raw=(forged + "\n").encode())
    assert decision == ("reject", "structural_validity:failed")


# --- the key --------------------------------------------------------------------------------------

def test_swapped_key_id_is_refused():
    chain = copy.deepcopy(CHAIN)
    chain[2]["unmapped"]["signature_key_id"] = "test-key-0"  # outside the signed bytes
    report, decision = judge(chain)
    assert report["records"][2]["signature"]["status"] == o.VERIFIED
    assert decision == ("reject", "key_binding:failed")


def test_key_id_naming_no_key_is_refused():
    chain = copy.deepcopy(CHAIN)
    chain[0]["unmapped"]["signature_key_id"] = "kid-nobody-holds"
    _, decision = judge(chain)
    assert decision == ("reject", "key_binding:failed")


def test_record_resigned_under_a_retired_key_is_refused():
    chain = copy.deepcopy(CHAIN)
    chain[-1] = seal(chain[-1], RETIRED, "test-key-0")  # key id and key agree; the window does not
    report, decision = judge(chain)
    assert report["records"][-1]["signature"]["key"] == "test-key-0"
    assert decision == ("reject", "key_binding:failed")


def test_two_live_keys_leave_the_binding_to_the_unsigned_key_id():
    both = policy((TEST, "test-key-1", AUTHORITY, {}), (RETIRED, "test-key-0", AUTHORITY, {}))
    report, decision = judge(CHAIN, trust=both, heads=[head(CHAIN[-1])])
    assert report["key_binding"]["status"] == o.UNAVAILABLE
    assert decision == ("accept", None)
    assert o.verdict(report, "strict")[1] == "key_named_by_signed_bytes:unavailable"


def test_key_of_another_authority_is_refused():
    other = policy((TEST, "test-key-1", "org-someone-else", {}))
    _, decision = judge(CHAIN, trust=other)
    assert decision == ("reject", "key_binding:failed")


def test_policy_listing_one_key_twice_is_refused():
    twice = policy((TEST, "test-key-1", AUTHORITY, {}), (TEST, "test-key-1b", AUTHORITY, {}))
    report, decision = judge(CHAIN, trust=twice)
    assert decision == ("reject", "trust_policy:failed")
    assert report["signature"]["status"] == o.NOT_CHECKED


# --- the chain and the stream ---------------------------------------------------------------------

def test_dropped_tail_reads_not_checked_without_a_head_and_failed_with_one():
    report, decision = judge(CHAIN[:-3])
    assert report["tail"]["status"] == o.NOT_CHECKED and decision == ("accept", None)
    report, decision = judge(CHAIN[:-3], heads=[head(CHAIN[-1])])
    assert decision == ("reject", "tail:failed")
    assert "3 records after seq 5 are missing" in report["tail"]["findings"][0]


def test_deleted_record_is_a_gap():
    report, decision = judge(CHAIN[:4] + CHAIN[5:])
    assert decision == ("reject", "chain_gaps:failed")
    assert report["stream_sequence"]["status"] == o.FAILED


def test_deleted_opening_is_unavailable_not_a_gap():
    report, decision = judge(CHAIN[2:])
    assert report["chain_head"]["status"] == o.UNAVAILABLE and decision == ("accept", None)


def test_changed_content_fails_the_fingerprint_and_a_new_fingerprint_fails_the_signature():
    chain = copy.deepcopy(CHAIN)
    chain[2]["unmapped"]["aid.decision"]["steps"][0]["detail"]["reason"] = "granted"
    _, decision = judge(chain)
    assert decision == ("reject", "fingerprint:failed")
    att = chain[2]["attestation_list"][0]
    att["fingerprint"]["value"] = hashlib.sha256(o.signing_input(chain[2])).hexdigest()
    _, decision = judge(chain)
    assert decision == ("reject", "signature:failed")


def test_fork_and_substituted_uid_are_refused():
    fork = copy.deepcopy(CHAIN[1])
    fork["unmapped"]["aid.span"]["span_id"] = "00f067aa0ba9ffff"
    fork["metadata"]["uid"] = "gw-1-test-000099"
    _, decision = judge(CHAIN + [seal(fork, TEST, "test-key-1")])
    assert decision[0] == "reject"
    substitute = copy.deepcopy(CHAIN[3])
    substitute["unmapped"]["aid.span"]["span_id"] = "00f067aa0ba9eeee"
    _, decision = judge(CHAIN + [seal(substitute, TEST, "test-key-1")])
    assert decision == ("reject", "record_uniqueness:failed")
    report, decision = judge(CHAIN + [CHAIN[3]])
    assert decision == ("accept", None) and report["record_uniqueness"]["status"] == o.VERIFIED


def test_stream_gap_and_emission_disorder_are_refused():
    _, decision = judge(DECISIONS[:2] + DECISIONS[3:])
    assert decision == ("reject", "stream_sequence:failed")
    bodies = copy.deepcopy(DECISIONS)
    bodies[4]["unmapped"]["aid.stream"]["emission_seq"] = 1
    _, decision = judge(bodies)
    assert decision == ("reject", "stream_sequence:failed")


def test_restart_under_a_larger_epoch_is_not_a_gap():
    bodies = copy.deepcopy(DECISIONS)
    for body in bodies[5:]:
        body["unmapped"]["aid.stream"]["epoch"] += 10**9
        body["unmapped"]["aid.stream"]["stream_seq"] -= 46
    report, _ = judge(bodies)
    assert report["stream_sequence"]["status"] == o.VERIFIED


def test_stream_tail_against_a_stream_head():
    stream = DECISIONS[0]["unmapped"]["aid.stream"]
    held = [{"epoch": stream["epoch"], "stream_id": stream["stream_id"], "stream_seq": 49}]
    _, decision = judge(DECISIONS[:-2], heads=held)
    assert decision == ("reject", "tail:failed")


# --- the ruling, numbers and the unsigned chain ---------------------------------------------------

def test_ruling_that_reads_two_ways_is_refused():
    bodies = copy.deepcopy(DECISIONS)
    bodies[2]["disposition"] = "Allowed"  # the id still says Blocked
    _, decision = judge(bodies)
    assert decision == ("reject", "decision_consistency:failed")
    bodies = copy.deepcopy(DECISIONS)
    del bodies[3]["unmapped"]["aid.decision"]["deny_ignored"]  # a suppressed deny no flag reports
    _, decision = judge(bodies)
    assert decision == ("reject", "decision_consistency:failed")


def test_integer_a_double_cannot_hold_fails_only_strict():
    bodies = copy.deepcopy(DECISIONS)
    for body in bodies:
        body["unmapped"]["aid.stream"]["epoch"] = 1755648000123456789
    chain = emit(bodies)
    report, decision = judge(chain, heads=[head(chain[-1])])
    assert decision == ("accept", None) and report["fingerprint"]["status"] == o.VERIFIED
    assert report["strict"]["numbers_interoperable"]["status"] == o.FAILED


def test_unsigned_chain_rewritten_end_to_end_passes_baseline_and_fails_strict():
    bodies = copy.deepcopy(DECISIONS)
    bodies[2]["action"], bodies[2]["action_id"] = "Allowed", 1
    bodies[2]["disposition"], bodies[2]["disposition_id"] = "Allowed", 1
    bodies[2]["unmapped"]["aid.decision"]["verdict"] = "allow"
    bodies[2]["unmapped"]["aid.decision"]["steps"][0]["action"] = "allowed"
    for member in ("status_id", "status_code", "status_detail"):
        bodies[2].pop(member, None)
    del bodies[2]["unmapped"]["aid.decision"]["steps"][0]["detail"]
    chain = emit(bodies, key=None)
    report, decision = judge(chain, heads=[head(chain[-1])])
    assert decision == ("accept", None)
    assert o.verdict(report, "strict") == ("reject", "signature_required:unavailable")


# --- the command line and corpus mode -------------------------------------------------------------

def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "agent_evidence_verify.cli", "ocsf-decision", *args],
                          capture_output=True, text=True, check=False)


def test_command_line_exit_codes(tmp_path):
    (tmp_path / "policy.json").write_text(json.dumps(TEST_POLICY))
    (tmp_path / "heads.json").write_text(json.dumps([head(CHAIN[-1])]))
    (tmp_path / "ok.ndjson").write_bytes(text(CHAIN))
    (tmp_path / "cut.ndjson").write_bytes(text(CHAIN[:-1]))
    (tmp_path / "dup.ndjson").write_text('{"class_uid":6003,"class_uid":6003}\n')
    base = ["--trust-policy", str(tmp_path / "policy.json"), "--heads", str(tmp_path / "heads.json")]
    assert run(str(tmp_path / "ok.ndjson"), *base).returncode == 0
    cut = run(str(tmp_path / "cut.ndjson"), *base)
    assert cut.returncode == 1 and json.loads(cut.stdout)["reason"] == "tail:failed"
    dup = run(str(tmp_path / "dup.ndjson"))
    assert dup.returncode == 2 and "verdict" not in json.loads(dup.stdout)


def test_corpus_mode_answers_the_suite(tmp_path):
    members = {"ok": {"records": text(CHAIN).decode(), "trust_policy": TEST_POLICY,
                      "relying_party": {"heads": [head(CHAIN[-1])]}, "profile": "strict"},
               "cut": {"records": text(CHAIN[:-1]).decode(), "trust_policy": TEST_POLICY,
                       "relying_party": {"heads": [head(CHAIN[-1])]}, "profile": "baseline"}}
    entries = []
    for name, member in members.items():
        (tmp_path / f"{name}.json").write_text(json.dumps(member))
        entries.append({"id": name, "path": f"{name}.json"})
    (tmp_path / "MANIFEST.json").write_text(json.dumps({"suite": o.SUITE, "corpusDigest": "x", "vectors": entries}))
    got = {line["vector"]: (line["verdict"], line["reason"]) for line in corpus.lines(tmp_path)}
    assert got == {"ok": ("reject", "opening_supplied:unavailable"), "cut": ("reject", "tail:failed")}


@pytest.mark.parametrize("bad", [b"\xff\n", b"[1]\n"])
def test_input_that_is_not_records_is_not_accepted(bad):
    report = o.read(bad)
    assert o.verdict(report)[0] == "reject"
