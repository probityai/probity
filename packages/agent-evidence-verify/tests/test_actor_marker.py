"""Corpus mode judges every member of the actor-marker-survival corpus as its manifest declares.

``tests/data/actor-marker-survival`` is a byte copy of ``corpora/vectors-actor-marker-survival``
of probityai/agent-evidence-vectors (MANIFEST.json, TRUST.json and every case directory), taken
at commit d28f577bad6ddf57403a1d69eada66a725d7c706. Every expectation below is read from that
manifest; none comes from this verifier. The reader shares no code with the corpus's readers.

Beyond the members, the tests hold the trust boundary: the verifying key and the writer's role
come from the bundle the verifier holds, a bundle the manifest does not pin is refused before
any member is judged, and a record that a lenient parser would read two ways is malformed.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from agent_evidence_verify import actor_marker, corpus
from agent_evidence_verify.cli import main

ROOT = Path(__file__).resolve().parent / "data" / "actor-marker-survival"
MANIFEST: dict[str, Any] = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
TRUST_BYTES = (ROOT / "TRUST.json").read_bytes()
LINES = {line["vector"]: line for line in corpus.lines(ROOT)}


def _record(case_id: str) -> bytes:
    entry = next(e for e in MANIFEST["vectors"] if e["id"] == case_id)
    return (ROOT / entry["path"] / "record.json").read_bytes()


def _trust(edit: Any = None) -> dict[str, Any]:
    bundle = json.loads(TRUST_BYTES)
    if edit is not None:
        edit(bundle)
    return actor_marker.load_trust(json.dumps(bundle).encode())


def test_manifest_is_complete() -> None:
    counts = MANIFEST["counts"]
    assert MANIFEST["suite"] == actor_marker.SUITE
    assert len(MANIFEST["vectors"]) == counts["accept"] + counts["reject"] == len(LINES)


@pytest.mark.parametrize("entry", MANIFEST["vectors"], ids=lambda e: e["id"])
def test_member(entry: dict[str, Any]) -> None:
    line = LINES[entry["id"]]
    assert line["suite"] == MANIFEST["suite"] and line["corpusDigest"] == MANIFEST["corpusDigest"]
    assert (line["verdict"], line["reason"]) == (
        entry["expected"]["decision"], entry["expected"]["reason"])


def test_the_cli_prints_every_member(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["corpus", str(ROOT)]) == 0
    printed = [json.loads(text) for text in capsys.readouterr().out.splitlines()]
    assert [line["vector"] for line in printed] == [e["id"] for e in MANIFEST["vectors"]]


def test_every_check_of_the_reader_is_forced_by_a_member() -> None:
    """A check no member fails could be deleted with every member still agreeing."""
    record = json.loads(_record("accept-two-hop"))
    names = {name for name, _ in actor_marker._rules(record["statements"], _trust()["writers"])}
    names |= {"contract_id_missing", "contract_id_unknown", "record_malformed"}
    rejected = {e["expected"]["reason"] for e in MANIFEST["vectors"]
                if e["expected"]["decision"] == "reject"}
    assert rejected == names


@pytest.mark.parametrize(("case_id", "reason"), [
    ("signature-forged", "statement_signature_invalid"),
    ("signature-swapped-key", "statement_signature_invalid"),
    ("hop-replayed-from-another-chain", "hop_link_broken"),
    ("deferred-dispatch-after-expiry", "principals_expired_at_use"),
    ("audience-mismatch", "audience_mismatch"),
    ("downgraded-to-user-alone", "downgraded_to_user_alone"),
    ("writer-not-in-trust-bundle", "statement_writer_unknown"),
])
def test_adversarial_members_fail_closed(case_id: str, reason: str) -> None:
    assert actor_marker.judge(_record(case_id), _trust()) == ("reject", reason)


def test_the_role_comes_from_the_trust_bundle() -> None:
    """The same signed chain fails once the bundle says the agent is only a relay."""
    assert actor_marker.judge(_record("accept-two-hop"), _trust()) == ("accept", "marker_survives")

    def demote(bundle: dict[str, Any]) -> None:
        bundle["writers"]["agent:planner"]["role"] = "relay"

    verdict, reason = actor_marker.judge(_record("accept-two-hop"), _trust(demote))
    assert verdict == "reject" and reason != "marker_survives"


def test_the_key_comes_from_the_trust_bundle() -> None:
    """A bundle that holds another writer's key for the origin refuses the origin's signature."""
    def swap(bundle: dict[str, Any]) -> None:
        writers = bundle["writers"]
        writers["idp.example"]["key"] = writers["gateway:edge"]["key"]

    assert actor_marker.judge(_record("accept-two-hop"), _trust(swap)) == (
        "reject", "statement_signature_invalid")


def test_a_repeated_member_is_malformed() -> None:
    """A parser keeping the last ``writer`` would judge a different chain than one keeping the first."""
    text = _record("accept-two-hop").decode()
    assert '"writer": "idp.example"' in text
    doubled = text.replace('"writer": "idp.example"',
                           '"writer": "idp.example", "writer": "agent:intruder"', 1)
    assert actor_marker.judge(doubled.encode(), _trust()) == ("reject", "record_malformed")


@pytest.mark.parametrize("edit", [
    lambda b: b.pop("contractId"),
    lambda b: b.update(writers=[]),
    lambda b: b.update(writers={}),
    lambda b: b["writers"]["agent:planner"].update(role="admin"),
    lambda b: b["writers"]["agent:planner"].update(key="AAAA"),
    lambda b: b["writers"]["agent:planner"].pop("key"),
], ids=["no-contract", "writers-list", "writers-empty", "unknown-role", "short-key", "no-key"])
def test_a_malformed_trust_bundle_is_refused(edit: Any) -> None:
    with pytest.raises(ValueError, match="trust bundle"):
        _trust(edit)


def test_a_trust_bundle_the_manifest_does_not_pin_is_refused(
        tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """No member is judged under a bundle other than the one the corpus published."""
    copy = tmp_path / "corpus"
    shutil.copytree(ROOT, copy)
    bundle = json.loads(TRUST_BYTES)
    bundle["writers"]["agent:intruder"]["role"] = "agent"
    bundle["writers"]["agent:intruder"]["key"] = bundle["writers"]["agent:planner"]["key"]
    (copy / "TRUST.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    assert main(["corpus", str(copy)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "trustSha256" in captured.err
