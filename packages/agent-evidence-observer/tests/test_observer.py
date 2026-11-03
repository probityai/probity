"""Offline packet checks over committed broker records: the bounded claim a consumer recomputes."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from fixture_records import load, materialize, pinned_keys, signing_keys
from probity_observer import SigningKey, VerificationError, Witness, verify_packet
from probity_observer.crypto import canonical, strict_loads
from probity_observer.history import read_history
from probity_observer.records import tree_root
from probity_observer.verify import _verify_commitment, _verify_request_sequence, verify_incomplete


def kinds(history: Path) -> list[str]:
    return [entry["event"]["kind"] for entry in read_history(history)]


def checked(name: str, tmp_path: Path, *, workspace: bool = True) -> tuple[Path, dict]:
    record = materialize(name, tmp_path)
    observer, witness = pinned_keys(record)
    claim = verify_packet(load(record / "packet.json"), record / "history.jsonl", observer, witness,
                          record / "workspace" if workspace else None)
    return record, claim


class TestPassingCases:
    def test_write_and_replay_bind_to_one_witnessed_history(self, tmp_path: Path) -> None:
        record, claim = checked("sealed-write", tmp_path)
        assert claim["coverage"]["noDetectedGap"] is True
        assert claim["witnessScope"] == "PEER"
        assert kinds(record / "history.jsonl") == ["begin", "write-intent", "write", "retry", "seal"]
        assert (record / "workspace/result").read_bytes() == b"data"

    def test_unbrokered_change_is_reported_as_gap(self, tmp_path: Path) -> None:
        _, claim = checked("bypass-gap", tmp_path, workspace=False)
        assert claim["coverage"]["noDetectedGap"] is False
        assert claim["coverage"]["knownGaps"] == ["workspace changed outside the broker"]

    def test_retry_after_a_direct_change_is_a_denied_gap(self, tmp_path: Path) -> None:
        record, claim = checked("retry-gap", tmp_path, workspace=False)
        assert claim["coverage"]["noDetectedGap"] is False
        assert kinds(record / "history.jsonl") == ["begin", "write-intent", "write", "denied", "gap", "seal"]

    def test_symlink_in_scope_is_an_explicit_gap(self, tmp_path: Path) -> None:
        _, claim = checked("symlink-gap", tmp_path, workspace=False)
        assert claim["coverage"]["noDetectedGap"] is False
        assert claim["coverage"]["knownGaps"] == ["workspace contains a symbolic link"]

    def test_repaired_bypass_does_not_erase_detected_gap(self, tmp_path: Path) -> None:
        record, claim = checked("repaired-bypass", tmp_path)
        assert not (record / "workspace/bypass").exists()
        assert claim["coverage"]["noDetectedGap"] is False
        assert claim["coverage"]["knownGaps"] == ["workspace changed outside the broker"]

    def test_witness_extends_same_history(self, tmp_path: Path) -> None:
        record = materialize("sealed-write", tmp_path)
        _, witness_key = signing_keys(record)
        packet = load(record / "packet.json")
        second = Witness(record / "witness-state.json", witness_key).checkpoint(record / "history.jsonl")
        assert (second["count"], second["head"]) == (packet["checkpoint"]["count"], packet["checkpoint"]["head"])
        assert second["keyid"] == witness_key.public_hex

    @pytest.mark.parametrize("name,identical", [("interrupted-changed", False), ("interrupted-identical", True)])
    def test_replacement_then_process_death_is_witnessed_as_incomplete(self, tmp_path: Path, name: str, identical: bool) -> None:
        record = materialize(name, tmp_path)
        observer, witness = pinned_keys(record)
        history = record / "history.jsonl"
        recovered = load(record / "incomplete.json")
        assert (record / "workspace/result").read_bytes() == (b"same" if identical else b"changed")
        assert kinds(history) == ["begin", "write-intent", "incomplete"]
        assert recovered["status"] == "incomplete"
        assert recovered["event"]["recoveryRoot"] == tree_root(record / "workspace")
        if identical:
            assert recovered["event"]["recoveryRoot"] == read_history(history)[0]["event"]["commitment"]["preimage"]["beforeRoot"]
        assert recovered["event"]["requestIds"] == ["one"]
        assert verify_incomplete(history, recovered["startCheckpoint"], recovered["checkpoint"], observer, witness) == recovered["event"]
        with pytest.raises(VerificationError, match="pinned witness key"):
            verify_incomplete(history, recovered["startCheckpoint"], recovered["checkpoint"], observer, SigningKey.generate().public_hex)


class TestFailingCases:
    def test_partial_history_line_is_refused(self, tmp_path: Path) -> None:
        history = materialize("sealed-write", tmp_path) / "history.jsonl"
        history.write_bytes(history.read_bytes().rstrip(b"\n"))
        with pytest.raises(VerificationError, match="incomplete line"):
            read_history(history)

    def test_intent_must_match_effect_event(self) -> None:
        begin = {"kind": "begin"}
        intent = {"kind": "write-intent", "requestId": "one", "path": "/work/result", "contentDigest": "a", "beforeRoot": "b"}
        changed = {"kind": "write", "requestId": "one", "path": "/work/result", "contentDigest": "c", "beforeRoot": "b"}
        with pytest.raises(VerificationError, match="differs from its durable intent"):
            _verify_request_sequence([{"event": event} for event in (begin, intent, changed, {"kind": "seal"})])
        with pytest.raises(VerificationError, match="unresolved write intent"):
            _verify_request_sequence([{"event": event} for event in (begin, intent, {"kind": "seal"})])

    def test_changed_history_fails_offline_check(self, tmp_path: Path) -> None:
        record = materialize("sealed-write", tmp_path)
        history = record / "history.jsonl"
        history.write_bytes(history.read_bytes().replace(b'"requestId":"one"', b'"requestId":"two"', 1))
        with pytest.raises(VerificationError, match="history entry digest differs"):
            verify_packet(load(record / "packet.json"), history, *pinned_keys(record))

    def test_truncated_history_fails_witness_binding(self, tmp_path: Path) -> None:
        record = materialize("sealed-write", tmp_path)
        history = record / "history.jsonl"
        history.write_bytes(history.read_bytes().splitlines()[0] + b"\n")
        with pytest.raises(VerificationError, match="history has no final seal"):
            verify_packet(load(record / "packet.json"), history, *pinned_keys(record))
        _, witness_key = signing_keys(record)
        with pytest.raises(VerificationError, match="history does not extend the witnessed head"):
            Witness(record / "witness-state.json", witness_key).checkpoint(history)

    def test_second_key_does_not_grant_observer_authority(self, tmp_path: Path) -> None:
        record = materialize("sealed-write", tmp_path)
        forged = copy.deepcopy(load(record / "packet.json"))
        forged["claim"]["witnessScope"] = "EXTERNAL"
        with pytest.raises(VerificationError, match="signature does not verify under the pinned key"):
            verify_packet(forged, record / "history.jsonl", *pinned_keys(record))

    def test_unpinned_witness_is_rejected(self, tmp_path: Path) -> None:
        record = materialize("sealed-write", tmp_path)
        observer, _ = pinned_keys(record)
        with pytest.raises(VerificationError, match="checkpoint key is not the pinned witness key"):
            verify_packet(load(record / "packet.json"), record / "history.jsonl", observer, SigningKey.generate().public_hex)

    def test_duplicate_json_member_is_refused(self) -> None:
        with pytest.raises(VerificationError, match="duplicate JSON member"):
            strict_loads(b'{"a":1,"a":2}')

    def test_noncanonical_encoding_is_refused(self) -> None:
        with pytest.raises(VerificationError, match="JSON document is not canonical"):
            strict_loads(b'{ "a": 1 }')

    def test_prototype_rejects_unsafe_number(self) -> None:
        with pytest.raises(VerificationError, match="integer exceeds the safe JSON range"):
            canonical({"n": 2**53})

    @pytest.mark.parametrize(
        ("events", "message"),
        [
            ([{"kind": "begin"}, {"kind": "begin"}, {"kind": "seal"}], "history has a duplicate interval boundary"),
            ([{"kind": "begin"}, {"kind": "retry", "requestId": "one", "path": "/work/x"}, {"kind": "seal"}], "history retry has no matching write"),
            ([{"kind": "begin"}, {"kind": "write", "requestId": "one", "path": "/work/x"}, {"kind": "write", "requestId": "one", "path": "/work/x"}, {"kind": "seal"}], "history repeats a write request id"),
            ([{"kind": "begin"}, {"kind": "unrecognized"}, {"kind": "seal"}], "history has an unknown event kind"),
        ],
    )
    def test_history_refuses_invalid_event_sequences(self, events: list[dict[str, str]], message: str) -> None:
        with pytest.raises(VerificationError, match=message):
            _verify_request_sequence([{"event": event} for event in events])

    def test_offset_timestamp_cannot_pass_lexical_order_gate(self, tmp_path: Path) -> None:
        record = materialize("sealed-write", tmp_path)
        observer_key, _ = signing_keys(record)
        packet = load(record / "packet.json")
        commitment = packet["commitment"]
        commitment["committedAt"] = "2026-09-18T20:00:00-05:00"
        payload = {"preimage": commitment["preimage"], "committedAt": commitment["committedAt"]}
        commitment["signature"] = observer_key.sign("probity-prior-commitment-v0", payload)
        with pytest.raises(VerificationError, match="record timestamps must use UTC second precision"):
            _verify_commitment(packet, observer_key.public_hex)
