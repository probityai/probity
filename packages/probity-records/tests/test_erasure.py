"""Record envelope v2: schema lint, sealing, opening, disclosure, what the verifier prints, and the shared vectors."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from probity_records import erasure as ev
from probity_records.erasure import (
    KEPT,
    PAYLOAD,
    PSEUDONYM,
    EnvelopeError,
    Rule,
    Schema,
)
from probity_records.erasure_vectors import check, vectors

SHARED = Path(__file__).resolve().parents[1] / "vectors" / "shared" / "erasure.json"

STRUCT = frozenset({"previous_record_sha256"})
SCHEMA = Schema("test@2", (
    Rule("sequence", KEPT), Rule("previous_record_sha256", KEPT), Rule("verdict", KEPT),
    Rule("session_sha256", PSEUDONYM, "user", personal=True, digest_of_personal=True),
    Rule("intent", PAYLOAD, "user", personal=True, commit=True),
    Rule("reasons", PAYLOAD, "user", personal=True),
    Rule("principals.user", PSEUDONYM, "user", personal=True),
    Rule("principals.approver", PSEUDONYM, "approver", personal=True),
), STRUCT)  # fmt: skip


def record(session: str = "s" * 64, args: str = "transfer 10 to bob") -> dict:
    return {"sequence": 3, "previous_record_sha256": "a" * 64, "verdict": "allow", "session_sha256": session,
            "intent": {"tool": "pay", "args": args}, "reasons": ["ok"],
            "principals": {"user": {"issuer": "https://idp", "subject": "alice"},
                           "approver": {"issuer": "https://idp", "subject": "carol"}}}  # fmt: skip


def keys() -> dict[str, bytes]:
    return {"user": os.urandom(32), "approver": os.urandom(32)}


def test_lint_refuses_a_kept_personal_field_and_a_plain_digest_of_one() -> None:
    bad = Schema("bad@2", (Rule("email", KEPT, personal=True), Rule("token_digest", KEPT, digest_of_personal=True),
                           Rule("response_sha256", KEPT)))  # fmt: skip
    assert ev.lint_schema(bad) == ["personal_field_kept:email", "plain_digest_of_personal:token_digest",
                                   "undeclared_digest_kept:token_digest", "undeclared_digest_kept:response_sha256"]
    assert ev.lint_schema(SCHEMA) == []
    with pytest.raises(EnvelopeError, match="schema_refused"):
        ev.seal(bad, {}, {}, None, None)


def test_seal_refuses_an_undeclared_field_and_a_digest_hidden_in_a_kept_one() -> None:
    with pytest.raises(EnvelopeError, match="field_undeclared: extra"):
        ev.seal(SCHEMA, {**record(), "extra": 1}, keys(), "call", "user")
    with pytest.raises(EnvelopeError, match="plain_digest_in_kept_field: verdict"):
        ev.seal(SCHEMA, {**record(), "verdict": "sha256:" + "b" * 64}, keys(), "call", "user")
    with pytest.raises(EnvelopeError, match="subject_key_missing"):
        ev.seal(SCHEMA, record(), {"user": os.urandom(32)}, "call", "user")


def test_committed_bytes_hold_no_personal_value_and_open_round_trips() -> None:
    k = keys()
    sealed = ev.seal(SCHEMA, record(), k, "call", "user")
    committed = ev.canonical({**sealed.kept, "erasure": sealed.erasure, "subject": sealed.subject_digest}).decode()
    for value in ("alice", "carol", "transfer 10 to bob", "s" * 64, "https://idp"):
        assert value not in committed
    assert sealed.erasure["classes"]["verdict"] == KEPT
    opened = ev.open_sealed(sealed.kept, sealed.erasure, sealed.blobs, k)
    assert opened.fields == record() and opened.erased == () and opened.missing == ()


def test_a_missing_key_reads_as_erased_and_a_wrong_key_is_refused() -> None:
    k = keys()
    sealed = ev.seal(SCHEMA, record(), k, "call", "user")
    opened = ev.open_sealed(sealed.kept, sealed.erasure, sealed.blobs, {"approver": k["approver"]})
    assert opened.erased == ("intent", "principals.user", "reasons", "session_sha256")
    assert opened.fields["principals"] == {"approver": record()["principals"]["approver"]}
    with pytest.raises(EnvelopeError, match="ciphertext_refused"):
        ev.open_sealed(sealed.kept, sealed.erasure, sealed.blobs, {**k, "user": os.urandom(32)})
    assert ev.erased_reading("2026-11-22T05:00:00Z") == "commitment only, content erased at 2026-11-22T05:00:00Z"


def test_equal_values_do_not_link_two_leaves() -> None:
    k = keys()
    a = ev.seal(SCHEMA, record(), k, "call", "user")
    b = ev.seal(SCHEMA, record(), k, "call", "user")
    for name in ("pseudonyms", "commitments"):
        assert set(a.erasure[name].values()).isdisjoint(b.erasure[name].values())
    assert a.subject_digest != b.subject_digest
    assert set(a.blobs).isdisjoint(b.blobs)


def test_a_blob_of_another_leaf_or_a_tampered_tag_is_refused() -> None:
    k = keys()
    a = ev.seal(SCHEMA, record(), k, "call", "user")
    b = ev.seal(SCHEMA, record(), k, "call", "user")
    swapped = {da: b.blobs[db] for da, db in zip(sorted(a.blobs), sorted(b.blobs), strict=True)}
    with pytest.raises(EnvelopeError, match="ciphertext_digest_mismatch"):
        ev.open_sealed(a.kept, a.erasure, swapped, k)
    relabelled = {**b.erasure, "ciphertexts": a.erasure["ciphertexts"]}
    with pytest.raises(EnvelopeError):
        ev.open_sealed(b.kept, relabelled, a.blobs, k)  # leaf b's AAD does not accept leaf a's ciphertext
    tampered = {**a.erasure, "commitments": {"intent": "0" * 64}}
    with pytest.raises(EnvelopeError, match="commitment_mismatch"):
        ev.open_sealed(a.kept, tampered, a.blobs, k)


def test_disclosure_releases_one_field_only() -> None:
    k = keys()
    sealed = ev.seal(SCHEMA, record(), k, "call", "user")
    shown = ev.disclose(k["user"], sealed.erasure, "intent", record()["intent"])
    assert ev.verify_disclosure(sealed.erasure, shown)
    assert not ev.verify_disclosure(sealed.erasure, {**shown, "value": {"tool": "pay", "args": "other"}})
    other = ev.seal(SCHEMA, record(), k, "call", "user")
    assert not ev.verify_disclosure(other.erasure, {**shown, "leaf": other.erasure["leaf"]})
    with pytest.raises(EnvelopeError, match="field_not_committed"):
        ev.disclose(k["user"], sealed.erasure, "reasons", ["ok"])


def test_padding_hides_value_length() -> None:
    k = keys()
    short = ev.seal(SCHEMA, record(args="a"), k, "call", "user")
    long = ev.seal(SCHEMA, record(args="a" * 120), k, "call", "user")
    assert sorted(len(b) for b in short.blobs.values()) == sorted(len(b) for b in long.blobs.values())


def test_verifier_labels_v1_not_erasable_and_prints_the_kept_class() -> None:
    sealed = ev.seal(SCHEMA, record(), keys(), "call", "user")
    v2 = {**sealed.kept, "erasure": sealed.erasure}
    report = ev.erasability([v2, v2])
    assert report.label == "erasable"
    assert report.kept == ("previous_record_sha256", "sequence", "verdict")
    assert "kept in clear (retention class kept): previous_record_sha256, sequence, verdict" in report.lines()
    mixed = ev.erasability([v2, record()])
    assert mixed.label == ev.NOT_ERASABLE and mixed.lines()[0].startswith("erasure: not erasable (1 of 2")


def test_a_malformed_block_is_refused() -> None:
    sealed = ev.seal(SCHEMA, record(), keys(), "call", "user")
    for change in ({"format": "probity-record-envelope/v1"}, {"leaf": "zz"}, {"pseudonyms": {}},
                   {"classes": {**sealed.erasure["classes"], "verdict": "secret"}}, {"ciphertexts": []}):  # fmt: skip
        with pytest.raises(EnvelopeError):
            ev.check_block({**sealed.erasure, **change})


def test_the_shared_vectors_are_current_and_cover_every_operation() -> None:
    rows = vectors()
    assert rows == vectors()
    assert json.loads(SHARED.read_text()) == json.loads(json.dumps(rows))
    assert check(json.loads(SHARED.read_text())) == []
    assert {v["op"] for v in rows} == {"seal", "open", "disclose", "verify-disclosure", "lint", "erasability"}
    assert {v["expected"]["refused"] for v in rows if "refused" in v["expected"]} >= {
        "field_undeclared", "plain_digest_in_kept_field", "subject_key_missing", "schema_refused",
        "ciphertext_digest_mismatch", "ciphertext_refused", "commitment_mismatch", "pseudonym_mismatch",
        "not_envelope_v2", "ciphertexts_do_not_cover_fields", "classes_malformed", "field_not_committed"}


def test_a_schema_round_trips_through_json_and_a_malformed_one_is_refused() -> None:
    assert Schema.from_json(SCHEMA.to_json()) == SCHEMA
    doc = SCHEMA.to_json()
    with pytest.raises(EnvelopeError, match="schema_malformed"):
        Schema.from_json({**doc, "rules": [{**doc["rules"][0], "personal": "yes"}]})
    with pytest.raises(EnvelopeError, match="schema_malformed"):
        Schema.from_json({"name": "x@2", "rules": []})
