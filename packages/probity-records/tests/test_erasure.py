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
    Rule("principals.approver", PSEUDONYM, "approver", personal=True, members=True),
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
    assert {v["op"] for v in rows} == {"seal", "open", "disclose", "verify-disclosure", "lint", "erasability",
                                       "check-padding", "reference", "personal-traces"}  # fmt: skip
    assert {v["expected"]["refused"] for v in rows if "refused" in v["expected"]} >= {
        "field_undeclared", "plain_digest_in_kept_field", "subject_key_missing", "schema_refused",
        "ciphertext_digest_mismatch", "ciphertext_refused", "commitment_mismatch", "pseudonym_mismatch",
        "not_envelope_v2", "ciphertexts_do_not_cover_fields", "classes_malformed", "field_not_committed",
        "payload_over_fixed_size", "ciphertext_length_mismatch"}
    by = {v["id"]: v["expected"] for v in rows}
    assert by["S8"]["erasure"]["ciphertexts"][0]["bytes"] == by["S9"]["erasure"]["ciphertexts"][0]["bytes"] == 540


def test_a_schema_round_trips_through_json_and_a_malformed_one_is_refused() -> None:
    assert Schema.from_json(SCHEMA.to_json()) == SCHEMA
    doc = SCHEMA.to_json()
    with pytest.raises(EnvelopeError, match="schema_malformed"):
        Schema.from_json({**doc, "rules": [{**doc["rules"][0], "personal": "yes"}]})
    with pytest.raises(EnvelopeError, match="schema_malformed"):
        Schema.from_json({"name": "x@2", "rules": []})
    sized = Schema("vote@2", VOTE_RULES, fixed=((PAYLOAD, 512),))
    assert Schema.from_json(sized.to_json()) == sized and sized.to_json()["fixed"] == {"payload": 512}
    for bad in ({"payload": "512"}, {"payload": True}, [["payload", 512]]):
        with pytest.raises(EnvelopeError, match="schema_malformed"):
            Schema.from_json({**sized.to_json(), "fixed": bad})
    with pytest.raises(EnvelopeError, match="schema_malformed"):
        Schema.from_json({k: v for k, v in sized.to_json().items() if k != "fixed"})


VOTE_RULES = (Rule("record_kind", KEPT), Rule("decision", KEPT), Rule("approver", PAYLOAD, "approver", personal=True),
              Rule("principal", PAYLOAD, "approver", personal=True))  # fmt: skip
VOTE = Schema("vote@2", VOTE_RULES, fixed=((PAYLOAD, 512),))


def vote(approver: str, principal: object = None) -> dict:
    return {"record_kind": "approval_vote", "decision": "deny", "approver": approver, "principal": principal}


def test_a_fixed_class_has_one_ciphertext_size_whoever_is_inside() -> None:
    """With padding to a multiple of 256 alone, an approver whose name and principal push the payload past a
    boundary is re-linked across every vote from the ciphertext length, after the approver key is destroyed."""
    key = {"approver": os.urandom(32)}
    names = ["al", "maximilian.alexander-worthington@example.com" * 4, "x" * 200]
    principals = [None, {"issuer": "https://idp.example", "subject": "s" * 150}]
    sizes = {len(blob) for n in names for pr in principals
             for blob in ev.seal(VOTE, vote(n, pr), key, "call", "approver").blobs.values()}  # fmt: skip
    assert sizes == {512 + ev.NONCE_BYTES + ev.TAG_BYTES}
    loose = Schema("vote@2", VOTE_RULES)
    assert len({len(b) for n in names for pr in principals
                for b in ev.seal(loose, vote(n, pr), key, "call", "approver").blobs.values()}) > 1  # fmt: skip
    sealed = ev.seal(VOTE, vote("al"), key, "call", "approver")
    assert ev.open_sealed(sealed.kept, sealed.erasure, sealed.blobs, key).fields == vote("al")
    with pytest.raises(EnvelopeError, match="payload_over_fixed_size"):
        ev.seal(VOTE, vote("a" * 512), key, "call", "approver")


def test_the_lint_refuses_a_fixed_size_it_cannot_honour() -> None:
    bad = Schema("bad@2", VOTE_RULES, fixed=((KEPT, 256), (PAYLOAD, 100), (PAYLOAD, 256), (PSEUDONYM, 0),
                                             (PAYLOAD, True)))  # type: ignore[arg-type]  # fmt: skip
    assert ev.lint_schema(bad) == ["fixed_size_malformed:kept:256", "fixed_size_malformed:payload:100",
                                   "fixed_size_duplicate:payload", "fixed_size_malformed:pseudonym:0",
                                   "fixed_size_duplicate:payload", "fixed_size_malformed:payload:True"]
    with pytest.raises(EnvelopeError, match="schema_refused"):
        ev.seal(bad, vote("al"), {"approver": os.urandom(32)}, "call", "approver")
    partial = Schema("vote@2", (*VOTE_RULES, Rule("request", PSEUDONYM, "approver", personal=True)),
                     fixed=((PAYLOAD, 512),))  # fmt: skip
    assert ev.lint_schema(partial) == ["fixed_size_partial:pseudonym"]
    whole = Schema("vote@2", partial.rules, fixed=((PAYLOAD, 512), (PSEUDONYM, 256)))
    assert ev.lint_schema(whole) == []
    key = {"approver": os.urandom(32)}
    sizes = {len(b) for n in ("a", "b" * 150) for b in
             ev.seal(whole, {**vote(n), "request": n}, key, "call", "approver").blobs.values()}  # fmt: skip
    assert sizes == {512 + 28, 256 + 28}


def test_check_padding_finds_a_writer_that_skipped_the_padding_from_the_signed_block() -> None:
    key = {"approver": os.urandom(32)}
    sealed = ev.seal(VOTE, vote("al"), key, "call", "approver")
    assert ev.check_padding(VOTE, sealed.erasure) == []
    loose = ev.seal(Schema("vote@2", VOTE_RULES), vote("al"), key, "call", "approver")
    assert ev.check_padding(VOTE, loose.erasure) == ["ciphertext_size_not_fixed:approver/payload:256"]
    [entry] = sealed.erasure["ciphertexts"]
    unpadded = {**sealed.erasure, "ciphertexts": [{**entry, "bytes": 28 + 77}]}
    assert ev.check_padding(Schema("vote@2", VOTE_RULES), unpadded) == ["ciphertext_not_padded:approver/payload:77"]
    assert ev.check_padding(SCHEMA, sealed.erasure) == ["schema_mismatch:vote@2"]
    for value in (27, True, "540"):
        with pytest.raises(EnvelopeError, match="ciphertexts_malformed"):
            ev.check_padding(VOTE, {**sealed.erasure, "ciphertexts": [{**entry, "bytes": value}]})


def test_a_signed_length_that_is_not_the_blob_length_is_refused() -> None:
    key = {"approver": os.urandom(32)}
    sealed = ev.seal(VOTE, vote("al"), key, "call", "approver")
    [entry] = sealed.erasure["ciphertexts"]
    lied = {**sealed.erasure, "ciphertexts": [{**entry, "bytes": entry["bytes"] + 256}]}
    with pytest.raises(EnvelopeError, match="ciphertext_length_mismatch"):
        ev.open_sealed(sealed.kept, lied, sealed.blobs, key)


def test_a_reference_is_keyed_per_leaf_and_label_and_dies_with_the_key() -> None:
    k, leaf, other = os.urandom(32), os.urandom(16), os.urandom(16)
    ref = ev.reference(k, "approver", leaf, "carol")
    assert ref == ev.reference(k, "approver", leaf, "carol")
    assert len({ref, ev.reference(k, "approver", other, "carol"), ev.reference(k, "principal", leaf, "carol"),
                ev.reference(k, "approver", leaf, "dave"), ev.reference(os.urandom(32), "approver", leaf, "carol"),
                ev.pseudonym(k, leaf, "approver", "carol")}) == 6  # fmt: skip
    with pytest.raises(EnvelopeError, match="subject_key_length"):
        ev.reference(b"short", "approver", leaf, "carol")


def test_personal_traces_finds_every_plain_form_and_nothing_in_a_sealed_record() -> None:
    import base64
    import hashlib

    name, obj = "Zoe Muller-Ozil", {"issuer": "https://idp", "subject": "alice"}
    jcs = hashlib.sha256(ev.canonical(name)).digest()
    utf8 = hashlib.sha256(name.encode()).digest()
    cases = {
        b'{"who":"zoe muller-ozil"}': ["clear:'Zoe Muller-Ozil'"],
        ('{"d":"sha256:' + utf8.hex().upper() + '"}').encode(): ["sha256(utf8):'Zoe Muller-Ozil'"],
        ('{"d":"' + base64.urlsafe_b64encode(jcs).decode().rstrip("=") + '"}').encode():
            ["sha256(jcs):base64:'Zoe Muller-Ozil'"],
        ('{"d":"' + base64.b64encode(utf8).decode() + '"}').encode(): ["sha256(utf8):base64:'Zoe Muller-Ozil'"],
        ev.canonical({"p": obj}): ["clear:" + repr(obj)],
        b'{"x":1}': [],
    }  # fmt: skip
    for signed, want in cases.items():
        assert ev.personal_traces(signed, [name, obj]) == want, signed
    accented = "Zo" + chr(0xEB)
    for signed in (json.dumps({"n": accented}, ensure_ascii=True).encode(),
                   json.dumps({"n": accented}, ensure_ascii=False).encode()):  # fmt: skip
        assert ev.personal_traces(signed, [accented]) == ["clear:" + repr(accented)], signed
    k = keys()
    sealed = ev.seal(SCHEMA, record(), k, "call", "user")
    signed = ev.canonical({**sealed.kept, "erasure": sealed.erasure, "subject": sealed.subject_digest})
    assert ev.personal_traces(signed, ["alice", "carol", "transfer 10 to bob", "https://idp",
                                       {"issuer": "https://idp", "subject": "alice"}]) == []  # fmt: skip
