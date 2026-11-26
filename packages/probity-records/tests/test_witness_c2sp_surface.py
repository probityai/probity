"""The whole C2SP witness surface: signed-note, tlog-checkpoint, tlog-cosignature, tlog-policy, tlog-witness and
tlog-proof, every signature type the specs assign (0x01, 0x02, 0x04, 0x05, 0x06), checkpoint and subtree
cosignatures, and stable refusal codes.

The conformance cases come from the specifications and from independent implementations (golang.org/x/mod sumdb,
transparency-dev/formats, filippo.io/torchwood); ``vectors/shared/c2sp-conformance.json`` names each source."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st
from probity_records import refusal_codes
from probity_records import witness as w
from probity_records.clock import NS_PER_S

VECTORS = json.loads((Path(__file__).resolve().parents[1] / "vectors" / "shared" / "c2sp-conformance.json").read_text())
ORIGIN = "example.com/log"
NOW = 1_800_000_000


class FixedClock:
    def __init__(self, seconds: int) -> None:
        self.seconds = seconds

    def now(self) -> int:
        return self.seconds * NS_PER_S


def code(exc: pytest.ExceptionInfo[BaseException]) -> str:
    return exc.value.code  # type: ignore[attr-defined]


# ---- conformance: the specifications' own examples and independent implementations ---------------------------
@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_published_signed_notes(case: dict[str, object]) -> None:
    key = w.parse_vkey(str(case["vkey"]))
    if case["verifies"]:
        opened = w.open_note(str(case["note"]), [key])
        assert [s.name for s, _ in opened.verified] == [key.name]
    else:
        with pytest.raises(w.NoteError) as exc:
            w.open_note(str(case["note"]), [key])
        assert code(exc) == case["code"]


@pytest.mark.parametrize("case", VECTORS["vkeys"], ids=lambda c: c["id"])
def test_rfc6962_vkeys_match_transparency_dev(case: dict[str, str]) -> None:
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    public = load_der_public_key(base64.b64decode(case["spki"]))
    assert w.VerifierKey.rfc6962(case["name"], public).encode() == case["vkey"]
    assert w.parse_vkey(case["vkey"]).sig_type == w.SIG_RFC6962


@pytest.mark.parametrize("case", VECTORS["checkpoints"], ids=lambda c: c["id"])
def test_spec_checkpoint_parses(case: dict[str, object]) -> None:
    cp = w.parse_checkpoint(w.parse_note(str(case["note"])).text)
    assert (cp.origin, cp.size, cp.extensions) == (case["origin"], case["size"], ())


@pytest.mark.parametrize("start,end,valid", VECTORS["valid_subtrees"]["cases"])
def test_valid_subtree_matches_torchwood(start: int, end: int, valid: bool) -> None:
    assert w.valid_subtree(start, end) is valid


def test_witness_example_request_parses() -> None:
    body = ("old 20852014\nPlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=\njrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=\n"
            "5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=\n/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=\n\n"
            + VECTORS["checkpoints"][0]["note"])
    old, proof, note = w.parse_add_checkpoint(body)
    assert old == 20852014 and len(proof) == 4 and w.parse_checkpoint(w.parse_note(note).text).size == 20852163


# ---- verifier keys: one constructor per type the specs assign -------------------------------------------------
def test_every_assigned_type_has_a_constructor_that_round_trips() -> None:
    ed, ml = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    p256, rsa_key = ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 2048)
    keys = [w.VerifierKey.ed25519("a", ed.public_key()), w.VerifierKey.cosignature_v1("b", ed.public_key()),
            w.VerifierKey.mldsa44("c", ml.public_key()), w.VerifierKey.ecdsa("d", p256.public_key()),
            w.VerifierKey.rfc6962("e", p256.public_key()), w.VerifierKey.rfc6962("f", rsa_key.public_key())]
    assert [k.sig_type for k in keys] == [0x01, 0x04, 0x06, 0x02, 0x05, 0x05]
    for k in keys:
        assert w.parse_vkey(k.encode()) == k
    assert keys[0].public_key().public_bytes_raw() == ed.public_key().public_bytes_raw()


def test_an_ecdsa_key_id_is_the_spki_hash_and_an_rfc6962_one_the_log_id() -> None:
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    k2, k5 = w.VerifierKey.ecdsa("n", p256), w.VerifierKey.rfc6962("n", p256)
    assert k2.id == hashlib.sha256(k2.public).digest()[:4]
    assert k5.id == hashlib.sha256(b"n\n\x05" + hashlib.sha256(k5.public).digest()).digest()[:4]


@pytest.mark.parametrize("make,expected", [
    (lambda: w.VerifierKey.ecdsa("n", ec.generate_private_key(ec.SECP256K1()).public_key()), "vkey_curve_unsupported"),
    (lambda: w.VerifierKey.mldsa44("n", Ed25519PrivateKey.generate().public_key()), "vkey_type_mismatch"),
    (lambda: w.VerifierKey.ed25519("bad name", Ed25519PrivateKey.generate().public_key()), "note_name_invalid"),
    (lambda: w.parse_vkey("a+00000000+" + base64.b64encode(b"\x03" + b"\x00" * 32).decode()), "vkey_type_unknown"),
    (lambda: w.parse_vkey("a+00000000+" + base64.b64encode(b"\x01" + b"\x00" * 31).decode()), "vkey_key_length"),
    (lambda: w.parse_vkey("a+00000000+" + w.VerifierKey.ed25519("a", Ed25519PrivateKey.generate().public_key())
                          .encode().split("+", 2)[2]), "vkey_id_mismatch"),
    (lambda: w.parse_vkey("no-plus"), "vkey_malformed"),
])  # fmt: skip
def test_vkey_refusals_carry_codes(make: object, expected: str) -> None:
    with pytest.raises(w.NoteError) as exc:
        make()  # type: ignore[operator]
    assert code(exc) == expected


# ---- signing for every type -----------------------------------------------------------------------------------
def test_every_signature_type_signs_and_verifies() -> None:
    cp = w.Checkpoint(ORIGIN, 5, b"\x07" * 32)
    text = cp.text()
    ed, ml, p256 = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate(), ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(65537, 2048)
    pairs = [
        (w.VerifierKey.ed25519(ORIGIN, ed.public_key()), w.log_signature(text, ORIGIN, ed), None),
        (w.VerifierKey.ecdsa(ORIGIN, p256.public_key()), w.ecdsa_signature(text, ORIGIN, p256), None),
        (w.VerifierKey.rfc6962(ORIGIN, p256.public_key()), w.rfc6962_signature(cp, p256, 1_700_000_000_123), None),
        (w.VerifierKey.rfc6962(ORIGIN, rsa_key.public_key()), w.rfc6962_signature(cp, rsa_key, 5), None),
        (w.VerifierKey.cosignature_v1("w", ed.public_key()), w.cosign(text, "w", ed, NOW), NOW),
        (w.VerifierKey.mldsa44("m", ml.public_key()), w.cosign_mldsa(text, "m", ml, NOW), NOW),
    ]
    for key, line, ts in pairs:
        assert w.verify_line(key, text, line) == ts
        tampered = w.SigLine(line.name, line.key_id, line.sig[:-1] + bytes([line.sig[-1] ^ 1]))
        with pytest.raises(w.NoteError) as exc:
            w.verify_line(key, text, tampered)
        assert code(exc) in {"note_signature_invalid", "note_signature_length"}
    assert w.rfc6962_timestamp(pairs[2][1]) == 1_700_000_000_123


def test_sign_checkpoint_with_a_post_quantum_line_and_a_timestamp() -> None:
    ed, ml = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    note = w.sign_checkpoint(w.Checkpoint(ORIGIN, 2, b"\x01" * 32), ed, pq=ml, timestamp=NOW)
    policy = w.parse_policy(f"log {w.VerifierKey.ed25519(ORIGIN, ed.public_key()).encode()}\n"
                            f"log {w.VerifierKey.mldsa44(ORIGIN, ml.public_key()).encode()}\nquorum none\n")
    assert w.verify_note(note, policy).log_types == {w.SIG_ED25519, w.SIG_MLDSA44}


# ---- checkpoint extension lines ----------------------------------------------------------------------------
def test_extension_lines_round_trip_and_ed25519_signs_them() -> None:
    cp = w.Checkpoint(ORIGIN, 3, b"\x02" * 32, ("ext one", "ext-two"))
    assert w.parse_checkpoint(cp.text()) == cp
    ed, wit = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    note = w.attach(w.sign_checkpoint(cp, ed), w.cosign(cp.text(), "w", wit, NOW).encode())
    policy = w.parse_policy(f"log {w.VerifierKey.ed25519(ORIGIN, ed.public_key()).encode()}\n"
                            f"witness w {w.VerifierKey.cosignature_v1('w', wit.public_key()).encode()}\nquorum w\n")
    assert w.verify_note(note, policy).checkpoint.extensions == ("ext one", "ext-two")


def test_extension_lines_no_log_signature_covers_are_refused() -> None:
    ml = MLDSA44PrivateKey.generate()
    cp = w.Checkpoint(ORIGIN, 3, b"\x02" * 32, ("ext",))
    with pytest.raises(w.NoteError) as exc:
        w.cosign_mldsa(cp.text(), ORIGIN, ml, NOW)
    assert code(exc) == "checkpoint_extensions_unsigned"
    # a log that authenticates only post-quantum cannot vouch for extension lines it did not sign
    plain = w.Checkpoint(ORIGIN, 3, b"\x02" * 32)
    line = w.cosign_mldsa(plain.text(), ORIGIN, ml, NOW)
    note = w.Note(cp.text(), (line,)).encode()
    policy = w.parse_policy(f"log {w.VerifierKey.mldsa44(ORIGIN, ml.public_key()).encode()}\nquorum none\n")
    with pytest.raises(w.NoteError) as exc:
        w.verify_note(note, policy)
    assert code(exc) == "checkpoint_extensions_unsigned"


def test_an_rfc6962_signature_refuses_extension_lines() -> None:
    p256 = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(w.NoteError) as exc:
        w.rfc6962_signature(w.Checkpoint(ORIGIN, 1, b"\x00" * 32, ("x",)), p256, 1)
    assert code(exc) == "checkpoint_extensions_unsigned"


# ---- subtrees, inclusion and tlog-proof -----------------------------------------------------------------------
LEAVES = [w.leaf_hash(bytes([i])) for i in range(23)]


@pytest.mark.parametrize("start,end", [(0, 1), (8, 13), (0, 13), (16, 23), (4, 8), (20, 22), (5, 5)])
def test_subtree_consistency_proofs_verify_and_tampering_fails(start: int, end: int) -> None:
    size = len(LEAVES)
    proof = w.subtree_consistency_proof(start, end, LEAVES)
    sub = w.subtree_hash(LEAVES, start, end)
    assert w.verify_subtree_consistency(proof, size, w.root(LEAVES), start, end, sub)
    assert not w.verify_subtree_consistency(proof, size, w.root(LEAVES), start, end, b"\x00" * 32)
    if proof:
        assert not w.verify_subtree_consistency([b"\x01" * 32, *proof[1:]], size, w.root(LEAVES), start, end, sub)


def test_mldsa_subtree_cosignature_has_no_timestamp_and_commits_to_the_bounds() -> None:
    ml = MLDSA44PrivateKey.generate()
    key = w.VerifierKey.mldsa44("w", ml.public_key())
    sub = w.subtree_hash(LEAVES, 8, 13)
    sig = w.cosign_subtree("w", ml, ORIGIN, 8, 13, sub)
    assert w.verify_subtree_cosignature(key, ORIGIN, 8, 13, sub, sig)
    assert not w.verify_subtree_cosignature(key, ORIGIN, 8, 14, sub, sig)
    with pytest.raises(w.NoteError) as exc:
        w.cosign_subtree("w", ml, ORIGIN, 2, 6, sub)
    assert code(exc) == "subtree_invalid"
    with pytest.raises(w.NoteError) as exc:
        w.subtree_message("w", 1, ORIGIN, 8, 13, sub)
    assert code(exc) == "cosignature_input_range"


@pytest.mark.parametrize("index", [0, 1, 7, 12, 22])
def test_inclusion_proofs(index: int) -> None:
    proof = w.inclusion_proof(index, LEAVES)
    assert w.verify_inclusion(index, len(LEAVES), LEAVES[index], proof, w.root(LEAVES))
    assert not w.verify_inclusion(index, len(LEAVES), LEAVES[index - 1], proof, w.root(LEAVES))


def _signed(leaves: list[bytes]) -> tuple[str, w.Policy]:
    ed, wit = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    cp = w.Checkpoint(ORIGIN, len(leaves), w.root(leaves))
    note = w.attach(w.sign_checkpoint(cp, ed), w.cosign_mldsa(cp.text(), "w", wit, NOW).encode())
    policy = w.parse_policy(f"log {w.VerifierKey.ed25519(ORIGIN, ed.public_key()).encode()}\n"
                            f"witness w {w.VerifierKey.mldsa44('w', wit.public_key()).encode()}\nquorum w\n")
    return note, policy


def test_tlog_proof_round_trip_and_verify() -> None:
    note, policy = _signed(LEAVES)
    proof = w.TlogProof(index=9, proof=tuple(w.inclusion_proof(9, LEAVES)), checkpoint=note, extra=b"ctx")
    text = proof.encode()
    assert text.startswith("c2sp.org/tlog-proof@v1\nextra Y3R4\nindex 9\n")
    assert w.parse_tlog_proof(text) == proof
    assert w.verify_tlog_proof(text, LEAVES[9], policy).checkpoint.size == len(LEAVES)
    with pytest.raises(w.NoteError) as exc:
        w.verify_tlog_proof(text, LEAVES[8], policy)
    assert code(exc) == "proof_inclusion_invalid"
    with pytest.raises(w.NoteError) as exc:
        w.parse_tlog_proof("c2sp.org/tlog-proof@v2\n" + text.split("\n", 1)[1])
    assert code(exc) == "proof_malformed"


# ---- tlog-policy: URLs, octets, codes -----------------------------------------------------------------------
def test_policy_keeps_urls_and_reads_bytes() -> None:
    ed, wit = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    log = w.VerifierKey.ed25519(ORIGIN, ed.public_key()).encode()
    wk = w.VerifierKey.cosignature_v1("w", wit.public_key()).encode()
    policy = w.parse_policy(f"  # c\nlog {log} https://log.example/\nwitness X {wk} https://w.example/\nquorum X\n"
                            .encode())
    assert policy.log_urls == {log: "https://log.example/"} and policy.witness_urls == {"X": "https://w.example/"}


@pytest.mark.parametrize("text,expected", [
    ("quorum none\nquorum none\n", "policy_quorum_count"),
    ("", "policy_quorum_count"),
    ("quorum nobody\n", "policy_quorum_undefined"),
    ("group g any none\nquorum g\n", "policy_group_members"),
    ("frobnicate x\nquorum none\n", "policy_line_malformed"),
    ("quorum none\x0b\n", "policy_control_character"),
])  # fmt: skip
def test_policy_refusals_carry_codes(text: str, expected: str) -> None:
    with pytest.raises(w.NoteError) as exc:
        w.parse_policy(text)
    assert code(exc) == expected


def test_a_log_line_with_a_cosignature_only_key_is_refused() -> None:
    k = w.VerifierKey.cosignature_v1(ORIGIN, Ed25519PrivateKey.generate().public_key()).encode()
    with pytest.raises(w.NoteError) as exc:
        w.parse_policy(f"log {k}\nquorum none\n")
    assert code(exc) == "policy_key_type"


def test_ecdsa_and_rfc6962_logs_are_policy_logs() -> None:
    p256 = ec.generate_private_key(ec.SECP256R1())
    cp = w.Checkpoint(ORIGIN, 1, w.leaf_hash(b"x"))
    for key, line in [(w.VerifierKey.ecdsa(ORIGIN, p256.public_key()), w.ecdsa_signature(cp.text(), ORIGIN, p256)),
                      (w.VerifierKey.rfc6962(ORIGIN, p256.public_key()), w.rfc6962_signature(cp, p256, 9))]:
        policy = w.parse_policy(f"log {key.encode()}\nquorum none\n")
        assert w.verify_note(w.Note(cp.text(), (line,)).encode(), policy).log_types == {key.sig_type}


# ---- every refusal is a registered code -----------------------------------------------------------------------
def test_every_note_error_code_is_registered() -> None:
    raised = {"note_control_character", "note_malformed", "checkpoint_log_signature_missing",
              "witness_quorum_not_met", "note_signature_duplicate", "note_base64_noncanonical"}
    for c in raised:
        assert c in refusal_codes.CODES, c
    assert w.NoteError("witness_quorum_not_met:q:cosigned_by_none").code == "witness_quorum_not_met"


def test_verify_note_refusal_codes() -> None:
    note, policy = _signed(LEAVES)
    empty = w.parse_policy("quorum none\n")
    with pytest.raises(w.NoteError) as exc:
        w.verify_note(note, empty)
    assert code(exc) == "checkpoint_log_signature_missing"
    with pytest.raises(w.NoteError) as exc:
        w.verify_note(note, policy, now=NOW + 7200, max_age=3600)
    assert code(exc) == "witness_quorum_not_met"


# ---- tlog-witness: ML-DSA witness keys, sign-subtree, monitor retrieval --------------------------------------
def _witness(tmp_path: Path) -> tuple[w.Witness, Ed25519PrivateKey, MLDSA44PrivateKey]:
    log, wed, wml = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    witness = w.Witness("witness.example/w1", wml, {ORIGIN: [w.VerifierKey.ed25519(ORIGIN, log.public_key())]},
                        tmp_path, clock=FixedClock(NOW), more_keys=(wed,))
    return witness, log, wml


def test_a_witness_cosigns_with_every_key_and_serves_its_latest_checkpoint(tmp_path: Path) -> None:
    witness, log, _ = _witness(tmp_path)
    cp = w.Checkpoint(ORIGIN, len(LEAVES), w.root(LEAVES))
    note = w.sign_checkpoint(cp, log)
    response = witness.add_checkpoint(w.encode_add_checkpoint(0, [], note))
    lines = w.parse_note("x\n\n" + response).sigs
    assert len(lines) == 2
    keys = {(k.name, k.id): k for k in witness.vkeys}
    assert all(w.verify_line(keys[(s.name, s.key_id)], cp.text(), s) == NOW for s in lines)
    origin_hash = hashlib.sha256(ORIGIN.encode()).hexdigest()
    served = witness.latest_checkpoint(origin_hash)
    assert served is not None and len(w.parse_note(served).sigs) == 3
    assert witness.latest_checkpoint("00" * 32) is None
    restarted = w.Witness(witness.name, witness.key, witness.logs, tmp_path, clock=FixedClock(NOW))
    assert restarted.latest_checkpoint(origin_hash) == served


def test_sign_subtree_returns_a_cosignature_from_the_checkpoint_key(tmp_path: Path) -> None:
    witness, log, wml = _witness(tmp_path)
    cp = w.Checkpoint(ORIGIN, len(LEAVES), w.root(LEAVES))
    cosig = [s for s in w.parse_note("x\n\n" + witness.add_checkpoint(
        w.encode_add_checkpoint(0, [], w.sign_checkpoint(cp, log)))).sigs if len(s.sig) > 72][0]
    reference = w.Note(cp.text(), (cosig,)).encode()
    sub = w.subtree_hash(LEAVES, 8, 13)
    body = w.encode_sign_subtree(8, 13, sub, w.subtree_consistency_proof(8, 13, LEAVES), reference)
    sig = base64.b64decode(witness.sign_subtree(body))
    assert w.verify_subtree_cosignature(w.VerifierKey.mldsa44(witness.name, wml.public_key()), ORIGIN, 8, 13, sub, sig)
    with pytest.raises(w.WitnessRefused) as exc:
        witness.sign_subtree(w.encode_sign_subtree(8, 13, b"\x00" * 32, w.subtree_consistency_proof(8, 13, LEAVES),
                                                   reference))
    assert exc.value.status == 422 and exc.value.code == "witness_subtree_proof_invalid"
    with pytest.raises(w.WitnessRefused) as exc:
        witness.sign_subtree(w.encode_sign_subtree(2, 6, sub, [], reference))
    assert exc.value.status == 400 and exc.value.code == "witness_subtree_invalid"


@pytest.mark.parametrize("mutate,status,expected", [
    (lambda b: b.replace("old 0", "old 01"), 400, "witness_request_malformed"),
    (lambda b: b.replace(ORIGIN, "other.example/log"), 404, "witness_origin_unknown"),
])  # fmt: skip
def test_add_checkpoint_refusals_carry_codes(tmp_path: Path, mutate: object, status: int, expected: str) -> None:
    witness, log, _ = _witness(tmp_path)
    body = w.encode_add_checkpoint(0, [], w.sign_checkpoint(w.Checkpoint(ORIGIN, 1, LEAVES[0]), log))
    with pytest.raises(w.WitnessRefused) as exc:
        witness.add_checkpoint(mutate(body))  # type: ignore[operator]
    assert (exc.value.status, exc.value.code) == (status, expected)


# ---- property tests: parse(serialize(x)) == x ----------------------------------------------------------------
NAMES = st.text(st.characters(min_codepoint=0x21, max_codepoint=0x7E, exclude_characters="+"), min_size=1, max_size=40)
EXTENSION = st.text(st.characters(min_codepoint=0x20, max_codepoint=0x2FFF, exclude_categories=("Cs",)), min_size=1,
                    max_size=30)


@settings(max_examples=200, deadline=None)
@given(NAMES, st.integers(0, 2**63 - 1), st.binary(min_size=32, max_size=32), st.lists(EXTENSION, max_size=3))
def test_checkpoint_round_trip(origin: str, size: int, root: bytes, ext: list[str]) -> None:
    cp = w.Checkpoint(origin, size, root, tuple(ext))
    assert w.parse_checkpoint(cp.text()) == cp


@settings(max_examples=200, deadline=None)
@given(st.text(st.characters(min_codepoint=0x20, max_codepoint=0x2FFF, exclude_categories=("Cs",)), max_size=40),
       st.lists(st.tuples(NAMES, st.binary(min_size=4, max_size=4), st.binary(min_size=1, max_size=80)), min_size=1,
                max_size=8, unique_by=lambda t: (t[0], t[1])))
def test_note_round_trip(body: str, sigs: list[tuple[str, bytes, bytes]]) -> None:
    note = w.Note(body + "\n", tuple(w.SigLine(n, k, s) for n, k, s in sigs))
    assert w.parse_note(note.encode()) == note


@settings(max_examples=100, deadline=None)
@given(NAMES, st.sampled_from([w.SIG_ED25519, w.SIG_COSIGNATURE_V1]), st.binary(min_size=32, max_size=32))
def test_vkey_round_trip(name: str, sig_type: int, public: bytes) -> None:
    key = w.VerifierKey(name, sig_type, public)
    assert w.parse_vkey(key.encode()) == key


@settings(max_examples=100, deadline=None)
@given(st.integers(0, 40), st.binary(max_size=20), st.data())
def test_tlog_proof_round_trip(size: int, extra: bytes, data: st.DataObject) -> None:
    leaves = [w.leaf_hash(bytes([i])) for i in range(size + 1)]
    index = data.draw(st.integers(0, size))
    proof = w.TlogProof(index, tuple(w.inclusion_proof(index, leaves)), VECTORS["checkpoints"][0]["note"],
                        extra or None)
    assert w.parse_tlog_proof(proof.encode()) == proof
    assert w.verify_inclusion(index, len(leaves), leaves[index], list(proof.proof), w.root(leaves))


@settings(max_examples=150, deadline=None)
@given(st.integers(1, 70), st.data())
def test_subtree_proof_property(size: int, data: st.DataObject) -> None:
    leaves = [w.leaf_hash(i.to_bytes(2, "big")) for i in range(size)]
    end = data.draw(st.integers(1, size))
    width = 1 << (end - 1).bit_length() if end > 1 else 1
    starts = [s for s in range(0, end) if w.valid_subtree(s, end)]
    start = data.draw(st.sampled_from(starts))
    assert width >= 1
    proof = w.subtree_consistency_proof(start, end, leaves)
    assert w.verify_subtree_consistency(proof, size, w.root(leaves), start, end, w.subtree_hash(leaves, start, end))


@settings(max_examples=100, deadline=None)
@given(st.integers(0, 60), st.data())
def test_consistency_proof_property(size: int, data: st.DataObject) -> None:
    leaves = [w.leaf_hash(i.to_bytes(2, "big")) for i in range(size)]
    old = data.draw(st.integers(0, size))
    proof = w.consistency_proof(old, leaves)
    assert w.verify_consistency(old, size, w.root(leaves[:old]), w.root(leaves), proof)


@settings(max_examples=100, deadline=None)
@given(st.integers(0, 2**63 - 1), st.integers(0, 20), st.lists(st.binary(min_size=32, max_size=32), max_size=63))
def test_add_checkpoint_round_trip(old: int, _n: int, proof: list[bytes]) -> None:
    note = VECTORS["checkpoints"][0]["note"]
    assert w.parse_add_checkpoint(w.encode_add_checkpoint(old, proof, note)) == (old, proof, note)
