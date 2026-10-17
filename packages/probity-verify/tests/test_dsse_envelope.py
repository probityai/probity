"""``probity verify`` on a DSSE envelope: signature first, then the claim in its payload.

``data/dsse_cross_lang_signing.json`` is copied from probityai/dsse at fdec7b9
(``vectors/cross_lang_signing.json``); the reference Go implementation made it.
"""

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from probity_verify import dsse
from probity_verify.cli import main
from probity_verify.common import CaseError

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "examples/dsse-bundle"
DONE = ROOT / "examples/done-receipt"
CROSS = json.loads((Path(__file__).parent / "data/dsse_cross_lang_signing.json").read_text())
TABLE = json.loads((VECTORS / "vectors.json").read_text())

# Written by hand, not derived from the generator.
EXPECTED = {
    "valid": (0, "supported", "done_checks_supported"),
    "tampered-receipt": (0, "contradicted", "external_effect_on_grader_path"),
    "tampered-payload": (0, "not_established", "dsse_signature_unverified"),
    "wrong-key": (0, "not_established", "dsse_signature_unverified"),
    "wrong-payload-type": (0, "not_established", "dsse_payload_type_unexpected"),
    "malformed-no-signatures": (2, None, None),
    "malformed-unpadded-base64": (2, None, None),
}


def _run(capsysbinary, envelope, case, policy, *keys):
    argv = [str(envelope), "--case", str(case), "--policy", str(policy), "--json"]
    for key in keys:
        argv += ["--key", str(key)]
    status = main(argv)
    out, err = capsysbinary.readouterr()
    return status, out, err


def test_every_vector_has_a_hand_written_expectation():
    assert set(TABLE) == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_vector_output_is_byte_exact(capsysbinary, name):
    row = TABLE[name]
    status, out, err = _run(capsysbinary, VECTORS / f"{name}.dsse.json", VECTORS / row["case"],
                            VECTORS / row["policy"], VECTORS / row["key"])
    code, decision, reason = EXPECTED[name]
    assert status == code == row["exit"]
    shown = out if code == 0 else err
    assert shown.replace(str(VECTORS).encode(), b"<vectors>") == (
        VECTORS / row["expected"]).read_bytes()
    if code == 0:
        result = json.loads(out)
        assert (result["decision"], result["reason"]) == (decision, reason)
        assert result["checks"][0]["id"] == "dsse_envelope"


def test_a_verified_bundle_gives_the_same_verdict_as_the_bare_receipt(capsysbinary):
    for run in ("honest", "tampered-grader"):
        bare = main([str(DONE / run / "receipt.case.json"), "--policy",
                     str(DONE / run / "receipt.policy.json"), "--json"])
        plain = json.loads(capsysbinary.readouterr().out)
        name = "valid" if run == "honest" else "tampered-receipt"
        status, out, _ = _run(capsysbinary, VECTORS / f"{name}.dsse.json",
                              DONE / run / "receipt.case.json",
                              DONE / run / "receipt.policy.json", VECTORS / "signer.pub")
        wrapped = json.loads(out)
        assert bare == status == 0
        envelope_check = wrapped["checks"].pop(0)
        assert wrapped["scope"].pop("envelope") == envelope_check
        assert wrapped == plain


def test_the_signed_payload_is_read_not_the_file_on_disk(tmp_path, capsysbinary):
    # A copy of the honest run whose receipt.json on disk is gone: the verdict
    # can only come from the envelope's payload.
    run = tmp_path / "honest"
    run.mkdir()
    for path in (DONE / "honest").iterdir():
        if path.name != "receipt.json":
            (run / path.name).write_bytes(path.read_bytes())
    status, out, _ = _run(capsysbinary, VECTORS / "valid.dsse.json", run / "receipt.case.json",
                          run / "receipt.policy.json", VECTORS / "signer.pub")
    assert status == 0
    assert json.loads(out)["decision"] == "supported"


def test_a_payload_no_check_reads_is_refused(capsysbinary):
    # The honest receipt signed, checked against a case that does not name it.
    status, _, err = _run(capsysbinary, VECTORS / "valid.dsse.json",
                          DONE / "honest/protected-paths.case.json",
                          DONE / "honest/protected-paths.policy.json", VECTORS / "signer.pub")
    assert status == 2
    assert b"envelope payload is not an artifact the claim reads" in err


def test_any_key_of_a_keyring_may_accept(capsysbinary):
    status, out, _ = _run(capsysbinary, VECTORS / "valid.dsse.json",
                          DONE / "honest/receipt.case.json", DONE / "honest/receipt.policy.json",
                          VECTORS / "other.pub", VECTORS / "signer.pub")
    assert status == 0
    assert json.loads(out)["decision"] == "supported"


def test_an_envelope_needs_a_key_and_a_case(capsysbinary):
    status = main([str(VECTORS / "valid.dsse.json"), "--policy",
                   str(DONE / "honest/receipt.policy.json"), "--case",
                   str(DONE / "honest/receipt.case.json")])
    assert status == 2
    assert b"at least one --key" in capsysbinary.readouterr().err
    status = main([str(VECTORS / "valid.dsse.json"), "--policy",
                   str(DONE / "honest/receipt.policy.json"), "--key", str(VECTORS / "signer.pub")])
    assert status == 2
    assert b"needs --case" in capsysbinary.readouterr().err


def test_envelope_flags_are_refused_on_a_case_input(capsysbinary):
    status = main([str(DONE / "honest/receipt.case.json"), "--policy",
                   str(DONE / "honest/receipt.policy.json"), "--key", str(VECTORS / "signer.pub")])
    assert status == 2
    assert b"apply only to a DSSE envelope" in capsysbinary.readouterr().err


def test_a_raw_32_byte_key_is_accepted(tmp_path, capsysbinary):
    pem = (VECTORS / "signer.pub").read_bytes()
    raw = dsse.load_key(pem, "k").public_bytes(Encoding.Raw, PublicFormat.Raw)
    (tmp_path / "raw.pub").write_bytes(raw)
    status, out, _ = _run(capsysbinary, VECTORS / "valid.dsse.json",
                          DONE / "honest/receipt.case.json", DONE / "honest/receipt.policy.json",
                          tmp_path / "raw.pub")
    assert status == 0 and json.loads(out)["decision"] == "supported"


@pytest.mark.parametrize("fixture", CROSS["fixtures"], ids=lambda f: f["name"])
def test_reference_go_fixtures_verify(fixture):
    key = dsse.load_key(CROSS["public_key_pem"].encode(), "cross")
    kind, payload, signatures = dsse.parse(fixture["envelope"])
    assert kind == fixture["payload_type"]
    assert dsse.pae(kind, payload) == base64.b64decode(fixture["pae_b64"])
    assert dsse.accepting_keys([key], dsse.pae(kind, payload), signatures) == [dsse.key_id(key)]


def test_pae_counts_bytes_not_characters():
    assert dsse.pae("té", "é".encode()) == "DSSEv1 3 té 2 é".encode()


@pytest.mark.parametrize("text, ok", [
    ("eA==", True), ("eB==", False), ("eA", False), ("eA==\n", False),
    ("_-8=", True), ("/+8=", True), ("", True),
])
def test_base64_must_be_canonical(text, ok):
    if ok:
        dsse.decode_b64(text, "f")
    else:
        with pytest.raises(CaseError):
            dsse.decode_b64(text, "f")


def test_one_key_counts_once_and_keyid_is_never_read():
    key = Ed25519PrivateKey.from_private_bytes(bytes(32))
    payload = b"{}"
    sig = key.sign(dsse.pae(dsse.IN_TOTO_PAYLOAD_TYPE, payload))
    signatures = [sig, sig]
    assert dsse.accepting_keys([key.public_key()], dsse.pae(dsse.IN_TOTO_PAYLOAD_TYPE, payload),
                               signatures) == [dsse.key_id(key.public_key())]
    envelope = {"payload": base64.b64encode(payload).decode(), "payloadType": "x",
                "signatures": [{"keyid": "not-this-key", "sig": base64.b64encode(sig).decode()}]}
    assert dsse.parse(envelope)[2] == [sig]


@pytest.mark.parametrize("envelope, message", [
    ({"payload": "", "payloadType": "", "signatures": [{"sig": ""}]}, "payloadType"),
    ({"payload": "", "payloadType": "x", "signatures": [{}]}, "with sig"),
    ({"payload": "", "payloadType": "x", "signatures": [{"sig": ""}] * 1025}, "more than"),
    ({"payload": "", "payloadType": "x"}, "expected payload"),
])
def test_malformed_envelopes_are_refused(envelope, message):
    with pytest.raises(CaseError, match=message):
        dsse.parse(envelope)


def test_a_non_ed25519_pem_key_is_refused():
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(CaseError, match="only Ed25519"):
        dsse.load_key(pem, "k")
    with pytest.raises(CaseError, match="raw or PEM"):
        dsse.load_key(b"not a key", "k")


def test_generator_reproduces_the_committed_bytes():
    completed = subprocess.run([sys.executable, str(VECTORS / "generate.py"), "--check"],
                               capture_output=True, text=True, check=False)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_one_key_supplied_twice_is_one_accepting_key():
    key = dsse.load_key((VECTORS / "signer.pub").read_bytes(), "k")
    kind, payload, signatures = dsse.parse(json.loads((VECTORS / "valid.dsse.json").read_text()))
    assert dsse.accepting_keys([key, key], dsse.pae(kind, payload), signatures) == [
        dsse.key_id(key)]


def test_supplied_bytes_must_match_their_digest():
    from probity_verify.common import supplied_artifacts

    with pytest.raises(CaseError, match="do not match their digest"):
        with supplied_artifacts({"0" * 64: b"x"}):
            pass
