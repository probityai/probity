"""Independent soundness review of the C2SP witness surface: each test builds an input the specification refuses
(or accepts) and states the verdict the specification gives. Sources are c2sp.org/signed-note, tlog-checkpoint,
tlog-cosignature, tlog-policy and tlog-witness at C2SP d35150e7, and filippo.io/torchwood at 1c05157b."""

from __future__ import annotations

import base64
import hashlib
import io
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey
from probity_records import refusal_codes
from probity_records import witness as w
from probity_records.clock import NS_PER_S

ORIGIN = "example.com/log"
NOW = 1_800_000_000


class FixedClock:
    def __init__(self, seconds: int = NOW) -> None:
        self.seconds = seconds

    def now(self) -> int:
        return self.seconds * NS_PER_S


def _leaves(n: int, salt: str = "") -> list[bytes]:
    return [w.leaf_hash(f"{salt}leaf {i}".encode()) for i in range(n)]


def _log_note(log: Ed25519PrivateKey, leaves: list[bytes], origin: str = ORIGIN) -> str:
    return w.sign_checkpoint(w.Checkpoint(origin, len(leaves), w.root(leaves)), log)


def _witness(key: object, log: Ed25519PrivateKey, origin: str = ORIGIN, **kwargs: object) -> w.Witness:
    logs = {origin: [w.VerifierKey.ed25519(origin, log.public_key())]}
    return w.Witness("witness.example/w", key, logs, clock=FixedClock(), **kwargs)  # type: ignore[arg-type]


def _policy(log: Ed25519PrivateKey, witnesses: dict[str, w.VerifierKey], tail: str) -> w.Policy:
    lines = [f"log {w.VerifierKey.ed25519(ORIGIN, log.public_key()).encode()}"]
    lines += [f"witness {name} {key.encode()}" for name, key in witnesses.items()]
    return w.parse_policy("\n".join(lines) + "\n" + tail)


# ---- tlog-policy: "Each defined name can be listed as a group member at most once" -------------------------------
def test_a_policy_that_lists_one_witness_in_two_groups_is_refused() -> None:
    """With w1 in both groups, w1 alone meets ``all g1 g2``; the specification forbids the reuse so that each
    witness contributes to the quorum in only one way, and torchwood refuses the same policy at lookup."""
    log = Ed25519PrivateKey.generate()
    keys = {f"w{i}": w.VerifierKey.cosignature_v1(f"w{i}", Ed25519PrivateKey.generate().public_key())
            for i in (1, 2, 3)}
    tail = "group g1 any w1 w2\ngroup g2 any w1 w3\ngroup q all g1 g2\nquorum q\n"
    with pytest.raises(w.NoteError) as exc:
        _policy(log, keys, tail)
    assert exc.value.code == "policy_group_members"


# ---- tlog-cosignature: timestamp zero with start zero is a subtree cosignature, not a checkpoint one --------------
def test_a_subtree_cosignature_is_not_counted_as_a_checkpoint_cosignature() -> None:
    """A witness that cosigned size 4 never cosigns the checkpoint of size 2 afterwards (cosignatures are monotonic),
    yet ``sign-subtree`` gives its signature over ``[0, 2)`` with timestamp 0. Those are the bytes of a checkpoint
    cosignature of size 2 dated 0, so a verifier that counts it accepts a rollback the witness refused."""
    log, wkey = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    witness = _witness(wkey, log)
    leaves = _leaves(4)
    note4 = _log_note(log, leaves)
    lines = witness.add_checkpoint(w.encode_add_checkpoint(0, [], note4))
    text4 = w.parse_note(note4).text
    reference = w.Note(text4, w.parse_note("x\n\n" + lines).sigs).encode()
    body = w.encode_sign_subtree(0, 2, w.subtree_hash(leaves, 0, 2), w.subtree_consistency_proof(0, 2, leaves),
                                 reference)
    subtree_sig = base64.b64decode(witness.sign_subtree(body))
    old = _log_note(log, leaves[:2])  # the log's own earlier checkpoint, which this witness never cosigned
    with pytest.raises(w.WitnessRefused):
        witness.add_checkpoint(w.encode_add_checkpoint(0, [], old))
    forged = w.SigLine(witness.name, witness.vkey.id, bytes(8) + subtree_sig)
    parsed = w.parse_note(old)
    policy = _policy(log, {"w": witness.vkey}, "quorum w\n")
    with pytest.raises(w.NoteError) as exc:
        w.verify_note(w.Note(parsed.text, (*parsed.sigs, forged)).encode(), policy)
    assert exc.value.code in {"witness_quorum_not_met", "note_signature_invalid"}


# ---- empty subtrees and the empty tree -------------------------------------------------------------------------
def _subtree_bytes(name: str, origin: str, start: int, end: int, digest: bytes) -> bytes:
    return b"".join([w.SUBTREE_LABEL, bytes([len(name)]), name.encode(), bytes(8), bytes([len(origin)]),
                     origin.encode(), start.to_bytes(8, "big"), end.to_bytes(8, "big"), digest])


def test_an_empty_subtree_is_signed_and_verified_only_with_the_empty_hash() -> None:
    """torchwood: "the hash of an empty subtree must be the hash of the empty string"."""
    key = MLDSA44PrivateKey.generate()
    vk = w.VerifierKey.mldsa44("w", key.public_key())
    wrong = b"\x11" * 32
    with pytest.raises(w.NoteError):
        w.cosign_subtree("w", key, ORIGIN, 5, 5, wrong)
    sig = key.sign(_subtree_bytes("w", ORIGIN, 5, 5, wrong))
    assert not w.verify_subtree_cosignature(vk, ORIGIN, 5, 5, wrong, sig)


def test_a_size_zero_checkpoint_with_another_root_is_refused() -> None:
    """RFC 6962 section 2.1: the hash of the empty tree is the hash of the empty string, so no other root is the
    root of a tree of size 0 (c2sp.org/tlog-witness refuses it with 422; torchwood's verifier refuses the line)."""
    log, wkey = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    vk = w.VerifierKey.mldsa44("w", wkey.public_key())
    wrong = b"\x11" * 32
    note = w.sign_checkpoint(w.Checkpoint(ORIGIN, 0, wrong), log)
    parsed = w.parse_note(note)
    line = w.SigLine("w", vk.id, bytes(8) + wkey.sign(_subtree_bytes("w", ORIGIN, 0, 0, wrong)))
    with pytest.raises(w.NoteError):
        w.verify_line(vk, parsed.text, line)
    with pytest.raises(w.NoteError):
        w.verify_note(note, _policy(log, {}, "quorum none\n"))


# ---- tlog-witness: a witness never forgets what it cosigned ------------------------------------------------------
def test_a_restarted_witness_remembers_a_log_with_a_long_origin(tmp_path: Path) -> None:
    """An origin may be 255 bytes. Its state file is named by the hex of the origin, which is past the 255-byte
    file-name limit from 123 bytes on: the cosigned checkpoint is published for monitors, the state write fails, and
    the restarted witness cosigns a fork from size 0 and publishes that too."""
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    origin = "example.com/" + "a" * 188
    origin_hash = hashlib.sha256(origin.encode()).hexdigest()
    assert w.valid_name(origin)
    served = []
    for leaves in (_leaves(2), _leaves(1, "fork ")):
        witness = _witness(key, log, origin, state_dir=tmp_path)  # a restart: state comes from the directory
        try:
            witness.add_checkpoint(w.encode_add_checkpoint(0, [], _log_note(log, leaves, origin)))
        except (OSError, w.WitnessRefused):
            pass
        note = witness.latest_checkpoint(origin_hash)
        if note is not None:
            parsed = w.parse_note(note)
            cosigned = [s for s in parsed.sigs if (s.name, s.key_id) == (witness.name, witness.vkey.id)]
            assert cosigned and w.verify_line(witness.vkey, parsed.text, cosigned[0]) == NOW
            served.append(w.parse_checkpoint(parsed.text))
    roots = {(cp.size, cp.root) for cp in served}
    assert len(roots) <= 1, f"the witness cosigned and served two inconsistent trees: sizes {[c.size for c in served]}"


def test_two_witness_processes_on_one_state_directory_do_not_roll_back(tmp_path: Path) -> None:
    """c2sp.org/tlog-witness: checking the old size and persisting the new checkpoint is atomic. Two live Witness
    objects over one directory each trust their own memory, so the second cosigns a fork of what the first signed."""
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    first = _witness(key, log, state_dir=tmp_path)
    second_ready = _witness(key, log, state_dir=tmp_path)
    first.add_checkpoint(w.encode_add_checkpoint(0, [], _log_note(log, _leaves(2))))
    with pytest.raises((w.WitnessRefused, w.NoteError, OSError)):
        second_ready.add_checkpoint(w.encode_add_checkpoint(0, [], _log_note(log, _leaves(1, "fork "))))


# ---- tlog-witness monitor retrieval ----------------------------------------------------------------------------
def test_the_monitor_checkpoint_holds_only_lines_the_witness_verified_or_made() -> None:
    """The served checkpoint "MUST include the cosignature(s) from the witness's key(s) ... and the cosignature from
    the log key(s) that the witness verified". Anyone may resubmit the current checkpoint (old = size), so lines the
    witness did not verify let a stranger replace the monitors' view with a note their verifier rejects."""
    log, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    witness = _witness(Ed25519PrivateKey.generate(), log)
    other_key = w.VerifierKey.cosignature_v1("other.example/w", other.public_key())
    note = _log_note(log, _leaves(3))
    witness.add_checkpoint(w.encode_add_checkpoint(0, [], note))
    parsed = w.parse_note(note)
    junk = w.SigLine(other_key.name, other_key.id, bytes(72))
    poisoned = w.Note(parsed.text, (*parsed.sigs, junk)).encode()
    witness.add_checkpoint(w.encode_add_checkpoint(3, [], poisoned))
    served = witness.latest_checkpoint(hashlib.sha256(ORIGIN.encode()).hexdigest())
    assert served is not None
    policy = _policy(log, {"w": witness.vkey, "other": other_key}, "quorum w\n")
    assert w.verify_note(served, policy).checkpoint.size == 3
    assert {(s.name, s.key_id) for s in w.parse_note(served).sigs} == {
        (ORIGIN, parsed.sigs[0].key_id), (witness.name, witness.vkey.id)}


def test_the_monitor_checkpoint_stays_within_the_signature_limit() -> None:
    log = Ed25519PrivateKey.generate()
    witness = _witness(Ed25519PrivateKey.generate(), log)
    note = _log_note(log, _leaves(3))
    parsed = w.parse_note(note)
    junk = tuple(w.SigLine(f"stranger{i}.example", bytes(4), bytes(64)) for i in range(w.MAX_SIGNATURES - 1))
    witness.add_checkpoint(w.encode_add_checkpoint(0, [], w.Note(parsed.text, (*parsed.sigs, *junk)).encode()))
    served = witness.latest_checkpoint(hashlib.sha256(ORIGIN.encode()).hexdigest())
    assert served is not None
    assert w.parse_note(served).text == parsed.text


# ---- tlog-witness sign-subtree: "MUST be from the same witness key that signed the checkpoint" --------------------
def _subtree_request(witness: w.Witness, log: Ed25519PrivateKey, line_of: int) -> tuple[str, list[bytes]]:
    leaves = _leaves(4)
    note = _log_note(log, leaves)
    lines = w.parse_note("x\n\n" + witness.add_checkpoint(w.encode_add_checkpoint(0, [], note))).sigs
    reference = w.Note(w.parse_note(note).text, (lines[line_of],)).encode()
    return w.encode_sign_subtree(2, 4, w.subtree_hash(leaves, 2, 4), w.subtree_consistency_proof(2, 4, leaves),
                                 reference), leaves


def test_a_subtree_cosignature_comes_from_the_key_that_cosigned_the_checkpoint() -> None:
    log = Ed25519PrivateKey.generate()
    witness = _witness(MLDSA44PrivateKey.generate(), log, more_keys=(MLDSA44PrivateKey.generate(),))
    body, leaves = _subtree_request(witness, log, 1)
    sig = base64.b64decode(witness.sign_subtree(body))
    assert w.verify_subtree_cosignature(witness.vkeys[1], ORIGIN, 2, 4, w.subtree_hash(leaves, 2, 4), sig)


def test_an_ed25519_cosigned_reference_gets_no_ml_dsa_subtree_cosignature() -> None:
    """An Ed25519 cosigner "can only generate checkpoint cosignatures"; the key that signed the reference cannot sign
    a subtree, and another key's signature is not what the specification promises."""
    log = Ed25519PrivateKey.generate()
    witness = _witness(MLDSA44PrivateKey.generate(), log, more_keys=(Ed25519PrivateKey.generate(),))
    body, _ = _subtree_request(witness, log, 1)
    with pytest.raises(w.WitnessRefused):
        witness.sign_subtree(body)


# ---- the feed: one faulty witness does not veto a quorum the others meet ------------------------------------------
def _feed(tmp_path: Path, log: Ed25519PrivateKey, honest: w.Witness, faulty_key: w.VerifierKey,
          faulty: object) -> w.Feed:
    journal_path = tmp_path / "journal.jsonl"
    journal_path.write_text("one\ntwo\nthree\n")
    journal = SimpleNamespace(directory=tmp_path, path=journal_path, signer=log)
    policy = _policy(log, {"bad": faulty_key, "good": honest.vkey}, "group g any bad good\nquorum g\n")

    def poster(url: str, body: str) -> str:
        return faulty(body) if url == "bad" else honest.add_checkpoint(body)  # type: ignore[operator]

    pairs = [("bad", faulty_key.encode()), ("good", honest.vkey.encode())]
    return w.Feed(journal, ORIGIN, pairs, policy=policy, poster=poster)


def test_a_witness_that_answers_with_another_witness_line_does_not_stop_the_feed(tmp_path: Path) -> None:
    """"The client MUST ignore any signatures from unknown keys": the feed asked witness ``bad``, so a line under
    another name is not from the key it asked. Kept, it collides with the honest witness's real line and the
    any-of-two quorum the honest witness meets alone is never published."""
    log = Ed25519PrivateKey.generate()
    honest = _witness(Ed25519PrivateKey.generate(), log)
    faulty_key = w.VerifierKey.cosignature_v1("bad.example/w", Ed25519PrivateKey.generate().public_key())
    impostor = w.SigLine(honest.name, honest.vkey.id, bytes(72)).encode()
    feed = _feed(tmp_path, log, honest, faulty_key, lambda _body: impostor)
    assert set(w.verify_note(feed.publish(), feed.policy).cosigned_at) == {"good"}  # type: ignore[arg-type]


def test_a_witness_that_answers_409_with_a_non_ascii_digit_does_not_crash_the_feed(tmp_path: Path) -> None:
    log = Ed25519PrivateKey.generate()
    honest = _witness(Ed25519PrivateKey.generate(), log)
    faulty_key = w.VerifierKey.cosignature_v1("bad.example/w", Ed25519PrivateKey.generate().public_key())

    def faulty(_body: str) -> str:
        raise w.WitnessRefused(409, "witness_old_size_mismatch", "²\n")

    feed = _feed(tmp_path, log, honest, faulty_key, faulty)
    assert set(w.verify_note(feed.publish(), feed.policy).cosigned_at) == {"good"}  # type: ignore[arg-type]


# ---- signed-note: lines from unknown keys are ignored -------------------------------------------------------------
def test_an_unknown_key_with_a_long_name_does_not_reject_a_note() -> None:
    """c2sp.org/signed-note puts no length limit on a key name (the 255-byte limit belongs to cosigner names), and
    "Verifiers MUST ignore signatures from unknown keys"."""
    key = Ed25519PrivateKey.generate()
    text = "a note\n"
    known = w.log_signature(text, "known.example", key)
    stranger = w.SigLine("s" * 300, bytes(4), bytes(64))
    opened = w.open_note(w.Note(text, (known, stranger)).encode(), [w.VerifierKey.ed25519("known.example",
                                                                                           key.public_key())])
    assert [s.name for s, _ in opened.verified] == ["known.example"] and len(opened.unknown) == 1


# ---- refusal codes: every code a caller reads is registered -------------------------------------------------------
def test_a_client_refusal_code_is_registered_whatever_the_remote_witness_says() -> None:
    def opener(req: object, timeout: float = 0) -> object:
        raise urllib.error.HTTPError("http://w.example", 409, "Conflict", None, io.BytesIO(b"7\n"))  # type: ignore[arg-type]

    with pytest.raises(w.WitnessRefused) as exc:
        w.add_checkpoint("http://w.example", "old 0\n\n", opener=opener)
    assert exc.value.status == 409 and exc.value.body == "7\n"
    assert exc.value.code in refusal_codes.CODES


def test_a_decimal_too_long_for_python_is_a_coded_refusal() -> None:
    """Past 4300 digits ``int()`` raises a bare ValueError, which carries no code and which the witness server does
    not turn into a 400."""
    digits = "9" * 5000
    root = base64.b64encode(bytes(32)).decode()
    with pytest.raises(w.NoteError) as exc:
        w.parse_checkpoint(f"{ORIGIN}\n{digits}\n{root}\n")
    assert exc.value.code == "note_decimal_invalid"
    with pytest.raises(w.WitnessRefused) as refused:
        w.parse_add_checkpoint(f"old {digits}\n\n")
    assert refused.value.status == 400


def test_a_crash_between_the_two_state_writes_does_not_roll_the_witness_back(tmp_path: Path) -> None:
    """``_save`` writes the cosigned checkpoint (served to monitors) and then the size and root it checks the next
    request against. A crash between the two leaves size 4 published and size 2 remembered."""
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    leaves = _leaves(4)
    witness = _witness(key, log, state_dir=tmp_path)
    witness.add_checkpoint(w.encode_add_checkpoint(0, [], _log_note(log, leaves[:2])))
    before = {p.name: p.read_bytes() for p in tmp_path.glob("*.state")}
    witness.add_checkpoint(w.encode_add_checkpoint(2, w.consistency_proof(2, leaves), _log_note(log, leaves)))
    for name, data in before.items():  # the crash: the checkpoint of size 4 is on disk, the state write is lost
        (tmp_path / name).write_bytes(data)
    restarted = _witness(key, log, state_dir=tmp_path)
    served = restarted.latest_checkpoint(hashlib.sha256(ORIGIN.encode()).hexdigest())
    assert served is not None and w.parse_checkpoint(w.parse_note(served).text).size == 4
    fork = [*leaves[:2], w.leaf_hash(b"fork")]
    with pytest.raises(w.WitnessRefused) as exc:
        restarted.add_checkpoint(w.encode_add_checkpoint(2, w.consistency_proof(2, fork), _log_note(log, fork)))
    assert exc.value.status == 409


def test_a_sign_subtree_reference_with_two_signatures_is_a_bad_request() -> None:
    """"The checkpoint MUST include exactly one note signature ... If the request is invalid according to the rules
    above, the witness MUST respond with a 400"."""
    log = Ed25519PrivateKey.generate()
    witness = _witness(MLDSA44PrivateKey.generate(), log)
    leaves = _leaves(4)
    note = _log_note(log, leaves)
    cosigned = w.attach(note, witness.add_checkpoint(w.encode_add_checkpoint(0, [], note)))
    body = w.encode_sign_subtree(2, 4, w.subtree_hash(leaves, 2, 4), w.subtree_consistency_proof(2, 4, leaves),
                                 cosigned)
    with pytest.raises(w.WitnessRefused) as exc:
        witness.sign_subtree(body)
    assert exc.value.status == 400
