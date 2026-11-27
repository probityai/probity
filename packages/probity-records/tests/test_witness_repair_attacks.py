"""Attempts to get past each repair of the witness soundness review. Every test builds the nearest input the repaired
check might still let through and states the verdict the specification gives. Sources: c2sp.org/signed-note,
tlog-checkpoint, tlog-cosignature, tlog-policy and tlog-witness at C2SP d35150e7."""

from __future__ import annotations

import base64
import hashlib
import http.client
import io
import os
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Self

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey
from probity_records import refusal_codes, refusal_lint
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


def _witness(key: object, log: Ed25519PrivateKey, origin: str = ORIGIN, seconds: int = NOW,
             **kwargs: object) -> w.Witness:
    logs = {origin: [w.VerifierKey.ed25519(origin, log.public_key())]}
    return w.Witness("witness.example/w", key, logs, clock=FixedClock(seconds), **kwargs)  # type: ignore[arg-type]


def _policy(log: Ed25519PrivateKey, witnesses: dict[str, w.VerifierKey], tail: str) -> w.Policy:
    lines = [f"log {w.VerifierKey.ed25519(ORIGIN, log.public_key()).encode()}"]
    lines += [f"witness {name} {key.encode()}" for name, key in witnesses.items()]
    return w.parse_policy("\n".join(lines) + "\n" + tail)


def _cosign_size(witness: w.Witness, log: Ed25519PrivateKey, leaves: list[bytes], old: int = 0) -> str:
    proof = w.consistency_proof(old, leaves) if old else []
    return witness.add_checkpoint(w.encode_add_checkpoint(old, proof, _log_note(log, leaves)))


# ---- D1: a witness contributes to the quorum in one way only --------------------------------------------------------
def test_a_group_listed_in_two_groups_is_refused() -> None:
    log = Ed25519PrivateKey.generate()
    keys = {f"w{i}": w.VerifierKey.cosignature_v1(f"w{i}", Ed25519PrivateKey.generate().public_key()) for i in (1, 2)}
    tail = "group a any w1 w2\ngroup b all a\ngroup c all a\ngroup q any b c\nquorum q\n"
    with pytest.raises(w.NoteError) as exc:
        _policy(log, keys, tail)
    assert exc.value.code == "policy_group_members"


def test_one_witness_key_under_two_names_is_refused() -> None:
    """tlog-policy: two vkeys wrapping the same public key are duplicates "even if they differ by key name and key
    id", so a second name cannot count the same witness twice."""
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    keys = {"a": w.VerifierKey.cosignature_v1("a.example", key.public_key()),
            "b": w.VerifierKey.cosignature_v1("b.example", key.public_key())}
    with pytest.raises(w.NoteError) as exc:
        _policy(log, keys, "group g all a b\nquorum g\n")
    assert exc.value.code == "policy_key_repeated"


def test_the_log_key_listed_again_as_a_witness_is_refused() -> None:
    log = Ed25519PrivateKey.generate()
    keys = {"w": w.VerifierKey.cosignature_v1("w", log.public_key())}
    with pytest.raises(w.NoteError) as exc:
        _policy(log, keys, "quorum w\n")
    assert exc.value.code == "policy_key_repeated"


def test_a_two_of_two_group_is_not_met_by_one_witness_with_two_lines() -> None:
    """A witness with an Ed25519 and an ML-DSA-44 key is two policy witnesses only if the policy lists two keys; a
    single listed witness that answers with two lines still counts once."""
    log, ed, pq = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    witness = _witness(pq, log, more_keys=(ed,))
    other = w.VerifierKey.cosignature_v1("other.example", Ed25519PrivateKey.generate().public_key())
    leaves = _leaves(3)
    lines = _cosign_size(witness, log, leaves)
    note = w.attach(_log_note(log, leaves), lines)
    policy = _policy(log, {"w": witness.vkeys[0], "o": other}, "group g 2 w o\nquorum g\n")
    with pytest.raises(w.NoteError) as exc:
        w.verify_note(note, policy)
    assert exc.value.code == "witness_quorum_not_met"


# ---- D2: an ML-DSA-44 line dated 0 is a subtree cosignature, in every role -------------------------------------------
def test_a_witness_line_dated_zero_is_refused_by_verify_line_and_open_note() -> None:
    key = MLDSA44PrivateKey.generate()
    vk = w.VerifierKey.mldsa44("w", key.public_key())
    leaves = _leaves(2)
    cp = w.Checkpoint(ORIGIN, 2, w.root(leaves))
    line = w.SigLine("w", vk.id, bytes(8) + w.cosign_subtree("w", key, ORIGIN, 0, 2, cp.root))
    with pytest.raises(w.NoteError) as exc:
        w.verify_line(vk, cp.text(), line)
    assert exc.value.code == "note_signature_invalid"
    with pytest.raises(w.NoteError):
        w.open_note(w.Note(cp.text(), (line,)).encode(), [vk])


def test_a_log_ml_dsa_line_dated_zero_does_not_authenticate_the_log() -> None:
    """The log's own 0x06 line follows the same rule: dated 0 it signs a subtree, not the checkpoint."""
    pq = MLDSA44PrivateKey.generate()
    leaves = _leaves(2)
    cp = w.Checkpoint(ORIGIN, 2, w.root(leaves))
    vk = w.VerifierKey.mldsa44(ORIGIN, pq.public_key())
    line = w.SigLine(ORIGIN, vk.id, bytes(8) + w.cosign_subtree(ORIGIN, pq, ORIGIN, 0, 2, cp.root))
    policy = w.parse_policy(f"log {vk.encode()}\nquorum none\n")
    with pytest.raises(w.NoteError):
        w.verify_note(w.Note(cp.text(), (line,)).encode(), policy)


def test_no_signer_makes_an_ml_dsa_checkpoint_cosignature_dated_zero() -> None:
    log, pq = Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    cp = w.Checkpoint(ORIGIN, 1, w.leaf_hash(b"x"))
    with pytest.raises(w.NoteError) as exc:
        w.cosign_mldsa(cp.text(), "w", pq, 0)
    assert exc.value.code == "cosignature_timestamp_range"
    with pytest.raises(w.NoteError):
        w.sign_checkpoint(cp, log, pq=pq)  # the default timestamp 0 would make a subtree cosignature
    assert w.parse_note(w.sign_checkpoint(cp, log, pq=pq, timestamp=NOW)).sigs[1].sig[:8] == NOW.to_bytes(8, "big")


def test_a_witness_whose_clock_reads_zero_refuses_and_the_server_answers(tmp_path: Path) -> None:
    log = Ed25519PrivateKey.generate()
    witness = _witness(MLDSA44PrivateKey.generate(), log, seconds=0, state_dir=tmp_path)
    body = w.encode_add_checkpoint(0, [], _log_note(log, _leaves(1)))
    with pytest.raises(w.NoteError):
        witness.add_checkpoint(body)
    assert witness.latest_checkpoint(hashlib.sha256(ORIGIN.encode()).hexdigest()) is None
    server = w.serve_witness(witness)
    try:
        with pytest.raises(w.WitnessRefused) as exc:
            w.add_checkpoint(f"http://127.0.0.1:{server.server_port}", body)
        assert exc.value.status == 500 and exc.value.body.strip() == "cosignature_timestamp_range"
    finally:
        server.shutdown()


# ---- D3: the empty tree and empty subtrees carry the hash of the empty string ----------------------------------------
def test_no_signer_signs_a_size_zero_checkpoint_with_another_root() -> None:
    log, ed, pq = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), MLDSA44PrivateKey.generate()
    cp = w.Checkpoint(ORIGIN, 0, b"\x22" * 32)
    for sign in (lambda: w.cosign(cp.text(), "w", ed, NOW), lambda: w.cosign_mldsa(cp.text(), "w", pq, NOW),
                 lambda: w.sign_checkpoint(cp, log)):
        with pytest.raises(w.NoteError) as exc:
            sign()
        assert exc.value.code in {"checkpoint_malformed", "cosignature_input_range"}
    good = w.Checkpoint(ORIGIN, 0, w.EMPTY_ROOT)
    assert w.verify_note(w.sign_checkpoint(good, log), w.parse_policy(
        f"log {w.VerifierKey.ed25519(ORIGIN, log.public_key()).encode()}\nquorum none\n")).checkpoint == good


def test_an_ed25519_cosigned_size_zero_note_with_another_root_is_refused() -> None:
    """A hand-made 0x04 cosignature over a size-0 checkpoint with a wrong root still fails ``verify_note``."""
    log, ed = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    cp = w.Checkpoint(ORIGIN, 0, b"\x22" * 32)
    text = cp.text()
    cosig = w.SigLine("w", w.VerifierKey.cosignature_v1("w", ed.public_key()).id,
                      NOW.to_bytes(8, "big") + ed.sign(w.cosignature_message(NOW, text)))
    note = w.Note(text, (w.log_signature(text, ORIGIN, log), cosig)).encode()
    vk = w.VerifierKey.cosignature_v1("w", ed.public_key())
    with pytest.raises(w.NoteError) as exc:
        w.verify_note(note, _policy(log, {"w": vk}, "quorum w\n"))
    assert exc.value.code == "checkpoint_malformed"


def test_an_empty_subtree_with_another_hash_never_verifies() -> None:
    key = MLDSA44PrivateKey.generate()
    vk = w.VerifierKey.mldsa44("w", key.public_key())
    good = w.cosign_subtree("w", key, ORIGIN, 4, 4, w.EMPTY_ROOT)
    assert w.verify_subtree_cosignature(vk, ORIGIN, 4, 4, w.EMPTY_ROOT, good)
    assert not w.verify_subtree_cosignature(vk, ORIGIN, 4, 4, b"\x33" * 32, good)
    assert not w.verify_subtree_consistency([], 8, w.root(_leaves(8)), 4, 4, b"\x33" * 32)


def test_the_witness_answers_422_for_a_size_zero_checkpoint_with_another_root() -> None:
    log = Ed25519PrivateKey.generate()
    witness = _witness(Ed25519PrivateKey.generate(), log)
    cp = w.Checkpoint(ORIGIN, 0, b"\x22" * 32)
    note = w.Note(cp.text(), (w.log_signature(cp.text(), ORIGIN, log),)).encode()
    with pytest.raises(w.WitnessRefused) as exc:
        witness.add_checkpoint(w.encode_add_checkpoint(0, [], note))
    assert exc.value.status == 422


# ---- D4: the witness never forgets what it cosigned --------------------------------------------------------------
def test_a_state_directory_from_release_0_12_0_is_remembered_then_replaced(tmp_path: Path) -> None:
    """0.12.0 wrote ``<hex of origin>.state``; dropping it unread would be a restart that forgets."""
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    leaves = _leaves(5)
    (tmp_path / (ORIGIN.encode().hex() + ".state")).write_text(
        f"4 {base64.b64encode(w.root(leaves[:4])).decode()}\n")
    witness = _witness(key, log, state_dir=tmp_path)
    with pytest.raises(w.WitnessRefused) as exc:
        _cosign_size(witness, log, _leaves(2, "fork "))
    assert exc.value.status == 409 and exc.value.body == "4\n"
    _cosign_size(witness, log, leaves, old=4)
    assert not list(tmp_path.glob("*.state"))
    restarted = _witness(key, log, state_dir=tmp_path)
    with pytest.raises(w.WitnessRefused) as again:
        _cosign_size(restarted, log, _leaves(2, "fork "))
    assert again.value.body == "5\n"


@pytest.mark.parametrize("damage", ["garbage", "other-origin"])
def test_a_witness_refuses_to_run_on_state_it_cannot_read(tmp_path: Path, damage: str) -> None:
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    _cosign_size(_witness(key, log, state_dir=tmp_path), log, _leaves(3))
    (state,) = tmp_path.glob("*.checkpoint")
    if damage == "garbage":
        state.write_text("not a note")
    else:  # a checkpoint moved under another origin's name: it would make that origin start from this one's size
        state.rename(tmp_path / (hashlib.sha256(b"example.com/other").hexdigest() + ".checkpoint"))
    with pytest.raises(w.WitnessRefused) as exc:
        _witness(key, log, state_dir=tmp_path)
    assert exc.value.code == "witness_state_unreadable"


def test_a_failed_persist_cosigns_nothing_and_forgets_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    witness = _witness(key, log, state_dir=tmp_path)
    leaves = _leaves(4)
    _cosign_size(witness, log, leaves[:2])

    def broken(self: Path, target: object) -> Path:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "replace", broken)
    with pytest.raises(w.WitnessRefused) as exc:
        _cosign_size(witness, log, leaves, old=2)
    assert exc.value.status == 500 and exc.value.code == "witness_state_unwritable"
    monkeypatch.undo()
    for fresh in (witness, _witness(key, log, state_dir=tmp_path)):  # memory and disk both still hold size 2
        with pytest.raises(w.WitnessRefused) as held:
            _cosign_size(fresh, log, _leaves(3, "fork "))
        assert held.value.body == "2\n"


def test_a_second_process_serves_what_the_first_persisted(tmp_path: Path) -> None:
    log, key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    first, second = _witness(key, log, state_dir=tmp_path), _witness(key, log, state_dir=tmp_path)
    _cosign_size(first, log, _leaves(3))
    served = second.latest_checkpoint(hashlib.sha256(ORIGIN.encode()).hexdigest())
    assert served is not None and w.parse_checkpoint(w.parse_note(served).text).size == 3
    assert second.latest_checkpoint("../" + "0" * 61) is None


def test_the_state_write_syncs_the_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A rename is durable only once its directory is synced; without that a crash can bring back the old file."""
    synced: list[bool] = []
    real = os.fsync

    def spy(fd: int) -> None:
        synced.append(os.path.isdir(f"/proc/self/fd/{fd}"))
        real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    log = Ed25519PrivateKey.generate()
    _cosign_size(_witness(Ed25519PrivateKey.generate(), log, state_dir=tmp_path), log, _leaves(1))
    assert synced[-1] is True


# ---- D5: the monitor copy holds what the witness verified or made ---------------------------------------------------
def test_a_line_that_shares_the_log_name_but_not_its_id_is_not_served(tmp_path: Path) -> None:
    log = Ed25519PrivateKey.generate()
    witness = _witness(Ed25519PrivateKey.generate(), log, state_dir=tmp_path)
    leaves = _leaves(2)
    parsed = w.parse_note(_log_note(log, leaves))
    stranger = w.SigLine(ORIGIN, b"\x00\x00\x00\x01", bytes(64))
    witness.add_checkpoint(w.encode_add_checkpoint(0, [], w.Note(parsed.text, (*parsed.sigs, stranger)).encode()))
    served = w.parse_note(witness.latest_checkpoint(hashlib.sha256(ORIGIN.encode()).hexdigest()) or "")
    assert stranger not in served.sigs and len(served.sigs) == 2
    w.verify_note(served.encode(), _policy(log, {"w": witness.vkey}, "quorum w\n"))


def test_a_witness_whose_monitor_copy_could_pass_the_signature_limit_is_refused() -> None:
    log = Ed25519PrivateKey.generate()
    keys = [w.VerifierKey.ed25519(ORIGIN, Ed25519PrivateKey.generate().public_key()) for _ in range(w.MAX_SIGNATURES)]
    with pytest.raises(w.NoteError) as exc:
        w.Witness("witness.example/w", Ed25519PrivateKey.generate(), {ORIGIN: keys}, clock=FixedClock())
    assert exc.value.code == "note_signature_count"
    del log


# ---- D7: one faulty witness is that witness's error --------------------------------------------------------------
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


def _faulty_cases(honest_line: str, bad_key: Ed25519PrivateKey, bad_vk: w.VerifierKey) -> dict[str, object]:
    def raises(exc: BaseException) -> object:
        def answer(_body: str) -> str:
            raise exc
        return answer

    def own_plus_impostor(body: str) -> str:
        text = w.parse_note(body.partition("\n\n")[2]).text
        return w.cosign(text, bad_vk.name, bad_key, NOW).encode() + honest_line

    return {
        "huge-409": raises(w.WitnessRefused(409, "witness_old_size_mismatch", "9" * 5000 + "\n")),
        "incomplete-read": raises(http.client.IncompleteRead(b"")),
        "not-utf8": raises(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")),
        "garbage": lambda _body: "no signature here\n",
        "own-plus-impostor": own_plus_impostor,
    }


@pytest.mark.parametrize("case", ["huge-409", "incomplete-read", "not-utf8", "garbage", "own-plus-impostor"])
def test_the_feed_publishes_whatever_one_faulty_witness_answers(tmp_path: Path, case: str) -> None:
    log = Ed25519PrivateKey.generate()
    honest = _witness(Ed25519PrivateKey.generate(), log)
    bad_key = Ed25519PrivateKey.generate()
    bad_vk = w.VerifierKey.cosignature_v1("bad.example/w", bad_key.public_key())
    impostor = w.SigLine(honest.name, honest.vkey.id, NOW.to_bytes(8, "big") + bytes(64)).encode()
    feed = _feed(tmp_path, log, honest, bad_vk, _faulty_cases(impostor, bad_key, bad_vk)[case])
    note = feed.publish()
    cosigned = set(w.verify_note(note, feed.policy).cosigned_at)  # type: ignore[arg-type]
    assert "good" in cosigned
    assert cosigned == ({"good", "bad"} if case == "own-plus-impostor" else {"good"})


def test_the_feed_never_attaches_a_witness_line_twice(tmp_path: Path) -> None:
    log = Ed25519PrivateKey.generate()
    honest = _witness(Ed25519PrivateKey.generate(), log)
    journal_path = tmp_path / "journal.jsonl"
    journal_path.write_text("one\n")
    journal = SimpleNamespace(directory=tmp_path, path=journal_path, signer=log)
    pairs = [("good", honest.vkey.encode()), ("again", honest.vkey.encode())]  # the same witness configured twice
    feed = w.Feed(journal, ORIGIN, pairs, policy=_policy(log, {"good": honest.vkey}, "quorum good\n"),
                  poster=lambda _url, body: honest.add_checkpoint(body))
    note = w.parse_note(feed.publish())
    assert len({(s.name, s.key_id) for s in note.sigs}) == len(note.sigs) == 2


# ---- D8: unknown keys never reject a note --------------------------------------------------------------------------
def test_unknown_lines_with_long_or_odd_names_are_ignored_by_verify_note() -> None:
    log = Ed25519PrivateKey.generate()
    cp = w.Checkpoint(ORIGIN, 1, w.leaf_hash(b"x"))
    text = cp.text()
    strangers = tuple(w.SigLine(name, bytes(4), bytes(64)) for name in ("s" * 1000, "é" * 200, "a/b?c=d#e"))
    note = w.Note(text, (w.log_signature(text, ORIGIN, log), *strangers)).encode()
    assert w.verify_note(note, _policy(log, {}, "quorum none\n")).checkpoint == cp
    for bad in ("with space", "with+plus", ""):  # what signed-note itself forbids still rejects
        with pytest.raises(w.NoteError):
            w.parse_note(w.Note(text, (w.log_signature(text, ORIGIN, log), w.SigLine(bad, bytes(4), bytes(64)))).encode())


# ---- D9: every refusal carries a registered code, and the lint sees every code position -------------------------
@pytest.mark.parametrize("source", [
    "def f(body):\n    raise WitnessRefused(409, body.strip())\n",
    "def f(exc):\n    raise NoteError(str(exc))\n",
    "def f(status, body):\n    raise WitnessRefused(status, body.strip() or 'witness_not_found', body)\n",
])
def test_the_lint_refuses_a_code_a_remote_party_or_an_exception_writes(source: str) -> None:
    findings = refusal_lint.lint_source("witness.py", source, refusal_codes.CODES, refusal_lint.PACKAGE_CONFIG)
    assert findings and all(f.problem == "refusal code composed at run time" for f in findings)


def test_the_lint_reads_the_code_argument_a_raiser_names() -> None:
    source = "def f():\n    raise WitnessRefused(400, 'witness_never_registered:detail')\n"
    findings = refusal_lint.lint_source("witness.py", source, refusal_codes.CODES, refusal_lint.PACKAGE_CONFIG)
    assert [f.problem for f in findings] == ["refusal code not registered"]


@pytest.mark.parametrize("length", ["-1", "abc", "1e3", "0" * 30 + "1", "99999999999999999999"])
def test_a_content_length_that_is_not_a_bounded_decimal_is_a_bad_request(length: str) -> None:
    log = Ed25519PrivateKey.generate()
    server = w.serve_witness(_witness(Ed25519PrivateKey.generate(), log))
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        conn.putrequest("POST", "/add-checkpoint")
        conn.putheader("Content-Length", length)
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read().decode()
        assert resp.status == 400 and body.split(":", 1)[0].strip() in refusal_codes.CODES
    finally:
        server.shutdown()


def test_a_reply_that_is_not_utf8_is_a_coded_refusal() -> None:
    class Resp(io.BytesIO):
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_: object) -> None:
            return None

    def opener(req: urllib.request.Request, timeout: float = 0) -> io.BytesIO:
        return Resp(b"\xff\xfe")

    with pytest.raises(w.WitnessRefused) as exc:
        w.add_checkpoint("http://w.example", "old 0\n\n", opener=opener)
    assert exc.value.code == "witness_response_malformed" and exc.value.code in refusal_codes.CODES


@pytest.mark.parametrize("text", ["9" * 20, str(w.MAX_TIMESTAMP + 1), "01", "²", "-1"])
def test_every_decimal_outside_the_range_is_note_decimal_invalid(text: str) -> None:
    with pytest.raises(w.NoteError) as exc:
        w.parse_decimal(text, "x")
    assert exc.value.code == "note_decimal_invalid"
    assert w.parse_decimal(str(w.MAX_TIMESTAMP), "x") == w.MAX_TIMESTAMP
