"""The checkpoint feed and the customer-held witness key.

The authority signs C2SP checkpoints of its journal; the customer's witness cosigns only checkpoints
an RFC 9162 consistency proof links to the last one it cosigned; the offline verifier, given the
customer's tlog-policy, refuses any journal the witness did not cosign.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from probity_records import Journal, Signer, Trust, verify_journal
from probity_records import witness as w

ORIGIN = "authority.example/journal"


def _leaves(n: int) -> list[bytes]:
    return [w.leaf_hash(f"line-{i}".encode()) for i in range(n)]


def test_consistency_proofs_hold_for_every_pair_and_fail_when_bent() -> None:
    for new in range(1, 18):
        leaves = _leaves(new)
        new_root = w.root(leaves)
        for old in range(1, new + 1):
            old_root = w.root(leaves[:old])
            proof = w.consistency_proof(old, leaves)
            assert w.verify_consistency(old, new, old_root, new_root, proof), (old, new)
            if proof:
                bent = [bytes(32), *proof[1:]]
                assert not w.verify_consistency(old, new, old_root, new_root, bent)
            if old < new:
                assert not w.verify_consistency(old, new, w.root(_leaves(old + 1)[1:]), new_root, proof)


def test_root_matches_rfc9162_shapes() -> None:
    a, b, c = _leaves(3)
    assert w.root([]) == w.EMPTY_ROOT
    assert w.root([a, b, c]) == w.node_hash(w.node_hash(a, b), c)


def _setup(tmp_path: Path, *, witnesses: int = 1):
    signer = Signer.generate()
    journal = Journal(tmp_path / "authority", signer)
    keys = [Ed25519PrivateKey.generate() for _ in range(witnesses)]
    servers, pairs = [], []
    feed_vkey = w.log_vkey(ORIGIN, signer)
    for n, key in enumerate(keys):
        wit = w.Witness(f"customer.example/witness-{n}", key, {ORIGIN: [w.parse_vkey(feed_vkey)]},
                        state_dir=tmp_path / f"witness-{n}")
        srv = w.serve_witness(wit)
        servers.append(srv)
        pairs.append((f"http://127.0.0.1:{srv.server_address[1]}", wit.vkey.encode()))
    _setup.keys = keys  # type: ignore[attr-defined]
    return signer, journal, servers, pairs, feed_vkey


def _policy(feed_vkey: str, pairs, quorum: str = "w0") -> str:
    lines = [f"log {feed_vkey}"]
    lines += [f"witness w{n} {vk}" for n, (_, vk) in enumerate(pairs)]
    return "\n".join([*lines, f"quorum {quorum}"]) + "\n"


def _append(journal: Journal, n: int) -> None:
    for i in range(n):
        journal.append("https://example.test/t", f"s{i}", "0" * 64, {"phase": "note", "i": i})


def test_customer_witness_cosigns_and_the_offline_verifier_requires_it(tmp_path) -> None:
    signer, journal, servers, pairs, feed_vkey = _setup(tmp_path)
    policy = _policy(feed_vkey, pairs)
    feed = w.Feed(journal, ORIGIN, pairs, policy=w.parse_policy(policy))
    _append(journal, 3)
    feed.publish()
    _append(journal, 4)
    note = feed.publish()  # the second checkpoint needed a consistency proof from size 3
    trust = Trust(witness_policy=policy)
    out = verify_journal(journal.directory, [signer.public_pem()], journal.checkpoint(), trust=trust,
                         witnessed_checkpoint=note)
    assert out["verdict"] == "PASS", out["failures"]
    assert out["witnessed"] == {"status": "verified", "size": 7, "of": 7, "cosigners": ["w0"], "origin": ORIGIN}
    # the same journal with the log's signature alone: refused offline
    bare = w.sign_checkpoint(w.Checkpoint(ORIGIN, 7, w.root(w.journal_leaves(journal.path))), signer)
    out = verify_journal(journal.directory, [signer.public_pem()], journal.checkpoint(), trust=trust,
                         witnessed_checkpoint=bare)
    assert out["verdict"] == "FAIL" and any("witness_quorum_not_met" in f for f in out["failures"])
    out = verify_journal(journal.directory, [signer.public_pem()], journal.checkpoint(), trust=trust)
    assert "witnessed_checkpoint_required_by_policy" in out["failures"]
    for s in servers:
        s.shutdown()


def test_a_rewritten_or_truncated_journal_fails_and_a_new_tail_is_not_established(tmp_path) -> None:
    signer, journal, servers, pairs, feed_vkey = _setup(tmp_path)
    policy = _policy(feed_vkey, pairs)
    feed = w.Feed(journal, ORIGIN, pairs, policy=w.parse_policy(policy))
    _append(journal, 4)
    note = feed.publish()
    trust = Trust(witness_policy=policy)
    _append(journal, 1)
    out = verify_journal(journal.directory, [signer.public_pem()], journal.checkpoint(), trust=trust,
                         witnessed_checkpoint=note)
    assert out["verdict"] == "NOT_ESTABLISHED" and out["witnessed"]["status"] == "tail_unwitnessed"
    # the authority rewrites history, re-signing every line with its own key: the witness root no longer holds
    lines = journal.path.read_text().splitlines()
    forged = Journal(tmp_path / "forged", signer)
    for i in range(len(lines)):
        forged.append("https://example.test/t", f"s{i}", "0" * 64, {"phase": "note", "i": 100 + i})
    out = verify_journal(forged.directory, [signer.public_pem()], forged.checkpoint(), trust=trust,
                         witnessed_checkpoint=note)
    assert "witnessed_checkpoint_root_differs_from_the_journal" in out["failures"]
    journal.path.write_text("\n".join(lines[:2]) + "\n")
    out = verify_journal(journal.directory, [signer.public_pem()], trust=trust, witnessed_checkpoint=note)
    assert "witnessed_checkpoint_size_4_journal_has_2" in out["failures"]
    for s in servers:
        s.shutdown()


def test_the_witness_refuses_a_split_view_and_an_unproven_extension(tmp_path) -> None:
    signer, journal, servers, pairs, feed_vkey = _setup(tmp_path)
    url = pairs[0][0]
    _append(journal, 3)
    leaves = w.journal_leaves(journal.path)
    note = w.sign_checkpoint(w.Checkpoint(ORIGIN, 3, w.root(leaves)), signer)
    w.add_checkpoint(url, w.encode_add_checkpoint(0, [], note))
    other = w.sign_checkpoint(w.Checkpoint(ORIGIN, 3, w.root(_leaves(3))), signer)
    with pytest.raises(w.WitnessRefused) as exc:  # same size, different root: a fork
        w.add_checkpoint(url, w.encode_add_checkpoint(3, [], other))
    assert exc.value.status == 422
    bigger = w.sign_checkpoint(w.Checkpoint(ORIGIN, 5, w.root(_leaves(5))), signer)
    with pytest.raises(w.WitnessRefused) as exc:  # not an extension of what it cosigned
        w.add_checkpoint(url, w.encode_add_checkpoint(3, w.consistency_proof(3, _leaves(5)), bigger))
    assert exc.value.status == 422
    with pytest.raises(w.WitnessRefused) as exc:
        w.add_checkpoint(url, w.encode_add_checkpoint(1, [], bigger))
    assert exc.value.status == 409 and exc.value.body.strip() == "3"
    rogue = w.sign_checkpoint(w.Checkpoint(ORIGIN, 3, w.root(leaves)), Signer.generate())
    with pytest.raises(w.WitnessRefused) as exc:
        w.add_checkpoint(url, w.encode_add_checkpoint(3, [], rogue))
    assert exc.value.status == 403
    for s in servers:
        s.shutdown()


def test_the_witness_remembers_across_restarts_and_the_feed_recovers_from_409(tmp_path) -> None:
    signer, journal, servers, pairs, feed_vkey = _setup(tmp_path)
    feed = w.Feed(journal, ORIGIN, pairs, policy=w.parse_policy(_policy(feed_vkey, pairs)))
    _append(journal, 2)
    feed.publish()
    key = _setup.keys[0]  # type: ignore[attr-defined]
    servers[0].shutdown()
    wit = w.Witness("customer.example/witness-0", key, {ORIGIN: [w.parse_vkey(feed_vkey)]},
                    state_dir=tmp_path / "witness-0")
    assert wit._latest[ORIGIN][0] == 2  # noqa: SLF001 - restored from its state directory
    srv = w.serve_witness(wit)
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    for f in feed.directory.glob("witness-*.size"):
        f.unlink()  # the feed forgot; the witness's 409 body tells it where to prove from
    feed.witnesses = [(url, wit.vkey.encode())]
    _append(journal, 3)
    note = feed.publish()
    assert w.parse_checkpoint(w.parse_note(note).text).size == 5
    # a witness restarted on an empty state would accept a fork; ours keeps refusing one
    forked = w.sign_checkpoint(w.Checkpoint(ORIGIN, 5, w.root(_leaves(5))), signer)
    with pytest.raises(w.WitnessRefused) as exc:
        w.add_checkpoint(url, w.encode_add_checkpoint(5, [], forked))
    assert exc.value.status == 422
    srv.shutdown()


def test_publish_fails_closed_when_the_quorum_is_missing_and_the_lag_gate_stops_permits(tmp_path) -> None:
    signer, journal, servers, pairs, feed_vkey = _setup(tmp_path, witnesses=2)
    text = _policy(feed_vkey, pairs, quorum="both").replace("quorum both", "group both all w0 w1\nquorum both")
    policy = w.parse_policy(text)
    feed = w.Feed(journal, ORIGIN, pairs, policy=policy)
    _append(journal, 2)
    feed.publish()
    servers[1].shutdown()
    _append(journal, 3)
    with pytest.raises(w.WitnessRefused) as exc:
        feed.publish()
    assert exc.value.status == 503 and "witness_quorum_not_met" in str(exc.value)
    assert feed.witnessed_size() == 2  # nothing unwitnessed was published
    gate = w.LagGate(feed, max_unwitnessed=2)
    assert gate() == "witness_lag_exceeded"
    assert w.LagGate(feed, max_unwitnessed=3)() is None
    servers[0].shutdown()


def test_policy_parsing_refuses_malformed_input() -> None:
    k = Ed25519PrivateKey.generate()
    vk = w.vkey("c.example/w", w.SIG_COSIGNATURE_V1, k.public_key()).encode()
    for bad in ["", f"witness a {vk}\n", "quorum nobody\n", f"witness a {vk}\nwitness b {vk}\nquorum a\n"]:
        with pytest.raises(w.NoteError):
            w.parse_policy(bad)
    with pytest.raises(w.NoteError):
        w.parse_vkey(vk.replace("+", "+0", 1))


def test_cosignature_bytes_follow_the_c2sp_layout() -> None:
    k = Ed25519PrivateKey.generate()
    text = w.Checkpoint(ORIGIN, 1, w.leaf_hash(b"x")).text()
    line = w.cosign(text, "c.example/w", k, 1700000000)
    assert line.key_id == w.note_key_id("c.example/w", 0x04, w._raw(k.public_key()))  # noqa: SLF001
    assert int.from_bytes(line.sig[:8], "big") == 1700000000
    k.public_key().verify(line.sig[8:], b"cosignature/v1\ntime 1700000000\n" + text.encode())
    assert line.encode().startswith("— c.example/w ")
    with pytest.raises(w.NoteError, match="share key name"):
        w.parse_note(w.Note(text, (line, line)).encode())
