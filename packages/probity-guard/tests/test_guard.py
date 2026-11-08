"""The guard's three properties, each tested over every chunk boundary, plus signed records."""

from __future__ import annotations

import pytest

from probity_guard import Blocked, Classifier, Guard, guarded_stream
from probity_records import Signer, Journal, verify_journal

AWS = "AKIAABCDEFGHIJKLMNOP"
CARD = "4111 1111 1111 1111"


def test_block_redact_allow() -> None:
    g = Guard()
    assert g.check("hello world").action == "allow"
    v = g.check(f"pay with {CARD} to bob@example.com")
    assert v.action == "redact"
    assert v.output == "pay with [REDACTED:payment_card] to [REDACTED:email]"
    assert g.check(f"key={AWS}").action == "block"
    assert g.check("-----BEGIN OPENSSH PRIVATE KEY-----\nabc").action == "block"
    assert g.check("4111 1111 1111 1112").action == "allow"  # fails Luhn: not a card


@pytest.mark.parametrize("cut", range(1, 40))
def test_a_secret_split_at_any_boundary_is_still_blocked(cut) -> None:
    text = f"prefix text {AWS} suffix"
    chunks = [text[:cut], text[cut:]]
    emitted: list[str] = []
    with pytest.raises(Blocked):
        for out in guarded_stream(Guard(), chunks):
            emitted.append(out)
    assert AWS[:4] not in "".join(emitted)


@pytest.mark.parametrize("cut", range(1, 30))
def test_a_card_split_at_any_boundary_is_redacted_whole(cut) -> None:
    text = f"card {CARD} ok"
    out = "".join(guarded_stream(Guard(max_match=64), [text[:cut], text[cut:]]))
    assert out == "card [REDACTED:payment_card] ok"


def test_block_stops_the_stream_deterministically() -> None:
    g = Guard(max_match=8)
    chunks = ["safe " * 10, f"then {AWS} ", "more " * 10, "and more"]
    for _ in range(15):  # the same outcome on every run
        sg = g.stream()
        emitted = []
        with pytest.raises(Blocked):
            for c in chunks:
                emitted.append(sg.feed(c))
        with pytest.raises(Blocked):
            sg.feed("after the block")
        with pytest.raises(Blocked):
            sg.close()
        assert "more" not in "".join(emitted)


def test_classifier_error_fails_closed_and_is_recorded(tmp_path) -> None:
    import re

    def boom(_m: str) -> bool:
        raise RuntimeError("model down")

    signer = Signer.generate()
    journal = Journal(tmp_path, signer)
    g = Guard(classifiers=[Classifier("flaky", re.compile("x"), "redact", boom)], journal=journal)
    v = g.check("x marks")
    assert (v.action, v.reason) == ("block", "classifier_error:RuntimeError")
    with pytest.raises(Blocked):
        list(guarded_stream(g, ["x"]))
    report = verify_journal(tmp_path, [signer.public_pem()], journal.checkpoint())
    assert report["verdict"] == "PASS", report["failures"]
    preds = [s["predicate"] for s in report["statements"]]
    assert [p["action"] for p in preds] == ["block", "block"]
    assert all("x marks" not in str(p) for p in preds)  # the record never carries the matched text


def test_content_guard_hook_blocks_redactable_arguments() -> None:
    hook = Guard().content_guard()
    assert hook("t", b'{"note":"hi"}')["action"] == "allow"
    assert hook("t", b'{"note":"bob@example.com"}')["action"] == "block"
