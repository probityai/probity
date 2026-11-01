"""The parent's link to the host broker, read in this process.

In a real run the link lives inside the parent's container, where no coverage is collected, so
its frames, its limits and its failures are driven here over pipes the test holds the far ends
of: the host's side of each exchange is written or read by the test.
"""

import base64
import json
import os

import pytest

from probity_observer.done import replay


def frame(**fields) -> bytes:
    return (json.dumps(fields) + "\n").encode()


@pytest.fixture
def link():
    """A link whose host side is the test: ``to_link`` feeds it, ``from_link`` is what it sent."""
    link_read, to_link = os.pipe()
    from_link, link_write = os.pipe()
    made = replay.HostLink(link_read, link_write)
    yield made, to_link, from_link
    replay.STARTED.clear()
    for fd in (link_read, to_link, from_link, link_write):
        try:
            os.close(fd)
        except OSError:
            pass


def test_a_sent_frame_reaches_the_host_as_one_json_line(link):
    made, _, from_link = link
    assert made.send({"op": "end", "child": 3})
    assert json.loads(os.read(from_link, 4096)) == {"op": "end", "child": 3}


def test_a_send_to_a_host_that_is_gone_marks_the_link_lost(link):
    made, _, from_link = link
    os.close(from_link)
    assert not made.send({"op": "end", "child": 0})
    assert made.lost


def test_output_end_and_answer_frames_are_filed_by_child(link):
    made, to_link, _ = link
    data = base64.b64encode(b"hello\n").decode()
    os.write(to_link, frame(op="out", child=1, data=data) + frame(op="eof", child=1)
             + frame(op="started", child=2))
    for _ in range(3):
        assert made.pump(replay.time.monotonic() + 5)
    assert bytes(made.inbox[1]) == b"hello\n"
    assert made.ended == {1}
    assert made.answers == {2: "started"}
    assert not made.lost


def test_a_pump_that_hears_nothing_before_its_deadline_says_so(link):
    made, _, _ = link
    assert not made.pump(replay.time.monotonic() + 0.05)
    assert not made.lost


@pytest.mark.parametrize("garbled", [b"not json\n", b'{"op": "out"}\n',
                                     frame(op="out", child=1, data="@@@")])
def test_a_garbled_frame_ends_every_child(link, garbled):
    made, to_link, _ = link
    os.write(to_link, garbled)
    assert made.pump(replay.time.monotonic() + 5)
    assert made.lost


def test_a_host_that_closes_its_end_ends_every_child(link):
    made, to_link, _ = link
    os.close(to_link)
    assert made.pump(replay.time.monotonic() + 5)
    assert made.lost


def test_a_pump_on_a_lost_link_returns_at_once(link):
    made, _, _ = link
    made.lost = True
    assert made.pump(replay.time.monotonic() - 1)


def test_a_child_is_started_only_when_the_host_says_started(link):
    made, to_link, from_link = link
    os.write(to_link, frame(op="started", child=0) + frame(op="refused", child=1))
    assert made.start() == 0
    assert made.start() is None
    assert json.loads(os.read(from_link, 4096).splitlines()[0]) == {"op": "start", "child": 0}


def test_a_start_the_host_never_answers_gives_no_child(link, monkeypatch):
    made, _, _ = link
    monkeypatch.setattr(replay, "BROKER_CLOSE_LIMIT", 0.05)
    assert made.start() is None


def test_a_start_on_a_lost_link_gives_no_child(link):
    made, _, from_link = link
    os.close(from_link)
    assert made.start() is None


def test_a_chunk_is_what_the_child_wrote_then_empty_at_its_end(link):
    made, to_link, _ = link
    os.write(to_link, frame(op="out", child=0, data=base64.b64encode(b"abc").decode())
             + frame(op="eof", child=0))
    assert made.chunk(0, 5) == b"abc"
    assert made.chunk(0, 5) == b""


def test_a_chunk_not_heard_within_its_time_is_none(link):
    made, _, _ = link
    assert made.chunk(0, 0.05) is None


def test_a_chunk_on_a_lost_link_is_empty(link):
    made, _, _ = link
    made.lost = True
    assert made.chunk(0, 5) == b""


def test_a_brokered_child_speaks_through_the_host_and_is_closed_by_it(link, monkeypatch):
    made, to_link, from_link = link
    monkeypatch.setattr(replay, "BROKER", made)
    os.write(to_link, frame(op="started", child=0) + frame(op="closed", child=0))
    child = replay.BrokeredChild(["unused"], None, 5)
    assert child.handle == 0 and not child.closed
    assert child._send("line\n") is None
    child.end_input()
    child.close()
    child.close()
    sent = [json.loads(line) for line in os.read(from_link, 1 << 16).splitlines()]
    assert [item["op"] for item in sent] == ["start", "write", "end", "close"]
    assert base64.b64decode(sent[1]["data"]) == b"line\n"
    assert child.closed


def test_a_brokered_child_the_host_refused_is_closed_from_the_start(link, monkeypatch):
    made, to_link, from_link = link
    monkeypatch.setattr(replay, "BROKER", made)
    os.write(to_link, frame(op="refused", child=0))
    child = replay.BrokeredChild(["unused"], None, 5)
    assert child.handle is None and child.closed
    child.end_input()
    child.close()
    assert [json.loads(line)["op"] for line in os.read(from_link, 4096).splitlines()] == ["start"]
    replay.STARTED.clear()


def test_a_brokered_child_sends_to_a_lost_link_as_an_exited_child(link, monkeypatch):
    made, to_link, from_link = link
    monkeypatch.setattr(replay, "BROKER", made)
    os.write(to_link, frame(op="started", child=0))
    child = replay.BrokeredChild(["unused"], None, 5)
    os.close(from_link)
    assert child._send("x\n") == "child-exited"
    assert child._chunk(0.05) == b""
    replay.STARTED.clear()
