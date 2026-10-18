"""S2: the eBPF trace program and its parser, against a trace recorded from a real container."""

from __future__ import annotations

from pathlib import Path

from probity_observer.done.basharena import observer

DATA = Path(__file__).with_name("data") / "bpftrace-alpine-exec.log"
SHIM = 744688


def _trace() -> observer.Trace:
    with DATA.open() as handle:
        return observer.parse(handle)


def test_the_program_is_filtered_to_one_cgroup_on_every_probe():
    text = observer.program(4242)
    probes = [line for line in text.splitlines() if line and not line.startswith(" ") and "{" in line]
    assert len(probes) == 10
    assert all("/cgroup == 4242/" in probe for probe in probes)


def test_the_recorded_trace_parses_with_no_loss_and_no_leftover_lines():
    trace = _trace()
    assert trace.lost == 0
    assert trace.unparsed == []


def test_the_exec_root_is_the_command_the_shim_started():
    roots = observer.exec_roots(_trace(), SHIM)
    assert [root.detail["argv"][:2] for root in roots] == [["sh", "-c"]]


def test_children_of_the_root_are_its_descendants():
    trace = _trace()
    root = observer.exec_roots(trace, SHIM)[0]
    below = trace.descendants(root.pid)
    commands = {e.detail["argv"][0] for e in trace.events if e.kind == "E" and e.pid in below}
    assert {"sh", "mv", "rm", "cat", "wget"} <= commands


def test_a_relative_write_resolves_to_its_container_path():
    events = [e for e in _trace().events if not e.upper]
    assert any(e.kind == "O" and e.path == "/etc/hostsx" and e.writes for e in events)
    assert any(e.kind == "N" and e.path == "/etc/hosts2" and e.detail["from"] == "/etc/hostsx"
               for e in events)
    assert any(e.kind == "U" and e.path == "/etc/hosts2" for e in events)


def test_upper_layer_duplicates_are_marked():
    upper = [e for e in _trace().events if e.upper]
    assert upper and all("snapshots" in e.path or "snapshots" in e.detail.get("from", "") for e in upper)


def test_a_procfs_open_gets_its_mount_prefix_back():
    assert any(e.kind == "O" and e.path == "/proc/1/status" and not e.writes for e in _trace().events)


def test_connect_and_kill_carry_their_targets():
    events = _trace().events
    assert any(e.kind == "C" and e.detail == {"family": 2, "address": "192.0.2.10", "port": 80}
               for e in events)
    assert any(e.kind == "K" and e.detail == {"target": 1, "signal": 0} for e in events)


def test_lost_events_are_counted_and_unknown_lines_kept():
    trace = observer.parse(["Lost 12 events", "Lost 3 events", "Z\tjunk", "D\t1\t2\tp\torphan"])
    assert trace.lost == 15
    assert trace.unparsed == ["Z\tjunk", "D\t1\t2\tp\torphan"]


def test_a_chain_that_never_reaches_its_root_is_truncated():
    trace = observer.parse(["O\t5\t9\tsh\t2\t1", "D\t5\t9\tp\tdeep", "T\t5\t9\tp"])
    (event,) = trace.events
    assert event.truncated and event.path == "/deep"


def test_an_argument_block_past_the_cap_is_marked_truncated():
    trace = observer.parse([f"E\t5\t9\t1\t/bin/x\t{observer.ARGV_BYTES + 1}", "A\t5\t9\t0\tx\\x00y"])
    (event,) = trace.events
    assert event.detail["argv"] == ["x", "y"] and event.detail["argv_truncated"]
