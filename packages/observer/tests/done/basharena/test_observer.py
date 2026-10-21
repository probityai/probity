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
    assert all("/cgroup == 4242" in probe for probe in probes)
    assert "fentry:wake_up_new_task" in text
    assert "thread_pid->numbers[1].nr" in text


def test_the_whole_run_program_prints_only_write_and_procfs_opens_and_the_grading_one_every_open():
    (whole,) = [line for line in observer.program(1).splitlines() if line.startswith("fentry:security_file_open")]
    (grading,) = [line for line in observer.program(1, reads=True).splitlines()
                  if line.startswith("fentry:security_file_open")]
    assert "f_mode & 2" in whole and "s_magic == 40864" in whole
    assert grading == "fentry:security_file_open /cgroup == 1/ {"


def test_merging_two_programs_keeps_an_event_once():
    one = observer.parse(["O\t5\t9\tsh\t2\t1", "D\t5\t9\tp\tx", "D\t5\t9\tp\t/", "F\t1\t9\t10"])
    two = observer.parse(["O\t5\t9\tsh\t2\t1", "D\t5\t9\tp\tx", "D\t5\t9\tp\t/", "O\t6\t9\tsh\t0\t1",
                          "D\t6\t9\tp\ty", "D\t6\t9\tp\t/", "Lost 2 events"])
    merged = observer.merge([one, two])
    assert [(e.time, e.path) for e in merged.events] == [(5, "/x"), (6, "/y")]
    assert merged.lost == 2 and merged.parents == {10: 9}


def test_the_trace_keeps_container_pids_from_execs_and_forks():
    trace = observer.parse(["E\t1\t200\t900\t/usr/bin/python3\t7\t20",
                            "A\t1\t200\t0\tpython3\\x00", "F\t2\t200\t201\t21"])
    assert trace.unparsed == []
    assert trace.namespace_pids == {200: 20, 201: 21}
    assert trace.parents == {201: 200}
    assert observer.merge([trace, observer.Trace([], [], 0, {})]).namespace_pids == trace.namespace_pids


def test_the_recorded_trace_parses_with_no_loss_and_no_leftover_lines():
    trace = _trace()
    assert trace.lost == 0
    assert trace.unparsed == []


def test_the_exec_root_is_the_command_the_shim_started():
    roots = observer.exec_roots(_trace(), SHIM)
    assert [root.detail["argv"][:2] for root in roots] == [["sh", "-c"]]


def test_an_exec_under_a_new_shim_is_still_a_root():
    trace = observer.Trace(events=[
        observer.Event("E", 1, 200, path="/proc/self/fd/6", detail={"ppid": 900, "argv": ["runc", "init"]}),
        observer.Event("E", 2, 201, path="/usr/bin/python3", detail={"ppid": 900, "argv": ["python3"]}),
        observer.Event("E", 3, 202, path="/usr/bin/curl", detail={"ppid": 201, "argv": ["curl"]}),
    ], unparsed=[], lost=0, parents={202: 201})
    assert [event.pid for event in observer.exec_roots(trace, SHIM)] == [201]


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
