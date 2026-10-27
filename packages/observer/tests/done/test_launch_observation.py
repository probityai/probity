import base64
import copy

import pytest

from probity_observer.done.launch_observation import observe_run


BASE = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONHASHSEED": "0",
}
PY = "a" * 64
NATIVE = "b" * 64
INSTALLS = {
    PY: dict(class_="cpython", python_version=[3, 12], trusted=True,
             mounts_trusted=True, no_site=False),
    NATIVE: dict(class_="native", trusted=True, mounts_trusted=True),
}
INSTALLS = {key: {("class" if k == "class_" else k): v for k, v in value.items()}
            for key, value in INSTALLS.items()}


def vector(items):
    raw = [item.encode() if isinstance(item, str) else item for item in items]
    try:
        return {"encoding": "utf8", "items": [item.decode() for item in raw]}
    except UnicodeError:
        return {"encoding": "base64",
                "items": [base64.b64encode(item).decode() for item in raw]}


def env(**changes):
    values = dict(BASE)
    values.update(changes)
    return vector([f"{key}={value}" for key, value in values.items()])


def exec_record(argv=None, *, sha=PY, task=0, parent=None, environment=None):
    return dict(kind="exec", logical_task_id=task, parent_id=parent,
                executable_sha256=sha, argv=vector(argv or ["python", "-I", "suite.py"]),
                env=environment or env(), cwd_at_capture="/work")


def base_plan(argv=None):
    return {"steps": [dict(
        id="entry", role="entry", predecessors=["worker-root"],
        executable_sha256=PY, argv_alternatives=[argv or ["python", "-I", "suite.py"]],
        min=1, max=1, allowed_terminations=[], admit={}, transition_profile=None
    )]}


def run(events=None, *, plan=None, baseline=None, installs=None, sensor_approved=True,
        closing=None):
    events = [exec_record()] if events is None else events
    close = closing or {"kind": "closing", "sensor": {
        "status": "complete", "collection_closed": True, "tasks_reaped": True
    }}
    records = [dict(event, seq=index) for index, event in enumerate([*events, close])]
    return observe_run(records, plan or base_plan(), BASE if baseline is None else baseline,
                       INSTALLS if installs is None else installs,
                       sensor_approved=sensor_approved)


def verdict(reason=None):
    return ("not_established", reason) if reason else ("supported", None)


def test_clean_run_supported():
    assert run() == verdict()


def test_python_without_I_or_P():
    assert run([exec_record(["python", "suite.py"])],
               plan=base_plan(["python", "suite.py"])) == verdict("python_startup_unisolated")


def test_python_P_clean_baseline():
    argv = ["python", "-P", "suite.py"]
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict()


def test_python_P_E_without_s():
    argv = ["python", "-PE", "suite.py"]
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict("python_startup_unisolated")


def test_python_P_E_s():
    argv = ["python", "-PEs", "suite.py"]
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict()


def test_python_supported_P_E_S():
    argv = ["python", "-PES", "suite.py"]
    installs = copy.deepcopy(INSTALLS)
    installs[PY]["no_site"] = True
    assert run([exec_record(argv)], plan=base_plan(argv), installs=installs) == verdict()


@pytest.mark.parametrize("argv", [
    ["python", "-c", "print('-I')"],
    ["python", "-m", "-I"],
])
def test_python_flag_in_payload(argv):
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict("python_startup_unisolated")


@pytest.mark.parametrize("argv", [
    ["python", "-W", "-I", "suite.py"],
    ["python", "-X-I", "suite.py"],
])
def test_python_flag_in_option_value(argv):
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict("python_startup_unisolated")


def test_python_flag_after_script():
    argv = ["python", "suite.py", "-I"]
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict("python_startup_unisolated")


def test_python_combined_effective_options():
    argv = ["python", "-vPEs", "suite.py"]
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict()


def wrapper_plan(argv, *, sha=NATIVE, role="launch", admit=None, profile=None):
    plan = base_plan()
    plan["steps"][0]["predecessors"] = ["wrapper"]
    plan["steps"].insert(0, dict(
        id="wrapper", role=role, predecessors=["worker-root"],
        executable_sha256=sha, argv_alternatives=[argv], min=1, max=1,
        allowed_terminations=[], admit=admit or {}, transition_profile=profile
    ))
    return plan


def hops(wrapper=None, entry=None):
    return [wrapper or exec_record(["wrap"], sha=NATIVE),
            {"kind": "task", "logical_task_id": 1, "parent_id": 0},
            entry or exec_record(task=1, parent=0)]


def test_python_dispatcher_checked():
    argv = ["python", "dispatcher.py"]
    plan = wrapper_plan(argv, sha=PY)
    assert run(hops(exec_record(argv)), plan=plan) == verdict("python_startup_unisolated")


def test_renamed_python_identity():
    argv = ["renamed", "-I", "suite.py"]
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict()


def test_embedded_python_unmodelled():
    installs = copy.deepcopy(INSTALLS)
    installs[PY]["class"] = "embedded-unmodelled"
    assert run(installs=installs) == verdict("interpreter_identity_unestablished")


def test_unresolved_shebang_identity():
    installs = copy.deepcopy(INSTALLS)
    installs[PY]["class"] = "unsupported"
    assert run(installs=installs) == verdict("interpreter_identity_unestablished")


def test_writable_venv():
    installs = copy.deepcopy(INSTALLS)
    installs[PY]["mounts_trusted"] = False
    assert run(installs=installs) == verdict("interpreter_installation_untrusted")


@pytest.mark.parametrize("name", ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"])
def test_ld_preload(name):
    assert run([exec_record(environment=env(**{name: "injected"}))]) == verdict("loader_injection")


def test_ld_library_path():
    test_ld_preload("LD_LIBRARY_PATH")


def test_ld_audit():
    test_ld_preload("LD_AUDIT")


@pytest.mark.parametrize("name", ["PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "X"])
def test_non_ld_loader_sensitive_environment(name):
    assert run([exec_record(environment=env(**{name: "injected"}))]) == verdict(
        "launch_environment_changed")


def test_duplicate_env_names():
    items = env()["items"] + ["PATH=/other"]
    assert run([exec_record(environment=vector(items))]) == verdict(
        "launch_environment_invalid")


@pytest.mark.parametrize("bad", ["BROKEN", "=empty", b"X=\0"])
def test_malformed_env_entry(bad):
    items = [item.encode() for item in env()["items"]] + [
        bad.encode() if isinstance(bad, str) else bad]
    assert run([exec_record(environment=vector(items))]) == verdict(
        "launch_environment_invalid")


def test_missing_baseline_key():
    baseline = dict(BASE)
    baseline.pop("HOME")
    assert run(baseline=baseline) == verdict("launch_environment_changed")


def test_environment_reason_precedence():
    items = env(LD_PRELOAD="x")["items"] + ["BROKEN"]
    assert run([exec_record(environment=vector(items))]) == verdict(
        "launch_environment_invalid")


def test_env_wrapper_assignment():
    wrapper = exec_record(["wrap"], sha=NATIVE, environment=env(X="1"))
    assert run(hops(wrapper), plan=wrapper_plan(["wrap"])) == verdict(
        "launch_environment_changed")


def test_unknown_dispatcher_not_exempt():
    installs = {PY: INSTALLS[PY]}
    assert run(hops(), plan=wrapper_plan(["wrap"]), installs=installs) == verdict(
        "interpreter_identity_unestablished")


def test_clean_wrapper_hops():
    assert run(hops(), plan=wrapper_plan(["wrap"])) == verdict()


def test_exact_make_bookkeeping():
    admitted = {"MAKELEVEL": "1", "MAKEFLAGS": "", "MFLAGS": ""}
    plan = wrapper_plan(["wrap"], admit=admitted, profile="pinned-make")
    assert run(hops(exec_record(["wrap"], sha=NATIVE, environment=env(**admitted))),
               plan=plan) == verdict()


def test_exact_shell_bookkeeping():
    admitted = {"PWD": "/work", "SHLVL": "2", "_": "/usr/bin/sh"}
    plan = wrapper_plan(["wrap"], admit=admitted, profile="pinned-shell")
    assert run(hops(exec_record(["wrap"], sha=NATIVE, environment=env(**admitted))),
               plan=plan) == verdict()


def test_unapproved_shell_bookkeeping():
    wrapper = exec_record(["wrap"], sha=NATIVE, environment=env(SHLVL="2"))
    assert run(hops(wrapper), plan=wrapper_plan(["wrap"])) == verdict(
        "launch_environment_changed")


def test_unapproved_makelevel():
    plan = wrapper_plan(["wrap"], admit={"MAKELEVEL": "0"}, profile="pinned-make")
    wrapper = exec_record(["wrap"], sha=NATIVE, environment=env(MAKELEVEL="0"))
    assert run(hops(wrapper), plan=plan) == verdict("launch_environment_changed")


def test_makeflags_other_nonempty_rejected():
    plan = wrapper_plan(["wrap"], admit={"MAKEFLAGS": "-j2"}, profile="pinned-make")
    wrapper = exec_record(["wrap"], sha=NATIVE, environment=env(MAKEFLAGS="-j2"))
    assert run(hops(wrapper), plan=plan) == verdict("launch_environment_changed")


def test_competing_entry_matches():
    plan = base_plan()
    other = copy.deepcopy(plan["steps"][0])
    other["id"] = "other"
    plan["steps"].append(other)
    assert run(plan=plan) == verdict("launch_boundary_ambiguous")


def test_unexpected_pre_entry_branch():
    events = [exec_record(["unexpected"], sha=NATIVE), exec_record()]
    assert run(events) == verdict("launch_boundary_ambiguous")


def test_required_entry_missing():
    assert run([]) == verdict("suite_entry_missing")


def test_declared_setup_termination():
    plan = wrapper_plan(["wrap"])
    plan["steps"][0]["terminal_branch"] = True
    plan["steps"][0]["allowed_terminations"] = [
        {"kind": "exited", "code": 0}, {"kind": "exited", "code": 2}]
    events = [exec_record(["wrap"], sha=NATIVE),
              {"kind": "observation", "logical_task_id": 0,
               "wait_status": {"kind": "exited", "code": 2}}]
    assert run(events, plan=plan) == verdict()


def test_post_entry_same_pid_exec():
    assert run([exec_record(), exec_record(["other"], sha=NATIVE)]) == verdict()


def test_post_entry_fork_without_exec():
    assert run([exec_record(), {"kind": "task", "logical_task_id": 1,
                                "parent_id": 0}]) == verdict()


def test_terminal_thread_exec_refused():
    plan = base_plan()
    plan["steps"][0]["role"] = "terminal"
    events = [exec_record(), {"kind": "task", "logical_task_id": 1, "parent_id": 0},
              exec_record(task=1, parent=0)]
    assert run(events, plan=plan) == verdict("launch_boundary_ambiguous")


def test_nonleader_thread_execve_reconciled():
    events = [{"kind": "task", "logical_task_id": 1, "parent_id": 0},
              exec_record(task=1, parent=0)]
    assert run(events) == verdict()


def test_unknown_sharing_state():
    events = [{"kind": "task", "logical_task_id": 1, "parent_id": 0,
               "fs_sharing_unknown": True}, exec_record()]
    assert run(events) == verdict("shared_fs_unsupported")


def test_clone_fs_cwd_race():
    test_unknown_sharing_state()


def test_failed_exec_not_new_environment():
    events = [{"kind": "exec_failed", "logical_task_id": 0, "parent_id": None,
               "env": env(X="1")}, exec_record()]
    assert run(events) == verdict()


def test_lost_lifecycle_event():
    records = [dict(exec_record(), seq=0),
               {"kind": "closing", "seq": 2, "sensor": {
                   "status": "complete", "collection_closed": True, "tasks_reaped": True}}]
    assert observe_run(records, base_plan(), BASE, INSTALLS) == verdict("trace_incomplete")


def test_supervisor_death():
    assert observe_run([dict(exec_record(), seq=0)], base_plan(), BASE, INSTALLS) == verdict(
        "trace_incomplete")


def test_failing_tracee_sensor_complete():
    events = [exec_record(), {"kind": "observation", "logical_task_id": 0,
                              "wait_status": {"kind": "exited", "code": 1}}]
    assert run(events) == verdict()


def test_controlled_entry_timeout():
    plan = base_plan()
    plan["steps"][0]["allowed_terminations"] = [{"kind": "timed_out"}]
    closing = {"kind": "closing", "termination": "timed_out", "sensor": {
        "status": "complete", "collection_closed": True, "tasks_reaped": True}}
    assert run(plan=plan, closing=closing) == verdict()


def test_timeout_without_close():
    close = {"kind": "closing", "termination": "timed_out", "sensor": {
        "status": "incomplete", "collection_closed": False, "tasks_reaped": False}}
    assert run(closing=close) == verdict("trace_incomplete")


def test_unsupported_sensor_configuration():
    assert run(sensor_approved=False) == verdict("sensor_configuration_unsupported")


def test_truncated_environment():
    record = exec_record()
    record["environment_reason"] = "environment_truncated"
    assert run([record]) == verdict("environment_truncated")


def test_large_complete_exec_vector():
    argv = ["python", "-I", "suite.py", "x" * 100_000]
    assert run([exec_record(argv)], plan=base_plan(argv)) == verdict()


def test_lossless_non_utf8_vector():
    record = exec_record()
    record["env"] = vector([item.encode() for item in env()["items"]] + [b"X=\xff"])
    assert run([record]) == verdict("launch_environment_changed")
