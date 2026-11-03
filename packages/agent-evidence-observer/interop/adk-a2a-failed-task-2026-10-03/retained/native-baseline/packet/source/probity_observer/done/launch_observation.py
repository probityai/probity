"""Per-run, evidence-level launch-isolation decision."""

import base64
import os
import re


def _refuse(reason):
    return "not_established", reason


def _vector(value):
    """Decode a complete, lossless supervisor vector."""
    if value["encoding"] == "utf8":
        return [item.encode("utf-8") for item in value["items"]]
    if value["encoding"] == "base64":
        return [base64.b64decode(item, validate=True) for item in value["items"]]
    raise ValueError("unknown vector encoding")


def _argv(value):
    if isinstance(value, dict):
        return _vector(value)
    return [item.encode() if isinstance(item, str) else item for item in value]


def _environment(record, step, baseline):
    try:
        entries = _vector(record["env"])
    except (KeyError, TypeError, ValueError, UnicodeError):
        return "launch_environment_invalid", None
    found = {}
    for item in entries:
        if b"\0" in item or b"=" not in item:
            return "launch_environment_invalid", None
        name, value = item.split(b"=", 1)
        if not name or name in found:
            return "launch_environment_invalid", None
        found[name] = value

    admitted = step.get("admit", {})
    required = {key.encode(): value.encode() for key, value in baseline.items()}
    required.update({key.encode(): value.encode() for key, value in admitted.items()})
    if any(name.startswith(b"LD_") and name not in required for name in found):
        return "loader_injection", None
    if found != required or not _admissions(record, step):
        return "launch_environment_changed", None
    return None, found


def _admissions(record, step):
    admitted = step.get("admit", {})
    profile = step.get("transition_profile")
    if not admitted:
        return True
    if not isinstance(profile, str):
        return False
    for name, value in admitted.items():
        if name == "PWD":
            valid = value == record.get("cwd_at_capture")
        elif name == "SHLVL":
            valid = "shell" in profile and _decimal(value, 0, 64)
        elif name == "_":
            valid = ("shell" in profile or "env" in profile) and os.path.isabs(value)
        elif name == "MAKELEVEL":
            valid = "make" in profile and _decimal(value, 1, 64)
        elif name in ("MAKEFLAGS", "MFLAGS"):
            valid = "make" in profile and value == ""
        else:
            valid = False
        if not valid:
            return False
    return True


def _decimal(value, low, high):
    return bool(re.fullmatch(r"(?:0|[1-9][0-9]*)", value)) and low <= int(value) <= high


def _python_options(argv, version, environment, no_site):
    """Parse CPython startup options, stopping at the command or script."""
    if not isinstance(version, (list, tuple)) or len(version) != 2:
        return False
    major, minor = version
    if major != 3 or not isinstance(minor, int) or minor < 0:
        return False
    try:
        args = [item.decode("utf-8") for item in argv]
    except UnicodeError:
        return False
    flags = set()
    index = 1  # argv[0] is the effective interpreter
    while index < len(args):
        token = args[index]
        if token == "--":
            break
        if not token.startswith("-") or token == "-":
            break
        if token == "--check-hash-based-pycs":
            index += 1
            if index >= len(args) or args[index] not in ("default", "always", "never"):
                return False
        elif token.startswith("--check-hash-based-pycs="):
            if token.split("=", 1)[1] not in ("default", "always", "never"):
                return False
        elif token.startswith("--"):
            return False
        else:
            offset = 1
            command = False
            while offset < len(token):
                option = token[offset]
                if option in "bBdEhiIOPsSqRtuUvVx":
                    flags.add(option)
                    offset += 1
                elif option in "cmWXQ":
                    if option == "Q" and major == 3:
                        return False
                    value = token[offset + 1:]
                    if not value:
                        index += 1
                        if index >= len(args):
                            return False
                        value = args[index]
                    if option in "cm":
                        command = True
                    break
                else:
                    return False
            if command:
                break
        index += 1
    if "I" in flags:
        return True
    if minor < 11 or "P" not in flags:
        return False
    return (
        "s" in flags
        or ("S" in flags and no_site)
        or ("E" not in flags and environment.get(b"PYTHONNOUSERSITE") == b"1")
    )


def _startup(record, installation, environment):
    identity = installation.get(record.get("executable_sha256"))
    if not identity or identity.get("class") not in ("native", "cpython", "chain"):
        return "interpreter_identity_unestablished"
    if not identity.get("trusted") or not identity.get("mounts_trusted"):
        return "interpreter_installation_untrusted"
    if identity["class"] != "cpython":
        return None
    try:
        argv = _argv(record["argv"])
        valid = _python_options(
            argv, identity.get("python_version"), environment, identity.get("no_site", False)
        )
    except (KeyError, TypeError, ValueError):
        valid = False
    return None if valid else "python_startup_unisolated"


def _tasks(records):
    parents = {0: None}
    sharing = set()
    for record in records:
        if record.get("kind") != "task":
            continue
        task = record.get("logical_task_id")
        parent = record.get("parent_id")
        if not isinstance(task, int) or task in parents or parent not in parents:
            return None, None
        parents[task] = parent
        if record.get("fs_sharing_unknown"):
            sharing.add(task)
    for record in records:
        if record.get("kind") not in ("exec", "exec_failed", "observation"):
            continue
        task = record.get("logical_task_id")
        if task is None:
            continue
        if task not in parents or (
            "parent_id" in record and record["parent_id"] != parents[task]
        ):
            return None, None
    return parents, sharing


def _ancestor(task, parents, last_images):
    while task is not None:
        if task in last_images:
            return last_images[task]
        task = parents[task]
    return None


def _termination(record, observations, closing):
    task = record["logical_task_id"]
    if closing.get("termination") == "timed_out":
        return {"kind": "timed_out"}
    for observation in reversed(observations.get(task, [])):
        status = observation.get("wait_status")
        if isinstance(status, dict):
            if status.get("kind") in ("exited", "signaled"):
                return {"kind": status["kind"], "code": status.get("code", status.get("signal"))}
        elif isinstance(status, int):
            if os.WIFEXITED(status):
                return {"kind": "exited", "code": os.WEXITSTATUS(status)}
            if os.WIFSIGNALED(status):
                return {"kind": "signaled", "code": os.WTERMSIG(status)}
    return None


def _matches(records, plan, parents, closing):
    steps = plan["steps"]
    images = [record for record in records if record.get("kind") == "exec"]
    observations = {}
    for record in records:
        if record.get("kind") == "observation":
            observations.setdefault(record.get("logical_task_id"), []).append(record)
    counts = {step["id"]: 0 for step in steps}
    last_images = {}
    covered = []
    terminal_branch = False
    entry_seen = False
    ambiguous = False
    for record in images:
        task = record["logical_task_id"]
        predecessor = _ancestor(task, parents, last_images)
        if predecessor is not None and predecessor["role"] == "entry":
            # Everything after entry is outside the covered launch boundary.
            last_images[task] = predecessor
            continue
        if predecessor is not None and predecessor["role"] == "terminal":
            ambiguous = True
            continue
        parent_id = predecessor["id"] if predecessor else "worker-root"
        try:
            argv = _argv(record["argv"])
        except (KeyError, TypeError, ValueError):
            ambiguous = True
            continue
        candidates = [
            step for step in steps
            if parent_id in step["predecessors"]
            and record.get("executable_sha256") == step["executable_sha256"]
            and argv in [_argv(alt) for alt in step["argv_alternatives"]]
            and counts[step["id"]] < step["max"]
        ]
        if len(candidates) != 1:
            ambiguous = True
            continue
        step = candidates[0]
        if entry_seen:
            ambiguous = True  # an unplanned sibling after an entry is still a branch
        counts[step["id"]] += 1
        covered.append((record, step))
        last_images[task] = step
        entry_seen |= step["role"] == "entry"
        termination = _termination(record, observations, closing)
        allowed = step.get("allowed_terminations", [])
        if termination is not None and allowed and termination not in allowed:
            ambiguous = True
        if step.get("terminal_branch") and termination in allowed[1:]:
            terminal_branch = True
    missing = any(
        step["role"] == "entry" and counts[step["id"]] < step["min"]
        for step in steps
    )
    if ambiguous:
        return "launch_boundary_ambiguous", covered
    if missing and not terminal_branch:
        return "suite_entry_missing", covered
    if any(
        counts[step["id"]] < step["min"] and step["role"] != "entry"
        for step in steps
    ):
        return "launch_boundary_ambiguous", covered
    return None, covered


def observe_run(records, plan, baseline, installations, *,
                sensor_approved=True, bookkeeping_profiles=None) -> tuple[str, str | None]:
    """Decide one run, in the refusal order of the evidence-level ruling."""
    if not sensor_approved:
        return _refuse("sensor_configuration_unsupported")
    if any(
        record.get("kind") == "exec"
        and record.get("environment_reason") == "environment_truncated"
        for record in records
    ):
        return _refuse("environment_truncated")
    if (
        not records
        or any(record.get("seq") != index for index, record in enumerate(records))
        or any(record.get("kind") in ("capture_failed", "trace_error") for record in records)
        or records[-1].get("kind") != "closing"
    ):
        return _refuse("trace_incomplete")
    closing = records[-1]
    sensor = closing.get("sensor", {})
    if (
        sensor.get("status") != "complete"
        or not sensor.get("collection_closed")
        or not sensor.get("tasks_reaped")
    ):
        if sensor.get("status") == "incomplete" and sensor.get("reason") == "shared_fs_unsupported":
            return _refuse("shared_fs_unsupported")
        return _refuse("trace_incomplete")
    parents, sharing = _tasks(records)
    if parents is None:
        return _refuse("trace_incomplete")
    if sharing:
        return _refuse("shared_fs_unsupported")
    reason, covered = _matches(records, plan, parents, closing)
    if reason:
        return _refuse(reason)
    for record, step in covered:
        reason, environment = _environment(record, step, baseline)
        if reason:
            return _refuse(reason)
        reason = _startup(record, installations, environment)
        if reason:
            return _refuse(reason)
    return "supported", None
