"""Records shared by the done-receipt adapters.

The done contract is sealed before an agent runs. The tree, observation and
grade records come from producers outside the agent. Each adapter pins every
record through the consumer policy; this module only parses and compares.
"""

from __future__ import annotations

import ast
import hashlib
import itertools
import posixpath
from pathlib import Path, PurePosixPath
from typing import Any

from ..common import CaseError, _artifact, _digest, _instant, _object, _string
from ..vocabulary import ACCEPTED_WITNESS_SCOPES, EXTERNAL, PEER, witness_scope_error
from . import witnessed
from .event_absence import _record, _scope, _witness

MUTATION_TYPES = frozenset(
    {"write", "create", "rename", "link", "unlink", "truncate", "chmod"})
EXEC_TYPE = "exec"
CONNECT_TYPE = "connect"
SCOPES = ACCEPTED_WITNESS_SCOPES
VANTAGES = ("independent", "self_reported")
GAP_CAUSES = ("agent", "host", "sensor", "unknown")
LOCATIONS = ("grader_path", "outside_workspace")
SPECIAL_KINDS = ("fifo", "socket", "char", "block")
LOADER_ENV = frozenset({
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME",
    "PYTHONSAFEPATH", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONNOUSERSITE",
    "PYTHONPYCACHEPREFIX", "PYTHONWARNINGS", "PYTEST_ADDOPTS", "PYTEST_PLUGINS",
    "NODE_OPTIONS", "NODE_PATH"})
# Files that change what a later run loads before any of its own code runs: Python's start-up
# hooks and environment marker, the dynamic loader's preload list, cache and configuration,
# and the grader's reward files. ``<name>._pth`` (Python's path file beside the
# interpreter) is matched by suffix in :func:`grader_path`.
GRADER_FILES = frozenset({"sitecustomize.py", "usercustomize.py", "reward.json", "reward.txt",
                          "pyvenv.cfg", "ld.so.preload", "ld.so.cache", "ld.so.conf"})
GRADER_SEGMENTS = frozenset({"site-packages", "dist-packages", "verifier", "ld.so.conf.d"})
# The grader's reward files, and honest scratch roots where they and a ``verifier`` directory
# are the agent's own: the grader runs in a fresh container whose /tmp is a new tmpfs.
REWARD_FILES = frozenset({"reward.json", "reward.txt"})
SCRATCH_ROOTS = ("/tmp/", "/var/tmp/")
SYSTEM_ROOTS = ("/etc/", "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/")
# Files pytest reads from the workspace and from every directory above it, with no flag.
ANCESTOR_CONFIG = frozenset({"conftest.py", "pytest.ini", "pyproject.toml", "tox.ini",
                             "setup.cfg"})
# Never a whole execution-surface entry: each holds or is shared with honest scratch space.
SURFACE_FORBIDDEN = frozenset({"/", "/tmp", "/var/tmp"})
ALIAS_HOPS = 40
# How the grader's trusted run of a command failed: an assertion on the answer, the
# candidate ending its own process, an exception the candidate's code raises wherever it runs,
# or anything else (an exception that can come from the trusted run's isolation, a timeout,
# a result the codec refused).
FAILURE_KINDS = ("assertion", "candidate_exit", "candidate_raised", "candidate")
EQUIVALENCES = ("python_ast",)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_BASE = "https://w3id.org/agent-evidence/predicate/v1/"
DONE_CONTRACT_PREDICATE = PREDICATE_BASE + "done-contract"
DONE_RECEIPT_PREDICATE = PREDICATE_BASE + "done-receipt"
RATCHET_ADMISSION_PREDICATE = PREDICATE_BASE + "ratchet-admission"


def path(value: Any, label: str) -> str:
    """A normalized workspace-relative POSIX path."""
    name = _string(value, label)
    if ("\x00" in name or name.startswith("/") or name.endswith("/")
            or any(part in ("", ".", "..") for part in name.split("/"))
            or str(PurePosixPath(name)) != name):
        raise CaseError(f"{label}: expected a normalized relative path")
    return name


def absolute(value: Any, label: str) -> str:
    """A normalized absolute POSIX path, as the observer writes container paths."""
    name = _string(value, label)
    if ("\x00" in name or not name.startswith("/") or name.startswith("//")
            or posixpath.normpath(name) != name):
        raise CaseError(f"{label}: expected a normalized absolute path")
    return name


def under(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix.rstrip("/") + "/")


def protects(entry: dict, name: str) -> bool:
    """Whether a protected entry covers a path, after its exclusions.

    An exclusion without ``/`` is a path segment name left out at any depth
    (``__pycache__``); one with ``/`` is a workspace path under the entry, left
    out together with everything below it.
    """
    if not under(name, entry["path"]):
        return False
    below = name[len(entry["path"]) + 1:].split("/") if name != entry["path"] else []
    for item in entry.get("exclude", ()):
        if (item in below) if "/" not in item else under(name, item):
            return False
    return True


def affects(entry: dict, name: str) -> bool:
    """Whether a mutation of ``name`` can change what a protected entry resolves to.

    That is a path the entry covers (:func:`protects`) or any ancestor directory of the
    entry: renaming, removing or replacing ``tests`` changes what ``tests/test_app.py``
    names, even when every byte under it is later moved back.
    """
    return protects(entry, name) or under(entry["path"], name)


def ancestor_config(name: str, root: str) -> bool:
    """A pytest configuration file in the workspace's own parent chain, which pytest
    reads for a run in the workspace whatever the command line says."""
    head, base = posixpath.split(name)
    return base in ANCESTOR_CONFIG and under(root, head)


def grader_path(name: str) -> bool:
    """A path where a mutation can change how a grader runs or scores a run: a grader file,
    or a grader directory or anything under one (a directory renamed onto
    ``site-packages`` replaces every module in it)."""
    parts = name.split("/")
    # A pyvenv.cfg configures only the interpreter beside it. Outside a system root that is a venv
    # the agent made in its own scratch, which the sealed grader never runs.
    if parts[-1] == "pyvenv.cfg" and not name.startswith(SYSTEM_ROOTS):
        return False
    # Start-up hooks and site directories count everywhere (Python loads a user site under
    # /tmp); a reward file or a ``verifier`` directory under a scratch root does not.
    scratch = name.startswith(SCRATCH_ROOTS)
    files = GRADER_FILES - REWARD_FILES if scratch else GRADER_FILES
    segments = GRADER_SEGMENTS - {"verifier"} if scratch else GRADER_SEGMENTS
    return (parts[-1] in files or parts[-1].endswith((".pth", "._pth"))
            or bool(set(parts) & segments))


def tree_digest(files: dict[str, str]) -> str:
    """SHA-256 over sorted ``"<sha256>  <path>\\n"`` lines, as sha256sum prints them."""
    lines = "".join(f"{files[name]}  {name}\n"
                    for name in sorted(files, key=lambda item: item.encode("utf-8")))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def record_digest(record: dict) -> str:
    """The ``probity-tree/v2`` digest: one sorted line per entry of the tree.

    ``<sha256>  <path>`` for a plain file, ``x:<sha256>  <path>`` for a file
    with an execute bit, ``l:<sha256 of the target>  <path>`` for a symbolic
    link and ``s:<kind>  <path>`` for a special file.
    """
    executable = set(record["executable"])
    lines = {name: ("x:" if name in executable else "") + digest
             for name, digest in record["files"].items()}
    for name, target in record["symlinks"].items():
        lines[name] = "l:" + hashlib.sha256(target.encode("utf-8", "surrogateescape")).hexdigest()
    for name, kind in record["special"].items():
        lines[name] = "s:" + kind
    text = "".join(f"{lines[name]}  {name}\n"
                   for name in sorted(lines, key=lambda item: item.encode("utf-8")))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _argv(value: Any, label: str) -> list[str]:
    if (not isinstance(value, list) or not value
            or any(not isinstance(item, str) for item in value) or not value[0]):
        raise CaseError(f"{label}: expected a nonempty list of strings")
    return value


def _count(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CaseError(f"{label}: expected a nonnegative integer")
    return value


def _exit(value: Any, label: str) -> int:
    if type(value) is not int or not -255 <= value <= 255:
        raise CaseError(f"{label}: expected an integer exit status")
    return value


def _choice(value: Any, label: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise CaseError(f"{label}: unsupported value")
    return value


def _distinct_paths(value: Any, label: str) -> list[str]:
    if (not isinstance(value, list)
            or len({item for item in value if isinstance(item, str)}) != len(value)):
        raise CaseError(f"{label}: expected a list of distinct paths")
    return [path(item, f"{label}[{index}]") for index, item in enumerate(value)]


def _exclude(names: Any, entry_path: str, kind: str, label: str) -> None:
    if (kind != "directory" or not isinstance(names, list) or not names
            or len({item for item in names if isinstance(item, str)}) != len(names)):
        raise CaseError(f"{label}.exclude: expected distinct names or paths on a directory")
    for item in names:
        if not isinstance(item, str):
            raise CaseError(f"{label}.exclude: expected strings")
        if "/" in item:
            if path(item, f"{label}.exclude") == entry_path or not under(item, entry_path):
                raise CaseError(f"{label}.exclude: a path must lie under the entry")
        elif item in ("", ".", "..") or "\x00" in item:
            raise CaseError(f"{label}.exclude: expected a path segment name")


def _protected_entry(item: Any, label: str) -> dict:
    entry = _object(item, label, {"path", "kind", "sha256"}, {"exclude", "equivalence"})
    name = path(entry["path"], f"{label}.path")
    kind = _choice(entry["kind"], f"{label}.kind", ("file", "directory"))
    _digest(entry["sha256"], f"{label}.sha256")
    if "exclude" in entry:
        _exclude(entry["exclude"], name, kind, label)
    if "equivalence" in entry:
        _choice(entry["equivalence"], f"{label}.equivalence", EQUIVALENCES)
        if kind != "file":
            raise CaseError(f"{label}.equivalence: only a file entry names one")
    return entry


PROBES = ("determinism", "type_strict", "import_side_effects")
TIERS = ("trusted", "synthesized")
STRENGTHS = ("gated", "reference_free", "synthesized_spec")


def _acceptance_entry(item: Any, label: str) -> dict:
    entry = _object(item, label, {"id", "argv"},
                    {"ids", "run_writes", "cwd", "exe", "interpreter", "tier", "probe",
                     "in_process_twin_of"})
    if "tier" in entry:
        _choice(entry["tier"], f"{label}.tier", TIERS)
    if "probe" in entry:
        # An oracle-free probe that probe_observed/v1 reads, not a behavioural command.
        _choice(entry["probe"], f"{label}.probe", PROBES)
    _string(entry["id"], f"{label}.id")
    _argv(entry["argv"], f"{label}.argv")
    if ("cwd" in entry) != ("exe" in entry):
        raise CaseError(f"{label}: cwd and exe are sealed together")
    if "cwd" in entry:
        absolute(entry["cwd"], f"{label}.cwd")
        exe = entry["exe"]
        if isinstance(exe, list):
            # Every path that names the one executable file (python, python3, python3.12).
            if not exe or exe != sorted(set(exe)):
                raise CaseError(f"{label}.exe: expected a path or sorted distinct paths")
            for index, name in enumerate(exe):
                absolute(name, f"{label}.exe[{index}]")
        else:
            absolute(exe, f"{label}.exe")
    if "interpreter" in entry:
        # The paths of the Python that runs the command's entry point as ``-m <module>``.
        found = entry["interpreter"]
        if "exe" not in entry or not isinstance(found, list) or not found or (
                found != sorted(set(found))):
            raise CaseError(f"{label}.interpreter: expected sorted distinct paths beside exe")
        for index, name in enumerate(found):
            absolute(name, f"{label}.interpreter[{index}]")
    if "in_process_twin_of" in entry:
        _string(entry["in_process_twin_of"], f"{label}.in_process_twin_of")
    if "ids" in entry:
        ids = entry["ids"]
        if (not isinstance(ids, list) or not ids or len(set(map(str, ids))) != len(ids)
                or any(not isinstance(test, str) or not test for test in ids)):
            raise CaseError(f"{label}.ids: expected distinct nonempty test ids")
    if "run_writes" in entry:
        _distinct_paths(entry["run_writes"], f"{label}.run_writes")
    return entry


def _adequacy(value: Any) -> dict:
    adequacy = _object(value, "contract.adequacy", {"mutants", "killed"},
                       {"by_class", "kill_vector_sha256", "gates"})
    if "gates" in adequacy:
        gates = adequacy["gates"]
        if not isinstance(gates, dict) or any(
                not isinstance(gate, dict) or type(gate.get("pass")) is not bool
                for gate in gates.values()):
            raise CaseError("contract.adequacy.gates: expected objects with a boolean pass")
    mutants = _count(adequacy["mutants"], "contract.adequacy.mutants")
    if _count(adequacy["killed"], "contract.adequacy.killed") > mutants:
        raise CaseError("contract.adequacy: more mutants killed than generated")
    if "kill_vector_sha256" in adequacy:
        _digest(adequacy["kill_vector_sha256"], "contract.adequacy.kill_vector_sha256")
    if "by_class" in adequacy:
        classes = adequacy["by_class"]
        if not isinstance(classes, dict) or not classes:
            raise CaseError("contract.adequacy.by_class: expected a nonempty object")
        totals = [0, 0]
        for name, counts in classes.items():
            label = f"contract.adequacy.by_class[{name}]"
            _string(name, label)
            counts = _object(counts, label, {"mutants", "killed"})
            made = _count(counts["mutants"], f"{label}.mutants")
            dead = _count(counts["killed"], f"{label}.killed")
            if dead > made:
                raise CaseError(f"{label}: more mutants killed than generated")
            totals = [totals[0] + made, totals[1] + dead]
        if totals != [mutants, adequacy["killed"]]:
            raise CaseError("contract.adequacy.by_class: counts do not sum to the totals")
    return adequacy


def contract(data: bytes) -> dict:
    record = _record(data, "contract",
                     {"schema_version", "contract_id", "protected_paths", "acceptance",
                      "adequacy"},
                     {"task", "heldout_split_sha256", "mutant_set_sha256", "authority_sha256",
                      "module_under_test", "strength", "native_loaded", "execution_surface",
                      "surface_aliases"})
    if "strength" in record:
        _choice(record["strength"], "contract.strength", STRENGTHS)
    if not isinstance(record.get("native_loaded", []), list):
        raise CaseError("contract.native_loaded: expected list")
    for index, item in enumerate(record.get("native_loaded", [])):
        loaded = _object(item, f"contract.native_loaded[{index}]", {"path", "sha256"})
        path(loaded["path"], f"contract.native_loaded[{index}].path")
        _digest(loaded["sha256"], f"contract.native_loaded[{index}].sha256")
    if record["schema_version"] != "probity-done-contract/v1":
        raise CaseError("unsupported contract schema_version")
    _string(record["contract_id"], "contract.contract_id")
    if "task" in record:
        _string(record["task"], "contract.task")
    for key in ("heldout_split_sha256", "mutant_set_sha256", "authority_sha256"):
        if key in record:
            _digest(record[key], f"contract.{key}")
    protected = record["protected_paths"]
    if not isinstance(protected, list):
        raise CaseError("contract.protected_paths: expected list")
    seen: set[str] = set()
    for index, item in enumerate(protected):
        name = _protected_entry(item, f"contract.protected_paths[{index}]")["path"]
        if name in seen:
            raise CaseError("contract.protected_paths: duplicate path")
        seen.add(name)
    acceptance = record["acceptance"]
    if not isinstance(acceptance, list) or not acceptance:
        raise CaseError("contract.acceptance: expected a nonempty list")
    ids: set[str] = set()
    for index, item in enumerate(acceptance):
        command_id = _acceptance_entry(item, f"contract.acceptance[{index}]")["id"]
        if command_id in ids:
            raise CaseError("contract.acceptance: duplicate id")
        ids.add(command_id)
    for index, item in enumerate(acceptance):
        twin = item.get("in_process_twin_of")
        if twin is not None and (twin == item["id"] or twin not in ids or any(
                other["id"] == twin and "probe" in other for other in acceptance)):
            raise CaseError(f"contract.acceptance[{index}].in_process_twin_of: expected "
                            "the id of another behavioural command")
    _surface(record)
    _adequacy(record["adequacy"])
    if "module_under_test" in record:
        modules = _distinct_paths(record["module_under_test"], "contract.module_under_test")
        if not modules:
            raise CaseError("contract.module_under_test: expected a nonempty list")
    return record


def _surface(record: dict) -> None:
    """The sealed execution surface: sorted distinct absolute directories, none of them a
    shared scratch root, and the image links that lead into it."""
    if "execution_surface" in record:
        entries = record["execution_surface"]
        if not isinstance(entries, list) or not entries or entries != sorted(set(entries)):
            raise CaseError("contract.execution_surface: expected sorted distinct paths")
        for index, name in enumerate(entries):
            if absolute(name, f"contract.execution_surface[{index}]") in SURFACE_FORBIDDEN:
                raise CaseError(f"contract.execution_surface[{index}]: a shared root is "
                                "never a whole surface entry")
    if "surface_aliases" in record:
        aliases = record["surface_aliases"]
        if not isinstance(aliases, dict) or "execution_surface" not in record:
            raise CaseError("contract.surface_aliases: expected an object beside "
                            "execution_surface")
        for link, target in aliases.items():
            absolute(link, "contract.surface_aliases key")
            absolute(target, f"contract.surface_aliases[{link}]")


def surface(contract: dict | None, record: dict) -> tuple[list[str], dict[str, str]]:
    """The contract's execution surface and aliases, checked against the observed run.

    An entry that is the workspace, lies inside it or above it would make honest work in
    the workspace into a mutation of the surface, so the contract is refused. The
    observation does not record ``HOME``; the observer that seals the surface from the
    agent image leaves the agent's ``HOME`` out."""
    if contract is None or "execution_surface" not in contract:
        return [], {}
    root = record["workspace_root"]
    for name in contract["execution_surface"]:
        if under(name, root) or under(root, name):
            raise CaseError(f"contract.execution_surface: {name} covers the workspace")
    return contract["execution_surface"], contract.get("surface_aliases", {})


def resolve(name: str, aliases: dict[str, str]) -> str:
    """A path with each image link prefix replaced by what it resolves to, longest first."""
    for _ in range(ALIAS_HOPS):
        link = max((key for key in aliases if under(name, key)), key=len, default=None)
        if link is None:
            return name
        name = (aliases[link].rstrip("/") + name[len(link):]) or "/"
    raise CaseError(f"contract.surface_aliases: more than {ALIAS_HOPS} link hops")


def on_surface(name: str, entries: list[str], aliases: dict[str, str]) -> bool:
    """Whether a path, as written or after the image links, lies under a surface entry."""
    return any(under(candidate, entry) for candidate in {name, resolve(name, aliases)}
               for entry in entries)


def surface_effects(record: dict, entries: list[str], aliases: dict[str, str]) -> list[str]:
    """Ids of outside mutations of any type, unlink included, on the execution surface."""
    return [entry["id"] for entry in record["external_mutations"]
            if any(on_surface(name, entries, aliases) for name in entry["paths"])]


def _origin_fields(record: dict, label: str) -> None:
    _string(record["claim_id"], f"{label}.claim_id")
    _string(record["invocation_id"], f"{label}.invocation_id")
    _string(record["producer"], f"{label}.producer")
    _choice(record["vantage"], f"{label}.vantage", VANTAGES)
    if record["witness_scope"] not in SCOPES:
        raise CaseError(f"{label}.{witness_scope_error(record['witness_scope'])}")


ORIGIN = {"claim_id", "invocation_id", "producer", "vantage", "witness_scope"}


def tree(data: bytes) -> dict:
    """A ``probity-tree/v2`` record: every non-directory entry of the final workspace."""
    record = _record(data, "tree", {"schema_version", "tree_sha256", "files", "executable",
                                    "symlinks", "special"} | ORIGIN)
    if record["schema_version"] != "probity-tree/v2":
        raise CaseError("unsupported tree schema_version")
    _origin_fields(record, "tree")
    names: list[str] = []
    for member, check in (("files", lambda value, label: _digest(value, label)),
                          ("symlinks", lambda value, label: _string(value, label)),
                          ("special", lambda value, label: _choice(value, label, SPECIAL_KINDS))):
        entries = record[member]
        if not isinstance(entries, dict):
            raise CaseError(f"tree.{member}: expected object")
        for name, value in entries.items():
            names.append(path(name, f"tree.{member} key"))
            check(value, f"tree.{member}[{name}]")
    if len(set(names)) != len(names):
        raise CaseError("tree: a path is listed under two kinds")
    ordered = sorted(names, key=lambda item: item.encode("utf-8"))
    if any(under(later, earlier) for earlier, later in itertools.pairwise(ordered)):
        raise CaseError("tree: an entry lies under another non-directory entry")
    executable = record["executable"]
    if (not isinstance(executable, list) or executable != sorted(set(executable))
            or any(name not in record["files"] for name in executable)):
        raise CaseError("tree.executable: expected sorted distinct paths of listed files")
    if record_digest(record) != _digest(record["tree_sha256"], "tree.tree_sha256"):
        raise CaseError("tree.tree_sha256: does not match the listed entries")
    return record


def _exec_fields(event: dict, label: str) -> None:
    _argv(event.get("argv"), f"{label}.argv")
    absolute(event.get("exe"), f"{label}.exe")
    absolute(event.get("cwd"), f"{label}.cwd")
    env = event.get("env")
    if (not isinstance(env, dict) or set(env) - LOADER_ENV
            or any(not isinstance(value, str) for value in env.values())):
        raise CaseError(f"{label}.env: expected loader environment strings")
    if "exit" in event:
        _exit(event["exit"], f"{label}.exit")
    if {"path", "target", "address"} & event.keys():
        raise CaseError(f"{label}: exec events carry argv, exe, cwd and env, not paths")


EXEC_FIELDS = {"argv", "exit", "exe", "cwd", "env"}


# An origin names an exec event id; a value that is not text names none.
def _event(item: Any, index: int, exec_ids: set[str]) -> dict:
    label = f"events[{index}]"
    event = _object(item, label, {"id", "type", "time", "step"},
                    {"path", "target", "origin", "address"} | EXEC_FIELDS)
    _string(event["id"], f"{label}.id")
    kind = _string(event["type"], f"{label}.type")
    _count(event["step"], f"{label}.step")
    if "origin" in event and (not isinstance(event["origin"], str)
                           or event["origin"] not in exec_ids):
        raise CaseError(f"{label}.origin: expected an earlier exec event id")
    if kind == EXEC_TYPE:
        _exec_fields(event, label)
        return event
    if EXEC_FIELDS & event.keys():
        raise CaseError(f"{label}: only exec events carry argv, exe, cwd, env and exit")
    if kind == CONNECT_TYPE:
        if not isinstance(event.get("address"), str) or {"path", "target"} & event.keys():
            raise CaseError(f"{label}: a connect event carries an address and no path")
        return event
    if "address" in event:
        raise CaseError(f"{label}.address: only connect events carry an address")
    if kind in MUTATION_TYPES and "path" not in event:
        raise CaseError(f"{label}.path: mutation events require a path")
    if "path" in event:
        path(event["path"], f"{label}.path")
    if "target" in event:
        if kind not in ("rename", "link"):
            raise CaseError(f"{label}.target: only rename and link name a target")
        path(event["target"], f"{label}.target")
    return event


def _external(item: Any, index: int, exec_ids: set[str], root: str) -> dict:
    label = f"external_mutations[{index}]"
    entry = _object(item, label, {"id", "step", "time", "type", "paths", "location"},
                    {"origin"})
    _string(entry["id"], f"{label}.id")
    _count(entry["step"], f"{label}.step")
    _choice(entry["type"], f"{label}.type", tuple(sorted(MUTATION_TYPES)))
    _choice(entry["location"], f"{label}.location", LOCATIONS)
    paths = entry["paths"]
    if not isinstance(paths, list) or not paths:
        raise CaseError(f"{label}.paths: expected a nonempty list")
    for position, name in enumerate(paths):
        if under(absolute(name, f"{label}.paths[{position}]"), root):
            raise CaseError(f"{label}.paths: an outside mutation names a workspace path")
    if "origin" in entry and (not isinstance(entry["origin"], str)
                           or entry["origin"] not in exec_ids):
        raise CaseError(f"{label}.origin: expected an earlier exec event id")
    return entry


def _gaps(record: dict, start: Any, end: Any) -> None:
    coverage = record["coverage"]
    gaps = record.get("gaps", [])
    if coverage == "incomplete":
        if not isinstance(gaps, list) or not gaps:
            raise CaseError("observation.gaps: incomplete coverage requires named gaps")
    elif "gaps" in record:
        raise CaseError("observation.gaps: only incomplete coverage can name gaps")
    for index, item in enumerate(gaps):
        gap = _object(item, f"gaps[{index}]", {"start", "end", "gap_cause"})
        _choice(gap["gap_cause"], f"gaps[{index}].gap_cause", GAP_CAUSES)
        if not start <= _instant(gap["start"], f"gaps[{index}].start") < _instant(
                gap["end"], f"gaps[{index}].end") <= end:
            raise CaseError("observation.gaps: gap outside scope or empty")


def observation(data: bytes) -> dict:
    """A ``probity-observation/v3`` record.

    ``events`` and ``external_mutations`` share one step sequence: steps are
    unique across both lists and increase within each, and an ``origin`` in
    either names an ``exec`` event with a smaller step.
    """
    record = _record(data, "observation",
                     {"schema_version", "scope", "coverage", "workspace_root", "events",
                      "external_mutations"} | ORIGIN, {"gaps"})
    if record["schema_version"] != "probity-observation/v3":
        raise CaseError("unsupported observation schema_version")
    _origin_fields(record, "observation")
    _scope(record["scope"], "observation.scope")
    root = absolute(record["workspace_root"], "observation.workspace_root")
    _choice(record["coverage"], "observation.coverage", ("complete", "incomplete", "unknown"))
    start = _instant(record["scope"]["start"], "observation.scope.start")
    end = _instant(record["scope"]["end"], "observation.scope.end")
    _gaps(record, start, end)
    events, external = record["events"], record["external_mutations"]
    if not isinstance(events, list) or not isinstance(external, list):
        raise CaseError("observation.events and external_mutations: expected lists")
    rows = [(item, False) for item in events] + [(item, True) for item in external]
    for item, _ in rows:
        if not isinstance(item, dict) or type(item.get("step")) is not int:
            raise CaseError("observation: every event needs an integer step")
    seen: set[str] = set()
    steps: set[int] = set()
    exec_ids: set[str] = set()
    indexes = {False: 0, True: 0}
    for item, outside in sorted(rows, key=lambda row: row[0]["step"]):
        index = indexes[outside]
        indexes[outside] += 1
        entry = (_external(item, index, exec_ids, root) if outside
                 else _event(item, index, exec_ids))
        instant = _instant(entry["time"], f"events[{index}].time")
        if entry["step"] in steps or (events if not outside else external)[index] is not item:
            raise CaseError("observation: steps must increase in record order, unique "
                            "across events and external_mutations")
        if entry["id"] in seen or not start <= instant <= end:
            raise CaseError("observation: duplicate or out-of-scope event")
        seen.add(entry["id"])
        steps.add(entry["step"])
        if not outside and entry["type"] == EXEC_TYPE:
            exec_ids.add(entry["id"])
    return record


def written(record: dict, before: int | None = None) -> set[str]:
    """Absolute paths the observed run made or changed, optionally before a step.

    Inside the workspace these are the paths and targets of mutation events
    other than ``unlink``, joined to ``workspace_root``; outside, the paths
    of ``external_mutations`` other than ``unlink``.
    """
    root = record["workspace_root"].rstrip("/")
    found: set[str] = set()
    for event in record["events"]:
        if (event["type"] in MUTATION_TYPES and event["type"] != "unlink"
                and (before is None or event["step"] < before)):
            found.update(f"{root}/{event[key]}" for key in ("path", "target") if key in event)
    for entry in record["external_mutations"]:
        if entry["type"] != "unlink" and (before is None or entry["step"] < before):
            found.update(entry["paths"])
    return found


def agent_gap(record: dict) -> str | None:
    """The contradiction a gap the agent caused gives, or ``None``.

    A gap that runs to the end of the scope means the trace stopped for good
    (``tracer_terminated_prematurely``); a bounded one means part of the run
    went unseen (``coverage_sabotaged``).
    """
    gaps = [gap for gap in record.get("gaps", []) if gap["gap_cause"] == "agent"]
    if not gaps:
        return None
    if any(gap["end"] == record["scope"]["end"] for gap in gaps):
        return "tracer_terminated_prematurely"
    return "coverage_sabotaged"


def external_grader_effects(record: dict) -> list[str]:
    """Ids of outside mutations at a grader path, by the record's label or by the path,
    of pytest configuration written in a directory above the workspace, and of a mutation
    of a directory above the workspace itself (moving it aside swaps every path below it,
    protected ones included, as an ancestor rename inside the workspace does)."""
    root = record["workspace_root"]
    return [entry["id"] for entry in record["external_mutations"]
            if entry["location"] == "grader_path"
            or any(grader_path(name) or ancestor_config(name, root) or under(root, name)
                   for name in entry["paths"])]


def _result(item: Any, label: str) -> dict:
    entry = _object(item, label, {"id", "argv", "exit"},
                    {"collected", "passed", "replay", "timed_out", "failure_kind"})
    _string(entry["id"], f"{label}.id")
    _argv(entry["argv"], f"{label}.argv")
    _exit(entry["exit"], f"{label}.exit")
    # The verifier stopped the run at its limit: present only as true, on a failed run.
    if "timed_out" in entry and (entry["timed_out"] is not True or entry["exit"] == 0):
        raise CaseError(f"{label}.timed_out: expected true on a run with a nonzero exit")
    if "failure_kind" in entry:
        _choice(entry["failure_kind"], f"{label}.failure_kind", FAILURE_KINDS)
        if entry["exit"] == 0:
            raise CaseError(f"{label}.failure_kind: only a failed run has one")
    if "collected" in entry:
        _count(entry["collected"], f"{label}.collected")
    # Of the sealed ids that ran, how many passed on every run (none failed or skipped).
    if "passed" in entry and ("collected" not in entry
                              or _count(entry["passed"], f"{label}.passed") > entry["collected"]):
        raise CaseError(f"{label}.passed: expected a count of collected ids, beside collected")
    if "replay" in entry:
        replay = _object(entry["replay"], f"{label}.replay",
                         {"calls_intercepted", "distinct_calls"})
        calls = _count(replay["calls_intercepted"], f"{label}.replay.calls_intercepted")
        if _count(replay["distinct_calls"], f"{label}.replay.distinct_calls") > calls:
            raise CaseError(f"{label}.replay: more distinct calls than calls")
    return entry


def _hunk(item: Any, label: str) -> dict:
    hunk = _object(item, label, {"path", "lines", "mutants", "killed"})
    path(hunk["path"], f"{label}.path")
    lines = hunk["lines"]
    if (not isinstance(lines, list) or len(lines) != 2
            or any(type(line) is not int or line < 1 for line in lines) or lines[0] > lines[1]):
        raise CaseError(f"{label}.lines: expected [first, last] line numbers")
    if _count(hunk["killed"], f"{label}.killed") > _count(hunk["mutants"], f"{label}.mutants"):
        raise CaseError(f"{label}: more mutants killed than generated")
    return hunk


# The visible-test detectors whose finding refuses a pass: the dynamic rules, in the order the
# grader reports them. Static findings (an unsatisfiable visible test, a table of the visible
# inputs, an identifying guard) are evidence only, because a one-line rewrite defeats them.
DETECTOR_REASONS = ("impure_on_visible", "type_strict_on_visible", "repeat_divergence",
                    "isolated_branch")
# The two findings that say who made the visible test unsatisfiable, and the parties each may
# name. The task pre-flight (``invalid_task_spec``, the visible test read statement by statement
# on evaluated arguments) always names the task and never refuses: it is a defect of the task,
# outside both verdicts.
ATTRIBUTIONS = {"visible_test_unsatisfiable": ("agent", "test_author"), "invalid_task_spec": ("task",)}


def _detectors(value: Any, label: str) -> dict:
    """The grader's visible-test detectors: a status and one finding per rule that fired.

    A finding that refuses names one of :data:`DETECTOR_REASONS`; a measured finding names any
    rule and never refuses. Only ``visible_test_unsatisfiable`` and the task pre-flight
    ``invalid_task_spec`` say who made the visible test unsatisfiable (``attribution``, one of the
    reason's :data:`ATTRIBUTIONS`); the pre-flight always says so."""
    block = _object(value, label, {"status", "findings"})
    _string(block["status"], f"{label}.status")
    if not isinstance(block["findings"], list):
        raise CaseError(f"{label}.findings: expected list")
    for index, item in enumerate(block["findings"]):
        where = f"{label}.findings[{index}]"
        finding = _object(item, where, {"reason", "refuses", "evidence"}, {"attribution"})
        reason = _string(finding["reason"], f"{where}.reason")
        if type(finding["refuses"]) is not bool:
            raise CaseError(f"{where}.refuses: expected a boolean")
        if finding["refuses"]:
            _choice(reason, f"{where}.reason", DETECTOR_REASONS)
        if reason == "invalid_task_spec" and "attribution" not in finding:
            raise CaseError(f"{where}.attribution: the task pre-flight names the task")
        if "attribution" in finding:
            if reason not in ATTRIBUTIONS:
                raise CaseError(f"{where}.attribution: only an unsatisfiable visible test has one")
            _choice(finding["attribution"], f"{where}.attribution", ATTRIBUTIONS[reason])
    return block


def grade(data: bytes) -> dict:
    record = _record(data, "grade",
                     {"schema_version", "contract_sha256", "tree_sha256", "results"} | ORIGIN,
                     {"hunks", "visible_detectors"})
    if record["schema_version"] != "probity-acceptance-grade/v1":
        raise CaseError("unsupported grade schema_version")
    _origin_fields(record, "grade")
    _digest(record["contract_sha256"], "grade.contract_sha256")
    _digest(record["tree_sha256"], "grade.tree_sha256")
    results = record["results"]
    if not isinstance(results, list):
        raise CaseError("grade.results: expected list")
    ids: set[str] = set()
    for index, item in enumerate(results):
        result_id = _result(item, f"grade.results[{index}]")["id"]
        if result_id in ids:
            raise CaseError("grade.results: duplicate id")
        ids.add(result_id)
    hunks = record.get("hunks", [])
    if not isinstance(hunks, list):
        raise CaseError("grade.hunks: expected list")
    for index, item in enumerate(hunks):
        _hunk(item, f"grade.hunks[{index}]")
    if "visible_detectors" in record:
        _detectors(record["visible_detectors"], "grade.visible_detectors")
    return record


COMPLETION_BASES = ("final_text", "tool_claim", "both")


def claims(data: bytes) -> dict:
    """The ``probity-tool-claims/v2`` record: the runs the agent claims and whether it
    asserted completion (``completion``: ``asserted`` and the ``basis`` the harness read it
    from, ``final_text``, ``tool_claim`` or ``both``; ``none`` exactly when not asserted)."""
    record = _record(data, "claims",
                     {"schema_version", "claim_id", "invocation_id", "producer", "claims",
                      "completion"})
    if record["schema_version"] != "probity-tool-claims/v2":
        raise CaseError("unsupported claims schema_version")
    completion = _object(record["completion"], "claims.completion", {"asserted", "basis"})
    if type(completion["asserted"]) is not bool:
        raise CaseError("claims.completion.asserted: expected a boolean")
    expected = COMPLETION_BASES if completion["asserted"] else ("none",)
    if completion["basis"] not in expected:
        raise CaseError(f"claims.completion.basis: expected one of {list(expected)}")
    for key in ("claim_id", "invocation_id", "producer"):
        _string(record[key], f"claims.{key}")
    items = record["claims"]
    if not isinstance(items, list):
        raise CaseError("claims.claims: expected list")
    ids: set[str] = set()
    for index, item in enumerate(items):
        label = f"claims[{index}]"
        entry = _object(item, label, {"id", "argv"}, {"exit"})
        claim_id = _string(entry["id"], f"{label}.id")
        _argv(entry["argv"], f"{label}.argv")
        if "exit" in entry:
            _exit(entry["exit"], f"{label}.exit")
        if claim_id in ids:
            raise CaseError("claims: duplicate id")
        ids.add(claim_id)
    return record


def start(case: Any, policy: Any, claim_type: str, fields: set[str],
          optional: set[str] = frozenset()) -> tuple[str, dict]:
    """Validate the case and policy envelopes and return the case's assessment."""
    case = _object(case, "case", {"schema_version", "case_id", "artifacts"})
    policy = _object(policy, "policy", {"schema_version", "witnesses", "assessments"})
    if (case["schema_version"] != "probity-case/v1"
            or policy["schema_version"] != "probity-policy/v1"):
        raise CaseError("unsupported schema_version")
    case_id = _string(case["case_id"], "case_id")
    if not isinstance(case["artifacts"], dict) or not isinstance(policy["witnesses"], dict):
        raise CaseError("artifacts and witnesses: expected objects")
    assessments = policy["assessments"]
    if not isinstance(assessments, dict) or case_id not in assessments:
        raise CaseError("case_id has no consumer assessment")
    assessment = _object(assessments[case_id], "assessment", fields, optional)
    if assessment["claim_type"] != claim_type:
        raise CaseError("unsupported claim_type")
    return case_id, assessment


def source(case: dict, root: Path, digest: str) -> bytes | None:
    """The bytes of a file by its SHA-256, from the case artifact ``source:<sha256>``.

    The artifact is bound by its own digest, so no consumer pin is needed: the
    contract or the pinned tree record already names the digest.
    """
    meta = case["artifacts"].get(f"source:{digest}")
    if meta is None:
        return None
    data, binding = _artifact(root, meta, f"artifacts.source:{digest}")
    return data if binding.get("sha256") == digest else None


def same_ast(first: bytes, second: bytes) -> bool:
    """Whether two Python sources parse to the same syntax tree.

    Comments, blank lines and layout do not reach the tree. Source that does
    not parse is never equivalent. Parsing runs none of the code.
    """
    try:
        trees = [ast.dump(ast.parse(data), include_attributes=False) for data in (first, second)]
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return trees[0] == trees[1]


def witnesses(case: dict, policy: dict, assessment: dict, root: Path,
              roles: dict[str, bool]) -> dict[str, tuple[bytes | None, dict]]:
    """Bind each named witness role; ``True`` roles need producer, vantage and scope pins.

    An ``EXTERNAL`` scope pin must also carry a ``witnessed`` pin, which is
    verified here against the bound record's bytes; its outcome replaces it in
    the bound pin. Only that outcome can make a record ``EXTERNAL``.
    """
    ids = {role: _string(assessment[f"{role}_witness"], f"{role}_witness") for role in roles}
    if len(set(ids.values())) != len(ids):
        raise CaseError("each witness role requires a separate witness")
    bound = {role: _witness(case, policy, ids[role], root, require_vantage=observed,
                            require_scope=observed, allow_witnessed=observed)
             for role, observed in roles.items()}
    if len({pin["artifact"] for _, pin in bound.values()}) != len(bound):
        raise CaseError("each witness role requires a separate artifact")
    for role, observed in roles.items():
        data, pin = bound[role]
        label = f"witness.{ids[role]}.witnessed"
        if observed and pin["witness_scope"] == EXTERNAL:
            if "witnessed" not in pin:
                raise CaseError(f"{label}: an EXTERNAL scope pin must name the witness "
                                "bundle, keys and operators")
            config = witnessed.parse(pin["witnessed"], label)
            pin["witnessed"] = witnessed.earn(case, root, data, config)
        elif "witnessed" in pin:
            raise CaseError(f"{label}: only an EXTERNAL scope pin names a witness")
    return bound


def independent(record: dict, pin: dict, observed_party: str) -> bool:
    """The consumer pin and the record agree on an independent producer."""
    return (record["vantage"] == pin["vantage"] == "independent"
            and record["producer"] == pin["producer"]
            and record["producer"] != observed_party)


def earned_scope(pin: dict) -> str:
    """The scope a pin's verified witness bundle earned; ``PEER`` without one."""
    return pin.get("witnessed", {}).get("witness_scope", PEER)


def scope_of(*pairs: tuple[dict | None, dict]) -> str:
    """EXTERNAL only when every record's verified witness bundle earned EXTERNAL.

    A record's own ``witness_scope`` is never read here: a launcher writes
    ``PEER`` into every record it produces (its receipt requires the records to
    match it), and a host that wrote ``EXTERNAL`` would be grading itself. Only
    ``witnessed.earn`` sets the earned scope, after a 2-of-2 co-signature check
    under the consumer's key and operator pins. Anything less is PEER.
    """
    external = bool(pairs) and all(record is not None and earned_scope(pin) == EXTERNAL
                                   for record, pin in pairs)
    return EXTERNAL if external else PEER


def unwitnessed_claims(*pairs: tuple[dict | None, dict]) -> list[dict]:
    """Records that claim EXTERNAL scope that no verified witness bundle earned."""
    claims = []
    for record, pin in pairs:
        if record is None or record["witness_scope"] != EXTERNAL:
            continue
        if earned_scope(pin) == EXTERNAL:
            continue
        outcome = pin.get("witnessed")
        claims.append({"witness": pin["id"], "claimed": EXTERNAL, "earned": PEER,
                       "reason": outcome["reason"] if outcome is not None
                       else "no witness bundle is pinned for this record"})
    return claims


def scope_fields(*pairs: tuple[dict | None, dict]) -> dict:
    """The decision members that report the witness scope a verdict rests on."""
    fields: dict[str, Any] = {"witness_scope": scope_of(*pairs)}
    claims = unwitnessed_claims(*pairs)
    if claims:
        fields["unwitnessed_scope_claims"] = claims
    return fields
