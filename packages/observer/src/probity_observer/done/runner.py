"""Run one acceptance command on one state of a task.

Each run gets a fresh copy of the state at ``<scratch>/workspace`` and, when the task has
held-out files, a copy of them at ``<scratch>/heldout``. Commands run with the workspace as
their working directory, so a held-out file is reached as ``../heldout/<name>``: the same
argv works for :class:`SubprocessRunner` here and for the docker runner in
:mod:`.verify_run`, which mounts the two directories at ``/workspace`` and ``/heldout``.

:class:`SubprocessRunner` isolates nothing beyond a scrubbed environment and a fresh copy.
The contract compiler may use it to measure stability and mutant kills on trusted states
(reference, pre-patch, mutants); grading an agent's tree always uses the docker runner.
"""

from __future__ import annotations

import json
import os
import posixpath
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from ..sensors import treedigest
from . import pytest_plugins
from . import replay as replay_harness
from .formats import DoneError

TIMEOUT_EXIT = 124
SCRUBBED_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONHASHSEED": "0",
}


@dataclass(frozen=True)
class Command:
    """One acceptance command: an id, its exact argv, and whether it is held out."""

    id: str
    argv: tuple[str, ...]
    heldout: bool = False
    prepatch: str = "fail"
    ids_from: int | None = None
    # The agent runs this command itself; the contract seals the working directory and the
    # executable its exec shows, so a claim of it can be matched to the run.
    agent_command: bool = False
    # An oracle-free probe (``determinism``, ``type_strict``, ``import_side_effects``): it asks
    # whether passing code passes for the right reason, and probity-verify reads it on the
    # integrity axis (``probe_observed/v1``), never as a behavioural test.
    probe: str | None = None
    # The test ids a wrapped command runs (``sh -c "<copy> && exec <sealed pytest> <ids>"``),
    # whose ids are not a tail of ``argv`` for ``ids_from`` to name.
    sealed_ids: tuple[str, ...] | None = None

    def record(self) -> dict:
        """The contract entry; a command the sealed pytest plugins run also seals its test
        ids, which the grade's ``collected`` and ``passed`` counts must match."""
        entry: dict = {"id": self.id, "argv": list(self.argv)}
        if self.probe is not None:
            entry["probe"] = self.probe
        if self.sealed_ids is not None:
            entry["ids"] = list(self.sealed_ids)
        elif self.ids_from is not None and (pytest_plugins.is_sealed_pytest(self.argv)
                                            or is_pytest_replay(self.argv)):
            entry["ids"] = list(self.argv[self.ids_from:])
        return entry


class Runner(Protocol):
    """Run ``argv`` on a copy of ``state`` (and ``heldout``) and return its exit status.

    When ``writes`` is a list, the runner appends every workspace path the run created,
    changed or removed (regular files, compared by digest). ``stdin`` is written to the run's
    standard input and closed (a sealed plugin's report key travels this way). When
    ``stopped`` is a list, the runner appends ``True`` if it stopped the run, or a replay
    probe's call inside it, at its time limit: no answer, as opposed to a wrong one.
    """

    name: str

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float, writes: list[str] | None = None,
            output: list[str] | None = None, stdin: bytes | None = None,
            stopped: list[bool] | None = None) -> int: ...

    def executable(self, name: str) -> str | list[str]:
        """The absolute path the kernel runs for ``name`` where this runner runs commands (a
        PATH lookup, which is what the observer records as an exec's ``exe``), or every PATH
        name of that same file, sorted (``python`` and ``python3``)."""
        ...


def _one_or_all(found: set[str], name: str, where: str, detail: str = "") -> str | list[str]:
    if not found:
        raise DoneError(f"cannot resolve {name!r} in {where}{detail}")
    ordered = sorted(found)
    return ordered[0] if len(ordered) == 1 else ordered


_SAME_FILE = ('p=$(command -v "$1") || exit 3; r=$(readlink -f "$p") || exit 4; echo "$p"; '
              'IFS=:; for d in $PATH; do for f in "$d"/*; do '
              '[ -x "$f" ] && [ "$(readlink -f "$f")" = "$r" ] && echo "$f"; done; done')


def image_executable(image: str, name: str, docker: str = "docker") -> str | list[str]:
    """:meth:`Runner.executable` inside ``image``.

    An agent that prints ``python test.py`` and runs ``python3 test.py`` ran the sealed
    interpreter; a different interpreter is a different file and stays unmatched."""
    done = subprocess.run([docker, "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh",
                           image, "-c", _SAME_FILE, "sh", name],
                          capture_output=True, text=True, timeout=300, check=False)
    found = {line for line in done.stdout.splitlines()
             if line.startswith("/") and posixpath.normpath(line) == line}
    if done.returncode not in (0, 1):
        found = set()
    return _one_or_all(found, name, f"the agent image {image}",
                       f": exit {done.returncode} {done.stderr.strip()[:200]}")


def path_executable(name: str, path: str) -> str | list[str]:
    """:meth:`Runner.executable` on this host, for the search list ``path``."""
    first = shutil.which(name, path=path)
    if first is None or not os.path.isabs(first):
        return _one_or_all(set(), name, f"PATH {path}")
    target = os.path.realpath(first)
    found = {os.path.normpath(first)}
    for directory in path.split(os.pathsep):
        if not os.path.isabs(directory) or not os.path.isdir(directory):
            continue
        for entry in os.scandir(directory):
            candidate = os.path.join(directory, entry.name)
            if (os.access(candidate, os.X_OK) and os.path.isfile(candidate)
                    and os.path.realpath(candidate) == target):
                found.add(os.path.normpath(candidate))
    return _one_or_all(found, name, f"PATH {path}")


def changed_paths(before: Path, after: Path) -> list[str]:
    """Regular-file paths that differ between two trees, sorted."""
    old, new = treedigest.scan(before).files, treedigest.scan(after).files
    return sorted(name for name in set(old) | set(new) if old.get(name) != new.get(name))


def stage(state: Path, heldout: Path | None, scratch: Path) -> Path:
    """Copy ``state`` (and ``heldout``) under an empty ``scratch``; return the workspace."""
    workspace = scratch / "workspace"
    shutil.copytree(state, workspace, symlinks=True)
    if heldout is not None:
        shutil.copytree(heldout, scratch / "heldout", symlinks=True)
    return workspace


def is_replay(argv: Sequence[str]) -> bool:
    return bool(argv) and argv[0] == replay_harness.COMMAND


DETERMINISM_RUNS = 2


PYTEST_FLAG = "--pytest"
# The sealed test root a pytest replay starts from, beside the sealed configuration.
PYTEST_ROOT = "pytest-root"
PYTEST_ROOT_ARG = f"../heldout/{PYTEST_ROOT}"
_PYTEST_KEYS = ("--config", "--overlay", "--remote", "--repeats")
PYTEST_IDS_FROM = 2 + 2 * len(_PYTEST_KEYS) + 1


def pytest_replay_argv(config: str | None, overlay: str | None, remote: Sequence[str],
                       repeats: int, ids: Sequence[str]) -> tuple[str, ...]:
    """The acceptance argv that runs sealed pytest ``ids`` by parent-compare replay.

    ``config`` and ``overlay`` are paths from the workspace into the sealed directory (the
    sealed pytest configuration, and for a held-out command the held-out tree laid over the
    sealed test root); ``remote`` names the top-level modules the child serves."""
    return (replay_harness.COMMAND, PYTEST_FLAG, "--config", config or "-", "--overlay",
            overlay or "-", "--remote", ",".join(sorted(remote)), "--repeats", str(repeats),
            "--", *ids)


def pytest_replay_fields(argv: Sequence[str]) -> dict | None:
    """The fields of a well-formed pytest replay argv, or ``None``."""
    items = list(argv)
    if (len(items) <= PYTEST_IDS_FROM or items[:2] != [replay_harness.COMMAND, PYTEST_FLAG]
            or items[2:PYTEST_IDS_FROM - 1:2] != list(_PYTEST_KEYS)
            or items[PYTEST_IDS_FROM - 1] != "--" or not items[9].isdigit()):
        return None
    remote = [name for name in items[7].split(",") if name]
    if not remote or any(not name.isidentifier() for name in remote):
        return None
    return {"config": None if items[3] == "-" else items[3],
            "overlay": None if items[5] == "-" else items[5], "remote": remote,
            "repeats": int(items[9]), "ids": items[PYTEST_IDS_FROM:]}


def is_pytest_replay(argv: Sequence[str]) -> bool:
    return pytest_replay_fields(argv) is not None


def replay_mode(argv: Sequence[str]) -> str | None:
    """The replay mode an argv names, or ``None`` when it is not a well-formed replay argv."""
    if len(argv) > 1 and argv[1] == PYTEST_FLAG:
        return "pytest" if is_pytest_replay(argv) else None
    if len(argv) == 4:
        return "assert"
    if len(argv) == 5 and argv[4] in replay_harness.MODES:
        return argv[4]
    return None


def run_replay(scratch: Path, argv: Sequence[str], child_argv, timeout: float,
               order_seed: str, results: list[dict] | None,
               stopped: list[bool] | None = None) -> int:
    """Run a parent-compare replay command staged under ``scratch``.

    ``argv`` is ``(COMMAND, <sealed test path from the workspace>, <module>, <entry>[, mode])``.
    Only the module's file is copied into the child's directory; ``child_argv(directory,
    source)`` returns the child's command line and working directory. A pytest replay
    (:func:`pytest_replay_argv`) gives the child a copy of the whole agent tree and the parent a
    test root of sealed files only. The determinism probe
    gives each of its child runs the whole ``timeout``, so the command's own limit is that
    many times longer.
    """
    mode = replay_mode(argv)
    if mode is None:
        return 2
    workspace = scratch / "workspace"
    if mode == "pytest":
        found = _pytest_request(scratch, argv, child_argv)
        if found is None:
            return 2
        request = {**found, "call_timeout": min(timeout, 60.0), "order_seed": order_seed,
                   "mode": mode, "run_timeout": timeout, "out": str(scratch / "replay.json")}
        return _run_parent(scratch, argv, request, timeout, results, stopped)
    _, test, module, entry = argv[:4]
    candidate = scratch / "candidate"
    candidate.mkdir()
    source = workspace / f"{module}.py"
    if source.is_file() and not source.is_symlink():
        shutil.copy2(source, candidate / f"{module}.py")
        os.chmod(candidate / f"{module}.py", 0o644)
    os.chmod(candidate, 0o755)
    os.chmod(scratch, 0o755)
    command, cwd = child_argv(candidate, replay_harness.child_source(
        module, entry, probe_import=mode == "import_side_effects"))
    request = {"test": str((workspace / test).resolve()), "child_argv": command,
               "child_cwd": cwd, "call_timeout": min(timeout, 60.0), "order_seed": order_seed,
               "mode": mode, "run_timeout": timeout, "out": str(scratch / "replay.json")}
    return _run_parent(scratch, argv, request, timeout, results, stopped)


def _sealed_path(scratch: Path, name: str) -> Path | None:
    """``name`` (a path from the workspace) resolved, when it lies inside the sealed directory."""
    sealed = (scratch / "heldout").resolve()
    found = (scratch / "workspace" / name).resolve()
    return found if found == sealed or sealed in found.parents else None


def _pytest_request(scratch: Path, argv: Sequence[str], child_argv) -> dict | None:
    """Lay out a pytest replay: the sealed test root (with the held-out tree over it for a
    held-out command) for the parent, and a readable copy of the agent's tree for the child.

    ``None`` when the argv names a path outside the sealed directory or the sealed root is
    missing."""
    fields = pytest_replay_fields(argv)
    assert fields is not None
    source = _sealed_path(scratch, PYTEST_ROOT_ARG)
    config = _sealed_path(scratch, fields["config"]) if fields["config"] else None
    overlay = _sealed_path(scratch, fields["overlay"]) if fields["overlay"] else None
    if (source is None or not source.is_dir() or (fields["config"] and config is None)
            or (fields["overlay"] and (overlay is None or not overlay.is_dir()))):
        return None
    root = scratch / "pytest-tests"
    shutil.copytree(source, root, symlinks=True)
    if overlay is not None:
        shutil.copytree(overlay, root, symlinks=True, dirs_exist_ok=True)
    candidate = scratch / "candidate"
    shutil.copytree(scratch / "workspace", candidate, symlinks=True)
    chmod_tree(candidate, 0o755, 0o644)
    os.chmod(scratch, 0o755)
    from . import pytest_replay

    command, cwd = child_argv(candidate, pytest_replay.child_source())
    return {"test_root": str(root.resolve()), "config": str(config) if config else None,
            "ids": fields["ids"], "remote": fields["remote"], "repeats": fields["repeats"],
            "child_argv": command, "child_cwd": cwd}


def _run_parent(scratch: Path, argv: Sequence[str], request: dict, timeout: float,
                results: list[dict] | None, stopped: list[bool] | None) -> int:
    mode = request["mode"]
    (scratch / "request.json").write_text(json.dumps(request))
    limit = timeout * DETERMINISM_RUNS + 30 if mode == "determinism" else timeout
    parent = subprocess.Popen([sys.executable, "-I", "-m", "probity_observer.done.replay",
                               str(scratch / "request.json")], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True)
    try:
        parent.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        stop_replay_parent(parent)
        if stopped is not None:
            stopped.append(True)
        return TIMEOUT_EXIT
    done = parent
    if (scratch / "replay.json").is_file():
        report = json.loads((scratch / "replay.json").read_text())
        if stopped is not None and report.get("timed_out") is True:
            stopped.append(True)
        if results is not None:
            results.append({"argv": list(argv), **report})
    return done.returncode


REPLAY_STOP_GRACE = 30.0


def stop_replay_parent(parent: subprocess.Popen) -> None:
    """Stop a replay parent that outran its limit without orphaning its candidate children.

    Each child runs in its own session (:class:`.replay.Child`), out of reach of a signal to the
    parent's group, so the parent is asked first: SIGTERM makes it close every child it started
    (its own ``close_all``). Only a parent that does not finish within the grace is killed,
    with its whole group."""
    try:
        os.killpg(parent.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        parent.wait(timeout=REPLAY_STOP_GRACE)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(parent.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        parent.wait()


class SubprocessRunner:
    """A local run with a scrubbed environment; no isolation from the host."""

    name = "subprocess"

    def __init__(self, python: str | None = None, order_seed: str = "subprocess") -> None:
        self.env = dict(SCRUBBED_ENV)
        self.python = python or sys.executable
        self.order_seed = order_seed
        self.replays: list[dict] = []
        if python is not None:
            self.env["PATH"] = f"{Path(python).parent}:{self.env['PATH']}"

    def child_argv(self, directory: Path, source: str) -> tuple[list[str], str]:
        return [self.python, "-I", "-P", "-c", source], str(directory)

    def executable(self, name: str) -> str | list[str]:
        return path_executable(name, self.env["PATH"])

    def run(self, state: Path, argv: Sequence[str], heldout: Path | None,
            timeout: float, writes: list[str] | None = None,
            output: list[str] | None = None, stdin: bytes | None = None,
            stopped: list[bool] | None = None) -> int:
        with tempfile.TemporaryDirectory(prefix="probity-done-") as scratch:
            workspace = stage(Path(state), heldout, Path(scratch))
            if is_replay(argv):
                return run_replay(Path(scratch), argv, self.child_argv, timeout,
                                  self.order_seed, self.replays, stopped)
            try:
                done = subprocess.run(list(argv), cwd=workspace, env=self.env,
                                      input=stdin if stdin is not None else b"",
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=timeout,
                                      check=False, start_new_session=True)
                code = done.returncode
                if output is not None:
                    output.append(done.stdout.decode("utf-8", "replace"))
            except subprocess.TimeoutExpired:
                code = TIMEOUT_EXIT
                if stopped is not None:
                    stopped.append(True)
            except OSError:
                code = 127
            if writes is not None:
                writes.extend(changed_paths(Path(state), workspace))
            return code


def chmod_tree(root: Path, mode_dirs: int = 0o777, mode_files: int = 0o666) -> None:
    """Open a scratch copy to an unprivileged worker uid (the copy is thrown away)."""
    for directory, dirnames, filenames in os.walk(root):
        os.chmod(directory, mode_dirs)
        for name in filenames:
            path = Path(directory) / name
            if not path.is_symlink():
                os.chmod(path, mode_files | (os.stat(path).st_mode & 0o111))
