"""A real-repository task from a proposal: acceptance commands and protected paths, sealed.

A proposal is one JSON object with exactly ``acceptance`` (1 to 8 test-runner commands, each
with ``id``, ``argv`` and ``expect_on_start``), ``protected_paths`` (``path`` and ``kind``)
and ``rationale``. It is only a proposal: every path is checked against the repository, every
command is rewritten into the sealed pytest form, and the compiler then runs each through the
same three-run stability step and mutant adequacy measurement as a dataset task.

``probity-done contract --dataset repo --proposal FILE`` reads one from a file; an installed
contract provider (:mod:`.providers`) may write one instead.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from . import mutants, pytest_plugins
from .changes import Changes
from .contract import (DEFAULT_TEST_CMD, EXCLUDE, Protected, Task, command_test_files,
                       is_test_path, sealed_config, source_changes)
from .formats import DoneError, sha256
from .runner import Command

SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".tox", ".pytest_cache"}


def repo_files(repo: Path) -> list[Path]:
    found = []
    for path in sorted(repo.rglob("*")):
        relative = path.relative_to(repo)
        if path.is_file() and not path.is_symlink() and not set(relative.parts) & SKIP_DIRS:
            found.append(path)
    return found


def proposal_object(text: str) -> dict[str, Any]:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise DoneError("the proposal holds no JSON object")
    try:
        value = json.loads(text[start:end + 1])
    except json.JSONDecodeError as exc:
        raise DoneError(f"the proposal is not JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"acceptance", "protected_paths", "rationale"}:
        raise DoneError("a proposal must have exactly acceptance, protected_paths, rationale")
    return value


def is_test_runner(argv: list[str]) -> bool:
    """``pytest``, ``python -m pytest`` or ``python -m unittest``, and nothing else."""
    first = argv[0].rsplit("/", 1)[-1]
    if first == "pytest":
        return True
    return (first in ("python", "python3") and len(argv) >= 3 and argv[1] == "-m"
            and argv[2] in ("pytest", "unittest"))


def proposed_commands(items: Any) -> list[Command]:
    if not isinstance(items, list) or not 1 <= len(items) <= 8:
        raise DoneError("acceptance must list 1 to 8 commands")
    commands, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"id", "argv", "expect_on_start"}:
            raise DoneError("each acceptance command has id, argv and expect_on_start")
        argv = item["argv"]
        if (not isinstance(argv, list) or not argv or any(not isinstance(arg, str) for arg in argv)
                or not isinstance(item["id"], str) or item["id"] in seen
                or item["expect_on_start"] not in ("fail", "pass")):
            raise DoneError(f"acceptance command is malformed: {item!r}")
        if not is_test_runner(argv):
            raise DoneError(f"acceptance command is not a test runner: {argv!r}")
        seen.add(item["id"])
        commands.append(Command(item["id"], tuple(argv), prepatch=item["expect_on_start"]))
    return commands


# Options the sealed prefix already sets, or that change only how much pytest prints.
_PREFIX_FLAGS = frozenset({"-q", "-qq", "-v", "-vv", "-x", "-s", "--quiet", "--verbose"})


def _runner_args(argv: tuple[str, ...]) -> tuple[str, list[str]]:
    """``("pytest" | "unittest", the arguments after the runner)``."""
    if argv[0].rsplit("/", 1)[-1] == "pytest":
        return "pytest", list(argv[1:])
    return argv[2], list(argv[3:])


def unittest_node(repo: Path, name: str) -> str | None:
    """The pytest node id of a ``python -m unittest`` name (``a.b.C.t`` to ``a/b.py::C::t``)."""
    parts = name.split(".")
    for index in range(len(parts), 0, -1):
        path = "/".join(parts[:index]) + ".py"
        if (repo / path).is_file():
            return "::".join([path, *parts[index:]])
    return None


def sealed_command(repo: Path, command: Command, prefix: tuple[str, ...]) -> Command | None:
    """``command`` in the sealed pytest form on ``prefix``, or ``None`` when a unittest name
    resolves to no file. A command whose arguments are all test ids or paths seals them
    (``ids_from``); one with other options keeps them after the prefix and seals no ids."""
    runner, args = _runner_args(command.argv)
    kept: list[str] = []
    index = 0
    while index < len(args):
        if args[index] in _PREFIX_FLAGS:
            index += 1
            continue
        if args[index:index + 2] == ["-p", "no:cacheprovider"]:
            index += 2
            continue
        kept.append(args[index])
        index += 1
    if runner == "unittest":
        names = [arg for arg in kept if not arg.startswith("-")]
        nodes = [unittest_node(repo, name) for name in names]
        if not names or any(node is None for node in nodes):
            return None
        kept = [node for node in nodes if node is not None]
    ids = not any(arg.startswith("-") for arg in kept) and bool(kept)
    return Command(command.id, prefix + tuple(kept), prepatch=command.prepatch,
                   ids_from=len(prefix) if ids else None)


def isolation_targets(reference: Path, changes: dict[str, Changes]) -> list[str]:
    """``path::name`` of every module-level function the reference change touches."""
    found = []
    for name, change in changes.items():
        tree = ast.parse((reference / name).read_text())
        for item in mutants.touched(tree, list(change.ranges), change.anchors):
            if "." not in item.qualname:
                found.append(f"{name}::{item.qualname}")
    return sorted(found)


def seal_commands(repo: Path, commands: list[Command], held: Path, tests: list[str],
                  isolate: list[str]
                  ) -> tuple[list[Command], list[dict[str, Any]], tuple[str, ...]]:
    """Every proposed command in the sealed pytest form, and the ones that cannot be.

    The start tree's pytest configuration and the sealed plugins are copied under ``held``;
    each test runs twice (``probity_repeat``) and each touched module-level function runs
    with no test frame (``probity_isolated_call``). Also returns the prefix before the
    plugins, which guard tests are sealed on.
    """
    base = DEFAULT_TEST_CMD + sealed_config(repo, held)
    pytest_plugins.install(held / "config")
    prefix = pytest_plugins.pytest_argv(base, tests, isolate, pytest_plugins.REPEATS)
    sealed, dropped = [], []
    for command in commands:
        found = sealed_command(repo, command, prefix)
        if found is None:
            dropped.append({"id": command.id, "argv": list(command.argv),
                            "reason": "unittest_unresolved"})
        else:
            sealed.append(found)
    return sealed, dropped, base


def protected_paths(repo: Path, items: Any) -> list[Protected]:
    if not isinstance(items, list):
        raise DoneError("protected_paths must be a list")
    found = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"path", "kind"}:
            raise DoneError("each protected path has path and kind")
        name, kind = item["path"], item["kind"]
        target = repo / str(name)
        if (not isinstance(name, str) or name.startswith("/") or ".." in name.split("/")
                or kind not in ("file", "directory")
                or not (target.is_file() if kind == "file" else target.is_dir())):
            raise DoneError(f"protected path is not in the repository: {item!r}")
        found.append(Protected(name, kind, EXCLUDE if kind == "directory" else ()))
    return found


def changed_sources(start: Path, reference: Path) -> dict[str, Changes]:
    """The changed lines of each Python source file the reference solution changes."""
    names = [path.relative_to(reference).as_posix() for path in repo_files(reference)]
    return source_changes(start, reference, [
        name for name in names if name.endswith(".py") and not is_test_path(name)
        and (not (start / name).is_file()
             or (start / name).read_bytes() != (reference / name).read_bytes())])


def read_proposal(path: Path) -> tuple[str, str]:
    """The proposal text in ``path`` and the file's SHA-256.

    The file is the bare proposal, or a recorded chat call (JSON with the ``request`` and
    ``response`` bodies), whose proposal is its first choice's message content."""
    data = Path(path).read_bytes()
    try:
        call = json.loads(data)
    except ValueError:
        call = None
    if isinstance(call, dict) and "response" in call:
        response = call["response"]
        response = json.loads(response) if isinstance(response, str) else response
        try:
            content = response["choices"][0]["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError) as error:
            raise DoneError("the recorded call has no choices[0].message") from error
        if not isinstance(content, str):
            raise DoneError("the recorded call has no content")
        return content, sha256(data)
    return data.decode("utf-8"), sha256(data)


def task_from_proposal(repo: Path, task_id: str, description: str, text: str,
                       reference: Path | None, work: Path) -> tuple[Task, dict[str, Any]]:
    """The unsealed task a proposal describes, and the record of what was proposed.

    Every proposed command is rewritten into the sealed pytest form, whose configuration and
    plugins go to ``work/heldout``. Without a ``reference`` (a known-good solution) the
    contract has no mutants to measure."""
    value = proposal_object(text)
    proposed = proposed_commands(value["acceptance"])
    targets = changed_sources(repo, reference) if reference else {}
    tests = sorted({name for command in proposed for name in command_test_files(command, repo)})
    held = work / "heldout"
    held.mkdir(parents=True, exist_ok=True)
    isolate = isolation_targets(reference, targets) if reference else []
    commands, dropped, base = seal_commands(repo, proposed, held, tests, isolate)
    if not commands:
        raise DoneError("no proposed command has a sealed pytest form")
    task = Task(task_id=task_id, source="repo", description=description, start=repo,
                commands=commands, protected=protected_paths(repo, value["protected_paths"]),
                heldout=held, reference=reference, mutation_targets=targets,
                guard_prefix=base, isolate=tuple(isolate))
    record = {"rationale": value["rationale"],
              "proposed": [{"id": command.id, "argv": list(command.argv)} for command in proposed],
              "dropped": dropped, "isolated_targets": isolate}
    return task, record


def from_file(repo: Path, task_id: str, description: str, path: Path, reference: Path | None,
              work: Path) -> Task:
    """:func:`task_from_proposal` on the proposal in ``path``, with its digest in the notes."""
    text, digest = read_proposal(path)
    task, record = task_from_proposal(repo, task_id, description, text, reference, work)
    record = {"source": "file", "proposal_sha256": digest, **record}
    task.notes = {"proposal": record}
    return task
