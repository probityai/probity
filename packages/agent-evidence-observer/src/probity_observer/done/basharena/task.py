"""A BashArena dataset row as the inputs of a sealed contract, with no model call.

The row's fields are the published dataset's: ``task_id``, ``description``, ``dockerfile``, ``tests``,
``setup_script_type``, ``setup_script_content``, ``app_file``, ``app_requirements``, ``metadata``. The
spec digests every input that shapes the environment, names each hidden test case by its pytest node id,
and lists the top-level modules the hidden tests import (the sealed runtime must provide them).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from ..formats import DoneError, sha256

DATASET = "Eccentricity/bashbench2"
TEST_FILE = "tests.py"


class Refused(DoneError):
    """The row cannot be sealed as a gradeable contract."""

    def __init__(self, task_id: str, reason: str, detail: str = "") -> None:
        super().__init__(f"{task_id}: {reason}" + (f": {detail}" if detail else ""))
        self.task_id = task_id
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Spec:
    """What the compiler read from one row."""

    task_id: str
    description: str
    tests: str
    tests_sha256: str
    test_ids: list[str]
    imports: list[str]
    environment: dict[str, Any] = field(default_factory=dict)


def _digest(text: str | None) -> str | None:
    return None if text is None else sha256(text.encode())


def _is_test_function(node: ast.AST) -> bool:
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")


def test_ids(source: str) -> list[str]:
    """Pytest node ids of the module's test functions and of test methods in ``Test*`` classes."""
    tree = ast.parse(source)
    found = []
    for node in tree.body:
        if _is_test_function(node):
            found.append(f"{TEST_FILE}::{node.name}")
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            found.extend(f"{TEST_FILE}::{node.name}::{item.name}"
                         for item in node.body if _is_test_function(item))
    return sorted(found)


def imported_modules(source: str) -> list[str]:
    """Top-level names of every absolute import in the source, anywhere in the file."""
    names = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return sorted(names)


def compile_spec(row: dict[str, Any], row_index: int, revision: str) -> Spec:
    """Read one dataset row; refuse a row whose hidden tests cannot grade it."""
    task_id = str(row["task_id"])
    tests = row.get("tests") or ""
    try:
        ids = test_ids(tests)
        imports = imported_modules(tests)
    except SyntaxError as exc:
        raise Refused(task_id, "tests_unparsable", str(exc)) from exc
    if not ids:
        raise Refused(task_id, "no_tests")
    setup = row.get("setup_script_content")
    environment = {
        "dataset": {"name": DATASET, "revision": revision, "row": row_index},
        "dockerfile": _digest(row.get("dockerfile")),
        "setup_script": _digest(setup),
        "setup_script_type": row.get("setup_script_type") if setup is not None else None,
        "app_file": _digest(row.get("app_file")),
        "app_requirements": _digest(row.get("app_requirements")),
    }
    return Spec(task_id=task_id, description=row["description"], tests=tests,
                tests_sha256=sha256(tests.encode()), test_ids=ids, imports=imports,
                environment=environment)
