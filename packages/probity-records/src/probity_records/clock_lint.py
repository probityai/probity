"""Refuse every direct read of the system clock outside the clock module.

    python -m probity_records.clock_lint SRC_DIR [SRC_DIR ...] [--allow PATH ...]

Each source file is parsed, import aliases are resolved (``import time as t``, ``from datetime import datetime as
dt``, ``from time import monotonic``), and every reference to a function that reads the wall or monotonic clock, or
schedules on it, is reported with its file and line, whether it is called or only passed along (``default=time.time``
reads the clock later). Code takes a ``probity_records.clock.Clock`` instead. Exit status: 0 clean, 1 findings, 2 a
file that does not parse or a directory with no Python source (a scan that read nothing is not a clean result).
The report always names how many files it scanned.
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

__all__ = ["FORBIDDEN", "Finding", "Scan", "scan_paths", "scan_source"]

#: Module-level functions that read the clock or wait on it, by module.
FORBIDDEN: dict[str, frozenset[str]] = {
    "time": frozenset({"time", "time_ns", "monotonic", "monotonic_ns", "perf_counter", "perf_counter_ns", "sleep",
                       "gmtime", "localtime", "ctime", "asctime", "strftime"}),
    "asyncio": frozenset({"sleep"}),
    "threading": frozenset({"Timer"}),
    "uuid": frozenset({"uuid1", "uuid6", "uuid7"}),
}
#: Class methods that read the clock: ``datetime.now()``, ``date.today()`` and their kin.
FORBIDDEN_METHODS: dict[tuple[str, str], frozenset[str]] = {
    ("datetime", "datetime"): frozenset({"now", "utcnow", "today"}),
    ("datetime", "date"): frozenset({"today"}),
}
#: Functions that read the clock only when the time argument is left out, with the arity that supplies it.
_ARITY: dict[tuple[str, str], int] = {("time", "gmtime"): 1, ("time", "localtime"): 1, ("time", "ctime"): 1,
                                      ("time", "asctime"): 1, ("time", "strftime"): 2}
_LOOP_FACTORIES = frozenset({"get_running_loop", "get_event_loop", "new_event_loop"})


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    name: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: reads the clock directly ({self.name}); take a Clock instead"


@dataclass(frozen=True)
class Scan:
    files: tuple[str, ...]
    findings: tuple[Finding, ...]


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.modules: dict[str, str] = {}  # local name -> module ("t" -> "time")
        self.members: dict[str, tuple[str, str]] = {}  # local name -> (module, member) ("dt" -> datetime.datetime)
        self.findings: list[Finding] = []
        self._called: set[int] = set()

    def _report(self, node: ast.AST, name: str) -> None:
        self.findings.append(Finding(self.path, getattr(node, "lineno", 0), name))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            if alias.asname:
                self.modules[alias.asname] = alias.name
            else:
                self.modules[top] = top

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None or node.level:
            return
        for alias in node.names:
            local = alias.asname or alias.name
            module, member = node.module, alias.name
            if member in FORBIDDEN.get(module, ()) and (module, member) not in _ARITY:
                self._report(node, f"{module}.{member}")
            self.members[local] = (module, member)

    def _resolve(self, node: ast.expr) -> tuple[str, ...] | None:
        """The dotted origin of a name or attribute chain, through import aliases."""
        if isinstance(node, ast.Name):
            if node.id in self.members:
                return self.members[node.id]
            if node.id in self.modules:
                return tuple(self.modules[node.id].split("."))
            return None
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            return None if base is None else (*base, node.attr)
        return None

    def _forbidden(self, origin: tuple[str, ...]) -> str | None:
        if len(origin) == 2 and origin[1] in FORBIDDEN.get(origin[0], ()):
            return ".".join(origin)
        if len(origin) == 3 and origin[2] in FORBIDDEN_METHODS.get((origin[0], origin[1]), ()):
            return ".".join(origin)
        return None

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        origin = self._resolve(func) if isinstance(func, ast.Name | ast.Attribute) else None
        if origin is not None and len(origin) == 2 and (origin[0], origin[1]) in _ARITY:
            self._called.add(id(func))
            if len(node.args) < _ARITY[(origin[0], origin[1])]:
                self._report(node, ".".join(origin) + " with no time argument")
        elif isinstance(func, ast.Attribute) and func.attr == "time" and not node.args and self._is_loop(func.value):
            self._report(node, "event loop time()")
        self.generic_visit(node)

    def _is_loop(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Call):
            origin = self._resolve(node.func) if isinstance(node.func, ast.Name | ast.Attribute) else None
            return origin is not None and origin[-1] in _LOOP_FACTORIES
        name = node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else ""
        return "loop" in name.lower()

    def _check_reference(self, node: ast.Name | ast.Attribute) -> None:
        if id(node) in self._called:
            return
        origin = self._resolve(node)
        if origin is None:
            return
        name = self._forbidden(origin)
        if name is not None:
            self._report(node, name)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._check_reference(node)
        if not isinstance(node.value, ast.Name):
            self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id in self.members:
            self._check_reference(node)


def scan_source(source: str, path: str = "<source>") -> list[Finding]:
    """Every direct clock read in one module's source."""
    visitor = _Visitor(path)
    visitor.visit(ast.parse(source, filename=path))
    return sorted(set(visitor.findings), key=lambda f: (f.path, f.line, f.name))


def _python_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    yield from sorted(p for p in root.rglob("*.py") if p.is_file())


def scan_paths(roots: Iterable[str | Path], allow: Iterable[str | Path] = ()) -> Scan:
    """Scan every ``.py`` file under ``roots``, skipping the ``allow``ed files (the clock module itself)."""
    allowed = {Path(a).resolve() for a in allow}
    files: list[str] = []
    findings: list[Finding] = []
    for root in roots:
        for path in _python_files(Path(root)):
            if path.resolve() in allowed:
                continue
            files.append(str(path))
            findings.extend(scan_source(path.read_text(encoding="utf-8"), str(path)))
    return Scan(tuple(files), tuple(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m probity_records.clock_lint")
    parser.add_argument("roots", nargs="+", type=Path)
    parser.add_argument("--allow", action="append", default=[], type=Path,
                        help="a file that may read the clock (the clock module); repeatable")
    args = parser.parse_args(argv)
    for root in args.roots:
        if not root.exists():
            print(f"clock-lint: {root} does not exist; nothing was scanned there", file=sys.stderr)
            return 2
    try:
        result = scan_paths(args.roots, args.allow)
    except SyntaxError as exc:
        print(f"clock-lint: {exc.filename}:{exc.lineno}: does not parse, so it was not checked", file=sys.stderr)
        return 2
    if not result.files:
        print("clock-lint: no Python files under the roots given; nothing was checked", file=sys.stderr)
        return 2
    for finding in result.findings:
        print(finding)
    print(f"clock-lint: {len(result.files)} files scanned, {len(result.findings)} direct clock reads")
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
