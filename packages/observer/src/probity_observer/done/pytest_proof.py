"""Which sealed pytest ids the verifier may count itself: a proof read off the sealed source.

A pytest replay (:mod:`.pytest_replay`) runs a sealed test in the verifier's process and serves
the candidate's modules from a child. A test passes there when its body returns without
raising, and that is only a check of the candidate when every decision in the body is a
comparison the parent makes against a value the candidate never chose. A test that hands the
decision to a function of the candidate's package (``assert_close(f(x), expected)``), or gates
its assertion on what the candidate returned (``for item in f(x): assert item == 1``), passes
whatever the candidate does. So the replay counts an id only when this module proves, from the
sealed bytes alone, that the test reduces to unconditional comparisons of this shape::

    assert <one call of a function the candidate serves> == <sealed literal>

with these conditions:

- the test is a module-level ``def`` named once, with no decorator but
  ``pytest.mark.parametrize`` over literal tables, and no parameter but the table's names
  (no fixture can hand it a candidate object);
- its body holds only these assertions (after an optional docstring): no loop, branch,
  ``try``, ``with``, ``return`` or other statement can stand between the body and an assertion;
- the called name is bound once in the module, by an import from a module the child serves;
  its arguments are literals or table names, so no call is nested in another and nothing the
  candidate returned is called;
- the expected side is a literal, or a table name that no call in the test receives, so the
  child never sees an expected value; it is not ``None``, it can cross as plain data, and a
  boolean one counts only where the same function is asserted both ``True`` and ``False``
  (:func:`degenerate`).

Everything else is not proven, the compiler leaves the id out of every replay, and the worker
alone counts it (``worker_counted``), which the admission rule set refuses. The check can only
withhold the verifier's count, never grant it: a shape it does not recognise is not proven.
The parent checks the same proof again before it runs a test, and holds the run to it
(:mod:`.pytest_replay`): the k-th call the test makes must be compared, once, with the k-th
assertion's sealed value (:meth:`Proof.expected`).
"""

from __future__ import annotations

import ast
import json
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .replay import plain

PARAMETRIZE = ("pytest", "mark", "parametrize")


@dataclass
class Site:
    """One proven assertion: the call the child answers and the sealed value it must equal."""

    callee: str
    call: ast.Call
    expected: ast.expr
    values: tuple[Any, ...]


@dataclass
class Proof:
    """A test function proven to reduce to :class:`Site` comparisons."""

    node: ast.FunctionDef
    params: tuple[str, ...]
    sites: list[Site] = field(default_factory=list)

    def expected(self, funcargs: dict[str, Any]) -> list[Any]:
        """The sealed value of each assertion, in order, for one run of the test: the literal,
        or the table value pytest passed for the expected name."""
        return [funcargs[site.expected.id] if isinstance(site.expected, ast.Name)
                else site.values[0] for site in self.sites]

    def booleans(self) -> dict[str, set[bool]]:
        """The boolean values each called function is asserted to return, by the place of
        the boolean in the answer (:func:`boolean_leaves`)."""
        found: dict[str, set[bool]] = {}
        for site in self.sites:
            for value in site.values:
                for key, leaf in boolean_leaves(site.callee, value):
                    found.setdefault(key, set()).add(leaf)
        return found


def leaves(value: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    """Each value inside a plain literal that is not a container, with its place: a list or
    tuple item by its index, a dict value by its key (a key is a leaf of its own, at
    ``{key}``), and every set item at one place (``{}``)."""
    kind = type(value)
    if kind is list or kind is tuple:
        for index, item in enumerate(value):
            yield from leaves(item, f"{path}[{index}]")
    elif kind is dict:
        for key, item in value.items():
            yield from leaves(key, f"{path}{{key}}")
            yield from leaves(item, f"{path}[{json.dumps(plain(key))}]")
    elif kind is set or kind is frozenset:
        for item in value:
            yield from leaves(item, f"{path}{{}}")
    else:
        yield path, value


def boolean_leaves(callee: str, value: Any) -> Iterator[tuple[str, bool]]:
    """Each boolean in a sealed value, keyed by the called function and its place in the
    answer: a function that always gives one boolean there satisfies a lone expectation of
    it, inside a container as at the top."""
    for path, leaf in leaves(value):
        if type(leaf) is bool:
            yield callee + path, leaf


class Unproven(Exception):
    """Why a test is not proven; the message is the reason."""


def _chain(node: ast.expr) -> list[str] | None:
    """``a.b.c`` as ``["a", "b", "c"]``, or ``None`` for any other expression."""
    names: list[str] = []
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return [node.id, *reversed(names)]


def _scope_nodes(tree: ast.Module) -> Iterable[ast.AST]:
    """Every node whose bindings are module-level: the module's own statements and
    expressions, not the bodies of functions, lambdas or classes."""
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # The name, the decorators and the defaults run in the module scope.
            stack.extend(node.decorator_list)
            if not isinstance(node, ast.ClassDef):
                stack.extend([*node.args.defaults, *node.args.kw_defaults])
            else:
                stack.extend([*node.bases, *(item.value for item in node.keywords)])
            continue
        if isinstance(node, ast.Lambda):
            continue
        stack.extend(ast.iter_child_nodes(node))


def bindings(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """Every node that binds or unbinds each module-level name, ``global`` declarations in
    any function included; a name bound more than once is never a proven callee."""
    found: dict[str, list[ast.AST]] = {}

    def bind(name: str, node: ast.AST) -> None:
        found.setdefault(name, []).append(node)

    for node in _scope_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(node.name, node)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                bind(alias.asname or alias.name.split(".", 1)[0], node)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bind(alias.asname or alias.name, node)
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            bind(node.id, node)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bind(node.name, node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bind(node.rest, node)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            # ``except E as name`` binds the name, and unbinds it when the handler ends.
            bind(node.name, node)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bind(name, node)
    return found


def _import_prefix(name: str, binding: ast.AST, remote: frozenset[str]) -> str:
    """The qualified name a module-level import binds ``name`` to, under a remote module."""
    if isinstance(binding, ast.ImportFrom):
        if binding.level or not binding.module:
            raise Unproven(f"{name} is imported relative to a sealed package")
        if binding.module.split(".", 1)[0] not in remote:
            raise Unproven(f"{name} is not imported from a module the child serves")
        alias = next(item for item in binding.names if (item.asname or item.name) == name)
        return f"{binding.module}.{alias.name}"
    if isinstance(binding, ast.Import):
        alias = next(item for item in binding.names
                     if (item.asname or item.name.split(".", 1)[0]) == name)
        if alias.name.split(".", 1)[0] not in remote:
            raise Unproven(f"{name} is not a module the child serves")
        # ``import a.b as n`` binds the submodule; a plain ``import a.b`` binds ``a``.
        return alias.name if alias.asname else name
    raise Unproven(f"{name} is not bound by an import")


class Module:
    """The proofs of one sealed test file."""

    def __init__(self, source: str, remote: frozenset[str], filename: str = "<sealed>") -> None:
        self.remote = remote
        self.filename = filename
        try:
            self.tree = ast.parse(source, filename)
        except SyntaxError as error:
            self.tree, self.error = None, f"the file does not parse: {error.msg}"
            return
        self.error = None
        if any(isinstance(node, ast.ImportFrom) and any(item.name == "*" for item in node.names)
               for node in _scope_nodes(self.tree)):
            self.error = "a star import can bind any name"
        self.bound = bindings(self.tree)
        self.cache: dict[str, Proof | str] = {}

    def proof(self, name: str) -> Proof | str:
        """The proof of the module-level test ``name``, or the reason there is none."""
        if self.error is not None or self.tree is None:
            return self.error or "no source"
        if name not in self.cache:
            try:
                self.cache[name] = self._prove(name)
            except Unproven as reason:
                self.cache[name] = str(reason)
        return self.cache[name]

    def _single(self, name: str) -> ast.AST:
        nodes = self.bound.get(name, [])
        if len(nodes) != 1:
            raise Unproven(f"{name} is bound {len(nodes)} times in the module")
        return nodes[0]

    def _root(self, name: str) -> ast.AST:
        """The one binding of a called name. ``import a`` and ``import a.b`` each bind ``a``
        to the same top-level module, so plain imports of one package count once."""
        nodes = self.bound.get(name, [])
        if len(nodes) > 1 and all(isinstance(node, ast.Import)
                                  and not any(alias.asname == name for alias in node.names)
                                  for node in nodes):
            return nodes[0]
        return self._single(name)

    def _prove(self, name: str) -> Proof:
        node = self._single(name)
        if not isinstance(node, ast.FunctionDef) or node not in self.tree.body:
            raise Unproven(f"{name} is not a module-level function")
        table = self._tables(node)
        args = node.args
        if (args.posonlyargs or args.vararg or args.kwonlyargs or args.kwarg or args.defaults):
            raise Unproven("the test takes parameters other than its table's names")
        params = tuple(arg.arg for arg in args.args)
        if set(params) != set(table):
            raise Unproven("the test takes a fixture")
        body = list(node.body)
        if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        proof = Proof(node, params)
        for statement in body:
            if isinstance(statement, ast.Pass):
                continue
            if not isinstance(statement, ast.Assert):
                raise Unproven(f"line {statement.lineno}: the body holds a "
                               f"{type(statement).__name__}, not only sealed comparisons")
            proof.sites.append(self._site(statement, params, table))
        if not proof.sites:
            raise Unproven("the test makes no sealed comparison")
        echoed = {arg.id for site in proof.sites for arg in _arguments(site.call)
                  if isinstance(arg, ast.Name)}
        for site in proof.sites:
            if isinstance(site.expected, ast.Name) and site.expected.id in echoed:
                raise Unproven(f"the expected value {site.expected.id} is sent to the child")
        return proof

    def _tables(self, node: ast.FunctionDef) -> dict[str, tuple[Any, ...]]:
        """Each table name and its values, from ``pytest.mark.parametrize`` decorators."""
        table: dict[str, tuple[Any, ...]] = {}
        for decorator in node.decorator_list:
            if not (isinstance(decorator, ast.Call) and _chain(decorator.func) == list(PARAMETRIZE)
                    and isinstance(self._single("pytest"), ast.Import)
                    and _import_prefix_plain(self._single("pytest")) == "pytest"):
                raise Unproven("a decorator other than pytest.mark.parametrize")
            names, rows = self._parametrize(decorator)
            for index, column in enumerate(names):
                if column in table:
                    raise Unproven(f"the table name {column} is given twice")
                table[column] = tuple(row[index] for row in rows)
        return table

    @staticmethod
    def _parametrize(decorator: ast.Call) -> tuple[list[str], list[tuple[Any, ...]]]:
        arguments: dict[str, ast.expr] = dict(
            zip(("argnames", "argvalues"), decorator.args, strict=False))
        if len(decorator.args) > 2:
            raise Unproven("parametrize takes more than its two tables")
        for keyword in decorator.keywords:
            if keyword.arg in ("argnames", "argvalues") and keyword.arg not in arguments:
                arguments[keyword.arg] = keyword.value
            elif keyword.arg == "ids":
                try:
                    ast.literal_eval(keyword.value)
                except ValueError:
                    raise Unproven("parametrize ids are not a literal") from None
            else:
                raise Unproven(f"parametrize takes {keyword.arg}")
        try:
            names_value = ast.literal_eval(arguments["argnames"])
            rows_value = ast.literal_eval(arguments["argvalues"])
        except (KeyError, ValueError):
            raise Unproven("a parametrize table is not a literal") from None
        if isinstance(names_value, str):
            names = [part.strip() for part in names_value.split(",") if part.strip()]
        elif isinstance(names_value, (list, tuple)) and all(isinstance(part, str)
                                                            for part in names_value):
            names = list(names_value)
        else:
            raise Unproven("parametrize names are not strings")
        if not names or not all(part.isidentifier() for part in names):
            raise Unproven("parametrize names are not identifiers")
        if not isinstance(rows_value, (list, tuple)) or not rows_value:
            raise Unproven("a parametrize table has no rows")
        rows: list[tuple[Any, ...]] = []
        for row in rows_value:
            if len(names) == 1:
                rows.append((row,))
            elif isinstance(row, (list, tuple)) and len(row) == len(names):
                rows.append(tuple(row))
            else:
                raise Unproven("a parametrize row does not match its names")
        return names, rows

    def _site(self, statement: ast.Assert, params: tuple[str, ...],
              table: dict[str, tuple[Any, ...]]) -> Site:
        line = f"line {statement.lineno}"
        if statement.msg is not None and not (isinstance(statement.msg, ast.Constant)
                                              and isinstance(statement.msg.value, str)):
            raise Unproven(f"{line}: the assertion message is not a literal")
        test = statement.test
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1
                and isinstance(test.ops[0], ast.Eq) and len(test.comparators) == 1):
            raise Unproven(f"{line}: the assertion is not one == comparison")
        left, right = test.left, test.comparators[0]
        if isinstance(left, ast.Call) and not isinstance(right, ast.Call):
            call, expected = left, right
        elif isinstance(right, ast.Call) and not isinstance(left, ast.Call):
            call, expected = right, left
        else:
            raise Unproven(f"{line}: the comparison is not one call against a sealed value")
        callee = self._callee(call, params, line)
        for argument in _arguments(call):
            if isinstance(argument, ast.Name):
                if argument.id not in params:
                    raise Unproven(f"{line}: the argument {argument.id} is not a table name")
            else:
                _literal(argument, line, "argument")
        if isinstance(expected, ast.Name):
            if expected.id not in params:
                raise Unproven(f"{line}: the expected value {expected.id} is not sealed")
            values = table[expected.id]
        else:
            values = (_literal(expected, line, "expected value"),)
        for value in values:
            try:
                plain(value)
            except TypeError:
                raise Unproven(f"{line}: the expected value cannot cross as plain data") from None
            # A function that returns None, or a container of None, satisfies it.
            found = [leaf for _, leaf in leaves(value)]
            if found and all(leaf is None for leaf in found):
                raise Unproven(f"{line}: the expected value is None at every place")
        return Site(callee, call, expected, values)

    def _callee(self, call: ast.Call, params: tuple[str, ...], line: str) -> str:
        names = _chain(call.func)
        if names is None:
            raise Unproven(f"{line}: the called expression is not a name")
        if names[0] in params:
            raise Unproven(f"{line}: the called name is a table name")
        if any(part.startswith("__") for part in names[1:]):
            raise Unproven(f"{line}: the call reads a dunder attribute")
        binding = self._root(names[0])
        prefix = _import_prefix(names[0], binding, self.remote)
        if len(names) == 1 and not isinstance(binding, ast.ImportFrom):
            raise Unproven(f"{line}: the call is of a module")
        return ".".join([prefix, *names[1:]])


def _import_prefix_plain(binding: ast.AST) -> str | None:
    """What an ``import`` binds, when it is a plain ``import pytest``."""
    if isinstance(binding, ast.Import) and len(binding.names) == 1:
        alias = binding.names[0]
        return alias.name if alias.asname is None else None
    return None


def _arguments(call: ast.Call) -> list[ast.expr]:
    if any(isinstance(item, ast.Starred) for item in call.args) or any(
            keyword.arg is None for keyword in call.keywords):
        raise Unproven(f"line {call.lineno}: the call unpacks its arguments")
    return [*call.args, *(keyword.value for keyword in call.keywords)]


def _literal(node: ast.expr, line: str, what: str) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        raise Unproven(f"{line}: the {what} is not a literal") from None


def split_id(test_id: str) -> tuple[str, str] | None:
    """``(file, function)`` for an id that names one module-level function (with or without
    a parameter suffix), or ``None`` for an id that names a file, a class or a method."""
    parts = test_id.split("::")
    if len(parts) != 2 or not parts[0].endswith(".py"):
        return None
    name = parts[1].split("[", 1)[0]
    return (parts[0], name) if name.isidentifier() else None


def degenerate(proofs: Sequence[Proof]) -> set[str]:
    """The called functions asserted to return a boolean only one way across ``proofs``: a
    function that always returns that value passes, so none of their assertions counts."""
    seen: dict[str, set[bool]] = {}
    for proof in proofs:
        for callee, values in proof.booleans().items():
            seen.setdefault(callee, set()).update(values)
    return {callee for callee, values in seen.items() if values != {True, False}}


class Sources:
    """Proofs of sealed test files under ``roots`` (the first root that holds a file wins)."""

    def __init__(self, roots: Sequence[Path], remote: Iterable[str]) -> None:
        self.roots = list(roots)
        self.remote = frozenset(remote)
        self.modules: dict[str, Module | str] = {}

    def module(self, path: str) -> Module | str:
        if path not in self.modules:
            inside = not any(part in ("", ".", "..") for part in path.split("/"))
            found = next((root / path for root in self.roots
                          if inside and (root / path).is_file()), None)
            if found is None:
                self.modules[path] = "the test file is not sealed"
            else:
                self.modules[path] = Module(found.read_text(encoding="utf-8"), self.remote,
                                            str(found))
        return self.modules[path]

    def proof(self, test_id: str) -> Proof | str:
        named = split_id(test_id)
        if named is None:
            return "the id does not name one module-level test function"
        module = self.module(named[0])
        return module if isinstance(module, str) else module.proof(named[1])


def proven(sources: Sources, ids: Sequence[str]) -> tuple[list[str], dict[str, str]]:
    """The ids of ``ids`` the verifier may count, and the reason each other id is not proven.

    A boolean comparison counts only where its function is asserted both ways among the
    proven ids, so ids are withdrawn until no degenerate function is left."""
    reasons: dict[str, str] = {}
    kept: dict[str, Proof] = {}
    for test_id in ids:
        found = sources.proof(test_id)
        if isinstance(found, str):
            reasons[test_id] = found
        else:
            kept[test_id] = found
    while True:
        weak = degenerate(list(kept.values()))
        dropped = [test_id for test_id, proof in kept.items() if weak & set(proof.booleans())]
        if not dropped:
            break
        for test_id in dropped:
            reasons[test_id] = "a boolean comparison its function never makes the other way"
            del kept[test_id]
    return [test_id for test_id in ids if test_id in kept], reasons
