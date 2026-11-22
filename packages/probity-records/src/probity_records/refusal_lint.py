"""Refuse an identity or authority refusal code that the refusal-code registry does not hold.

A refusal string is ``<code>`` or ``<code>:<detail>``: the code is a registered snake-case name, the detail is
free text for the producer's own log and never part of the code. The lint reads Python source with ``ast`` and
checks every string that sits where a refusal code goes:

1. ``return "x"``, ``return None, "x"`` and a returned ``dict`` member named in ``keywords``, when the string has
   the shape of a code (a lowercase word, then ``-`` or ``_`` and another word; a detail may follow ``:``);
2. every string argument of a call to a name in ``carriers`` (``Hop(False, "x")``), ``refusal_calls``
   (``_refuse("x")``) or ``raisers`` (``raise RevocationError("x: ...")``), in any position;
3. every string given to a keyword named in ``keywords`` (``reason="x"``), and compared with a name in
   ``keywords`` (``reason == "x"``, ``reason in {"x", "y"}``);
4. the value of a module-level name used in any of those positions (``NO_EDGE = "no_edge"``).

An f-string or a ``+`` concatenation in one of those positions is checked by its leading text, which must be a
registered code followed by ``:``; one that composes the code itself (``f"delegation-{reason}"``) is refused,
because a composed code is a code nobody registered. ``sentinels`` (``ok``, the empty string) are not codes.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: A registered code: lowercase words joined by single underscores, at least two words.
CODE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
#: A string with the shape of a code in either form, optionally with a detail.
CANDIDATE = re.compile(r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+(?::.*)?$", re.DOTALL)
#: The literal start of a composed string that is building a code: a word and a separator.
HEAD = re.compile(r"^[a-z][a-z0-9]*[-_]")
#: A location a verifier puts before a code (``line_3:intent_without_permit``): the journal line, the session key
#: certificate line, the approval binding, the revocation entry, the principal role. It is never a code itself:
#: ``refusal_codes`` refuses a registry that holds a code of this form, and ``refusal_codes.code_of`` skips it.
LOCATION = re.compile(r"(line|keys_line|binding|entry)_\d+|principal_(user|agent|sponsor|approver)")


@dataclass(frozen=True)
class Config:
    """Where refusal codes sit in one code base."""

    carriers: frozenset[str] = frozenset()
    refusal_calls: frozenset[str] = frozenset()
    raisers: frozenset[str] = frozenset()
    exempt_functions: frozenset[str] = frozenset()
    located_lists: frozenset[str] = frozenset()
    assigned: frozenset[str] = frozenset()
    exempt_calls: frozenset[str] = frozenset()
    keywords: frozenset[str] = frozenset({"reason", "code", "refusal"})
    sentinels: frozenset[str] = frozenset({"", "ok"})

    @classmethod
    def load(cls, data: Mapping[str, Any]) -> Config:
        unknown = set(data) - {"carriers", "refusal_calls", "raisers", "exempt_functions", "located_lists",
                              "assigned", "exempt_calls", "keywords", "sentinels"}
        if unknown:
            raise ValueError(f"unknown lint settings {sorted(unknown)}")
        return cls(**{k: frozenset(map(str, v)) for k, v in data.items()})

    def has(self, kind: frozenset[str], file: str, name: str) -> bool:
        """``name`` is configured for every file, or for this file as ``<file name>::<name>``."""
        return self.positions(kind, file, name) is not None

    def positions(self, kind: frozenset[str], file: str, name: str) -> frozenset[int] | None:
        """The argument positions of a configured call (``name@1`` names one; bare, every one), or None."""
        found: set[int] = set()
        every = False
        for entry in kind:
            spec, _, at = entry.partition("@")
            if spec in (name, f"{Path(file).name}::{name}"):
                if at:
                    found.add(int(at))
                else:
                    every = True
        if every:
            return frozenset(range(-1, 64))
        return frozenset(found) if found else None


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    text: str
    problem: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.problem}: {self.text!r}"


@dataclass
class _Scan:
    path: str
    config: Config
    registry: frozenset[str]
    findings: list[Finding] = field(default_factory=list)
    used_names: dict[str, bool] = field(default_factory=dict)  # name -> every string judged, not only code-shaped

    def judge(self, line: int, text: str) -> None:
        code = text.split(":", 1)[0]
        if text in self.config.sentinels:
            return
        if not CODE.match(code):
            self.findings.append(Finding(self.path, line, text, "refusal code not in snake form"))
        elif code not in self.registry:
            self.findings.append(Finding(self.path, line, text, "refusal code not registered"))

    def strings(self, node: ast.AST, *, shaped_only: bool) -> None:
        """Judge the strings ``node`` puts in a refusal position."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if not shaped_only or CANDIDATE.match(node.value):
                self.judge(node.lineno, node.value)
        elif (literal := _formatted(node)) is not None and _builds_code(literal, shaped_only=shaped_only):
            # "grant-%s" % x, "grant-{}".format(x), "-".join(...): a code built by formatting is a composed code
            self.findings.append(Finding(self.path, getattr(node, "lineno", 0), ast.unparse(node),
                                         "refusal code composed at run time"))
        elif isinstance(node, ast.BinOp) and _head(node) is None and not isinstance(node.left, ast.JoinedStr):
            self.strings(node.left, shaped_only=shaped_only)  # NAMES + OTHERS: each operand is judged where made
            self.strings(node.right, shaped_only=shaped_only)
        elif isinstance(node, (ast.JoinedStr, ast.BinOp)):
            self.composed(node, shaped_only=shaped_only)
        elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for element in node.elts:
                self.strings(element, shaped_only=shaped_only)
        elif isinstance(node, ast.IfExp):
            self.strings(node.body, shaped_only=shaped_only)
            self.strings(node.orelse, shaped_only=shaped_only)
        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                self.strings(value, shaped_only=shaped_only)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            self.strings(node.elt, shaped_only=shaped_only)
        elif isinstance(node, (ast.NamedExpr, ast.Starred)):
            self.strings(node.value, shaped_only=shaped_only)
        elif isinstance(node, ast.Name):
            self.used_names[node.id] = self.used_names.get(node.id, False) or not shaped_only
        elif isinstance(node, ast.Call) and _name(node.func) in ("frozenset", "set", "tuple", "list"):
            for arg in node.args:
                self.strings(arg, shaped_only=shaped_only)

    def located(self, node: ast.AST) -> None:
        """A problem string ``<where>:<code>[:<detail>]``: the code is the segment after the first ``:``."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            self.judge(node.lineno, unlocated(node.value))
        elif isinstance(node, ast.Tuple):
            for element in node.elts:
                if isinstance(element, (ast.Constant, ast.JoinedStr)):
                    self.located(element)
        elif isinstance(node, (ast.List, ast.Set)):
            for element in node.elts:
                self.located(element)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            self.located(node.elt)
        elif isinstance(node, ast.IfExp):
            self.located(node.body)
            self.located(node.orelse)
        elif isinstance(node, ast.JoinedStr):
            code = _located_code(node.values)
            if code is None:
                self.findings.append(Finding(self.path, node.lineno, ast.unparse(node),
                                             "refusal code composed at run time"))
            elif code:
                self.judge(node.lineno, code)
        elif isinstance(node, ast.Name):
            self.used_names[node.id] = True

    def composed(self, node: ast.JoinedStr | ast.BinOp, *, shaped_only: bool) -> None:
        head = _head(node)
        first = _segments(node.values)[0] if isinstance(node, ast.JoinedStr) else []
        if first and not any(isinstance(piece, str) for piece in first):
            return  # f"{code}: detail": the code is a value, judged where it was made
        if head is None:
            if not shaped_only:
                self.findings.append(Finding(self.path, node.lineno, ast.unparse(node), "refusal code composed at run time"))
            return
        if shaped_only and not HEAD.match(head):
            return
        if ":" not in head:
            self.findings.append(Finding(self.path, node.lineno, ast.unparse(node), "refusal code composed at run time"))
            return
        self.judge(node.lineno, head)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _segments(values: list[ast.expr]) -> list[list[ast.expr | str]]:
    """Split an f-string's parts on every literal ``:``."""
    out: list[list[ast.expr | str]] = [[]]
    for value in values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            pieces = value.value.split(":")
            for i, piece in enumerate(pieces):
                if i:
                    out.append([])
                if piece.strip():
                    out[-1].append(piece.strip())
        else:
            out[-1].append(value)
    return out


def _located_code(values: list[ast.expr]) -> str | None:
    """The code of ``<where>:...:<code>[:<detail>]``: the first segment that is all literal text.

    Segments before it may hold values (``{where}``, ``binding_{n}``): they are the location. ``""`` means the
    code is a value passed through (``{where}:{problem}``, checked where the value was made); ``None`` means the
    code itself is composed (``exception_{outcome}``, ``{where}:{reason}_allow``)."""
    segments = _segments(values)
    for at, segment in enumerate(segments):
        if segment and all(isinstance(piece, str) for piece in segment):
            text = "".join(segment)  # type: ignore[arg-type]
            if LOCATION.fullmatch(text) and at < len(segments) - 1:
                continue  # a literal location (principal_sponsor:{why}): the code comes after it
            return text
        if at == len(segments) - 1:
            return None if any(isinstance(piece, str) for piece in segment) else ""
    return ""


def _head(node: ast.AST) -> str | None:
    """The literal text a composed string starts with, or None when it starts with a value."""
    if isinstance(node, ast.JoinedStr):
        first = node.values[0] if node.values else None
        return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = node.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str):
            return left.value
        return _head(left)
    return None


def unlocated(refusal: str) -> str:
    """``refusal`` without the location segments a verifier put before its code."""
    segments = refusal.split(":")
    at = 0
    while at < len(segments) - 1 and LOCATION.fullmatch(segments[at]):
        at += 1
    return ":".join(segments[at:])


def _formatted(node: ast.AST) -> str | None:
    """The literal of a string built by ``%``, ``str.format`` or ``str.join`` on a literal, or None."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        left = node.left
        return left.value if isinstance(left, ast.Constant) and isinstance(left.value, str) else None
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "join")
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)):
        return node.func.value.value
    return None


def _builds_code(literal: str, *, shaped_only: bool) -> bool:
    """Whether formatting on ``literal`` builds a code: always where only codes go, else when it starts like one
    (``"grant-%s"``) or joins words with a code separator (``"_".join``)."""
    return not shaped_only or bool(HEAD.match(literal)) or literal in ("-", "_")


def _exempt_nodes(tree: ast.Module, names: frozenset[str]) -> set[int]:
    """The ids of every node inside a function the configuration exempts (it returns a label, not a refusal)."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            out.update(id(inner) for inner in ast.walk(node))
    return out


def _returned_locals(scan: _Scan, function: ast.FunctionDef | ast.AsyncFunctionDef, exempt: set[int]) -> None:
    """A local name a function returns in a refusal position (``r = "x"; return r``, ``return None, r``): every
    string bound to it in the function is judged as if it were returned directly."""
    bound: dict[str, list[ast.expr]] = {}
    returned: set[str] = set()
    for node in ast.walk(function):
        if id(node) in exempt:  # a nested exempt function returns labels
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bound.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
            bound.setdefault(node.target.id, []).append(node.value)
        elif isinstance(node, ast.Return) and node.value is not None:
            value = node.value
            for item in value.elts if isinstance(value, ast.Tuple) else [value]:
                if isinstance(item, ast.Name):
                    returned.add(item.id)
    for name in sorted(returned & set(bound)):
        located = scan.config.has(scan.config.located_lists, scan.path, name)
        for value in bound[name]:
            if located:
                scan.located(value)
            else:
                scan.strings(value, shaped_only=True)  # as if returned directly


def _visit(scan: _Scan, tree: ast.Module) -> None:
    cfg = scan.config
    exempt = _exempt_nodes(tree, cfg.exempt_functions)
    for node in ast.walk(tree):
        if id(node) in exempt:
            continue
        if isinstance(node, ast.Lambda) or (isinstance(node, (ast.Return, ast.Yield)) and node.value is not None):
            value = node.body if isinstance(node, ast.Lambda) else node.value
            if value is None:
                continue
            if isinstance(value, ast.Dict):
                for key, item in zip(value.keys, value.values, strict=True):
                    if isinstance(key, ast.Constant) and key.value in cfg.keywords:
                        scan.strings(item, shaped_only=False)
            elif not isinstance(value, ast.Call) or _formatted(value) is not None:
                scan.strings(value, shaped_only=True)
        elif isinstance(node, ast.Call):
            called = _name(node.func)
            if cfg.has(cfg.exempt_calls, scan.path, called):
                continue  # its arguments and keywords name something other than a refusal (a policy change's cause)
            at = cfg.positions(cfg.carriers, scan.path, called) or cfg.positions(cfg.refusal_calls, scan.path, called)
            if at is not None:
                for index, arg in enumerate(node.args):
                    if index in at:
                        scan.strings(arg, shaped_only=False)
            elif (called in ("append", "extend", "add") and isinstance(node.func, ast.Attribute)
                  and cfg.has(cfg.located_lists, scan.path, _name(node.func.value)) and node.args):
                scan.located(node.args[0])
            elif cfg.has(cfg.raisers, scan.path, called) and node.args:
                scan.strings(node.args[0], shaped_only=False)  # the code; a second argument is the detail
            for keyword in node.keywords:
                if keyword.arg in cfg.keywords:
                    scan.strings(keyword.value, shaped_only=False)
        elif (isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
              and any(cfg.has(cfg.assigned | cfg.keywords, scan.path, _name(t))
                      for t in (node.targets if isinstance(node, ast.Assign) else [node.target]))):
            scan.strings(node.value, shaped_only=True)
        elif isinstance(node, ast.Compare) and _name(node.left) in cfg.keywords:
            for comparator in node.comparators:
                scan.strings(comparator, shaped_only=False)
        if (isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None
                and any(cfg.has(cfg.located_lists, scan.path, _name(t))
                        for t in (node.targets if isinstance(node, ast.Assign) else [node.target]))):
            scan.located(node.value)  # problems = [...], problems += [...]: each element is a located problem
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _returned_locals(scan, node, exempt)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        used = [scan.used_names[t.id] for t in targets if isinstance(t, ast.Name) and t.id in scan.used_names]
        if used:
            scan.strings(value, shaped_only=not any(used))


#: Where this package's own checks put refusal codes.
PACKAGE_CONFIG = Config(
    raisers=frozenset({"RevocationError", "IdentityStringError", "IdentityDigestError@0", "_JwkRefused",
                       "grants.py::ValueError"}),
    exempt_functions=frozenset({"act_grade", "possession_grade"}),  # they return grades, never refusals
    located_lists=frozenset({"problems", "found", "ignored", "failures"}),
    assigned=frozenset({"result", "problem", "verdict", "outcome"}))
#: The modules whose refusals the registry holds: identity, possession, authority, approval, revocation, journal.
PACKAGE_MODULES = ("authority", "canonical_identity", "celexpr", "constraints", "digests", "governance", "grants",
                   "identity", "journal", "oidc_approval", "possession", "quorum", "revocation", "walk")
#: Every other module of the package, with the reason it holds no identity or authority refusal. A module named in
#: neither tuple fails ``test_every_module_is_linted_or_excluded_with_a_reason``, so a new check cannot escape the lint
#: by being added under a new name.
NOT_LINTED = {
    "__init__": "re-exports only",
    "__main__": "the command line; it prints what the checks return",
    "canonical_identity_vectors": "generates vectors from the checks",
    "clock": "the clock protocol; it refuses nothing",
    "clock_lint": "a source lint with its own findings, not a record check",
    "clock_tripwire": "a test tripwire, not a record check",
    "core": "envelope and canonical JSON primitives; their errors reach a record check only as a detail",
    "digests_vectors": "generates vectors from the checks",
    "erasure": "record envelope v2, a record format check outside identity and authority",
    "erasure_vectors": "generates vectors from the checks",
    "exports": "the export seal, a record format check outside identity and authority",
    "identity_vectors": "generates vectors from the checks",
    "otel": "the audit-log stream, a record format check outside identity and authority",
    "receipt_map": "the receipt map's proofs, a log check outside identity and authority",
    "records": "record builders; the readers they call are linted where they live",
    "refusal_codes": "the registry itself",
    "refusal_lint": "this lint",
    "signing": "signing backends; a session-key delegation refusal reaches a record only as the detail of "
               "session_key_delegation_invalid",
    "witness": "the witness note format, a log check outside identity and authority",
}


def lint_package() -> list[Finding]:
    """Every unregistered refusal code in this package's own checks."""
    from . import refusal_codes

    here = Path(__file__).parent
    findings: list[Finding] = []
    for name in PACKAGE_MODULES:
        path = here / f"{name}.py"
        findings += lint_source(path.name, path.read_text(encoding="utf-8"), refusal_codes.CODES, PACKAGE_CONFIG)
    return findings


def lint_source(path: str, source: str, registry: Iterable[str], config: Config) -> list[Finding]:
    """Every refusal string in ``source`` that is not a registered code."""
    scan = _Scan(path, config, frozenset(registry))
    _visit(scan, ast.parse(source, filename=path))
    return sorted(set(scan.findings), key=lambda f: (f.path, f.line, f.text))


def registered(*registry_paths: Path) -> frozenset[str]:
    """The codes of the packaged registry, or of the registry files given (a private projection adds its own).

    A file is read for its codes alone, so this module runs as a single file beside any registry; the registry
    format itself is checked by ``refusal_codes.parse``."""
    if not registry_paths:
        from . import refusal_codes

        return frozenset(refusal_codes.CODES)
    out: set[str] = set()
    for path in registry_paths:
        for entry in json.loads(path.read_text(encoding="utf-8"))["codes"]:
            if not CODE.match(entry["code"]):
                raise ValueError(f"{path}: {entry['code']!r} is not a snake-case code")
            out.add(entry["code"])
    return frozenset(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--registry", type=Path, action="append", default=[],
                        help="a registry file (repeatable); the packaged registry when none is given")
    parser.add_argument("--config", type=Path, required=True,
                        help="JSON: carriers, refusal_calls, raisers, exempt_functions, located_lists, assigned")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)
    config = Config.load(json.loads(args.config.read_text(encoding="utf-8")))
    codes = registered(*args.registry)
    findings: list[Finding] = []
    files = sorted({f for p in args.paths for f in ([p] if p.is_file() else p.rglob("*.py"))})
    for file in files:
        findings += lint_source(str(file), file.read_text(encoding="utf-8"), codes, config)
    for finding in findings:
        print(finding)
    print(f"refusal-lint: {len(files)} files, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
