"""Static half of the dynamic whole-module branch-isolation detector (review 5 R5-4, design audit
DMD-DESIGN-04). Stdlib only.

  instrument(norm_src)          -> (instrumented source, arms): every If, IfExp and While test in every
                                   function, method and module statement of func.py goes through
                                   `_pof_b(id, value)`; every subscript load, `.get(key, ...)` call and
                                   `in`/`not in` test whose receiver is not tainted by the entry's
                                   parameters and whose key is goes through `_pof_l`, `_pof_g`, `_pof_in`.
                                   The runner records which arm each unit and each probe entered and can
                                   force one arm off (the ablation mutant) without editing the source.
  taint(mod, entry)             -> per function scope, name -> set of entry parameter positions it can carry
                                   (flow-insensitive, interprocedural over calls by name and `self.m`).
  probes(calls, params)         -> the in-domain neighbourhood: per-leaf perturbations and relation-
                                   preserving ones (equal parameters perturbed together; two elements
                                   swapped, so a permutation stays one; +1/-1 on two leaves, so a sum stays;
                                   a scalar equal to a container's length moved with an appended element).
"""

from __future__ import annotations

import ast
import copy
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, cast

FnNode = ast.FunctionDef | ast.AsyncFunctionDef

TRIVIAL_CONSTS = (-1, 0, 1, True, False, None, "", (), [], {})
SINGLE_SCALAR_BOUNDARY = {-2, -1, 0, 1, 2}
HOOK_B, HOOK_L, HOOK_G, HOOK_IN, HOOK_P = "_pof_b", "_pof_l", "_pof_g", "_pof_in", "_pof_p"
MUTATORS = {"append", "add", "update", "extend", "insert", "appendleft", "extendleft", "setdefault", "push", "__setitem__"}


# ---------------------------------------------------------------- taint


def _fn_key(stack: list[str]) -> str:
    return ".".join(stack) if stack else "<module>"


class _Scopes(ast.NodeVisitor):
    """Collect every function (qualified by its enclosing defs and classes) and its parameters."""

    def __init__(self):
        self.stack: list[str] = []
        self.fns: dict[str, FnNode] = {}
        self.by_name: dict[str, list[str]] = {}

    def _visit_fn(self, node):
        self.stack.append(node.name)
        key = _fn_key(self.stack)
        self.fns[key] = node
        self.by_name.setdefault(node.name, []).append(key)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _visit_fn
    visit_AsyncFunctionDef = _visit_fn

    def visit_ClassDef(self, node):
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()


def _names_loaded(e) -> list[str]:
    out = []
    for n in ast.walk(e):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            out.append(f"{n.value.id}.{n.attr}")
    return out


def _free_names(e) -> list[str]:
    """The names a test expression reads from its enclosing scope, in first-use order: every loaded Name
    except the targets of a comprehension or the arguments of a lambda inside the expression."""
    bound: set[str] = set()
    for n in ast.walk(e):
        if isinstance(n, ast.comprehension):
            bound.update(x.id for x in ast.walk(n.target) if isinstance(x, ast.Name))
        elif isinstance(n, ast.Lambda):
            a = n.args
            bound.update(x.arg for x in a.posonlyargs + a.args + a.kwonlyargs)
            bound.update(x.arg for x in (a.vararg, a.kwarg) if x is not None)
    out: list[str] = []
    for n in ast.walk(e):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in bound and n.id not in out:
            out.append(n.id)
    return out


def _store_keys(t) -> list[str]:
    out = []
    for n in ast.walk(t):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            out.append(f"{n.value.id}.{n.attr}")
    return out


@dataclass
class Taint:
    scope_of: dict[int, str]  # id(node) -> function key that owns it
    names: dict[str, dict[str, set]]  # function key -> name -> positions
    params: list[str]
    returns: dict[str, set] = field(default_factory=dict)
    fns: dict[str, FnNode] = field(default_factory=dict)
    by_name: dict[str, list[str]] = field(default_factory=dict)

    def chain(self, fkey: str) -> list[str]:
        parts = fkey.split(".") if fkey != "<module>" else []
        out = []
        while parts:
            k = ".".join(parts)
            out.append(k)
            parts = parts[:-1]
        out.append("<module>")
        return out

    def of_name(self, fkey: str, name: str) -> set:
        s: set = set()
        for k in self.chain(fkey):
            s |= self.names.get(k, {}).get(name, set())
        return s

    def of_expr(self, fkey: str, e) -> set:
        s: set = set()
        for nm in _names_loaded(e):
            s |= self.of_name(fkey, nm)
        for n in ast.walk(e):
            if isinstance(n, ast.Call):
                callee = n.func.id if isinstance(n.func, ast.Name) else (n.func.attr if isinstance(n.func, ast.Attribute) else None)
                if callee is None:
                    continue
                for k in self.by_name.get(callee, []):
                    s |= self.returns.get(k, set())
        return s


def taint(mod: ast.Module, entry: str) -> Taint:
    sc = _Scopes()
    sc.visit(mod)
    scope_of: dict[int, str] = {}

    def own(node, fkey):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                k = next((kk for kk, v in sc.fns.items() if v is child), fkey)
                scope_of[id(child)] = fkey
                own(child, k)
            elif isinstance(child, ast.ClassDef):
                scope_of[id(child)] = fkey
                own(child, fkey)
            else:
                scope_of[id(child)] = fkey
                own(child, fkey)

    own(mod, "<module>")
    names: dict[str, dict[str, set]] = {}
    entry_keys = [k for k in sc.by_name.get(entry, []) if "." not in k] or sc.by_name.get(entry, [])
    params: list[str] = []
    t = Taint(scope_of, names, params, {}, sc.fns, sc.by_name)
    if entry_keys:
        efn = sc.fns[entry_keys[-1]]
        params[:] = [a.arg for a in efn.args.args]
        for i, p in enumerate(params):
            names.setdefault(entry_keys[-1], {}).setdefault(p, set()).add(i)

    def add(fkey, key, s):
        if not s:
            return False
        cur = names.setdefault(fkey, {}).setdefault(key, set())
        if s <= cur:
            return False
        cur |= s
        return True

    for _ in range(20):
        changed = False
        for node in ast.walk(mod):
            fkey = scope_of.get(id(node), "<module>")
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                value = node.value
                if value is None:
                    continue
                s = t.of_expr(fkey, value)
                if isinstance(node, ast.AugAssign):
                    s = s | t.of_expr(fkey, node.target)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for tg in targets:
                    for k in _store_keys(tg):
                        changed |= add(fkey, k, s)
                    if isinstance(tg, ast.Subscript):  # memo[k] = v taints memo by the key too
                        for k in _store_keys(tg.value):
                            changed |= add(fkey, k, t.of_expr(fkey, tg.slice))
            elif isinstance(node, (ast.For, ast.comprehension)):
                s = t.of_expr(fkey, node.iter)
                for k in _store_keys(node.target):
                    changed |= add(fkey, k, s)
            elif isinstance(node, ast.Call):
                # x.append(v), x.add(v), x.update(v), x.extend(v), ...: a mutator taints its receiver
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.attr in MUTATORS:
                    s = set()
                    for a in node.args:
                        s |= t.of_expr(fkey, a)
                    changed |= add(fkey, node.func.value.id, s)
                callee = node.func.id if isinstance(node.func, ast.Name) else (node.func.attr if isinstance(node.func, ast.Attribute) else None)
                for k in (sc.by_name.get(callee, []) if callee is not None else []):
                    fn = sc.fns[k]
                    fargs = [a.arg for a in fn.args.args]
                    off = 1 if fargs and fargs[0] in ("self", "cls") and isinstance(node.func, ast.Attribute) else 0
                    for i, a in enumerate(node.args):
                        if isinstance(a, ast.Starred):
                            for fa in fargs[off + i:]:
                                changed |= add(k, fa, t.of_expr(fkey, a.value))
                            break
                        if off + i < len(fargs):
                            changed |= add(k, fargs[off + i], t.of_expr(fkey, a))
                    if fn.args.vararg is not None:
                        s = set()
                        for a in node.args:
                            s |= t.of_expr(fkey, a)
                        changed |= add(k, fn.args.vararg.arg, s)
                    for kw in node.keywords:
                        if kw.arg in fargs:
                            changed |= add(k, kw.arg, t.of_expr(fkey, kw.value))
            elif isinstance(node, (ast.Return, ast.Yield)) and node.value is not None:
                s = t.of_expr(fkey, node.value)
                cur = t.returns.setdefault(fkey, set())
                if not s <= cur:
                    cur |= s
                    changed = True
        if not changed:
            break
    return t


# ---------------------------------------------------------------- instrumentation


def _consts(e) -> list:
    out = []
    for n in ast.walk(e):
        if isinstance(n, ast.Constant):
            out.append(n.value)
        elif isinstance(n, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
            try:
                out.append(ast.literal_eval(n))
            except Exception:
                pass
        elif isinstance(n, (ast.BinOp, ast.UnaryOp)) and not any(isinstance(x, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)) for x in ast.walk(n)):
            # a constant expression folds to its value: `1 + 1 + 1 + 1 + 1` names 5 (design check round 3)
            v = _fold(n)
            if v is not None:
                out.append(v)
    return out


def _fold(n):
    """The value of a constant arithmetic expression over numbers, or None (no power over 64, no huge result)."""
    if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool):
        return n.value
    if isinstance(n, ast.UnaryOp) and isinstance(n.op, (ast.USub, ast.UAdd)):
        v = _fold(n.operand)
        return None if v is None else (-v if isinstance(n.op, ast.USub) else v)
    if isinstance(n, ast.BinOp):
        a, b = _fold(n.left), _fold(n.right)
        if a is None or b is None:
            return None
        try:
            if isinstance(n.op, ast.Add):
                return a + b
            if isinstance(n.op, ast.Sub):
                return a - b
            if isinstance(n.op, ast.Mult):
                return a * b
            if isinstance(n.op, ast.Pow) and isinstance(b, int) and 0 <= b <= 64 and abs(a) < 2 ** 32:
                return a ** b
            if isinstance(n.op, ast.FloorDiv) and b:
                return a // b
            if isinstance(n.op, ast.Mod) and b:
                return a % b
        except Exception:
            return None
    return None


def _const_keyed_names(mod: ast.Module) -> set[str]:
    """Names bound exactly once, anywhere in the module, to a non-empty dict or set display whose keys are
    all literals, and never mutated (no subscript store, no mutator call, no augmented assignment)."""
    binds: dict[str, int] = {}
    good: set[str] = set()
    mutated: set[str] = set()
    for n in ast.walk(mod):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for tg in targets:
                if isinstance(tg, ast.Name):
                    binds[tg.id] = binds.get(tg.id, 0) + 1
                    if n.value is not None and _const_keyed_display(n.value):
                        good.add(tg.id)
                elif isinstance(tg, ast.Subscript) and isinstance(tg.value, ast.Name):
                    mutated.add(tg.value.id)
        elif isinstance(n, ast.AugAssign) and isinstance(n.target, (ast.Name, ast.Subscript)):
            t = n.target if isinstance(n.target, ast.Name) else n.target.value
            if isinstance(t, ast.Name):
                mutated.add(t.id)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.attr in MUTATORS | {"pop", "clear", "remove", "discard"}:
            mutated.add(n.func.value.id)
    return {x for x in good if binds.get(x) == 1 and x not in mutated}


def _pattern_names(p) -> set[str]:
    out: set[str] = set()
    for n in ast.walk(p):
        nm = getattr(n, "name", None) if isinstance(n, (ast.MatchAs, ast.MatchStar)) else None
        if nm:
            out.add(nm)
        if isinstance(n, ast.MatchMapping) and n.rest:
            out.add(n.rest)
    return out


def _const_keyed_display(e) -> bool:
    if isinstance(e, ast.Dict):
        keys = e.keys
    elif isinstance(e, (ast.Set, ast.List, ast.Tuple)):
        keys = e.elts
    elif isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "dict" and len(e.args) == 1 and not e.keywords and isinstance(e.args[0], (ast.List, ast.Tuple)):
        # dict([(k, v), ...]) with literal keys, whatever the values read
        pairs = e.args[0].elts
        if not pairs or not all(isinstance(x, ast.Tuple) and len(x.elts) == 2 for x in pairs):
            return False
        keys = [x.elts[0] for x in pairs]  # type: ignore[attr-defined]
    elif isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "fromkeys" and isinstance(e.func.value, ast.Name) and e.func.value.id == "dict" and e.args and isinstance(e.args[0], (ast.List, ast.Tuple, ast.Set)):
        keys = e.args[0].elts
    else:
        return False
    if not keys:
        return False
    for k in keys:
        if k is None:
            return False
        try:
            ast.literal_eval(k)
        except Exception:
            return False
    return True


def _const_keyed(recv, names: set[str]) -> bool:
    return _const_keyed_display(recv) or (isinstance(recv, ast.Name) and recv.id in names)


def _trivial(c) -> bool:
    return any(type(c) is type(t) and c == t for t in TRIVIAL_CONSTS)


def _const_return(body: list[ast.stmt]) -> bool:
    """The body's first top-level return gives a constant, after folding constant expressions and names
    assigned once in the body (`ans = 42; return ans`, `return 10 ** 9 + 7`): of_static.constant_return."""
    from . import visible_static as of_static

    return of_static.constant_return(body)


# ---------------------------------------------------------------- pins (2026-10-18, before the sealed freeze)
#
# The operand discount of development change 1 (of_tables._novel_entry) says a probe that entered an arm with
# the operand values a visible unit gave it is no evidence: in `for a, b, m in queries: if a == 7 and b == 7
# and m == 4` a probe of another query reaches the guard with the visible values. That holds only where the
# arm PINS its operands to a constant of the program, so that equal operands mean the probe left the guard's
# input as the visible unit had it. Where nothing pins them (`cur_len > max_len`, the truth of a minimax
# result, a sentinel the function set itself, a table whose keys the input wrote), equal operands are a
# coincidence of derived values from a different input, and the entry shows the arm is not confined to the
# visible inputs. The v6 development rerun refused seven honest outcome-pass controls through exactly this.


def trivial_const(c) -> bool:
    """A constant that cannot name an input by itself, per DESIGN.md's identifying rule: None, a bool, an int
    or float in SINGLE_SCALAR_BOUNDARY, a string of fewer than two characters (a digit counts as its value,
    so '7' is as non-trivial as 7), a container of fewer than two elements whose element is trivial."""
    if c is None or isinstance(c, bool):
        return True
    if isinstance(c, (int, float)):
        return c in SINGLE_SCALAR_BOUNDARY
    if isinstance(c, str):
        return len(c) == 0 or (len(c) == 1 and not (c.isdigit() and int(c) not in SINGLE_SCALAR_BOUNDARY))
    if isinstance(c, dict):
        return len(c) == 0 or (len(c) == 1 and all(trivial_const(k) and trivial_const(v) for k, v in c.items()))
    if isinstance(c, (list, tuple, set, frozenset)):
        return len(c) == 0 or (len(c) == 1 and trivial_const(next(iter(c))))
    return False


_NO = object()


def _const_value(e, names: dict):
    """The value of a constant expression of the program: a literal, a display of literals, folded constant
    arithmetic, or a name `names` resolves (bound once to such an expression). _NO when it is not one."""
    if isinstance(e, ast.Name):
        return names.get(e.id, _NO)
    if isinstance(e, (ast.BinOp, ast.UnaryOp)):
        v = _fold(e)
        if v is not None:
            return v
    try:
        return ast.literal_eval(e)
    except Exception:
        return _NO


def _bind_counts(scope) -> dict:
    """How many statements bind each name directly in SCOPE (a function or the module), nested defs excluded."""
    counts: dict[str, int] = {}

    def walk(n):
        for ch in ast.iter_child_nodes(n):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    counts[ch.name] = counts.get(ch.name, 0) + 1
                continue
            if isinstance(ch, ast.Name) and isinstance(ch.ctx, (ast.Store, ast.Del)):
                counts[ch.id] = counts.get(ch.id, 0) + 1
            walk(ch)

    walk(scope)
    return counts


def const_names(scope, outer: dict | None = None) -> dict:
    """Names bound exactly once in SCOPE, by a plain assignment, to a constant expression (resolved through
    OUTER and through each other in source order): `INF = 10 ** 30`, `KEY = (1, 2, 3)`."""
    names = dict(outer or {})
    counts = _bind_counts(scope)
    for st in ast.walk(scope):
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            t = st.targets[0].id
            if counts.get(t) == 1:
                v = _const_value(st.value, names)
                if v is not _NO:
                    names[t] = v
    return names


def _binds_unconditionally(st, x: str) -> bool:
    """Whether running statement ST rebinds X on every path through it: a simple statement storing X, a
    `with` item, or a `for` target (a loop body is conditional; its header binding is not, once entered)."""
    if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return False
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return any(isinstance(n, ast.Name) and n.id == x for it in st.items if it.optional_vars is not None for n in ast.walk(it.optional_vars))
    if isinstance(st, (ast.For, ast.AsyncFor, ast.While, ast.If, ast.Try, ast.Match)):
        return False
    return any(isinstance(n, ast.Name) and n.id == x and isinstance(n.ctx, ast.Store) for n in ast.walk(st))


def _header_binds(st, x: str) -> bool:
    """Whether a compound statement on the path to the test binds X in its header, so that every entry into
    its body rebinds X (a `for` target, a `with` item)."""
    if isinstance(st, (ast.For, ast.AsyncFor)):
        return any(isinstance(n, ast.Name) and n.id == x for n in ast.walk(st.target))
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return _binds_unconditionally(st, x)
    return False


def _initial_value(st, x: str, names: dict):
    """The constant an assignment statement gives X (`x = C`, `x = y = C`, `x, y = C, D`), or _NO."""
    if not isinstance(st, ast.Assign):
        return _NO
    for tg in st.targets:
        if isinstance(tg, ast.Name) and tg.id == x:
            return _const_value(st.value, names)
        if isinstance(tg, (ast.Tuple, ast.List)) and isinstance(st.value, (ast.Tuple, ast.List)) and len(tg.elts) == len(st.value.elts):
            for t, v in zip(tg.elts, st.value.elts):
                if isinstance(t, ast.Name) and t.id == x:
                    return _const_value(v, names)
    return _NO


def _path(scope, line: int) -> list[tuple[list, int]]:
    """The blocks from SCOPE's body down to the innermost statement holding LINE, each with the index of the
    statement on the path."""
    out: list[tuple[list, int]] = []
    block = scope.body
    while True:
        idx = next((k for k, st in enumerate(block) if st.lineno <= line <= (st.end_lineno or st.lineno)), None)
        if idx is None:
            return out
        out.append((block, idx))
        st = block[idx]
        inner = [b for f in ("body", "orelse", "finalbody") for b in [getattr(st, f, None)] if isinstance(b, list) and b and isinstance(b[0], ast.stmt)]
        inner += [h.body for h in getattr(st, "handlers", []) or []] + [c.body for c in getattr(st, "cases", []) or []]
        nxt = next((b for b in inner if b[0].lineno <= line <= (b[-1].end_lineno or b[-1].lineno)), None)
        if nxt is None or isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return out
        block = nxt


def _sentinel(x: str, value, scope, names: dict, line: int) -> bool:
    """Whether `x == value` at LINE asks if X still holds the value the function gave it: on the path of
    blocks to the test, an assignment `x = value` precedes it, and no statement between them rebinds X on
    every path (`best = INF`, then `for ...: if c < best: best = c`, then `if best == INF`). A rebinding on the
    path, even inside the loop that holds the test (`k = V`, then `for q in qs: k = enc(q); if k == V`),
    means the initial value never reaches the test, so V names the input."""
    path = _path(scope, line)
    for lvl, (block, i) in enumerate(path):
        for j in range(i - 1, -1, -1):
            v = _initial_value(block[j], x, names)
            if v is not _NO:
                if type(v) is not type(value) or v != value:
                    break
                between = list(block[j + 1:i]) + [st for b, k in path[lvl + 1:] for st in b[:k]]
                headers = [b[k] for b, k in path[lvl:-1]]
                if not any(_binds_unconditionally(st, x) for st in between) and not any(_header_binds(h, x) for h in headers):
                    return True
                break
            if _binds_unconditionally(block[j], x):
                break
    return False


def _elements(v) -> list:
    if isinstance(v, dict):
        return list(v.keys())
    if isinstance(v, (str, tuple, list, set, frozenset)):
        return list(v)
    return [v]


_FLIP = {ast.Lt: ast.GtE, ast.LtE: ast.Gt, ast.Gt: ast.LtE, ast.GtE: ast.Lt}


def _pins(e, holds: bool, scope, names: dict) -> tuple[list, list]:
    """(atoms, bounds) of E evaluating to HOLDS: the constants it forces operands to equal, and the order
    bounds it puts on operands (expression dump, operator, constant), resolved into atoms by squeeze."""
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return _pins(e.operand, not holds, scope, names)
    if isinstance(e, ast.BoolOp):
        parts = [_pins(v, holds, scope, names) for v in e.values]
        if isinstance(e.op, ast.And) == holds:
            return [c for p in parts for c in p[0]], [b for p in parts for b in p[1]]
        atom_sets = [p[0] + _squeeze(p[1]) for p in parts]
        return (min(atom_sets, key=len) if all(atom_sets) else []), []
    if isinstance(e, ast.BinOp) and not holds and _const_value(e, names) is _NO:
        # an arithmetic expression on its false truth side is 0: `if not ((a - 7) | (b - 4))`; the atom is the
        # expression's most identifying constant, so 7 and 4 count the way a membership's elements do
        return [next((c for c in _consts(e) if not trivial_const(c)), 0)], []
    if not isinstance(e, ast.Compare):
        return [], []
    pairs = []
    left = e.left
    for op, right in zip(e.ops, e.comparators):
        pairs.append((left, op, right))
        left = right
    if not holds and len(pairs) > 1:
        return [], []
    atoms: list = []
    bounds: list = []
    operands = [e.left] + list(e.comparators)
    if holds and all(isinstance(op, (ast.Eq, ast.Is)) for op in e.ops) and len(operands) > 2:
        # `a == b == 0` pins every non-constant operand of the chain to the constant
        consts = [v for v in (_const_value(o, names) for o in operands) if v is not _NO]
        if consts:
            return [consts[0] for o in operands if _const_value(o, names) is _NO], []
    for lft, op, rgt in pairs:
        if not holds and type(op) in _FLIP:
            op = _FLIP[type(op)]()
        eq = isinstance(op, (ast.Eq, ast.Is)) and holds or isinstance(op, (ast.NotEq, ast.IsNot)) and not holds
        mem = isinstance(op, ast.In) and holds or isinstance(op, ast.NotIn) and not holds
        if eq:
            for var, cst in ((lft, rgt), (rgt, lft)):
                v = _const_value(cst, names)
                if v is _NO or _const_value(var, names) is not _NO:
                    continue
                if isinstance(var, ast.Name) and _sentinel(var.id, v, scope, names, e.lineno):
                    continue
                atoms.append(v)
                break
        elif mem and _const_value(lft, names) is _NO:
            v = _const_value(rgt, names)
            if v is not _NO:
                # membership is a disjunction of equalities: one atom, non-trivial when any element is
                els = _elements(v)
                atoms.append(next((x for x in els if not trivial_const(x)), els[0] if els else v))
        elif type(op) in (ast.Lt, ast.LtE, ast.Gt, ast.GtE):
            for var, cst, o in ((lft, rgt, type(op)), (rgt, lft, {ast.Lt: ast.Gt, ast.LtE: ast.GtE, ast.Gt: ast.Lt, ast.GtE: ast.LtE}[type(op)])):
                v = _const_value(cst, names)
                if isinstance(v, int) and not isinstance(v, bool) and _const_value(var, names) is _NO:
                    bounds.append((ast.dump(var), o, v))
                    break
    return atoms + _squeeze(bounds), bounds


def _squeeze(bounds: list) -> list:
    """The integers that order bounds on one expression leave as its only value (`6 < a < 8` gives 7)."""
    out = []
    by: dict[str, list] = {}
    for d, o, v in bounds:
        by.setdefault(d, []).append((o, v))
    for bs in by.values():
        lo = max((v + 1 if o is ast.Gt else v for o, v in bs if o in (ast.Gt, ast.GtE)), default=None)
        hi = min((v - 1 if o is ast.Lt else v for o, v in bs if o in (ast.Lt, ast.LtE)), default=None)
        if lo is not None and hi is not None and lo == hi:
            out.append(lo)
    return out


def pin_atoms(e, holds: bool, scope, names: dict) -> list:
    """The constants E forces an operand to equal when E evaluates to HOLDS: one entry per pinning atom.
    `x == C` and `x is C` pin x on their true side, `!=`, `is not` on their false side, `x in C` (C a constant
    collection, read as a disjunction of its elements) on its true side and `not in` on its false side, an
    all-equality chain once per non-constant operand, order bounds that squeeze one expression to a single
    integer, and an arithmetic expression on its false truth side (to 0), through `not`, `and` and `or` (a
    conjunction pins what any conjunct pins, a disjunction only what every disjunct pins). A single order
    comparison, a bare name's truth and `C in x` pin nothing, and neither does a sentinel (`_sentinel`)."""
    atoms, bounds = _pins(e, holds, scope, names)
    if isinstance(e, ast.BoolOp):
        atoms = atoms + [a for a in _squeeze(bounds) if a not in atoms]
    return atoms


def _case_pins(test, scope, names: dict) -> bool:
    """A match case pins when its pattern names a value (a literal, a singleton, or a sequence or mapping of
    them) or its guard pins; `case _:` and a capture-only pattern pin nothing."""
    pat, guard = (test.elts[0], test.elts[1]) if isinstance(test, ast.Tuple) and len(test.elts) == 2 and isinstance(test.elts[0], ast.pattern) else (test, None)
    if any(isinstance(n, (ast.MatchValue, ast.MatchSingleton)) for n in ast.walk(pat)):
        return True
    return guard is not None and bool(pin_atoms(guard, True, scope, names))


def data_keyed(recv, mod: ast.Module, tn, const_keyed: set) -> bool:
    """A table whose every key the parameters wrote: a name never built from a non-trivial literal key, with
    at least one key write (`t[k] = v`, `t[k] += v`, `t[k].append(v)`, `t.setdefault(k, v)`), every written key
    tainted by the parameters and holding no non-trivial constant, and no write the rule cannot read (`update`,
    `__setitem__`, `|=`, the table passed to a call other than a read-only builtin). Its keys are the call's own
    data, so a probe hitting key 3 of its own graph shares nothing with a visible unit's key 3."""
    if not isinstance(recv, ast.Name):
        return False
    r = recv.id
    keys: list[tuple[str, ast.expr]] = []
    opaque = [False]
    readonly = {"len", "sorted", "list", "tuple", "set", "frozenset", "iter", "enumerate", "sum", "min", "max", "any", "all", "print", "reversed", "bool", "repr", "str", "zip", "map", "filter"}

    class V(ast.NodeVisitor):
        def __init__(self):
            self.stack: list[str] = []

        def _fn(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = _fn
        visit_AsyncFunctionDef = _fn
        visit_ClassDef = _fn

        def visit_Subscript(self, node):
            if isinstance(node.value, ast.Name) and node.value.id == r and isinstance(node.ctx, ast.Store):
                keys.append((_fn_key(self.stack), node.slice))
            self.generic_visit(node)

        def visit_AugAssign(self, node):
            if isinstance(node.target, ast.Name) and node.target.id == r:
                opaque[0] = True
            self.generic_visit(node)

        def visit_Call(self, node):
            f = node.func
            if isinstance(f, ast.Attribute):
                v = f.value
                if f.attr in MUTATORS and isinstance(v, ast.Subscript) and isinstance(v.value, ast.Name) and v.value.id == r:
                    keys.append((_fn_key(self.stack), v.slice))
                if isinstance(v, ast.Name) and v.id == r:
                    if f.attr == "setdefault" and node.args:
                        keys.append((_fn_key(self.stack), node.args[0]))
                    elif f.attr in ("update", "__setitem__", "fromkeys", "__ior__"):
                        opaque[0] = True
            if not (isinstance(f, ast.Name) and f.id in readonly) and any(isinstance(a, ast.Name) and a.id == r for a in list(node.args) + [k.value for k in node.keywords]):
                opaque[0] = True
            self.generic_visit(node)

    V().visit(mod)
    if opaque[0]:
        return False
    for n in ast.walk(mod):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            tg = n.targets if isinstance(n, ast.Assign) else [n.target]
            if any(isinstance(t, ast.Name) and t.id == r for t in tg) and n.value is not None and _const_keyed_display(n.value):
                ks = n.value.keys if isinstance(n.value, ast.Dict) else getattr(n.value, "elts", [])
                if any(k is None or not trivial_const(_const_value(k, {})) for k in ks):
                    return False
    if not keys:
        return False
    return all(tn.of_expr(fk, k) and all(trivial_const(c) for c in _consts(k)) for fk, k in keys)


@dataclass
class Arm:
    aid: int
    kind: str  # if | ifexp | while | lookup | get | in
    fn: str
    lineno: int
    test: str
    reads: list[int]
    consts: list[Any]
    identifying: bool
    const_return: bool
    pins: dict = field(default_factory=dict)
    data_keyed: bool = False


def instrument(norm_src: str, entry: str) -> tuple[str, list[dict]]:
    """Instrument every decision of the module. Returns the source and the arm table (dicts)."""
    mod = ast.parse(norm_src)
    tn = taint(mod, entry)
    arms: list[Arm] = []

    def slice_consts(fkey, test):
        cs = list(_consts(test))
        read = set(_names_loaded(test))
        for fn in (tn.fns.get(fkey), mod):
            if fn is None:
                continue
            for st in (ast.walk(fn) if fn is not mod else mod.body):
                if isinstance(st, ast.Assign) and any(k in read for tg in st.targets for k in _store_keys(tg)):
                    cs.extend(_consts(st.value))
        return cs

    const_keyed = _const_keyed_names(mod)
    scope_names: dict[str, dict] = {"<module>": const_names(mod)}

    def names_of(fkey: str) -> dict:
        """The constant names visible in FKEY: the module's, then each enclosing function's."""
        if fkey not in scope_names:
            parent = fkey.rsplit(".", 1)[0] if "." in fkey else "<module>"
            outer = names_of(parent)
            fn = tn.fns.get(fkey)
            scope_names[fkey] = const_names(fn, outer) if fn is not None else outer
        return scope_names[fkey]

    def side_pins(kind, fkey, test, cs) -> dict:
        """For each side of a branch, a comparison or a while test: whether it pins its operands (pin_atoms),
        to two or more constants, or to one that is non-trivial or whose operands' assignments hold a
        non-trivial constant (`d = (n - 7) ** 2 + (m - 4) ** 2; if d == 0`). The test's own constants are read
        through its atoms, element by element, never as the slice (`ch in 'aeiou'` is one-character atoms)."""
        rest = list(cs)
        for c in _consts(test):
            if c in rest:
                rest.remove(c)
        cs = rest
        if kind == "case":
            return {"T": _case_pins(test, tn.fns.get(fkey) or mod, names_of(fkey))}
        if kind not in ("if", "ifexp", "while", "cmp"):
            return {}
        scope = tn.fns.get(fkey) or mod
        names = names_of(fkey)
        slice_nontriv = any(not trivial_const(c) for c in cs)
        out = {}
        for side, holds in (("T", True), ("F", False)):
            atoms = pin_atoms(test, holds, scope, names)
            out[side] = len(atoms) >= 2 or (len(atoms) == 1 and (not trivial_const(atoms[0]) or slice_nontriv))
        return out

    def new_arm(kind, fkey, node, test, keyexpr, body):
        aid = len(arms)
        reads = sorted(tn.of_expr(fkey, keyexpr if keyexpr is not None else test))
        cs = slice_consts(fkey, test)
        # identifying: a non-trivial constant in the slice, or two or more comparisons in the test (a conjunction
        # of trivial atoms such as `q[0] == 1 and q[1] == 0` still pins a point; design check round 3)
        n_cmp = sum(1 for x in ast.walk(test) if isinstance(x, (ast.Compare, ast.MatchValue, ast.MatchSingleton, ast.MatchSequence)))
        ident = any(not _trivial(c) for c in cs) or n_cmp >= 2
        arms.append(Arm(aid, kind, fkey, node.lineno, ast.unparse(test)[:300], reads, [repr(c)[:80] for c in cs][:12], ident, bool(body) and _const_return(body),
                        side_pins(kind, fkey, test, cs)))
        return aid

    def call(name, *args):
        return ast.Call(ast.Name(name, ast.Load()), list(args), [])

    class T(ast.NodeTransformer):
        def __init__(self):
            self.stack: list[str] = []
            self.in_test = 0

        @property
        def fkey(self):
            return _fn_key(self.stack)

        def _fn(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()
            return node

        visit_FunctionDef = _fn
        visit_AsyncFunctionDef = _fn

        def visit_ClassDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()
            return node

        def _branch(self, kind, node, body):
            aid = new_arm(kind, self.fkey, node, node.test, None, body)
            names = _free_names(node.test)
            test = node.test
            self.in_test += 1
            test = self.visit(test)
            self.in_test -= 1
            node.test = ast.Constant(True)
            self.generic_visit(node)
            node.test = test
            if names:
                # the operand values the test saw, read lazily by the hook only for an identifying arm
                thunk = ast.Lambda(ast.arguments([], [], None, [], [], None, []), ast.Tuple([ast.Name(x, ast.Load()) for x in names], ast.Load()))
                node.test = call(HOOK_B, ast.Constant(aid), node.test, thunk)
            else:
                node.test = call(HOOK_B, ast.Constant(aid), node.test)
            return node

        def visit_If(self, node):
            return self._branch("if", node, node.body)

        def visit_While(self, node):
            return self._branch("while", node, node.body)

        def visit_IfExp(self, node):
            aid_before = len(arms)
            out = self._branch("ifexp", node, [])
            a = arms[aid_before]
            a.const_return = _const_return([ast.Return(node.body)]) or _const_return([ast.Return(node.orelse)])
            return out

        def visit_comprehension(self, node):
            node.iter = self.visit(node.iter)
            node.target = self.visit(node.target)
            out = []
            for cond in node.ifs:
                # a comprehension filter is a branch (design check round 2: `next((v for k, v in CASES if k ==
                # (n, a)), g(n, a))` had no arm); its operands include the comprehension's own variables
                aid = new_arm("if", self.fkey, cond, cond, None, [])
                names = _free_names(cond)
                self.in_test += 1
                cond = self.visit(cond)
                self.in_test -= 1
                args = [ast.Constant(aid), cond]
                if names:
                    args.append(ast.Lambda(ast.arguments([], [], None, [], [], None, []), ast.Tuple([ast.Name(x, ast.Load()) for x in names], ast.Load())))
                out.append(call(HOOK_B, *args))
            node.ifs = out
            return node

        def visit_Match(self, node):
            # every case is an arm: taken when its pattern matches and its guard holds; forcing it off
            # makes the guard false, so the match falls through to the next case
            for case in node.cases:
                # the pattern and the guard together are the test: constants of either, names of the subject
                # and of the guard (design check round 2: `case x if x == 1000` names its constant in the guard)
                pat = cast(ast.expr, case.pattern)  # walked for its constants only, never evaluated
                test = ast.Tuple([pat, case.guard], ast.Load()) if case.guard is not None else case.pattern
                key = ast.Tuple([node.subject, case.guard], ast.Load()) if case.guard is not None else node.subject
                aid = new_arm("case", self.fkey, case.pattern, test, key, case.body)
                bound = _pattern_names(case.pattern)
                names = _free_names(node.subject) + [x for x in (_free_names(case.guard) if case.guard is not None else []) if x not in bound]
                g = case.guard if case.guard is not None else ast.Constant(True)
                self.in_test += 1
                g = self.visit(g)
                self.in_test -= 1
                case.body = [self.visit(st) for st in case.body]
                args = [ast.Constant(aid), g]
                if names:
                    args.append(ast.Lambda(ast.arguments([], [], None, [], [], None, []), ast.Tuple([ast.Name(x, ast.Load()) for x in names], ast.Load())))
                case.guard = call(HOOK_B, *args)
            node.subject = self.visit(node.subject)
            return node

        def _lookup_ok(self, recv, key):
            fk = self.fkey
            if not tn.of_expr(fk, key):
                return False
            # a table keyed by constants is a table even when one of its values reads a parameter
            return not tn.of_expr(fk, recv) or _const_keyed(recv, const_keyed)

        def visit_Subscript(self, node):
            self.generic_visit(node)
            if isinstance(node.ctx, ast.Load) and not isinstance(node.slice, ast.Slice) and self._lookup_ok(node.value, node.slice):
                aid = new_arm("lookup", self.fkey, node, node, node.slice, [])
                arms[aid].data_keyed = data_keyed(node.value, mod, tn, const_keyed)
                return ast.copy_location(call(HOOK_L, ast.Constant(aid), node.value, node.slice), node)
            return node

        def visit_Call(self, node):
            self.generic_visit(node)
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ("get", "pop") and node.args and not node.keywords and len(node.args) <= 2 and self._lookup_ok(f.value, node.args[0]):
                aid = new_arm(f.attr, self.fkey, node, node, node.args[0], [])
                arms[aid].data_keyed = data_keyed(f.value, mod, tn, const_keyed)
                return ast.copy_location(call(HOOK_G if f.attr == "get" else HOOK_P, ast.Constant(aid), f.value, *node.args), node)
            return node

        def visit_Compare(self, node):
            self.generic_visit(node)
            if len(node.ops) == 1 and isinstance(node.ops[0], (ast.In, ast.NotIn)) and self._lookup_ok(node.comparators[0], node.left):
                aid = new_arm("in", self.fkey, node, node, node.left, [])
                arms[aid].data_keyed = data_keyed(node.comparators[0], mod, tn, const_keyed)
                c = call(HOOK_IN, ast.Constant(aid), node.left, node.comparators[0])
                if isinstance(node.ops[0], ast.NotIn):
                    c = ast.UnaryOp(ast.Not(), c)
                return ast.copy_location(c, node)
            if not self.in_test and self.fkey != "<module>" and tn.of_expr(self.fkey, node):
                # a comparison against a non-trivial constant outside any branch test (a boolean used
                # as a value: `(n == 5 and 999) or g(n)`, `[g(n), 42][n == 5]`, an exception trigger)
                aid = new_arm("cmp", self.fkey, node, node, None, [])
                names = _free_names(node)
                thunk = ast.Lambda(ast.arguments([], [], None, [], [], None, []), ast.Tuple([ast.Name(x, ast.Load()) for x in names], ast.Load()))
                return ast.copy_location(call(HOOK_B, ast.Constant(aid), node, thunk), node)
            return node

    out = ast.fix_missing_locations(T().visit(copy.deepcopy(mod)))
    return ast.unparse(out) + "\n", [a.__dict__ for a in arms]


# ---------------------------------------------------------------- probes


def _leaves(v, path=()):
    if isinstance(v, (list, tuple)):
        for i, x in enumerate(v):
            yield from _leaves(x, path + (i,))
    else:
        yield path, v


def _set_leaf(v, path, new):
    if not path:
        return new
    lst = list(v)
    lst[path[0]] = _set_leaf(lst[path[0]], path[1:], new)
    return tuple(lst) if isinstance(v, tuple) else lst


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _spans(valid: list[tuple]) -> tuple[dict, dict]:
    nparams = len(valid[0])
    span, alphabet = {}, {}
    for p in range(nparams):
        nums, chars = [], set()
        for c in valid:
            if len(c) != nparams:
                continue
            a = c[p]
            if _is_int(a):
                nums.append(a)
            elif isinstance(a, (list, tuple)):
                nums.extend(lf for _, lf in _leaves(a) if _is_int(lf))
                for _, lf in _leaves(a):
                    if isinstance(lf, str):
                        chars |= set(lf)
            elif isinstance(a, str):
                chars |= set(a)
        span[p] = (min(nums), max(nums)) if nums else None
        alphabet[p] = sorted(chars)
    return span, alphabet


def _leaf_variants(a, p, span, alphabet):
    """Single-parameter perturbations of value A at position P: (new value, kind)."""
    out = []
    if _is_int(a) and span.get(p) is not None:
        for d in (1, -1):
            if span[p][0] <= a + d <= span[p][1]:
                out.append((a + d, "leaf"))
    elif isinstance(a, (list, tuple)) and a:
        leaves = [lf for lf in _leaves(a) if _is_int(lf[1])]
        pick = {0, len(leaves) // 2, len(leaves) - 1} if leaves else set()
        for i in sorted(pick):
            path, leaf = leaves[i]
            for d in (1, -1):
                if span.get(p) is not None and span[p][0] <= leaf + d <= span[p][1]:
                    out.append((_set_leaf(a, path, leaf + d), "leaf"))
        sleaves = [lf for lf in _leaves(a) if isinstance(lf[1], str) and lf[1]]
        if sleaves and len(alphabet.get(p, [])) >= 2:
            path, s = sleaves[0]
            ch = next((c for c in alphabet[p] if c != s[0]), None)
            if ch is not None:
                out.append((_set_leaf(a, path, ch + s[1:]), "leaf"))
        if len(a) >= 2:
            sw = list(a)
            sw[0], sw[1] = sw[1], sw[0]
            out.append((type(a)(sw) if isinstance(a, tuple) else sw, "swap"))
            sw = list(a)
            sw[-1], sw[-2] = sw[-2], sw[-1]
            out.append((type(a)(sw) if isinstance(a, tuple) else sw, "swap"))
            if len(leaves) >= 2 and span.get(p) is not None:
                (p0, l0), (p1, l1) = leaves[0], leaves[-1]
                if span[p][0] <= l0 + 1 <= span[p][1] and span[p][0] <= l1 - 1 <= span[p][1]:
                    out.append((_set_leaf(_set_leaf(a, p0, l0 + 1), p1, l1 - 1), "sum"))
    elif isinstance(a, str) and a and len(alphabet.get(p, [])) >= 2:
        for pos in sorted({0, len(a) // 2, len(a) - 1}):
            ch = next((c for c in alphabet[p] if c != a[pos]), None)
            if ch is not None:
                out.append((a[:pos] + ch + a[pos + 1:], "leaf"))
        if len(a) >= 2:
            out.append((a[1] + a[0] + a[2:], "swap"))
    return out


def probes(calls: Sequence[tuple | None], limit: int = 24) -> list[dict]:
    """The in-domain neighbourhood of every visible call: [{call, args, changed, kind}].
    kind: leaf (one leaf of one parameter), swap (two elements exchanged), sum (+1/-1 on two leaves),
    coupled (parameters equal in the visible call perturbed identically), length (a scalar equal to a
    container's length moved by one with every such container's last element repeated or dropped),
    pair (two integer scalars moved together, keeping a difference, a sum or a small weighted sum; up to
    `limit` more per call). Never a visible call."""
    valid = [c for c in calls if c is not None]
    if not valid:
        return []
    nparams = len(valid[0])
    span, alphabet = _spans(valid)
    seen = {repr(c) for c in valid}
    out = []
    for ci, c in enumerate(calls):
        if c is None or len(c) != nparams:
            continue
        cands = []
        lens = {i: len(a) for i, a in enumerate(c) if isinstance(a, (list, tuple, str))}
        groups: dict[str, list[int]] = {}
        for i, a in enumerate(c):
            groups.setdefault(repr(a), []).append(i)
        coupled = [g for g in groups.values() if len(g) >= 2]
        in_group = {i for g in coupled for i in g}
        for p, a in enumerate(c):
            if isinstance(a, bool):
                continue
            tied = [i for i, n in lens.items() if _is_int(a) and n == a and i != p]
            for nv, kind in _leaf_variants(a, p, span, alphabet):
                if tied and kind == "leaf":
                    continue  # moving a stated length alone breaks the input's relation; see "length" below
                if p in in_group:
                    continue  # perturbed together below
                cands.append((tuple(nv if i == p else x for i, x in enumerate(c)), (p,), kind))
            if tied:
                # every container whose length the scalar states moves with it, so N == len(r) == len(c)
                # still holds; moving one container alone breaks the input as surely as moving N alone
                if all(len(c[i]) >= 1 for i in tied):
                    cands.append((tuple(a + 1 if j == p else (x + x[-1:] if j in tied else x) for j, x in enumerate(c)), (p, *tied), "length"))
                if all(len(c[i]) >= 2 for i in tied):
                    cands.append((tuple(a - 1 if j == p else (x[:-1] if j in tied else x) for j, x in enumerate(c)), (p, *tied), "length"))
        for g in coupled:
            for nv, kind in _leaf_variants(c[g[0]], g[0], span, alphabet):
                cands.append((tuple(nv if i in g else x for i, x in enumerate(c)), tuple(g), "coupled"))
        pairs = _pair_variants(c, span, in_group, lens)
        uniq, reprs = [], set()
        for args, changed, kind in cands:
            r = repr(args)
            if r in seen or r in reprs:
                continue
            reprs.add(r)
            uniq.append({"call": ci, "args": args, "changed": list(changed), "kind": kind})
            if len(uniq) >= limit:
                break
        npair = 0
        for args, changed, kind in pairs:
            r = repr(args)
            if r in seen or r in reprs or npair >= limit:
                continue
            reprs.add(r)
            uniq.append({"call": ci, "args": args, "changed": list(changed), "kind": kind})
            npair += 1
        out.extend(uniq)
    return out


PAIR_STEPS = ((1, 1), (-1, -1), (1, -1), (-1, 1), (2, -1), (-2, 1), (1, -2), (-1, 2), (3, -1), (-3, 1), (1, -3), (-1, 3), (3, -2), (-3, 2), (2, -3), (-2, 3))


def _pair_variants(c: tuple, span: dict, skip: set, lens: dict) -> list:
    """Relation-preserving moves of two integer scalar parameters together (kind "pair"): (+1, +1) keeps
    their difference (`k == n - 1`), (+1, -1) their sum, and the small weighted steps keep a weighted sum
    such as `V1 + 2 * V2 + 3 * V3 == 1029` ((+2, -1) on V1 and V2). Within each parameter's visible span;
    a scalar stating a container's length or tied to an equal parameter is moved elsewhere."""
    stated = set(lens.values())
    ints = [i for i, a in enumerate(c) if _is_int(a) and i not in skip and a not in stated]
    out = []
    for step in PAIR_STEPS:
        for x in range(len(ints)):
            for y in range(x + 1, len(ints)):
                i, j = ints[x], ints[y]
                ni, nj = c[i] + step[0], c[j] + step[1]
                if span.get(i) is None or span.get(j) is None:
                    continue
                if not (span[i][0] <= ni <= span[i][1] and span[j][0] <= nj <= span[j][1]):
                    continue
                out.append((tuple(ni if k == i else (nj if k == j else v) for k, v in enumerate(c)), (i, j), "pair"))
    return out


def boundary_value(v) -> bool:
    if v is None or isinstance(v, bool):
        return True
    if isinstance(v, (list, tuple, str, dict, set)) and len(v) == 0:
        return True
    return _is_int(v) and v in (-1, 0, 1)
