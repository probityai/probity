"""Mutation check for the visible-test detectors: every mutant must turn their tests red.

The mutants are the oracle-free detector study's own, from its frozen mutation check (89 of its
94; the other five mutate the research harness's container runner and its table bootstrap, which
the observer does not ship), each pointed at the shipped file that carries the mutated line, plus
the observer's own: the gate, the pre-flight finding, the repeat source and the worker's isolate
mode. Each mutant is applied to a copy of ``src`` and ``tests``, the detector tests run on that
copy (``PYTHONPATH`` puts the copy first), and the copy is removed, so mutants run in parallel and
the checkout is never edited. A mutant the tests do not kill is a guarantee no test holds. Run from
``packages/observer`` in an environment with the ``test`` and ``done`` extras:

    python scripts/mutate-visible-detectors.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path("src/probity_observer/done")
STATIC = ROOT / "visible_static.py"
RULES = ROOT / "visible_rules.py"
ISOLATE = ROOT / "visible_isolate.py"
DETECT = ROOT / "visible_detect.py"
WORKER = ROOT / "visible_runner.txt"
CALLS = ROOT / "visible_calls.txt"
REWRITES = Path("tests/done/rewrites.py")
# Fastest first: with -x the first red file ends the run.
TESTS = ["tests/done/test_visible_static.py", "tests/done/test_visible_rules.py",
         "tests/done/test_visible_pins.py", "tests/done/test_visible_isolate.py",
         "tests/done/test_visible_detect.py"]
MUTANTS = [
    (RULES,
     '    return bool(meta.get("identifying")) and bool(meta["pins"].get(side, False))',
     '    return bool(meta.get("identifying"))'),
    (RULES,
     '        if meta["data_keyed"]:',
     '        if False:'),
    (RULES,
     '    from .visible_isolate import SINGLE_SCALAR_BOUNDARY, trivial_const\n\n    consts = []',
     '    from .visible_isolate import SINGLE_SCALAR_BOUNDARY, _trivial as trivial_const\n\n    consts = []'),
    (ISOLATE,
     '            out[side] = len(atoms) >= 2 or (len(atoms) == 1 and (not trivial_const(atoms[0]) or slice_nontriv))',
     '            out[side] = True'),
    (ISOLATE,
     '            out[side] = len(atoms) >= 2 or (len(atoms) == 1 and (not trivial_const(atoms[0]) or slice_nontriv))',
     '            out[side] = len(atoms) >= 2 or (len(atoms) == 1 and not trivial_const(atoms[0]))'),
    (ISOLATE,
     '            out[side] = len(atoms) >= 2 or (len(atoms) == 1 and (not trivial_const(atoms[0]) or slice_nontriv))',
     '            out[side] = False'),
    (ISOLATE,
     '                if isinstance(var, ast.Name) and _sentinel(var.id, v, scope, names, e.lineno):\n                    continue',
     '                pass'),
    (ISOLATE,
     '                if not any(_binds_unconditionally(st, x) for st in between) and not any(_header_binds(h, x) for h in headers):\n                    return True',
     '                if True:\n                    return True'),
    (ISOLATE,
     '    return all(tn.of_expr(fk, k) and all(trivial_const(c) for c in _consts(k)) for fk, k in keys)',
     '    return False'),
    (ISOLATE,
     '    return all(tn.of_expr(fk, k) and all(trivial_const(c) for c in _consts(k)) for fk, k in keys)',
     '    return all(tn.of_expr(fk, k) for fk, k in keys)'),
    (ISOLATE,
     '        return c in SINGLE_SCALAR_BOUNDARY',
     '        return c in (-1, 0, 1)'),
    (ISOLATE,
     '        return len(c) == 0 or (len(c) == 1 and not (c.isdigit() and int(c) not in SINGLE_SCALAR_BOUNDARY))',
     '        return len(c) <= 1'),
    (ISOLATE,
     '        return len(c) == 0 or (len(c) == 1 and trivial_const(next(iter(c))))',
     '        return len(c) <= 1'),
    (ISOLATE,
     '        return (min(atom_sets, key=len) if all(atom_sets) else []), []',
     '        return [c for s in atom_sets for c in s], []'),
    (RULES,
     '    if fired != ["isolated_branch"] or not items:',
     '    if not items:'),
    (RULES,
     '            cands = guard_literals(meta.get("test") or "")',
     '            cands = list(meta.get("consts") or [])'),
    (RULES,
     '        return v not in LITERAL_TRIVIAL',
     '        return True'),
    (RULES,
     '        if hit is None:\n            return None',
     '        if hit is None:\n            continue'),
    (RULES,
     ' for k, us in t.get("matched", []) if units & set(us)]',
     ' for k, us in t.get("matched", [])]'),
    (RULES,
     '            roots = list(args) + ([args] if len(args) >= 2 else [])',
     '            roots = list(args)'),
    (STATIC,
     'SINGLE_SCALAR_BOUNDARY = {-2, -1, 0, 1, 2}',
     'SINGLE_SCALAR_BOUNDARY = {-2, -1, 0, 1}'),
    (STATIC,
     'MULTI_ATOM_TRIVIAL = {-1, 0, 1}',
     'MULTI_ATOM_TRIVIAL = {-1, 0, 1, 2}'),
    (STATIC,
     'return c not in SINGLE_SCALAR_BOUNDARY and c not in doc_ints',
     'return c not in doc_ints'),
    (STATIC,
     '        if s.startswith(">>>"):\n            skip_next = True\n            continue\n',
     ''),
    (STATIC,
     '        return sa in (f"not {sb}", f"not ({sb})") or sb in (f"not {sa}", f"not ({sa})")',
     '        return False'),
    (STATIC,
     '    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):\n        return expr.operand\n    return None',
     '    return None'),
    (STATIC,
     '            if self.depth and name in self.vars:',
     '            if False:'),
    (STATIC,
     '            if any(v is not None for v in vs):\n                nested_bind.setdefault(n.func.id, vs)',
     '            pass'),
    (STATIC,
     '    if isinstance(expr, ast.BoolOp) and isinstance(expr.op, ast.Or):\n        out = []',
     '    if False:\n        out = []'),
    (STATIC,
     '                if a in lens:\n                    continue\n',
     ''),
    (STATIC,
     '        if isinstance(e, ast.UnaryOp):\n            return is_const(e.operand)',
     '        if isinstance(e, ast.UnaryOp):\n            return False'),
    (STATIC,
     '        if isinstance(a, int) and a in MULTI_ATOM_TRIVIAL:\n            continue\n        return False',
     '        return False'),
    (STATIC,
     '                    else:\n                        add(neg, st.body, "not_body", "If", st.lineno)',
     '                    else:\n                        pass'),
    (RULES,
     '    if crash_counts and et in CRASHES:',
     '    if crash_counts:'),
    (ISOLATE,
     ' and node.func.attr in MUTATORS:',
     ':'),
    (ISOLATE,
     '        for g in coupled:',
     '        for g in []:'),
    (ISOLATE,
     '        if len(a) >= 2:\n            sw = list(a)\n            sw[0], sw[1] = sw[1], sw[0]',
     '        if False:\n            sw = list(a)\n            sw[0], sw[1] = sw[1], sw[0]'),
    (ISOLATE,
     '            return not tn.of_expr(fk, recv) or _const_keyed(recv, const_keyed)',
     '            return True'),
    (RULES,
     '(not reads or set(m["changed"]) & set(reads))',
     'True'),
    (RULES,
     '        if not all(mu[i]["passed"] for i in range(n) if i not in F):\n            continue\n',
     ''),
    (RULES,
     '        if not all(unit_failed(mu[i], True) is True for i in F):\n            continue\n',
     ''),
    (RULES,
     'if p.get("raised") is None and (not reads',
     'if (not reads'),
    (RULES,
     '    if boundary or structural:',
     '    if structural:'),
    (RULES,
     '    structural = not nontriv and coupled_enter',
     '    structural = False'),
    (RULES,
     '("const" if len(E) >= 2 and len(outs) == 1 else None)',
     'None'),
    (RULES,
     '    if not ok and len(raised) == len(prs):\n        return "control_hardcoded:exhaustive_lookup"\n',
     ''),
    (RULES,
     '        E = [k for k in E_any if _scalar_change(pm[k], first, reads) or _novel_entry(arm, meta, [base[i] for i in F], prs[k])]',
     '        E = E_any'),
    (RULES,
     '    if {"?", "overflow"} & keys:\n        return True\n',
     ''),
    (RULES,
     '        if len(F) == n and _per_key_partition(arm, base):',
     '        if False:'),
    (RULES,
     '        if i >= len(args) or not isinstance(args[i], (list, tuple, dict, set, frozenset)):\n            return True',
     '        if i >= len(args):\n            return True'),
    (RULES,
     '        if len(k) != 1 or k[0] == "overflow":',
     '        if not k:'),
    (ISOLATE,
     '            names = _free_names(node.test)\n',
     '            names = []\n'),
    (ISOLATE,
     '            bound.update(x.id for x in ast.walk(n.target) if isinstance(x, ast.Name))',
     '            pass'),
    (ISOLATE,
     'PAIR_STEPS = ((1, 1), (-1, -1), (1, -1), (-1, 1), (2, -1),',
     'PAIR_STEPS = ((1, 1), (-1, -1), (1, -1), (-1, 1),) and () or ((2, -1),'),
    (ISOLATE,
     'if j == p else (x + x[-1:] if j in tied else x)',
     'if j == p else (x + x[-1:] if j == tied[0] else x)'),
    (RULES,
     '            P = [k for k in P if sides & set(prs[k].get("arms", []))]',
     '            pass'),
    (ISOLATE,
     '            return not tn.of_expr(fk, recv) or _const_keyed(recv, const_keyed)',
     '            return not tn.of_expr(fk, recv)'),
    (ISOLATE,
     'f.attr in ("get", "pop")',
     'f.attr in ("get",)'),
    (ISOLATE,
     '                case.guard = call(HOOK_B, *args)',
     '                pass'),
    (RULES,
     '        if len(Fk) >= n or not all(unit_failed(mu[i], True) is True for i in Fk):',
     '        if len(Fk) >= n or not all(unit_failed(mu[i], True) is True for i in range(n)):'),
    (RULES,
     '    if one_scalar and not nontrivial(not meta.get("const_return")) and',
     '    if one_scalar and not nontrivial(True) and'),
    (RULES,
     '                        and (_scalar_change(pm[k], first, reads) or _novel_entry(arm, meta, F_units, prs[k])) for k in range(len(pm)))',
     '                        for k in range(len(pm)))'),
    (ISOLATE,
     '                out.append(call(HOOK_B, *args))\n            node.ifs = out',
     '                out.append(args[1])\n            node.ifs = out'),
    (ISOLATE,
     '            if not self.in_test and self.fkey != "<module>" and tn.of_expr(self.fkey, node):',
     '            if False:'),
    (ISOLATE,
     '                test = ast.Tuple([pat, case.guard], ast.Load()) if case.guard is not None else case.pattern',
     '                test = case.pattern'),
    (WORKER,
     '    if _is_table(recv) or isinstance(recv, (list, tuple)):',
     '    if _is_table(recv):'),
    (RULES,
     '        src = cv[i][0] if i < len(cv) and cv[i] else c',
     '        src = c'),
    (ISOLATE,
     '        ident = any(not _trivial(c) for c in cs) or n_cmp >= 2',
     '        ident = any(not _trivial(c) for c in cs)'),
    (RULES,
     '    elif arm_pins(arm, meta):\n        field = "opvals"\n    else:\n        return True',
     '    else:\n        field = "opvals"'),
    (RULES,
     '        return all(dict(q) != (v if isinstance(v, dict) else {}) for v in us)',
     '        return not set(q) <= {k for v in us for k in v}'),
    (ISOLATE,
     '            v = _fold(n)\n            if v is not None:\n                out.append(v)',
     '            pass'),
    (CALLS,
     '                key = _call_key(n, ns)\n                if key is not None:\n                    subjects[ast.unparse(n)] = key',
     '                key = ast.unparse(n)\n                if key is not None:\n                    subjects[ast.unparse(n)] = key'),
    (CALLS,
     '            lit = _literal_or_none(self.ns[node.id])',
     '            lit = None'),
    (DETECT,
     '    return [visible_test] + ([private_source] if private_source else [])',
     '    return [private_source] if private_source else []'),
    (WORKER,
     '        FORCE[int(aid)] = "miss" if side == "hit" else (side != "T")',
     '        pass'),
    (WORKER,
     '            return default[0] if default else None\n    return recv.get(key, *default)',
     '            pass\n    return recv.get(key, *default)'),
    (REWRITES,
     '    tables = [tb for tb in an.tables if tb.matched_keys] if t in TABLE_TRANSFORMS else []',
     '    tables = []'),
    (RULES,
     'if not rp["timeout"] and len(runs) == 2 and runs[0]["passed"]:',
     'if not rp["timeout"] and len(runs) == 2:'),
    (RULES,
     '        elif body_units != F:\n            continue',
     '        elif False:\n            continue'),
    (RULES,
     '        if args is None or boundary_input(args):\n            continue',
     '        if args is None:\n            continue'),
    (RULES,
     '        if neigh and not any(ifn["body_lineno"] in ls for ls, _ in neigh):',
     '        if neigh:'),
    (RULES,
     'if lu["passed"] and not su["passed"] and su.get("error_type") == "AssertionError":',
     'if lu["passed"] and not su["passed"]:'),
    (RULES,
     '        if len(t["matched"]) >= 2:\n            f["visible_input_table"] = True',
     '        if len(t["matched"]) >= 1:\n            f["visible_input_table"] = True'),
    (RULES,
     '        if items and any(b not in entered_by_probe for b in body_lines):',
     '        if items and body_lines:'),
    (RULES,
     '        if items and any(b not in entered_by_probe for b in body_lines):',
     '        if items and body_lines and all(b not in entered_by_probe for b in body_lines):'),
    (RULES,
     '        body_lines = {it["body_lineno"] for it in fired if "body_lineno" in it}',
     '        body_lines = {g["body_lineno"] for g in r["static"]["guards"] if g["identifying"] and g["matched"]}'),
    (RULES,
     '        if (not r2["passed"] and not r2["error"].startswith("MemoryError")) or not rp["same_calls"]:',
     '        if not r2["passed"] or not rp["same_calls"]:'),
    (RULES,
     'and len(ok) == len(items) and not (only & vis_results):',
     'and len(ok) == len(items):'),
    (RULES,
     'neigh_read = [ls for ls, changed in neigh if changed is not None and (not read or changed in read)]',
     'neigh_read = [ls for ls, changed in neigh if changed is not None]'),
    # the observer's own guarantees
    (DETECT,
     'GATE = ("impure_on_visible", "type_strict_on_visible", "repeat_divergence", "isolated_branch")',
     'GATE = ("impure_on_visible", "type_strict_on_visible", "repeat_divergence")'),
    (DETECT,
     '        out.append({"reason": PREFLIGHT, "refuses": False, "attribution": "task", "evidence": conflicts[:3]})',
     '        out.append({"reason": PREFLIGHT, "refuses": False, "attribution": "test_author", "evidence": conflicts[:3]})'),
    (DETECT,
     '    if conflicts:\n        out.append({"reason": PREFLIGHT',
     '    if False:\n        out.append({"reason": PREFLIGHT'),
    (DETECT,
     '"sources": repeat_sources(test, private)',
     '"sources": [test]'),
    (DETECT,
     '        rec["isolate"] = isolate_record(worker, root, scratch, norm, entry, calls, prelude, us)',
     '        rec["isolate"] = {"status": "no_result"}'),
    (DETECT,
     '        for name in rules.NEW + rules.MEASURED + list(ISOLATE):',
     '        for name in rules.NEW + rules.MEASURED:'),
    (WORKER,
     ', "isolate": run_isolate}',
     ', "isolate": run_probes}'),
]


def run(tree: Path) -> int:
    env = dict(os.environ, PYTHONPATH=str(tree / "src"))
    return subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *TESTS],
                          cwd=tree, env=env, capture_output=True, check=False).returncode


def one(index: int, path: Path, old: str, new: str) -> str:
    with tempfile.TemporaryDirectory(prefix="visible-mutant-") as scratch:
        tree = Path(scratch)
        shutil.copytree("src", tree / "src", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree("tests", tree / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        target = tree / path
        source = target.read_text()
        if source.count(old) != 1:
            return f"MUTANT {index} NOT APPLICABLE ({path.name})"
        target.write_text(source.replace(old, new, 1))
        return f"MUTANT {index} {path.name} {'KILLED' if run(tree) != 0 else 'SURVIVED'}"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="visible-baseline-") as scratch:
        tree = Path(scratch)
        shutil.copytree("src", tree / "src", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree("tests", tree / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        if run(tree) != 0:
            print("BASELINE RED")
            return 1
    workers = max(1, min(8, os.cpu_count() or 1))
    with ThreadPoolExecutor(workers) as pool:
        lines = list(pool.map(lambda item: one(item[0], *item[1]), enumerate(MUTANTS)))
    for line in lines:
        print(line)
    survived = sum(1 for line in lines if not line.endswith("KILLED"))
    print(f"MUTANTS {len(MUTANTS)} surviving={survived}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
