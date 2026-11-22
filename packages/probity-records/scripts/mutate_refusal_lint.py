"""Mutation check of the refusal lint: switch off each rule in turn; the registry tests must turn red every time.

Run from packages/probity-records: ``uv run python scripts/mutate_refusal_lint.py``. Exit 0 when every mutant is
killed, 1 when one survives (the tests do not hold that rule), 2 when the unmutated tests are not green.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

LINT = Path("src/probity_records/refusal_lint.py")
TEST = "tests/test_refusal_registry.py"
MUTANTS = {
    "return-rule": ("                scan.strings(value, shaped_only=True)\n", "                pass\n"),
    "dict-return-rule": ("                        scan.strings(item, shaped_only=False)\n",
                         "                        pass\n"),
    "carriers-and-calls": (
        "            if cfg.has(cfg.carriers, scan.path, called) or cfg.has(cfg.refusal_calls, scan.path, called):",
        "            if False:"),
    "raisers": ("            elif cfg.has(cfg.raisers, scan.path, called) and node.args:", "            elif False:"),
    "keywords": ("                if keyword.arg in cfg.keywords:", "                if False:"),
    "compare": ("        elif isinstance(node, ast.Compare) and _name(node.left) in cfg.keywords:",
                "        elif False:"),
    "module-constants": ("        if any(isinstance(t, ast.Name) and t.id in scan.used_names for t in targets):",
                         "        if False:"),
    "assigned": ("              and any(cfg.has(cfg.assigned | cfg.keywords, scan.path, _name(t))",
                 "              and False and any(cfg.has(cfg.assigned | cfg.keywords, scan.path, _name(t))"),
    "located": ("                scan.located(node.args[0])", "                pass"),
    "composed-in-located": ("            if code is None:\n", "            if False:\n"),
    "composed": ('        if ":" not in head:\n', "        if False:\n"),
    "snake-form": ("        if not CODE.match(code):", "        if False:"),
    "registered": ("        elif code not in self.registry:", "        elif False:"),
    "sentinels": ("        if text in self.config.sentinels:", "        if True:"),
    "per-file-names": ('        return name in kind or f"{Path(file).name}::{name}" in kind',
                       '        return name in kind or any(k.endswith("::" + name) for k in kind)'),
    "exempt-functions": ("        if id(node) in exempt:", "        if False:"),
    "frozenset-values": (
        '        elif isinstance(node, ast.Call) and _name(node.func) in ("frozenset", "set", "tuple", "list"):',
        "        elif False:"),
}


def green() -> bool:
    done = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", TEST],
                          capture_output=True, text=True, check=False)
    return done.returncode == 0


def main() -> int:
    original = LINT.read_text(encoding="utf-8")
    if not green():
        print("CONTROL red: the unmutated tests fail")
        return 2
    survived = []
    try:
        for name, (old, new) in MUTANTS.items():
            if original.count(old) != 1:
                print(f"MUTANT {name}: the target text is not in the lint exactly once")
                survived.append(name)
                continue
            LINT.write_text(original.replace(old, new), encoding="utf-8")
            killed = not green()
            print(f"MUTANT {name}: {'killed' if killed else 'SURVIVED'}")
            if not killed:
                survived.append(name)
    finally:
        LINT.write_text(original, encoding="utf-8")
    print(f"MUTATION {len(MUTANTS) - len(survived)} of {len(MUTANTS)} killed; survived={survived}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
