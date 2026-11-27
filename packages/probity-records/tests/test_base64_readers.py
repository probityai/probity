"""Every received base64 text is read through one canonical helper, in Python and in TypeScript.

A reader that calls the library decoder itself keeps stray low bits of the last digit (``AB==`` reads as ``AA==``), so
one signed document has many spellings and a verifier that reads canonically refuses what this one grades. The helpers
are ``core.unb64`` (padded standard base64) and ``identity.unb64url`` (unpadded base64url) in Python, ``unb64`` and
``strictB64url`` in ``verify.ts``. These tests fail when any other source function decodes base64.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SRC = PACKAGE / "src" / "probity_records"
TS_SRC = PACKAGE.parents[1] / "node" / "probity-records-verify" / "src"

#: Every call that turns base64 text (or any other base-N text) into bytes.
DECODERS = frozenset({"b64decode", "urlsafe_b64decode", "standard_b64decode", "decodebytes", "a2b_base64", "b32decode"})
#: The only functions that may call one, as ``module.function``.
PY_HELPERS = frozenset({"core.unb64", "identity.unb64url"})
#: A TypeScript decode: ``Buffer.from(x, "base64")`` (or ``"base64url"``, ``"hex"`` is not base64), and ``atob``.
TS_DECODE = re.compile(r"""Buffer\.from\([^;]*?,\s*["']base64(?:url)?["']\s*\)|\batob\s*\(""")
#: The only TypeScript functions that may decode, and the one line that keeps RFC 8941's own rule.
TS_HELPERS = {("verify.ts", "unb64"), ("verify.ts", "strictB64url")}
TS_RFC8941 = ("sf.ts", "bytes")  # RFC 8941 section 4.2.7: padding optional, stray bits accepted, as the Python reader does


def _py_decode_sites() -> list[str]:
    sites: list[str] = []
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text())

        def walk(node: ast.AST, scope: str, module: str = path.stem) -> None:
            for child in ast.iter_child_nodes(node):
                name = scope
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    name = child.name if not scope else scope
                if isinstance(child, ast.Call):
                    f = child.func
                    called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                    if called in DECODERS:
                        sites.append(f"{module}.{scope or '<module>'}:{child.lineno}")
                walk(child, name, module)

        walk(tree, "")
    return sites


def test_the_python_decode_sites_are_found_at_all() -> None:
    """Both helpers decode, so a scan that finds none is a broken scan."""
    helpers = {s.rsplit(":", 1)[0] for s in _py_decode_sites()}
    assert PY_HELPERS <= helpers, sorted(helpers)


def test_no_python_module_decodes_base64_outside_the_canonical_helpers() -> None:
    stray = [s for s in _py_decode_sites() if s.rsplit(":", 1)[0] not in PY_HELPERS]
    assert not stray, f"decode base64 through core.unb64 or identity.unb64url: {stray}"


def _ts_decode_sites() -> list[tuple[str, str, int]]:
    sites: list[tuple[str, str, int]] = []
    for path in sorted(TS_SRC.glob("*.ts")):
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            if line.lstrip().startswith(("//", "*", "/*")) or not TS_DECODE.search(line):
                continue
            scope = "<module>"
            for j in range(i, -1, -1):
                found = re.match(r"\s*(?:export\s+)?function\s+(\w+)|\s{2}(\w+)\(\)\s*:\s*\w+\s*\{", lines[j])
                if found:
                    scope = found.group(1) or found.group(2)
                    break
            sites.append((path.name, scope, i + 1))
    return sites


def test_the_typescript_decode_sites_are_found_at_all() -> None:
    found = {(f, s) for f, s, _ in _ts_decode_sites()}
    assert TS_HELPERS | {TS_RFC8941} <= found, sorted(found)


def test_no_typescript_module_decodes_base64_outside_the_canonical_helpers() -> None:
    stray = [f"{f}:{n} ({s})" for f, s, n in _ts_decode_sites() if (f, s) not in TS_HELPERS | {TS_RFC8941}]
    assert not stray, f"decode base64 through unb64 or strictB64url in verify.ts: {stray}"
