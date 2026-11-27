"""No reader turns a received value into text, and none hands received text to a platform parser.

``str(x)`` and ``String(x)`` give every JSON value a text: ``String(["EdDSA"])`` is ``"EdDSA"`` and ``str(["EdDSA"])`` is
``"['EdDSA']"``, so a header whose ``alg`` is a list verified in one reader and not in the other. The platform text
functions have the same fault: Python's ``\\d``, ``int``, ``str.strip()`` and ``str.lower()`` and JavaScript's
``parseInt``, ``Number``, ``trim()``, ``toLowerCase()``, ``Date`` and ``X509Certificate`` each read more than the format
does, each in its own way. A reader checks the type first and reads text by its grammar (``grammar/*.json``).

These tests count such calls in every source file of both packages. The request readers (the contract of the grammar
files) have none. Every other file is pinned at exactly the number it has today, so none can be added and a
pin cannot stay loose after a file loses a call; a file that is in no table fails.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SRC = PACKAGE / "src" / "probity_records"
TS_SRC = PACKAGE.parents[1] / "node" / "probity-records-verify" / "src"

#: The Python request readers: no finding of any kind.
PY_STRICT = ("certificate", "possession", "stamp", "trust_bundle", "verified_identities")
#: Files that read no received value: builders of the shared vectors, the lints, the command line, the registry of codes.
PY_NOT_READERS = ("__init__", "__main__", "canonical_identity_vectors", "clock_lint", "clock_tripwire",
                  "delegation_vectors", "digests_vectors", "erasure_vectors", "grant_body_vectors", "identity_vectors",
                  "refusal_codes", "refusal_lint", "verified_identities_vectors")  # fmt: skip
#: Every other Python file, with the findings it has today. The count is exact: a file that loses a call lowers its pin in the same change. ``core`` keeps one
#: ``int``: ``decimal``, the one function that turns grammar-matched digits into a number. The older record readers
#: (journal, quorum, authority, governance, oidc_approval, otel, exports) still turn received members into text; they
#: have no generated differential yet and are tracked as their own item.
PY_PINNED: dict[str, dict[str, int]] = {
    'authority': {'str()': 7},
    'bundle': {},
    'canonical_identity': {'int()': 1},
    'celexpr': {'int()': 2, 'str()': 1},
    'clock': {},
    'constraints': {'int()': 3, 'lower()': 3, 'platform parser': 1},
    'core': {'int()': 1, 'str()': 2},
    'digests': {'int()': 1, 'str()': 1},
    'erasure': {'int()': 2, 'lower()': 2},
    'exports': {'str()': 4},
    'governance': {'str()': 2, 'strip()': 1},
    'grants': {'int()': 1},
    'identifiers': {},
    'identity': {'str()': 2},
    'journal': {'int()': 1, 'platform parser': 2, 'str()': 16, 'strip()': 4},
    'oidc_approval': {'platform parser': 2, 'str()': 4},
    'otel': {'int()': 10, 'lower()': 2, 'platform parser': 2, 'str()': 24, 'strip()': 1},
    'quorum': {'str()': 1},
    'receipt_map': {},
    'records': {'str()': 1},
    'registry': {'isdigit()': 1, 'lower()': 1, 'platform parser': 2, 'str()': 2, 'strip()': 1},
    'renewal': {'int()': 1, 'str()': 3},
    'revocation': {'platform parser': 1, 'str()': 4},
    'signing': {'int()': 1, 'str()': 3},
    'walk': {},
    'witness': {'int()': 6, 'isdigit()': 2, 'str()': 1, 'strip()': 3},
}
#: The TypeScript request readers: no finding of any kind.
TS_STRICT = ("verified.ts", "x509.ts")
#: Every other TypeScript file, with the findings it has today. ``sf.ts`` reads a number from digits its own pattern
#: matched and writes one back; ``verify.ts`` holds the older record readers.
TS_PINNED: dict[str, dict[str, int]] = {
    'cli.ts': {},
    'corpus.ts': {'String()': 1},
    'delegation.ts': {},
    'identifiers.ts': {},
    'identity.ts': {'parseInt()': 1, 'toLowerCase()': 1},
    'revocation.ts': {'Date': 1},
    'sf.ts': {'Number()': 1, 'String()': 1},
    'verify.ts': {'Date': 1, 'Number()': 3, 'String()': 36, 'toLowerCase()': 3, 'trim()': 1},
    'webbotauth.ts': {'Date': 3, 'Number()': 1, 'String()': 1, '\\d in a pattern': 6, 'parseInt()': 1, 'toLowerCase()': 11, 'trim()': 1},
}

STRIP = frozenset({"strip", "lstrip", "rstrip"})
CASE = frozenset({"lower", "upper", "casefold", "title", "swapcase", "capitalize"})
CLASSIFY = frozenset({"isdigit", "isdecimal", "isnumeric", "isalnum", "isalpha", "isspace"})
PARSERS = frozenset({"fromisoformat", "strptime", "urlsplit", "urlparse", "load_der_x509_certificate",
                     "load_pem_x509_certificate", "timestamp", "parsedate_to_datetime"})  # fmt: skip
REGEX_CALLS = frozenset({"compile", "match", "fullmatch", "search", "sub", "findall", "split", "finditer"})
REGEX_CLASS = re.compile(r"\\[dDwWsSb]")


def py_findings(source: str) -> Counter[str]:
    """Each kind of platform text call in one Python source, counted."""
    tree = ast.parse(source)
    caught = {h.name for h in ast.walk(tree) if isinstance(h, ast.ExceptHandler) and h.name}
    found: Counter[str] = Counter()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name):
            if f.id == "str" and node.args and not (isinstance(node.args[0], ast.Name) and node.args[0].id in caught):
                found["str()"] += 1  # the text of a caught exception is this package's own
            if f.id in ("map", "filter") and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id == "str":
                found["str()"] += 1
            if f.id in ("int", "float") and node.args:
                found["int()"] += 1
            if f.id in PARSERS:
                found["platform parser"] += 1
        elif isinstance(f, ast.Attribute):
            if f.attr in STRIP and not node.args:
                found["strip()"] += 1
            if f.attr in CASE and not node.args:
                found["lower()"] += 1
            if f.attr in CLASSIFY:
                found["isdigit()"] += 1
            if f.attr in PARSERS:
                found["platform parser"] += 1
            if (f.attr in REGEX_CALLS and isinstance(f.value, ast.Name) and f.value.id == "re" and node.args
                    and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
                    and REGEX_CLASS.search(node.args[0].value)):  # fmt: skip
                found[r"\d in a pattern"] += 1
    return found


TS_RULES = {
    "String()": re.compile(r"(?<![.\w])String\("),
    "trim()": re.compile(r"\.trim(?:Start|End)?\(\)"),
    "parseInt()": re.compile(r"\bparse(?:Int|Float)\("),
    "Number()": re.compile(r"(?<![.\w])Number\("),
    "Date": re.compile(r"\bDate\.(?:parse|UTC)\(|\bnew Date\("),
    "X509Certificate": re.compile(r"\bX509Certificate\b"),
    "toLowerCase()": re.compile(r"\.to(?:Locale)?(?:Lower|Upper)Case\(\)"),
    r"\d in a pattern": re.compile(r"\\[dDwWsS]"),
}


def ts_findings(source: str) -> Counter[str]:
    """Each kind of platform text call in one TypeScript source, counted; comments are not code."""
    found: Counter[str] = Counter()
    for line in source.splitlines():
        if line.lstrip().startswith(("//", "*", "/*")):
            continue
        code = re.sub(r"\s//\s.*$", "", line)
        for name, pattern in TS_RULES.items():
            found[name] += len(pattern.findall(code))
    return found


def test_the_scans_find_what_they_look_for() -> None:
    """A scan that finds nothing in code that has it is a broken scan."""
    sample = ("import re\ntry:\n    pass\nexcept ValueError as exc:\n    a = str(exc)\n"
              "b = str(x)\nc = list(map(str, y))\nd = int(z)\ne = t.strip()\nf = t.strip(' ')\ng = t.lower()\n"
              "h = t.isdigit()\ni = re.compile(r'\\d+')\nj = when.timestamp()\nk = urlsplit(u)\n")  # fmt: skip
    assert py_findings(sample) == {"str()": 2, "int()": 1, "strip()": 1, "lower()": 1, "isdigit()": 1,
                                   r"\d in a pattern": 1, "platform parser": 2}  # fmt: skip
    twin = ('const a = String(x); // String(y)\n// String(z)\nconst b = s.trim(), c = parseInt(s, 10), d = Number(s);\n'
            'const e = Date.parse(s), f = new Date(0), g = new X509Certificate(der), h = s.toLowerCase();\n'
            'const i = /^\\d+$/, j = String.fromCharCode(65), k = n.toString(10);\n')  # fmt: skip
    assert ts_findings(twin) == {"String()": 1, "trim()": 1, "parseInt()": 1, "Number()": 1, "Date": 2,
                                 "X509Certificate": 1, "toLowerCase()": 1, r"\d in a pattern": 1}  # fmt: skip


def test_every_python_file_is_a_request_reader_pinned_or_not_a_reader() -> None:
    names = sorted(p.stem for p in SRC.glob("*.py"))
    listed = sorted([*PY_STRICT, *PY_NOT_READERS, *PY_PINNED])
    assert names == listed, f"unlisted: {sorted(set(names) - set(listed))}; gone: {sorted(set(listed) - set(names))}"


def test_no_python_request_reader_turns_a_value_into_text_or_calls_a_platform_parser() -> None:
    found = {name: dict(+py_findings((SRC / f"{name}.py").read_text())) for name in PY_STRICT}
    assert not any(found.values()), {name: f for name, f in found.items() if f}


def _moved(pinned: dict[str, int], now: Counter[str]) -> dict[str, tuple[int, int]]:
    """(pinned, now) for each kind whose count is not the pinned one."""
    return {kind: (pinned.get(kind, 0), now[kind]) for kind in sorted({*pinned, *now}) if pinned.get(kind, 0) != now[kind]}


def test_every_other_python_file_has_exactly_its_pinned_calls() -> None:
    moved = {}
    for name, pinned in PY_PINNED.items():
        differs = _moved(pinned, py_findings((SRC / f"{name}.py").read_text()))
        if differs:
            moved[name] = differs
    assert not moved, f"(pinned, now) by kind; a rise: read the value by its type and its grammar; a fall: lower the pin: {moved}"


def test_every_typescript_file_is_a_request_reader_or_pinned() -> None:
    names = sorted(p.name for p in TS_SRC.glob("*.ts"))
    listed = sorted([*TS_STRICT, *TS_PINNED])
    assert names == listed, f"unlisted: {sorted(set(names) - set(listed))}; gone: {sorted(set(listed) - set(names))}"


def test_no_typescript_request_reader_turns_a_value_into_text_or_calls_a_platform_parser() -> None:
    found = {name: dict(+ts_findings((TS_SRC / name).read_text())) for name in TS_STRICT}
    assert not any(found.values()), {name: f for name, f in found.items() if f}


def test_every_other_typescript_file_has_exactly_its_pinned_calls() -> None:
    moved = {}
    for name, pinned in TS_PINNED.items():
        differs = _moved(pinned, ts_findings((TS_SRC / name).read_text()))
        if differs:
            moved[name] = differs
    assert not moved, f"(pinned, now) by kind; a rise: read the value by its type and its grammar; a fall: lower the pin: {moved}"
