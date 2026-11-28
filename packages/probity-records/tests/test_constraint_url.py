"""A grant's URL constraints have one verdict: both readers read the URL by ``grammar/constraint-url.json``.

``constraints.url_parts`` and the twin's ``urlParts`` are the one reader each of the URL a ``url_pattern`` or
``url_safe`` constraint is asked about. These tests bind each to the grammar file (the patterns are its text, and its
accepted and refused cases are judged as it says), then run both on every value ``url_cases`` generates: the parts
each reader reads (or its refusal) and its verdict under each constraint of ``url_cases.CONSTRAINTS`` must be the
same, and neither may raise.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
import url_cases
from probity_records import constraints

PACKAGE = Path(__file__).resolve().parents[1]
TWIN = PACKAGE.parents[1] / "node" / "probity-records-verify" / "src" / "verify.ts"
PATTERNS = {
    "uri-text": constraints.URI_TEXT,
    "url": constraints.URL,
    "authority": constraints.AUTHORITY,
    "host-label": constraints.HOST_LABEL,
    "numeric-label": constraints.NUMERIC_LABEL,
    "ipv4": constraints.IPV4,
    "path": constraints.PATH,
    "path-escape": constraints.PATH_ESCAPE,
}
_JUDGE = """
import(process.argv[1]).then((m) => {
  const { values, constraints } = JSON.parse(require("node:fs").readFileSync(process.argv[2], "utf8"));
  const run = (f) => { try { return f(); } catch (e) { return "RAISED:" + e.constructor.name; } };
  const out = values.map((v) => ({ parts: run(() => m.urlParts(v)), checks: constraints.map((c) => run(() => m.check(c, v))) }));
  require("node:fs").writeFileSync(process.argv[3], JSON.stringify({ grammar: m.URL_GRAMMAR, bounds: [m.URL_PORT_MAX, m.URL_HOST_MAX], out }));
});
"""


def _python(v: Any) -> dict[str, Any]:
    def run(f: Any) -> Any:
        try:
            return f()
        except Exception as exc:  # noqa: BLE001 - a raise is itself the finding
            return f"RAISED:{type(exc).__name__}"

    parts = run(lambda: constraints.url_parts(v))
    return {"parts": list(parts) if isinstance(parts, tuple) else parts,
            "checks": [run(lambda c=c: constraints.check(c, v)) for c in url_cases.CONSTRAINTS]}  # fmt: skip


@pytest.fixture(scope="module")
def judged(tmp_path_factory: pytest.TempPathFactory) -> tuple[list[Any], list[dict[str, Any]], dict[str, Any]]:
    """(values, Python's answers, the twin's document) on every generated value."""
    values = url_cases.values()
    work = tmp_path_factory.mktemp("constraint-url")
    (work / "in.json").write_text(json.dumps({"values": values, "constraints": url_cases.CONSTRAINTS}))
    done = subprocess.run(["node", "-e", _JUDGE, str(TWIN), str(work / "in.json"), str(work / "out.json")],
                          capture_output=True, text=True, check=False)  # fmt: skip
    assert done.returncode == 0, f"the TypeScript twin did not run: {done.stderr[-800:]}"
    return values, [_python(v) for v in values], json.loads((work / "out.json").read_text())


def test_the_python_reader_is_the_grammar() -> None:
    doc = url_cases.grammar()
    rules = doc["productions"]
    assert sorted(PATTERNS) == sorted(rules)
    for name, pattern in PATTERNS.items():
        assert pattern.pattern == rules[name]["pattern"], name
        assert not pattern.flags & 0x2, name  # re.IGNORECASE
    assert constraints.PORT_MAX == rules["authority"]["bounds"]["portMax"]
    assert constraints.HOST_MAX == rules["host-label"]["bounds"]["hostMax"]
    for url, *parts in doc["cases"]["accept"]:
        assert constraints.url_parts(url) == tuple(parts), url
    for url in doc["cases"]["refuse"]:
        assert constraints.url_parts(url) is None, url


def test_the_twin_reads_the_same_grammar(judged: tuple[list[Any], list[dict[str, Any]], dict[str, Any]]) -> None:
    _, _, twin = judged
    rules = url_cases.grammar()["productions"]
    assert twin["grammar"] == {name: rule["pattern"] for name, rule in rules.items()}
    assert twin["bounds"] == [rules["authority"]["bounds"]["portMax"], rules["host-label"]["bounds"]["hostMax"]]


def test_the_twin_judges_the_grammar_cases_as_the_file_says(
    judged: tuple[list[Any], list[dict[str, Any]], dict[str, Any]],
) -> None:
    values, _, twin = judged
    index = {json.dumps(v): i for i, v in enumerate(values)}
    cases = url_cases.grammar()["cases"]
    for url, *parts in cases["accept"]:
        assert twin["out"][index[json.dumps(url)]]["parts"] == parts, url
    for url in cases["refuse"]:
        assert twin["out"][index[json.dumps(url)]]["parts"] is None, url


def test_both_readers_read_every_generated_url_alike(judged: tuple[list[Any], list[dict[str, Any]], dict[str, Any]]) -> None:
    """The differential: the same parts or the same refusal, the same verdict under every constraint, and no raise."""
    values, mine, twin = judged
    assert len(values) > 15000
    differ = [(i, values[i], mine[i], twin["out"][i]) for i in range(len(values)) if mine[i] != twin["out"][i]]
    raised = [(i, values[i]) for i in range(len(values)) if "RAISED:" in json.dumps([mine[i], twin["out"][i]])]
    accepted = sum(1 for answer in mine if answer["parts"] is not None)
    allowed = sum(1 for answer in mine if any(x is True for x in answer["checks"]))
    print(f"URL_DIFFERENTIAL total={len(values)} differ={len(differ)} raised={len(raised)} accepted={accepted} allowed={allowed}")
    assert not differ, f"{len(differ)} of {len(values)} differ, first: " + "\n".join(repr(d)[:300] for d in differ[:10])
    assert not raised, raised[:10]
    # a differential where both readers refuse nearly everything proves little: enough must be read and allowed
    assert accepted > 1500 and allowed > 1000, (accepted, allowed)
