"""The page that says where each identity piece lives names files that exist, and the package README points at it."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "packages" / "probity-records" / "docs" / "identity-homes.md"
README = ROOT / "packages" / "probity-records" / "README.md"
MODULES = {"identity", "authority", "adapter", "broker", "journal", "receiver", "data", "evaluation", "consumer"}
PYTHON_HOMES = ("packages/probity-records/src/probity_records/", "packages/probity-records/docs/", "packages/agent-evidence-verify/src/")
TWIN_HOME = "node/probity-records-verify/src/"
CODE = re.compile(r"`([^`]+)`")


def _rows(text: str) -> list[list[str]]:
    """The cells of each data row of the page's table."""
    rows = [line for line in text.splitlines() if line.startswith("|")]
    return [[cell.strip() for cell in row.strip("|").split("|")] for row in rows[2:]]


def problems(text: str, root: Path) -> list[str]:
    """Everything wrong with a page: a row that is not shaped as the table says, or a path that is not in the tree."""
    found: list[str] = []
    rows = _rows(text)
    if not rows:
        return ["the page has no table rows"]
    for cells in rows:
        if len(cells) != 4:
            found.append(f"row has {len(cells)} cells, not 4: {cells[:1]}")
            continue
        piece, module, python, twins = cells
        if module not in MODULES:
            found.append(f"{piece}: {module!r} is not a wire-contract module")
        py_paths = CODE.findall(python.replace("<br>", " "))
        twin_paths = CODE.findall(twins.replace("<br>", " "))
        if not py_paths:
            found.append(f"{piece}: no Python path")
        for path in py_paths:
            if not path.startswith(PYTHON_HOMES):
                found.append(f"{piece}: {path} is outside the public Python homes")
        for path in twin_paths:
            if not path.startswith(TWIN_HOME):
                found.append(f"{piece}: {path} is outside the TypeScript twin")
        for path in py_paths + twin_paths:
            if not (root / path).is_file():
                found.append(f"{piece}: {path} does not exist")
    return found


def test_every_path_on_the_page_exists_in_the_tree() -> None:
    assert problems(PAGE.read_text(encoding="utf-8"), ROOT) == []


def test_the_page_lists_every_module_the_readme_names() -> None:
    readme = README.read_text(encoding="utf-8")
    section = readme.split("## Where each identity piece lives", 1)[1]
    named = re.findall(r"`([a-z_]+)`", section.split("[The table]", 1)[0])
    modules = [name for name in named if (ROOT / "packages/probity-records/src/probity_records" / f"{name}.py").is_file()]
    assert modules == named and len(modules) >= 5
    page = PAGE.read_text(encoding="utf-8")
    for name in modules:
        assert f"/{name}.py`" in page, f"{name} is named in the README but not in the table"


def test_the_readme_links_the_page() -> None:
    assert "(docs/identity-homes.md)" in README.read_text(encoding="utf-8")
    assert PAGE.is_file()


def test_a_path_that_moved_is_found(tmp_path: Path) -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert any("does not exist" in p for p in problems(text, tmp_path))


def test_a_path_outside_the_public_homes_is_found(tmp_path: Path) -> None:
    text = "| Piece | Module | Python | Twin |\n|---|---|---|---|\n| X | identity | `services/src/x.py` | - |\n"
    assert any("outside the public Python homes" in p for p in problems(text, tmp_path))


def test_an_unknown_module_and_a_short_row_are_found(tmp_path: Path) -> None:
    text = "| Piece | Module | Python | Twin |\n|---|---|---|---|\n| X | plumbing | `packages/probity-records/src/probity_records/x.py` | - |\n| Y | identity |\n"
    found = problems(text, tmp_path)
    assert any("not a wire-contract module" in p for p in found)
    assert any("not 4" in p for p in found)


def test_a_page_with_no_table_is_found(tmp_path: Path) -> None:
    assert problems("# nothing\n", tmp_path) == ["the page has no table rows"]
