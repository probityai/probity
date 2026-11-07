#!/usr/bin/env python3
"""Write the download badges of the README tables as static SVG files.

A table badge fetched from shields.io at view time shows "rate limited by upstream
service" whenever pepy or crates.io throttles shields. These files are written by the
pin-refresh run (see .github/workflows/pin-refresh.yml) with scripts/make-badge.py,
committed, and served from the repository, so no table badge calls a third party when
the README is viewed. A source that cannot be read leaves the committed file unchanged.

The packages are the ones the README names as assets/badges/dl-pypi-NAME.svg or
assets/badges/dl-crates-NAME.svg. A distribution that was renamed keeps one badge for
its whole history: COMBINED maps a file the README names to the PyPI names whose totals
add up to it. A combined badge is written only from the pepy API (the keyless fallback
covers 180 days, which is not the total), and pepy answers 404 for a name nothing has
downloaded yet, which counts as 0.

usage: refresh-badges.py [--out DIR]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REF = re.compile(r"assets/badges/dl-(pypi|crates)-([A-Za-z0-9._-]+)\.svg")
COMBINED_REF = re.compile(r"assets/badges/(dl-[a-z0-9-]+-total)\.svg")
UA = "probityai-badge-refresh"

# file stem -> (badge title, PyPI names whose pepy totals are summed)
COMBINED: dict[str, tuple[str, tuple[str, ...]]] = {
    "dl-verifier-total": ("verifier downloads", ("probity-verify", "agent-evidence-verify")),
}


PEPY_PAGE = "https://pepy.tech/projects/"
PEPY_PAGE_REF = re.compile(re.escape(PEPY_PAGE) + r"(?:probity-verify|agent-evidence-verify)")
# README files whose combined-badge line links the pepy page of the verifier.
LINKED_READMES = ("README.md", "packages/agent-evidence-verify/README.md")


def page_exists(url: str) -> bool:
    """True when the page answers 200; any other answer or no answer is False."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status == 200
    except OSError:
        return False


def verifier_pepy_page(old: str, new: str, exists=page_exists) -> str:
    """The pepy page the verifier badge links: the new name once its page is live."""
    return PEPY_PAGE + (new if exists(PEPY_PAGE + new) else old)


def relink_verifier(root: Path, target: str) -> list[str]:
    """Point the pepy link on each badge line at target; return the files changed."""
    changed = []
    for rel in LINKED_READMES:
        path = root / rel
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        out = [
            PEPY_PAGE_REF.sub(target, ln) if "dl-verifier-total" in ln else ln for ln in lines
        ]
        if out != lines:
            path.write_text("".join(out), encoding="utf-8")
            changed.append(rel)
    return changed


def fetch(url: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def pypi_total(name: str) -> int:
    key = os.environ.get("PEPY_API_KEY")
    if key:
        data = fetch(
            f"https://api.pepy.tech/api/v2/projects/{name}", {"X-API-Key": key}
        )
        return int(data["total_downloads"])
    data = fetch(f"https://pypistats.org/api/packages/{name}/overall")
    return sum(r["downloads"] for r in data["data"] if r["category"] == "with_mirrors")


def pepy_total(name: str, key: str) -> int:
    """The pepy total of one name; 404 means no download was ever recorded."""
    try:
        data = fetch(f"https://api.pepy.tech/api/v2/projects/{name}", {"X-API-Key": key})
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 0
        raise
    return int(data["total_downloads"])


def combined_total(names: tuple[str, ...]) -> int:
    key = os.environ.get("PEPY_API_KEY")
    if not key:
        raise ValueError("PEPY_API_KEY is not set; a combined total needs the pepy API")
    return sum(pepy_total(name, key) for name in names)


def crate_total(name: str) -> int:
    return int(fetch(f"https://crates.io/api/v1/crates/{name}")["crate"]["downloads"])


def human(n: int) -> str:
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k".replace(".0k", "k")
    return f"{n / 1_000_000:.1f}M".replace(".0M", "M")


def load_make_badge():
    path = Path(__file__).with_name("make-badge.py")
    spec = importlib.util.spec_from_file_location("make_badge", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def refresh_one(build, out: Path, stem: str, title: str, shown: str, getter) -> int:
    """Write one badge file from getter(); 1 when the source could not be read."""
    target = out / f"{stem}.svg"
    try:
        total = getter()
    except (OSError, ValueError, KeyError, TypeError) as exc:  # no answer changes nothing
        note = "file left unchanged"
        if not target.exists():  # a README must never point at a missing image
            target.write_text(build("n/a", shown, "#9f9f9f", None, title), encoding="utf-8")
            note = "no earlier file, wrote an n/a badge"
        print(f"FAILED {stem}: {type(exc).__name__}: {exc}; {note}")
        return 1
    target.write_text(build(human(total), shown, "#007ec6", None, title), encoding="utf-8")
    print(f"{stem}: {total}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parent.parent / "assets" / "badges"
    ap.add_argument("--out", type=Path, default=default)
    args = ap.parse_args(argv)
    build = load_make_badge().build
    readme = args.out.parent.parent / "README.md"
    text = readme.read_text(encoding="utf-8")
    getters = {"pypi": pypi_total, "crates": crate_total}
    jobs = [
        (f"dl-{kind}-{name}", f"{name} downloads", "↓", lambda g=getters[kind], n=name: g(n))
        for kind, name in sorted(set(REF.findall(text)))
    ]
    for stem, (title, names) in COMBINED.items():
        if f"assets/badges/{stem}.svg" in text:
            jobs.append((stem, title, "verifier ↓", lambda n=names: combined_total(n)))
    if not jobs:
        print(f"FAILED: {readme} names no assets/badges/dl-*.svg file")
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    failed = sum(refresh_one(build, args.out, *job) for job in jobs)
    if any(job[0] == "dl-verifier-total" for job in jobs):
        old, new = COMBINED["dl-verifier-total"][1]
        target = verifier_pepy_page(old, new)
        for rel in relink_verifier(readme.parent, target):
            print(f"{rel}: verifier downloads link is {target}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
