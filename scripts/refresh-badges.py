#!/usr/bin/env python3
"""Write the download badges of the READMEs as shields.io endpoint JSON files.

A badge that shields.io builds from pepy or crates.io at view time shows "rate limited by
upstream service" whenever the registry throttles shields, and a static file committed to
main goes stale between pull requests. The READMEs instead point shields at one small JSON
file per badge, dl-pypi-NAME.json, dl-crates-NAME.json or dl-NAME-total.json, on the
unprotected `badges` branch. The badges workflow (.github/workflows/badges.yml) runs this
script hourly and pushes the files straight to that branch, so no pull request is needed and
no count goes stale. A source that cannot be read leaves the file unchanged.

The badges are the ones the root README names as badges%2Fdl-pypi-NAME.json,
badges%2Fdl-crates-NAME.json or badges%2Fdl-NAME-total.json inside an
img.shields.io/endpoint URL. A distribution that was renamed keeps one badge for its whole
history: COMBINED maps a total to the PyPI names whose totals add up to it, and the run
writes downloads.md beside the JSON with each name's total, the sum and the source. A
combined badge is written only from the pepy API (the keyless fallback covers 180 days,
which is not the total), and pepy answers 404 for a name nothing has downloaded yet, which
counts as 0.

usage: refresh-badges.py [--out DIR]   (DIR is a checkout of the badges branch)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

REF = re.compile(r"badges%2Fdl-(pypi|crates)-([A-Za-z0-9._-]+)\.json")
COMBINED_REF = re.compile(r"badges%2F(dl-[a-z0-9-]+-total)\.json")
UA = "probityai-badge-refresh"

# file stem -> PyPI names whose pepy totals are summed
COMBINED: dict[str, tuple[str, ...]] = {
    "dl-verifier-total": ("probity-verify", "agent-evidence-verify"),
}

# A name whose count is fixed at the moment its last release made it depend on the next
# name. From then on installing the old name also downloads the new one, so adding the
# old name's live total would count those installs twice. probity-verify 0.5.1 (published
# 2026-11-08 about 17:30 UTC) depends on agent-evidence-verify; 10,003 is its pepy API
# total read at 2026-11-08 16:44 UTC, before that release.
FROZEN: dict[str, tuple[int, str]] = {"probity-verify": (10_003, "2026-11-08 16:44 UTC")}

DOWNLOADS_DOC = "downloads.md"
STAMP = re.compile(r"all-time totals\) at [^.]*UTC")


def fetch(url: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def pypi_total(name: str) -> int:
    key = os.environ.get("PEPY_API_KEY")
    if key:
        data = fetch(f"https://api.pepy.tech/api/v2/projects/{name}", {"X-API-Key": key})
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


def combined_totals(names: tuple[str, ...]) -> dict[str, int]:
    key = os.environ.get("PEPY_API_KEY")
    if not key:
        raise ValueError("PEPY_API_KEY is not set; a combined total needs the pepy API")
    return {name: FROZEN[name][0] if name in FROZEN else pepy_total(name, key) for name in names}


def crate_total(name: str) -> int:
    return int(fetch(f"https://crates.io/api/v1/crates/{name}")["crate"]["downloads"])


def downloads_page(totals: dict[str, int], at: str) -> str:
    """The page the summed badge links: each name's total, the sum, the time and the source."""
    rows = "".join(
        f"| [`{n}`](https://pypi.org/project/{n}/) | {v:,}{' (fixed)' if n in FROZEN else ''} | [pepy.tech/projects/{n}](https://pepy.tech/projects/{n}) |\n"
        for n, v in totals.items()
    )
    names = list(totals)
    return (
        "# Verifier downloads\n\n"
        f"The verifier was published on PyPI as `{names[0]}` and is now published as "
        f"`{names[-1]}`. PyPI has no way to rename a project, so each name keeps its own count. "
        "The downloads badge in the README is the sum of both.\n\n"
        "| PyPI name | Downloads | Source |\n|---|--:|---|\n"
        f"{rows}| **Total** | **{sum(totals.values()):,}** | sum of the rows above |\n\n"
        + "".join(
            f"`{n}` is fixed at its pepy API total read at {FROZEN[n][1]}, just before its last "
            "release made it install the new name; counting it live after that would count each "
            "of those installs twice.\n\n"
            for n in names
            if n in FROZEN
        )
        + f"Read from the pepy.tech API (`api.pepy.tech/api/v2/projects/<name>`, all-time totals) at {at}. "
        "This page and the badge are written by the same hourly run "
        "([scripts/refresh-badges.py](https://github.com/probityai/probity/blob/main/scripts/refresh-badges.py)), "
        "so they always show the same numbers.\n\n"
        f"Install the current name: `pip install {names[-1]}`.\n"
    )


def human(n: int) -> str:
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n / 1000:.1f}k".replace(".0k", "k")
    return f"{n / 1_000_000:.1f}M".replace(".0M", "M")


def payload(message: str, color: str) -> str:
    """The shields.io endpoint document: one flat badge reading "↓ <number>"."""
    doc = {
        "schemaVersion": 1,
        "label": "",
        "message": f"↓ {message}",
        "color": color,
        "cacheSeconds": 3600,
    }
    return json.dumps(doc, ensure_ascii=False) + "\n"


def refresh_one(out: Path, stem: str, getter) -> int:
    """Write one badge file from getter(); 1 when the source could not be read.

    getter returns an int, or a dict of per-name totals for a summed badge, in which case
    the downloads page is written beside the JSON from the same numbers."""
    target = out / f"{stem}.json"
    try:
        total = getter()
        if isinstance(total, dict):
            doc = out / DOWNLOADS_DOC
            at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
            page = downloads_page(total, at)
            # rewrite only when a count moved, so the time alone never makes a commit
            if not doc.exists() or STAMP.sub("", doc.read_text(encoding="utf-8")) != STAMP.sub("", page):
                doc.write_text(page, encoding="utf-8")
            total = sum(total.values())
    except (OSError, ValueError, KeyError, TypeError) as exc:  # no answer changes nothing
        note = "file left unchanged"
        if not target.exists():  # a README must never point at a missing file
            target.write_text(payload("n/a", "lightgrey"), encoding="utf-8")
            note = "no earlier file, wrote an n/a badge"
        print(f"FAILED {stem}: {type(exc).__name__}: {exc}; {note}")
        return 1
    target.write_text(payload(human(total), "007ec6"), encoding="utf-8")
    print(f"{stem}: {total}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    ap.add_argument("--out", type=Path, default=root / "badges-out")
    ap.add_argument("--readme", type=Path, default=root / "README.md")
    args = ap.parse_args(argv)
    text = args.readme.read_text(encoding="utf-8")
    getters = {"pypi": pypi_total, "crates": crate_total}
    jobs = [
        (f"dl-{kind}-{name}", lambda g=getters[kind], n=name: g(n))
        for kind, name in sorted(set(REF.findall(text)))
    ]
    for stem in sorted(set(COMBINED_REF.findall(text))):
        names = COMBINED.get(stem)
        if names is None:
            print(f"FAILED: {args.readme} names {stem}.json, which COMBINED does not define")
            return 1
        jobs.append((stem, lambda n=names: combined_totals(n)))
    if not jobs:
        print(f"FAILED: {args.readme} names no badges%2Fdl-*.json endpoint")
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    failed = sum(refresh_one(args.out, *job) for job in jobs)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
