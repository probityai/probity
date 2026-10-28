#!/usr/bin/env python3
"""Refuse a built distribution that carries a private name or a file nobody listed.

    DIST_CLEAN_PRIVATE_NAMES=... python3 scripts/check-dist-clean.py [--allowlist FILE] [--distribution NAME] <file>...
    python3 scripts/check-dist-clean.py --self-test

Each file is a wheel, a zip, a source distribution (.tar.gz) or a crate (.crate). Every
member is opened and checked three ways:

* its path may not be a private-work path (TODO.md, research/, .handoff/, .claude/ and
  the like);
* its bytes may not contain a private name, matched as a substring without regard to case;
* when an allowlist is given, its path must match a pattern the allowlist names for that
  distribution and archive kind (`sdist` or `wheel`). A file the allowlist does not name is
  a failure, so a new top-level directory has to be listed on purpose.

The private names are not written in this repository. They come from the environment
variable DIST_CLEAN_PRIVATE_NAMES (one name per line), which CI fills from a repository
secret, and the set must hash to PRIVATE_NAMES_SHA256 below. A missing, empty or altered
list stops the check with exit 2, so a run without the secret fails closed instead of
passing. A finding names the list entry by number, never by text, because CI logs of a
public repository are public.

Exit 0 when every file is clean, 1 when any member fails, 2 when a file cannot be read, a
name is missing from the allowlist, or the private-name list is missing or does not match. The check reads the archive, never the working tree,
so it sees what a user downloads. Standard library only: CI runs it before any install.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import os
import re
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

# A sentence that names TODO.md is not the file; the path check below refuses the file itself.
NAMES_ENV = "DIST_CLEAN_PRIVATE_NAMES"
# SHA-256 of the lowercased names, sorted and joined with newlines. It pins the secret's
# content so a truncated or edited secret fails closed; it does not reveal the names.
PRIVATE_NAMES_SHA256 = "e9273d9340a3e1c1fe5d3e620f5a7f0a268ac972fb7f7f05641b70728e8a4618"


class NameListError(ValueError):
    """The private-name list is missing, empty, or does not match its pinned digest."""


def canonical_names(text: str) -> tuple[str, ...]:
    """The names in ``text`` (one per line), lowercased, stripped, deduplicated and sorted."""
    return tuple(sorted({line.strip().lower() for line in text.splitlines() if line.strip()}))


def names_digest(names: tuple[str, ...]) -> str:
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


def load_names(text: str | None, expected_sha256: str = PRIVATE_NAMES_SHA256) -> tuple[bytes, ...]:
    """Return the needles for ``text``, or raise NameListError so the caller fails closed."""
    if not text or not text.strip():
        raise NameListError(f"{NAMES_ENV} is not set or is empty; the check cannot run without it")
    names = canonical_names(text)
    if names_digest(names) != expected_sha256:
        raise NameListError(f"{NAMES_ENV} holds {len(names)} name(s) whose digest does not match the pinned one")
    return tuple(n.encode() for n in names)


# Directories that only private working state has: the first group at the archive root, the second at any depth.
PRIVATE_ROOT_DIRS = frozenset({"research", "_raw", "private", "captures"})
PRIVATE_DIRS = frozenset({".handoff", ".claude", ".humanizer"})
PRIVATE_FILES = re.compile(
    r"(TODO.*\.md|CLAUDE\.md|SESSION_HANDOFF\.md|PROJECT_CONTEXT\.md|DECISION_LOG\.md|\.env(\..*)?)\Z",
    re.IGNORECASE,
)


def _members(path: Path):
    """Yield (member path, bytes) for every regular file in an archive."""
    name = path.name
    if name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir():
                    yield info.filename, z.read(info)
    elif name.endswith((".tar.gz", ".crate", ".tgz")):
        with tarfile.open(path, "r:gz") as t:
            for info in t:
                if info.isfile():
                    f = t.extractfile(info)
                    yield info.name, (f.read() if f else b"")
    else:
        raise ValueError(f"{path.name}: not a wheel, zip, tar.gz or crate")


def _relative(member: str, kind: str) -> str:
    """The path inside the archive's own root: sdists and crates sit under `<name>-<version>/`."""
    parts = PurePosixPath(member).parts
    return "/".join(parts[1:]) if kind != "wheel" and len(parts) > 1 else "/".join(parts)


def _kind(path: Path) -> str:
    return "wheel" if path.name.endswith((".whl", ".zip")) else "sdist"


def load_allowlist(path: Path, distribution: str) -> dict[str, list[str]]:
    table = tomllib.loads(path.read_text()).get("distribution", {})
    if distribution not in table:
        raise KeyError(f"{path} has no [distribution.{distribution}] table")
    return {k: list(v) for k, v in table[distribution].items()}


def _name_hits(data: bytes, needles: tuple[bytes, ...]) -> list[tuple[int, int]]:
    """Every (line number, list entry number) where a private name occurs, found without regard to case."""
    lowered = data.lower()
    found: list[tuple[int, int]] = []
    for index, needle in enumerate(needles, start=1):
        at = lowered.find(needle)
        while at >= 0:
            found.append((data.count(b"\n", 0, at) + 1, index))
            at = lowered.find(needle, at + 1)
    return sorted(found)


def check_path(rel: str) -> str | None:
    parts = PurePosixPath(rel).parts
    if len(parts) > 1 and parts[0] in PRIVATE_ROOT_DIRS:
        return f"private directory {parts[0]}/"
    for part in parts[:-1]:
        if part in PRIVATE_DIRS:
            return f"private directory {part}/"
    if parts and PRIVATE_FILES.match(parts[-1]):
        return f"private file {parts[-1]}"
    return None


def scan(path: Path, needles: tuple[bytes, ...], allowlist: dict[str, list[str]] | None = None) -> list[str]:
    """Return one failure line per offending member or content hit; empty means clean."""
    kind = _kind(path)
    failures: list[str] = []
    for member, data in _members(path):
        rel = _relative(member, kind)
        why = check_path(rel)
        if why:
            failures.append(f"{path.name}: {member}: {why}")
        failures.extend(f"{path.name}: {member}:{line}: private name #{index}" for line, index in _name_hits(data, needles))
        if allowlist is not None and not any(fnmatch.fnmatchcase(rel, p) for p in allowlist.get(kind, [])):
            failures.append(f"{path.name}: {member}: not on the {kind} allowlist")
    return failures


def _self_test() -> int:
    """Each refusal fires on a planted file, a clean archive passes, and the list fails closed.

    The planted names are made up: the real list never appears in this repository.
    """
    ok = True
    names = "Example-Private-Name\nexample.invalid/private\n"
    needles = load_names(names, names_digest(canonical_names(names)))
    for bad in (None, "", "  \n", "some-other-name\n"):
        try:
            load_names(bad)
        except NameListError:
            continue
        print(f"SELF-TEST FAIL name list {bad!r} was accepted")
        ok = False
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def build(name: str, files: dict[str, bytes]) -> Path:
            target = root / name
            with tarfile.open(target, "w:gz") as t:
                for rel, data in files.items():
                    info = tarfile.TarInfo(f"pkg-1.0/{rel}")
                    info.size = len(data)
                    t.addfile(info, io.BytesIO(data))
            return target

        base = {"pyproject.toml": b"[project]\n", "src/pkg/__init__.py": b"x = 1\n"}
        allow = {"sdist": ["pyproject.toml", "src/pkg/*.py"]}
        cases: dict[str, tuple[dict[str, bytes], int]] = {
            "clean": (base, 0),
            "todo-file": ({**base, "TODO.md": b"nothing private here\n"}, 1),
            "research-dir": ({**base, "research/1/notes.txt": b"x\n"}, 1),
            "handoff-dir": ({**base, ".handoff/entries/a.md": b"x\n"}, 1),
            "private-name-in-source": ({**base, "src/pkg/a.py": b"# see example.invalid/private PR 43\n"}, 1),
            "name-in-url": ({**base, "src/pkg/c.py": b"# https://example.invalid/private.git\n"}, 1),
            "name-case": ({**base, "src/pkg/b.py": b"# EXAMPLE-private-NAME\n"}, 1),
            "unlisted-file": ({**base, "extra/notes.txt": b"x\n"}, 1),
        }
        for label, (files, want_min) in cases.items():
            got = scan(build(f"{label}.tar.gz", files), needles, allow)
            if bool(got) != bool(want_min):
                print(f"SELF-TEST FAIL {label}: expected {'a failure' if want_min else 'clean'}, got {got}")
                ok = False
    print("self-test " + ("passed" if ok else "FAILED"))
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--allowlist", type=Path)
    ap.add_argument("--distribution")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--names-sha256", default=PRIVATE_NAMES_SHA256,
                    help="digest the name list must match (default: the pinned digest of the real list)")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.files:
        ap.error("name at least one file")
    try:
        needles = load_names(os.environ.get(NAMES_ENV), args.names_sha256)
    except NameListError as exc:
        print(f"private-name list unusable: {exc}", file=sys.stderr)
        return 2
    allow = None
    if args.allowlist:
        if not args.distribution:
            ap.error("--allowlist needs --distribution")
        try:
            allow = load_allowlist(args.allowlist, args.distribution)
        except (KeyError, OSError, tomllib.TOMLDecodeError) as exc:
            print(f"allowlist unreadable: {exc}", file=sys.stderr)
            return 2
    failed = False
    for path in args.files:
        try:
            problems = scan(path, needles, allow)
        except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
            print(f"cannot read {path}: {exc}", file=sys.stderr)
            return 2
        for line in problems:
            print(line)
        failed = failed or bool(problems)
        print(f"{'FAIL' if problems else 'clean'} {path.name}: {len(problems)} finding(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
