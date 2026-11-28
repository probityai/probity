"""Check, and refresh, every committed digest pin of a live repository file.

Profiles under ``packages/`` pin the bytes of files they select: sha256 and git blob digests in
JSON selections, contracts and source pins. A change to a pinned file (a dependency added to a
``pyproject.toml``, a relocked requirements file, a reordered import) leaves each such pin stale,
and the job that reads it fails far from the change. This script finds every pin of a tracked
file and compares it with the file's current bytes.

    python scripts/pinned-digests.py check     # exit 1 and list every stale pin
    python scripts/pinned-digests.py update    # rewrite stale digests in place, then check

A pin is a JSON string of 64 hex digits (sha256) or 40 hex digits (git blob) that names a file:
the key it sits under is a relative path, or its object carries a ``path`` field next to
``sha256`` / ``git_blob_sha1``. A path resolves against the pin file's directory, each ancestor
up to the repository root, and ``src/`` under each; it is current when any resolved file has
those bytes. Files under ``retained/`` record past runs and are never read. Historical pins and
path aliases are declared in ``scripts/pinned-digests.toml``. Files with their own recorder are
refreshed by it (see ``generators`` in that file); ``update`` is the recorder for the others.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "scripts" / "pinned-digests.toml"
SHA256 = re.compile(r"[0-9a-f]{64}")
BLOB = re.compile(r"[0-9a-f]{40}")
BLOB_KEYS = ("git_blob_sha1", "gitBlob", "git_blob", "blob")


@dataclass(frozen=True)
class Pin:
    """One digest in one pin file that names one repository file."""

    source: str
    name: str
    kind: str
    value: str
    candidates: tuple[Path, ...]


def git_blob(raw: bytes) -> str:
    """The git object id of a blob with these bytes."""
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


def digest(kind: str, raw: bytes) -> str:
    """The digest of ``raw`` of the given kind."""
    return hashlib.sha256(raw).hexdigest() if kind == "sha256" else git_blob(raw)


def tracked_json() -> list[str]:
    """Tracked JSON files outside retained run records."""
    names = subprocess.run(["git", "ls-files", "-z", "*.json"], cwd=ROOT, check=True, capture_output=True).stdout
    # A sparse checkout leaves some tracked files absent; CI reads a full checkout.
    return sorted(n for n in names.decode().split("\0") if n and "/retained/" not in n and (ROOT / n).is_file())


def bases(source: Path) -> list[Path]:
    """Directories a relative pin path is resolved against, nearest first."""
    out, here = [], source.parent
    while True:
        out += [here, here / "src"]
        if here == ROOT:
            return out
        here = here.parent


def candidates(source: str, name: str, aliases: list[dict]) -> tuple[Path, ...]:
    """Every tracked file the pin name can mean."""
    if not isinstance(name, str) or name.startswith("/") or ".." in Path(name).parts:
        return ()
    for alias in aliases:
        if fnmatch.fnmatch(source, alias["file"]) and name.startswith(alias["prefix"]):
            name = alias["to"] + name[len(alias["prefix"]):]
            found = ROOT / name
            return (found,) if found.is_file() else ()
    found = []
    for base in bases(ROOT / source):
        path = base / name
        if path.is_file() and path.resolve().is_relative_to(ROOT) and path not in found:
            found.append(path)
    return tuple(found)


def pins_in(source: str, aliases: list[dict]) -> list[Pin]:
    """Every file pin in one JSON file."""
    try:
        data = json.loads((ROOT / source).read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        # Not JSON, or an adversarial nesting vector: neither can pin a file.
        return []
    found: list[Pin] = []

    def add(name: object, kind: str, value: object) -> None:
        pattern = SHA256 if kind == "sha256" else BLOB
        if isinstance(name, str) and isinstance(value, str) and pattern.fullmatch(value):
            paths = candidates(source, name, aliases)
            if paths:
                found.append(Pin(source, name, kind, value, paths))

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        if isinstance(node.get("path"), str):
            add(node["path"], "sha256", node.get("sha256"))
            for key in BLOB_KEYS:
                add(node["path"], "blob", node.get(key))
        for key, value in node.items():
            if isinstance(value, str):
                add(key, "sha256" if len(value) == 64 else "blob", value)
            elif isinstance(value, dict) and "path" not in value:
                add(key, "sha256", value.get("sha256"))
                for blob_key in BLOB_KEYS:
                    add(key, "blob", value.get(blob_key))
            walk(value)

    walk(data)
    return found


def exempt(pin: Pin, rules: list[dict]) -> bool:
    """A historical pin the configuration records on purpose."""
    return any(fnmatch.fnmatch(pin.source, rule["file"]) and fnmatch.fnmatch(pin.name, rule.get("name", "*"))
               for rule in rules)


def stale(config: dict) -> list[Pin]:
    """Pins whose value matches no file they can name."""
    aliases, rules = config.get("alias", []), config.get("historical", [])
    out = []
    for source in tracked_json():
        for pin in pins_in(source, aliases):
            current = {digest(pin.kind, path.read_bytes()) for path in pin.candidates}
            if pin.value not in current and not exempt(pin, rules):
                out.append(pin)
    return out


def update(pins: list[Pin]) -> int:
    """Replace each stale value with the current digest of the one file it names."""
    refused = 0
    for pin in pins:
        if len(pin.candidates) != 1:
            names = ", ".join(str(p.relative_to(ROOT)) for p in pin.candidates)
            print(f"ambiguous: {pin.source}: {pin.name} can mean {names}; add an alias", file=sys.stderr)
            refused += 1
            continue
        path = ROOT / pin.source
        text = path.read_text(encoding="utf-8")
        new = digest(pin.kind, pin.candidates[0].read_bytes())
        path.write_text(text.replace('"' + pin.value + '"', '"' + new + '"'), encoding="utf-8")
    return refused


def main() -> int:
    """Run ``check`` or ``update``."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("check", "update"))
    args = parser.parse_args()
    config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    if args.command == "update" and update(stale(config)):
        return 1
    found = stale(config)
    for pin in found:
        print(f"stale {pin.kind}: {pin.source}: {pin.name}")
    if found:
        recorders = "; ".join(f"{g['files']}: {g['command']}" for g in config.get("generators", []))
        print(f"{len(found)} stale pins. Refresh with their recorder ({recorders}), "
              "or `python scripts/pinned-digests.py update` for the rest.", file=sys.stderr)
        return 1
    print("every pin of a live file matches its bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
