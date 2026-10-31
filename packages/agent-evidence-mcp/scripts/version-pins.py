#!/usr/bin/env python3
"""Hold every version a page names to the one place that version is decided.

A version written on a page has an owner: the manifest of the package that
releases it (pyproject.toml, Cargo.toml, package.json, a VERSION file), or, for
a package another repository releases, one line of the family lock in
version-pins.toml. This check finds every pin, link and statement of a tracked
package's version in the tracked pages and refuses any that differs from its
owner. Because the owner is the manifest, a release is one edit: bump the
manifest, run `version-pins.py write`, and the release pull request carries
every page at the new version, so the tagged commit (and the page a registry
renders from it) names the version it publishes.

    version-pins.py check      exit 1 when a page disagrees with its owner
    version-pins.py write      rewrite every disagreeing pin to its owner
    version-pins.py registry   compare manifests, tags and registries (network)
    version-pins.py refresh    move the family lock to the registries, then write
    version-pins.py badges     fetch every image a page shows (network)

What it reads, besides the pins of tracked packages:

* a markdown link whose text names one version and whose target names another;
* a link into this repository that names a file the tree does not hold;
* a relative link on a page a registry renders (it 404s on PyPI and crates.io).

A page that records history (a changelog, a dated experiment, a paper's tested
setup) is listed under [scan] historical; one line is exempted with an HTML
comment `version-pins: keep`, a stretch with `version-pins: off` ... `on`.

Exit 0 when everything agrees, 1 when something disagrees, 2 when the check
could not run (unreadable config, no git, a registry that did not answer).
Standard library only, and byte-identical in every repository that runs it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

CONFIG = "version-pins.toml"
ORG = "probityai"
V = r"\d+\.\d+\.\d+(?:(?:a|b|rc|\.dev|\.post)\d+)?"
VERSION = re.compile(rf"^{V}$")
SHA = re.compile(r"^[0-9a-f]{7,40}$")
USER_AGENT = "probityai-version-pins (https://github.com/probityai)"
DEFAULT_INCLUDE = ("**/*.md", "**/llms.txt", ".github/workflows/*.yml", ".github/workflows/*.yaml")
DEFAULT_HISTORICAL = (
    "**/CHANGELOG*",
    "**/HISTORY*",
    "**/NEWS*",
    "**/research/**",
    "**/release-notes/**",
)
KEEP = "version-pins: keep"
OFF = "version-pins: off"
ON = "version-pins: on"
# "github" is a project released only as a GitHub release of its tag; "action" is an Action.
REGISTRIES = ("pypi", "crates", "npm", "action", "github")
TAG_ONLY = ("action", "github")


class ConfigError(Exception):
    """The configuration or a manifest cannot be read; nothing was checked."""


@dataclass
class Entry:
    """One tracked package and the version every page must name for it."""

    registry: str
    name: str
    version: str
    source: str
    own: bool
    repo: str | None = None
    tag: str = "v{version}"
    pages: list[str] = field(default_factory=list)
    publisher: str | None = None
    manifest: str | None = None
    released: bool = True

    @property
    def key(self) -> str:
        return f"{self.registry}:{self.name}"

    def tag_for(self, version: str) -> str:
        return self.tag.format(version=version)

    def tag_regex(self) -> str:
        prefix, _, suffix = self.tag.partition("{version}")
        return re.escape(prefix) + f"({V})" + re.escape(suffix)


@dataclass
class Finding:
    path: str
    line: int
    message: str
    start: int = -1
    end: int = -1
    replacement: str | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.message}"


# ---------------------------------------------------------------- configuration


def _glob_regex(pattern: str) -> re.Pattern[str]:
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def matches(path: str, patterns: list[str] | tuple[str, ...]) -> bool:
    return any(_glob_regex(p).match(path) for p in patterns)


def read_manifest(root: Path, rel: str) -> str:
    """The version a manifest declares; the file kind decides where to look."""
    path = root / rel
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read manifest {rel}: {exc}") from exc
    name = path.name
    try:
        if name == "pyproject.toml":
            version = tomllib.loads(text)["project"]["version"]
        elif name == "Cargo.toml":
            data = tomllib.loads(text)
            version = data["package"]["version"]
            if isinstance(version, dict):
                version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))[
                    "workspace"
                ]["package"]["version"]
        elif name == "package.json":
            version = json.loads(text)["version"]
        elif name.endswith(".rb"):
            found = re.search(rf"[-_]({V})\.(?:tar\.gz|zip|whl)\"", text)
            if found is None:
                raise KeyError("url")
            version = found.group(1)
        else:
            version = text.strip()
    except (KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{rel} declares no readable version ({exc})") from exc
    if not VERSION.match(str(version)):
        raise ConfigError(f"{rel} declares {version!r}, which is not a release version")
    return str(version)


def _release_units(root: Path, rel: str, repo: str) -> list[Entry]:
    """Own entries read from a release.toml of [[unit]] tables, so it stays the one list."""
    try:
        data = tomllib.loads((root / rel).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {rel}: {exc}") from exc
    kinds = {
        "crates.io": ("crates", "Cargo.toml"),
        "pypi": ("pypi", "pyproject.toml"),
        "npm": ("npm", "package.json"),
        "github-actions": ("action", "VERSION"),
    }
    entries: dict[str, Entry] = {}
    for unit in data.get("unit", []):
        registry, manifest_name = kinds[unit["registry"]]
        manifest = f"{unit['directory']}/{manifest_name}"
        name = repo if registry == "action" else unit["name"]
        entry = Entry(
            registry=registry,
            name=name,
            version=read_manifest(root, manifest),
            source=manifest,
            own=True,
            repo=repo,
            tag=f"{unit['prefix']}-v{{version}}",
            manifest=manifest,
        )
        # Two units may publish one package under two prefixes; the first is canonical.
        entries.setdefault(entry.key, entry)
    return list(entries.values())


@dataclass
class Config:
    root: Path
    repository: str
    entries: list[Entry]
    include: list[str]
    historical: list[str]
    skip: list[str]
    registry_pages: dict[str, str]
    link_ref: str


def load_config(root: Path, rel: str = CONFIG) -> Config:
    try:
        data = tomllib.loads((root / rel).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {rel}: {exc}") from exc
    repository = data.get("repository")
    if not isinstance(repository, str) or "/" not in repository:
        raise ConfigError(f"{rel}: `repository` must be owner/name")
    repo_name = repository.split("/", 1)[1]
    entries: list[Entry] = []
    if "release_units" in data:
        entries.extend(_release_units(root, data["release_units"], repo_name))
    for item in data.get("own", []):
        registry, _, name = item["key"].partition(":")
        if registry not in REGISTRIES or not name:
            raise ConfigError(f"{rel}: own key {item['key']!r} is not <registry>:<name>")
        found = [e for e in entries if e.key == item["key"]]
        if found:
            entry = found[0]
            entry.pages = list(item.get("pages", entry.pages))
            entry.publisher = item.get("publisher", entry.publisher)
            entry.tag = item.get("tag", entry.tag)
            continue
        manifest = item["manifest"]
        entries.append(
            Entry(
                registry=registry,
                name=name,
                version=read_manifest(root, manifest),
                source=manifest,
                own=True,
                repo=item.get("repo", repo_name),
                tag=item.get("tag", "v{version}"),
                pages=list(item.get("pages", [])),
                publisher=item.get("publisher"),
                manifest=manifest,
                released=bool(item.get("released", True)),
            )
        )
    for key, spec in data.get("family", {}).items():
        registry, _, name = key.partition(":")
        if registry not in REGISTRIES or not name:
            raise ConfigError(f"{rel}: family key {key!r} is not <registry>:<name>")
        if isinstance(spec, str):
            spec = {"version": spec}
        version = spec.get("version", "")
        if not VERSION.match(version):
            raise ConfigError(f"{rel}: family {key} = {version!r} is not a release version")
        entries.append(
            Entry(
                registry=registry,
                name=name,
                version=version,
                source=f"{rel} [family]",
                own=False,
                repo=spec.get("repo", name if registry == "action" else None),
                tag=spec.get("tag", "v{version}"),
                publisher=spec.get("publisher"),
            )
        )
    keys = [e.key for e in entries]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    if duplicates:
        raise ConfigError(f"{rel}: {', '.join(duplicates)} has two owners")
    scan = data.get("scan", {})
    return Config(
        root=root,
        repository=repository,
        entries=entries,
        include=list(scan.get("include", DEFAULT_INCLUDE)),
        historical=list(DEFAULT_HISTORICAL) + list(scan.get("historical", [])),
        skip=list(scan.get("skip", [])),
        registry_pages=dict(data.get("registry_pages", {})),
        link_ref=str(data.get("link_ref", "main")),
    )


# ---------------------------------------------------------------- the scan


def tracked_files(root: Path) -> list[str]:
    done = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False
    )
    if done.returncode != 0:
        raise ConfigError(f"git ls-files failed in {root}: {done.stderr.decode().strip()}")
    return sorted(p for p in done.stdout.decode().split("\0") if p)


def _name(name: str) -> str:
    return r"(?<![\w./-])" + re.escape(name) + r"(?![\w-])"


NPM_WORDS = re.compile(r"\b(?:npm|npx|pnpm|yarn|bun)\b")


@dataclass
class Rule:
    entry: Entry
    pattern: re.Pattern[str]
    label: str
    # When a crate and an npm package share a name, the command on the line decides which.
    line_kind: str | None = None


def pin_rules(entries: list[Entry]) -> list[Rule]:
    """Every way a page names a tracked package's version, one capture group each."""
    rules: list[Rule] = []
    names = {}
    for e in entries:
        names.setdefault(e.name, []).append(e)
    for e in entries:
        n = _name(e.name)
        q = re.escape(e.name)
        if e.registry == "pypi":
            rules += [
                Rule(e, re.compile(rf"{n}(?:\[[^\]\s]*\])?==({V})(?!\w|\.\d)"), "pin"),
                Rule(e, re.compile(rf"{n}@({V})(?!\w|\.\d)"), "pin"),  # uvx, uv tool, MCP args
                Rule(e, re.compile(rf"pypi\.org/project/{q}/({V})(?!\w|\.\d)"), "PyPI link"),
            ]
        if e.registry in ("crates", "npm"):
            siblings = {x.registry for x in names[e.name]} & {"crates", "npm"}
            kind = None if len(siblings) == 1 else e.registry
            rules.append(Rule(e, re.compile(rf"{n}@=?({V})(?!\w|\.\d)"), "pin", kind))
        if e.registry == "crates":
            rules += [
                Rule(e, re.compile(rf"(?m)^\s*{q}\s*=\s*\"[=^~]?({V})\""), "Cargo pin"),
                Rule(
                    e,
                    re.compile(rf"(?m)^\s*{q}\s*=\s*\{{[^}}\n]*\bversion\s*=\s*\"[=^~]?({V})\""),
                    "Cargo pin",
                ),
                Rule(e, re.compile(rf"docs\.rs/{q}/({V})(?!\w|\.\d)"), "docs.rs link"),
                Rule(e, re.compile(rf"crates\.io/crates/{q}/({V})(?!\w|\.\d)"), "crates.io link"),
            ]
        if e.registry == "npm":
            rules.append(
                Rule(e, re.compile(rf"npmjs\.com/package/{q}/v/({V})(?!\w|\.\d)"), "npm link")
            )
        if e.repo:
            r = re.escape(e.repo)
            t = e.tag_regex()
            end = r"(?=[/)#\s\"'`>]|$)"
            rules += [
                Rule(
                    e,
                    re.compile(
                        rf"github\.com/{ORG}/{r}(?:\.git)?/(?:blob|tree|raw|releases/tag|"
                        rf"archive/refs/tags|archive|commits?|compare/[^\s)]*\.\.\.)/{t}{end}"
                    ),
                    "tag link",
                ),
                Rule(e, re.compile(rf"raw\.githubusercontent\.com/{ORG}/{r}/{t}{end}"), "tag link"),
                Rule(e, re.compile(rf"github\.com/{ORG}/{r}(?:/[^@\s`)]*)?@{t}{end}"), "pin"),
                Rule(e, re.compile(rf"--branch\s+{t}\s+https://github\.com/{ORG}/{r}\b"), "pin"),
            ]
        if e.registry == "action":
            r = re.escape(e.name)
            rules.append(
                Rule(
                    e,
                    re.compile(rf"uses:\s*{ORG}/{r}(?:/[^@\s]*)?@{e.tag_regex()}(?=\s|$)"),
                    "Action pin",
                )
            )
        # Prose: `name` 0.1.2, `name` (0.1.2), name (v0.1.2) and "0.1.2 on PyPI (`name`)".
        rules += [
            Rule(e, re.compile(rf"`{q}`\s*\(?\s*v?({V})(?!\w|\.\d)"), "stated version"),
            Rule(e, re.compile(rf"{n}\s*\(\s*v?({V})\s*\)"), "stated version"),
            Rule(e, re.compile(rf"({V}) on (?:PyPI|crates\.io|npm) \(`{q}`\)"), "stated version"),
        ]
        for page in e.pages:
            rules.append(
                Rule(
                    e,
                    re.compile(rf"(?<![\w.])(?:[Vv]ersion|crate version) v?({V})(?!\w|\.\d)"),
                    f"stated version@{page}",
                )
            )
    return rules


ON_REGISTRY = re.compile(rf"(?<![\w.])({V}) on (?:PyPI|crates\.io|npm)\b(?! \(`)")
MD_LINK = re.compile(r"\[((?:[^\[\]]|\[[^\]]*\])*)\]\((https?://[^)\s]+)\)")
VERSION_IN = re.compile(rf"(?<![\w.])v?({V})(?!\w|\.\d)")
LINK_HOSTS = ("github.com/", "pypi.org/", "crates.io/", "docs.rs/", "npmjs.com/")
LINK_TARGET = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
SRC_OR_HREF = re.compile(r"""\b(?:src|href)=["']([^"']+)["']""")
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|#|//|mailto:)", re.IGNORECASE)
FENCE = re.compile(r"^\s*(```|~~~)")


def _exempt_lines(text: str) -> set[int]:
    exempt: set[int] = set()
    off = False
    for number, line in enumerate(text.splitlines(), start=1):
        if OFF in line:
            off = True
        if off or KEEP in line:
            exempt.add(number)
        if ON in line:
            off = False
    return exempt


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _registry_line_owner(line: str, entries: list[Entry]) -> Entry | None:
    """The tracked package a `X on PyPI` statement on this line is about, if one is named."""
    best: tuple[int, Entry] | None = None
    for e in entries:
        for m in re.finditer(_name(e.name), line):
            if best is None or len(e.name) > len(best[1].name):
                best = (m.start(), e)
    return best[1] if best else None


def scan_text(cfg: Config, rel: str, text: str, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    exempt = _exempt_lines(text)
    seen: set[tuple[int, int]] = set()
    for rule in rules:
        if rule.label.startswith("stated version@"):
            if rule.label.split("@", 1)[1] != rel:
                continue
        for m in rule.pattern.finditer(text):
            span = m.span(1)
            line = _line_of(text, span[0])
            if line in exempt or span in seen:
                continue
            if rule.line_kind is not None:
                start = text.rfind("\n", 0, span[0]) + 1
                stop = text.find("\n", span[0])
                is_npm = bool(NPM_WORDS.search(text[start : stop if stop >= 0 else None]))
                if is_npm != (rule.line_kind == "npm"):
                    continue
            seen.add(span)
            pinned = m.group(1)
            if pinned != rule.entry.version:
                findings.append(
                    Finding(
                        rel,
                        line,
                        f"{rule.entry.key} {rule.label.split('@')[0]} names {pinned}; "
                        f"{rule.entry.source} says {rule.entry.version}",
                        span[0],
                        span[1],
                        rule.entry.version,
                    )
                )
    # "0.2.2 on PyPI" in a row or sentence that names the package elsewhere on the line.
    offset = 0
    for number, line in enumerate(text.splitlines(keepends=True), start=1):
        if number not in exempt:
            for m in ON_REGISTRY.finditer(line):
                span = (offset + m.start(1), offset + m.end(1))
                owner = _registry_line_owner(line, cfg.entries)
                if owner is None or span in seen:
                    continue
                seen.add(span)
                if m.group(1) != owner.version:
                    findings.append(
                        Finding(
                            rel,
                            number,
                            f"{owner.key} stated version names {m.group(1)}; "
                            f"{owner.source} says {owner.version}",
                            span[0],
                            span[1],
                            owner.version,
                        )
                    )
        offset += len(line)
    findings.extend(_link_text_findings(rel, text, exempt))
    findings.extend(_own_link_findings(cfg, rel, text, exempt))
    if rel in cfg.registry_pages:
        findings.extend(_relative_link_findings(cfg, rel, text, exempt))
    return findings


def _link_text_findings(rel: str, text: str, exempt: set[int]) -> list[Finding]:
    found: list[Finding] = []
    for m in MD_LINK.finditer(text):
        label, url = m.group(1), m.group(2)
        if not any(h in url for h in LINK_HOSTS) or label.startswith("!["):
            continue
        said = VERSION_IN.findall(label)
        target = VERSION_IN.findall(urllib.parse.urlsplit(url).path)
        line = _line_of(text, m.start())
        if line in exempt or not said or not target:
            continue
        if len(set(said)) == 1 and said[0] not in target:
            found.append(
                Finding(rel, line, f"link text says {said[0]} and its target names {target[0]}: {url}")
            )
    return found


def _own_link_findings(cfg: Config, rel: str, text: str, exempt: set[int]) -> list[Finding]:
    owner, name = cfg.repository.split("/", 1)
    pattern = re.compile(
        rf"https?://(?:github\.com/{re.escape(owner)}/{re.escape(name)}/(?:blob|tree|raw)|"
        rf"raw\.githubusercontent\.com/{re.escape(owner)}/{re.escape(name)})/"
        r"([^/\s)\"'>]+)/([^\s)\"'>#?]+)"
    )
    found: list[Finding] = []
    for m in pattern.finditer(text):
        ref, path = m.group(1), urllib.parse.unquote(m.group(2)).rstrip(".,;:")
        line = _line_of(text, m.start())
        if line in exempt or SHA.match(ref):
            continue
        if not (cfg.root / path).exists():
            found.append(
                Finding(rel, line, f"link into this repository names {path}, which the tree does not hold")
            )
    return found


def _split_code(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    inside = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE.match(line):
            inside = not inside
            continue
        if not inside:
            out.append((number, line))
    return out


def _relative_link_findings(cfg: Config, rel: str, text: str, exempt: set[int]) -> list[Finding]:
    """A page a registry renders cannot use a relative link: the registry has no tree."""
    found: list[Finding] = []
    base = Path(rel).parent
    offsets: dict[int, int] = {}
    pos = 0
    for number, line in enumerate(text.splitlines(keepends=True), start=1):
        offsets[number] = pos
        pos += len(line)
    for number, line in _split_code(text):
        if number in exempt:
            continue
        for rx in (LINK_TARGET, SRC_OR_HREF, REF_DEF):
            for m in rx.finditer(line):
                target = m.group(1)
                if EXTERNAL.match(target):
                    continue
                path = (base / target.split("#", 1)[0].split("?", 1)[0]).as_posix()
                path = re.sub(r"(^|/)\./", r"\1", path)
                openers = {o.end() for o in re.finditer(r"!\[[^\]]*\]\(", line)}
                image = m.start(1) in openers or (rx is SRC_OR_HREF and "src=" in m.group(0))
                anchor = "#" + target.split("#", 1)[1] if "#" in target else ""
                absolute = absolute_url(cfg, path, image) + anchor
                start = offsets[number] + m.start(1)
                found.append(
                    Finding(
                        rel,
                        number,
                        f"relative link '{target}' 404s where {cfg.registry_pages[rel]} renders "
                        f"this page; use {absolute}",
                        start,
                        start + len(target),
                        absolute,
                    )
                )
    return found


def absolute_url(cfg: Config, path: str, image: bool) -> str:
    if image:
        return f"https://raw.githubusercontent.com/{cfg.repository}/{cfg.link_ref}/{path}"
    kind = "tree" if (cfg.root / path).is_dir() else "blob"
    return f"https://github.com/{cfg.repository}/{kind}/{cfg.link_ref}/{path}"


def scan(cfg: Config) -> tuple[list[Finding], int]:
    rules = pin_rules(cfg.entries)
    findings: list[Finding] = []
    files = 0
    for rel in tracked_files(cfg.root):
        if not matches(rel, cfg.include) or matches(rel, cfg.historical) or matches(rel, cfg.skip):
            continue
        try:
            text = (cfg.root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        files += 1
        findings.extend(scan_text(cfg, rel, text, rules))
    findings.sort(key=lambda f: (f.path, f.line, f.start))
    return findings, files


def write(cfg: Config) -> tuple[int, list[Finding]]:
    """Rewrite every finding that has a replacement; return the count and what remains."""
    findings, _ = scan(cfg)
    changed = 0
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        if f.replacement is not None:
            by_file.setdefault(f.path, []).append(f)
    for rel, items in by_file.items():
        path = cfg.root / rel
        text = path.read_text(encoding="utf-8")
        for f in sorted(items, key=lambda x: x.start, reverse=True):
            text = text[: f.start] + f.replacement + text[f.end :]
            changed += 1
        path.write_text(text, encoding="utf-8")
    remaining, _ = scan(cfg)
    return changed, remaining


# ---------------------------------------------------------------- the network


class Unread(Exception):
    """A registry or host did not give a usable answer; nothing was established."""


def fetch_json(url: str, *, missing_ok: bool = False, headers: dict[str, str] | None = None):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and missing_ok:
            return None
        raise Unread(f"{url} answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise Unread(f"{url} gave no usable answer: {exc}") from exc


def registry_latest(e: Entry) -> str | None:
    """The newest published version, or None when the registry holds none."""
    if e.registry == "pypi":
        data = fetch_json(f"https://pypi.org/pypi/{e.name}/json", missing_ok=True)
        return None if data is None else data["info"]["version"]
    if e.registry == "crates":
        data = fetch_json(f"https://crates.io/api/v1/crates/{e.name}", missing_ok=True)
        if data is None:
            return None
        crate = data["crate"]
        return crate.get("max_stable_version") or crate["max_version"]
    if e.registry == "npm":
        data = fetch_json(f"https://registry.npmjs.org/{e.name}", missing_ok=True)
        return None if data is None else data.get("dist-tags", {}).get("latest")
    return None


_TAGS: dict[str, list[str]] = {}


def remote_tags(repo: str) -> list[str]:
    if repo not in _TAGS:
        done = subprocess.run(
            ["git", "ls-remote", "--tags", "--refs", f"https://github.com/{ORG}/{repo}.git"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        if done.returncode != 0:
            raise Unread(f"git ls-remote {repo} failed: {done.stderr.strip()}")
        _TAGS[repo] = [line.split("refs/tags/", 1)[1] for line in done.stdout.splitlines()]
    return _TAGS[repo]


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version)[:3])


def newest_tag(e: Entry) -> str | None:
    if not e.repo:
        return None
    rx = re.compile(e.tag_regex() + r"\Z")
    found = [m.group(1) for t in remote_tags(e.repo) if (m := rx.match(t))]
    return max(found, key=_vkey) if found else None


def publisher_of(e: Entry, version: str) -> str | None:
    """The repository a registry records as the publisher of `version`."""
    if e.registry == "pypi":
        data = fetch_json(f"https://pypi.org/pypi/{e.name}/{version}/json")
        repos = set()
        for item in data["urls"]:
            prov = fetch_json(
                f"https://pypi.org/integrity/{e.name}/{version}/{item['filename']}/provenance",
                missing_ok=True,
                headers={"Accept": "application/vnd.pypi.integrity.v1+json"},
            )
            if prov is None:
                return None
            repos |= {b["publisher"].get("repository") for b in prov["attestation_bundles"]}
        return ",".join(sorted(r for r in repos if r)) or None
    if e.registry == "crates":
        data = fetch_json(f"https://crates.io/api/v1/crates/{e.name}/{version}")
        trust = data["version"].get("trustpub_data") or {}
        return trust.get("repository")
    raise Unread(f"no publisher record is read for {e.registry}")


def verify_entry(cfg: Config, e: Entry) -> tuple[str, str]:
    """('OK'|'SHORT', explanation) for one entry; raises Unread when it cannot say."""
    repo = cfg.repository.split("/", 1)[1]
    if not e.released:
        return "OK", f"declared {e.version} ({e.source}); not released by design (released = false)"
    tag = newest_tag(e) if e.repo else None
    latest = registry_latest(e) if e.registry not in TAG_ONLY else tag
    facts = f"declared {e.version} ({e.source}), newest tag {e.tag_for(tag) if tag else 'none'}"
    if e.registry not in TAG_ONLY:
        facts += f", {e.registry} {latest or 'none'}"
    problems: list[str] = []
    if e.own:
        release = (
            f"release it (gh release create {e.tag_for(e.version)} --target main "
            f"-R {ORG}/{e.repo or repo}) or set {e.source} back to the published version"
        )
        if tag is None or _vkey(e.version) > _vkey(tag):
            problems.append(f"{e.source} was bumped and no tag carries it; {release}")
        elif _vkey(e.version) < _vkey(tag):
            problems.append(f"{e.source} is behind its own newest tag")
        if e.registry not in TAG_ONLY:
            if latest is None:
                problems.append(f"{e.name} is not published on {e.registry}")
            elif tag and _vkey(latest) < _vkey(tag):
                problems.append(f"tag {e.tag_for(tag)} exists and {e.registry} lacks it: the publish did not happen")
            elif _vkey(latest) > _vkey(e.version):
                problems.append(f"{e.registry} holds {latest}, newer than the source")
        if e.publisher and latest:
            who = publisher_of(e, latest)
            if who is None:
                raise Unread(f"{e.key} {latest} carries no publisher record")
            if who != e.publisher:
                problems.append(f"{e.key} {latest} was published from {who}, not {e.publisher}")
    else:
        if latest is None:
            problems.append(f"{e.key} is pinned here and not published")
        elif latest != e.version:
            problems.append(
                f"the family lock names {e.version} and the newest release is {latest}; "
                "run python3 scripts/version-pins.py refresh"
            )
    return ("SHORT" if problems else "OK", facts + ("; " + "; ".join(problems) if problems else ""))


def registry_report(cfg: Config) -> int:
    ok = short = unread = 0
    for e in cfg.entries:
        try:
            verdict, note = verify_entry(cfg, e)
        except Unread as exc:
            verdict, note = "UNREAD", str(exc)
        print(f"{verdict:6} {e.key:40} {note}")
        ok += verdict == "OK"
        short += verdict == "SHORT"
        unread += verdict == "UNREAD"
    total = len(cfg.entries)
    print(f"registry: {ok} of {total} agree; {short} short; {unread} could not be read")
    return 1 if short else 2 if unread else 0


def refresh(cfg: Config, rel: str = CONFIG) -> int:
    """Move every family lock line to the registry's newest release."""
    path = cfg.root / rel
    text = path.read_text(encoding="utf-8")
    moved = 0
    for e in cfg.entries:
        if e.own:
            continue
        latest = newest_tag(e) if e.registry in TAG_ONLY else registry_latest(e)
        if latest is None or latest == e.version:
            continue
        pattern = re.compile(rf'(?m)^("{re.escape(e.key)}"\s*=\s*(?:\{{[^}}\n]*version\s*=\s*)?"){re.escape(e.version)}"')
        text, n = pattern.subn(lambda m: f'{m.group(1)}{latest}"', text)
        if n != 1:
            raise ConfigError(f"could not move {e.key} in {rel}")
        print(f"family {e.key}: {e.version} -> {latest}")
        moved += 1
    path.write_text(text, encoding="utf-8")
    return moved


IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)|<img[^>]+src=[\"'](https?://[^\"']+)[\"']")


def badge_report(cfg: Config) -> int:
    urls: dict[str, str] = {}
    for rel in tracked_files(cfg.root):
        if not rel.endswith(".md") or matches(rel, cfg.skip):
            continue
        try:
            text = (cfg.root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in IMAGE.finditer(text):
            urls.setdefault(m.group(1) or m.group(2), rel)
    broken = 0
    for url, rel in sorted(urls.items()):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                kind = response.headers.get("Content-Type", "")
                good = response.status == 200 and (kind.startswith("image/") or "svg" in kind)
                note = f"HTTP {response.status} {kind}"
        except (urllib.error.URLError, TimeoutError) as exc:
            good, note = False, str(exc)
        if not good:
            broken += 1
            print(f"BROKEN {url} ({rel}): {note}")
    print(f"badges: {len(urls) - broken} of {len(urls)} images load")
    return 1 if broken else 0


# ---------------------------------------------------------------- entry point


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("mode", nargs="?", default="check",
                        choices=("check", "write", "registry", "refresh", "badges"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--config", default=CONFIG)
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.root, args.config)
        if args.mode == "registry":
            return registry_report(cfg)
        if args.mode == "badges":
            return badge_report(cfg)
        if args.mode == "refresh":
            refresh(cfg, args.config)
            cfg = load_config(args.root, args.config)
            args.mode = "write"
        if args.mode == "write":
            changed, remaining = write(cfg)
            print(f"version-pins: rewrote {changed} pins")
            for f in remaining:
                print(f)
            return 1 if remaining else 0
        findings, files = scan(cfg)
    except (ConfigError, Unread) as exc:
        print(f"version-pins: could not run: {exc}", file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    owners = len(cfg.entries)
    if findings:
        print(f"version-pins: {len(findings)} disagreements in {files} pages "
              f"({owners} tracked packages); `version-pins.py write` fixes the pins")
        return 1
    print(f"version-pins: {files} pages agree with {owners} tracked packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
