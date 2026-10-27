"""Fail-closed approval of a pinned CPython 3.12 startup installation."""

from __future__ import annotations

import hashlib
import os
import posixpath
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

INSTALL = "interpreter_installation_untrusted"
IDENTITY = "interpreter_identity_unestablished"
OPTIONS = "python_startup_unisolated"


@dataclass(frozen=True)
class Source:
    """A pinned startup entry: file digest, symlink target, or directory."""

    kind: str
    sha256: str = ""
    target: str = ""


@dataclass(frozen=True)
class Mount:
    """A measured mount and whether its source is worker-writable."""

    target: str
    source: str
    filesystem: str
    read_only: bool
    worker_writable_source: bool = False


@dataclass(frozen=True)
class Startup:
    """The approved effective image and its startup-source closure."""

    kind: str
    executable: str
    sha256: str
    roots: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    site_dirs: tuple[str, ...] = ()
    venv_prefixes: tuple[str, ...] = ()
    override_candidates: tuple[str, ...] = ()
    override: str | None = None
    embedded_python: bool = False
    chain_script: str | None = None


@dataclass(frozen=True)
class Installation:
    """Externally approved content inventory and mount topology."""

    installation_id: str
    python_version: str
    images: Mapping[str, Startup]
    sources: Mapping[str, Source]
    mounts: tuple[Mount, ...]


@dataclass(frozen=True)
class Runtime:
    """The observed namespace snapshot and measured worker write identity."""

    root: Path
    mounts: tuple[Mount, ...]
    uid: int
    groups: tuple[int, ...]
    writable_roots: tuple[str, ...]


@dataclass(frozen=True)
class Observation:
    """A stopped image's effective identity, argv, and validated environment."""

    path: str
    sha256: str
    argv: tuple[bytes, ...]
    env: Mapping[str, str]
    submitted_path: str | None = None


@dataclass(frozen=True)
class Approval:
    """Installation classification and producer-side refusal, if any."""

    classification: str
    reason: str | None


class _Refuse(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def _absolute(path: str) -> bool:
    return path.startswith("/") and posixpath.normpath(path) == path


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _host(runtime: Runtime, path: str) -> Path:
    return runtime.root / path.lstrip("/")


def _resolve(runtime: Runtime, path: str) -> str:
    if not _absolute(path):
        raise _Refuse(INSTALL)
    pending = path.split("/")[1:]
    parts: list[str] = []
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        name = "/" + "/".join((*parts, part))
        try:
            mode = _host(runtime, name).lstat().st_mode
        except FileNotFoundError:
            parts.append(part)
            continue
        if stat.S_ISLNK(mode):
            hops += 1
            if hops > 40:
                raise _Refuse(INSTALL)
            target = os.readlink(_host(runtime, name))
            parts = [] if target.startswith("/") else parts
            pending = target.split("/") + pending
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def _node(runtime: Runtime, path: str) -> Path:
    parent = _resolve(runtime, posixpath.dirname(path))
    return _host(runtime, parent) / posixpath.basename(path)


def _safe(runtime: Runtime, path: str) -> None:
    if not _absolute(path) or any(_under(path, root) for root in runtime.writable_roots):
        raise _Refuse(INSTALL)
    for mount in runtime.mounts:
        if _under(path, mount.target) and mount.worker_writable_source:
            raise _Refuse(INSTALL)
    for end in range(1, len(Path(path).parts) + 1):
        node = _node(runtime, str(Path(*Path(path).parts[:end])))
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        mode = info.st_mode
        writable = ((mode & stat.S_IWOTH) or
                    (info.st_uid == runtime.uid and mode & stat.S_IWUSR) or
                    (info.st_gid in runtime.groups and mode & stat.S_IWGRP))
        if writable:
            raise _Refuse(INSTALL)


def _check(runtime: Runtime, pins: Mapping[str, Source], path: str) -> str:
    _safe(runtime, path)
    name = _resolve(runtime, path)
    _safe(runtime, name)
    for item in (path, name):
        pin = pins.get(item)
        if pin is None:
            raise _Refuse(INSTALL)
        try:
            info = _node(runtime, item).lstat()
        except FileNotFoundError:
            raise _Refuse(INSTALL) from None
        kind = ("link" if stat.S_ISLNK(info.st_mode) else
                "dir" if stat.S_ISDIR(info.st_mode) else
                "file" if stat.S_ISREG(info.st_mode) else "special")
        if kind != pin.kind:
            raise _Refuse(INSTALL)
        node = _node(runtime, item)
        if kind == "link" and os.readlink(node) != pin.target:
            raise _Refuse(INSTALL)
        if kind == "file" and hashlib.sha256(node.read_bytes()).hexdigest() != pin.sha256:
            raise _Refuse(INSTALL)
    return name


def _inventory(runtime: Runtime, pins: Mapping[str, Source], root: str) -> None:
    actual = _check(runtime, pins, root)
    found: set[str] = set()
    for directory, dirs, files in os.walk(_host(runtime, actual), followlinks=False):
        relative = Path(directory).relative_to(_host(runtime, actual))
        prefix = actual if relative == Path(".") else posixpath.join(actual, relative.as_posix())
        found.add(prefix)
        for entry in dirs + files:
            path = posixpath.join(prefix, entry)
            found.add(path)
            _check(runtime, pins, path)
    if found != {path for path in pins if _under(path, actual)}:
        raise _Refuse(INSTALL)


def _isolated(flags: set[str], env: Mapping[str, str]) -> bool:
    if "I" in flags:
        return True
    return "P" in flags and ("s" in flags or "S" in flags or
                             ("E" not in flags and env.get("PYTHONNOUSERSITE") == "1"))


def _options(argv: tuple[bytes, ...], env: Mapping[str, str],
             version: str) -> tuple[bool, bool]:
    if version != "3.12" or not argv:
        raise _Refuse(OPTIONS)
    flags: set[str] = set()
    index = 1
    while index < len(argv):
        try:
            arg = argv[index].decode("utf-8")
        except UnicodeDecodeError:
            raise _Refuse(OPTIONS) from None
        if arg in ("--", "-") or not arg.startswith("-"):
            break
        if arg in ("--help", "--version", "-?"):
            break
        if arg.startswith("--"):
            raise _Refuse(OPTIONS)
        offset = 1
        while offset < len(arg):
            flag = arg[offset]
            if flag in "bBdEhiIOPqRsSuvVx":
                flags.add(flag)
                offset += 1
                continue
            if flag not in "cmWX":
                raise _Refuse(OPTIONS)
            value = arg[offset + 1:]
            if not value:
                index += 1
                if index >= len(argv):
                    raise _Refuse(OPTIONS)
                value = argv[index].decode("utf-8", "surrogateescape")
            if flag == "X" and value not in ("dev", "utf8", "no_debug_ranges"):
                raise _Refuse(OPTIONS)
            if flag in "cm":
                return _isolated(flags, env), "S" not in flags
            break
        index += 1
    return _isolated(flags, env), "S" not in flags


def _site(runtime: Runtime, pins: Mapping[str, Source], directory: str) -> None:
    _safe(runtime, directory)
    name = _resolve(runtime, directory)
    _safe(runtime, name)
    if not _host(runtime, name).exists():
        return
    _check(runtime, pins, directory)
    for path in sorted(pins):
        if posixpath.dirname(path) != name or not path.endswith(".pth"):
            continue
        file = _check(runtime, pins, path)
        try:
            lines = _host(runtime, file).read_text("utf-8").splitlines()
        except UnicodeError:
            raise _Refuse(INSTALL) from None
        for line in lines:
            if not line.strip() or line.startswith("#"):
                continue
            if line.startswith(("import ", "import\t")):
                raise _Refuse(INSTALL)
            entry = posixpath.normpath(posixpath.join(name, line.rstrip()))
            _safe(runtime, entry)
            resolved = _resolve(runtime, entry)
            _safe(runtime, resolved)
            if _host(runtime, resolved).exists():
                _check(runtime, pins, entry)


def _override(runtime: Runtime, pins: Mapping[str, Source],
              startup: Startup) -> bool | None:
    present = []
    for path in startup.override_candidates:
        _safe(runtime, path)
        if _host(runtime, _resolve(runtime, path)).exists():
            present.append(path)
    if present != ([startup.override] if startup.override else []):
        raise _Refuse(INSTALL)
    if not present:
        return None
    path = _check(runtime, pins, present[0])
    try:
        lines = _host(runtime, path).read_text("utf-8").splitlines()
    except UnicodeError:
        raise _Refuse(INSTALL) from None
    site = False
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "import site":
            site = True
            continue
        if line.startswith("import"):
            raise _Refuse(INSTALL)
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), line))
        _safe(runtime, target)
        resolved = _resolve(runtime, target)
        _safe(runtime, resolved)
        if _host(runtime, resolved).exists():
            _check(runtime, pins, target)
    return site


def _shebang(observation: Observation, startup: Startup, runtime: Runtime,
             pins: Mapping[str, Source]) -> None:
    script = observation.submitted_path
    if script is None or script == observation.path:
        return
    if not _absolute(script):
        raise _Refuse(IDENTITY)
    resolved = _check(runtime, pins, script)
    first = _host(runtime, resolved).read_bytes().split(b"\n", 1)[0]
    if not first.startswith(b"#!"):
        raise _Refuse(IDENTITY)
    words = first[2:].strip().split(None, 1)
    try:
        interpreter = words[0].decode("utf-8")
        argument = words[1].decode("utf-8") if len(words) > 1 else None
    except (IndexError, UnicodeError):
        raise _Refuse(IDENTITY) from None
    expected = ((interpreter.encode(),) + ((argument.encode(),) if argument else ())
                + (script.encode(),))
    if interpreter != startup.executable or observation.argv[:len(expected)] != expected:
        raise _Refuse(IDENTITY)


def approve(installation: Installation, observation: Observation,
            runtime: Runtime) -> Approval:
    """Check effective identity, pinned sources, write access, and Python options.

    Args:
        installation: Consumer-approved content and mount inventory.
        observation: Stopped image's effective identity and initial vectors.
        runtime: Independently measured namespace and worker access.

    Returns:
        Classification and exact producer-side refusal, if any.
    """
    startup = installation.images.get(observation.sha256)
    kind = startup.kind if startup else "unsupported"
    if (startup is None or startup.sha256 != observation.sha256
