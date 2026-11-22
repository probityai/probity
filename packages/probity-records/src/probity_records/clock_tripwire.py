"""Fail any run that reads the real clock: the check that "every site takes a Clock" is true while code runs.

The lint (``clock_lint``) reads source; this module watches execution. While installed:

* every call to a clock-reading builtin (``time.time``, ``time.monotonic``, ``time.sleep``, ``datetime.now``,
  ``date.today``, ``uuid.uuid1`` and the rest of ``clock_lint.FORBIDDEN``) is seen through ``sys.monitoring`` CALL
  events, so a name bound before installation (``from time import monotonic``) and the C methods of ``datetime``
  are caught as well as an attribute lookup;
* the module attributes themselves (``time.time`` and kin, ``asyncio.sleep``) are replaced by wrappers that raise
  ``WallClockUse`` at the call site, so most reads fail where they happen.

``SystemClock`` is not exempt: under the tripwire a component runs on a ``FixedClock`` or a simulated clock, and a
real read anywhere is a finding. Each read is attributed twice: the *reader* is the module whose code called the
clock function, and the *origin* is the first frame outside the standard library and the clock modules, which is
the code that chose to wait or read. An exemption names a reader, an origin, or both (``Exemption``); the
consuming project keeps them in a file (``CLOCK-EXEMPT.toml``) with a reason each. The test harness itself
(pytest, pluggy, hypothesis, coverage) is never under test and is ignored.

Reads made by native code (OpenSSL checking a certificate, a Rust core) do not pass through Python and are not
seen here; the simulated tier adds a native check for those.

As a pytest plugin (``pytest -p probity_records.clock_tripwire``), it installs when the plugin loads, before test
modules are imported, fails each test that read the clock with the reads listed, and fails the session for reads
made outside any test. ``PROBITY_CLOCK_EXEMPT`` names the exemption file.
"""

from __future__ import annotations

import asyncio
import datetime as _datetime_module
import fnmatch
import functools
import inspect
import os
import sys
import sysconfig
import threading
import time
import tomllib
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import CodeType, FrameType
from typing import Any

from .clock_lint import FORBIDDEN, FORBIDDEN_METHODS

__all__ = ["Exemption", "Read", "Tripwire", "WallClockUse", "installed", "load_exemptions"]

#: Modules that drive tests and are never the code under test.
HARNESS = ("_pytest", "_pytest.*", "pytest", "pluggy", "pluggy.*", "hypothesis", "hypothesis.*", "coverage",
           "coverage.*", "_hypothesis_*", "xdist", "xdist.*", "execnet", "execnet.*")
_OWN = (__name__,)
_CLOCK = ("probity_records.clock",)
_TOOL_ID = 4
_STDLIB = tuple(str(Path(p).resolve()) for p in {sysconfig.get_paths()["stdlib"], sysconfig.get_paths()["platstdlib"]})


class WallClockUse(RuntimeError):
    """Raised where code read the real clock while the tripwire was installed."""

    def __init__(self, read: Read, detail: str = "") -> None:
        super().__init__(detail or str(read))
        self.read = read


@dataclass(frozen=True)
class Read:
    """One real clock read: what was called, by which module, from where."""

    function: str
    reader: str
    origin: str
    where: str

    def __str__(self) -> str:
        return f"{self.function} read by {self.reader} (origin {self.origin}) at {self.where}"


@dataclass(frozen=True)
class Exemption:
    """A read the project accepts, with the reason and the tier it forces the component into."""

    reason: str
    reader: str | None = None
    origin: str | None = None
    functions: tuple[str, ...] = ()
    tier: str = ""
    row: str = ""

    def __post_init__(self) -> None:
        if not self.reader and not self.origin:
            raise ValueError("an exemption names a reader, an origin, or both")
        if not self.reason.strip():
            raise ValueError("an exemption carries its reason")

    def matches(self, read: Read) -> bool:
        if self.reader and not fnmatch.fnmatchcase(read.reader, self.reader):
            return False
        if self.origin and not fnmatch.fnmatchcase(read.origin, self.origin):
            return False
        return not self.functions or read.function in self.functions


def load_exemptions(path: str | os.PathLike[str]) -> tuple[Exemption, ...]:
    """The ``[[exempt]]`` tables of a TOML file; any other top-level key, or a field it does not know, is refused."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    unknown = set(data) - {"exempt"}
    if unknown:
        raise ValueError(f"{path}: unknown keys {sorted(unknown)}")
    out = []
    for i, entry in enumerate(data.get("exempt", [])):
        extra = set(entry) - {"reason", "reader", "origin", "functions", "tier", "row"}
        if extra:
            raise ValueError(f"{path}: exempt[{i}] has unknown fields {sorted(extra)}")
        if not entry.get("row"):
            raise ValueError(f"{path}: exempt[{i}] names no board row")
        out.append(Exemption(reason=entry.get("reason", ""), reader=entry.get("reader"), origin=entry.get("origin"),
                             functions=tuple(entry.get("functions", ())), tier=entry.get("tier", ""),
                             row=entry["row"]))
    return tuple(out)


def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


@functools.lru_cache(maxsize=4096)
def _is_stdlib(filename: str) -> bool:
    if filename.startswith("<"):
        return True
    try:
        resolved = str(Path(filename).resolve())
    except OSError:
        return False
    return resolved.startswith(_STDLIB) and "site-packages" not in resolved


def _forbidden_name(target: Any) -> str | None:
    """The clock function a callable is, or None. Works for builtins however they were bound."""
    name = getattr(target, "__name__", None)
    if name is None or getattr(target, _MARK, False):
        return None
    owner = getattr(target, "__self__", None)
    if isinstance(owner, type):
        for (module, cls), methods in FORBIDDEN_METHODS.items():
            real = getattr(_REAL_MODULES[module], cls)
            if name in methods and issubclass(owner, real):
                return f"{module}.{cls}.{name}"
        return None
    module = getattr(target, "__module__", None)
    if module in FORBIDDEN and name in FORBIDDEN[module]:
        return f"{module}.{name}"
    return None


_MARK = "__probity_clock_tripwire__"
_REAL_MODULES = {"datetime": _datetime_module, "time": time, "asyncio": asyncio, "threading": threading,
                 "uuid": uuid}


@dataclass
class Tripwire:
    """Watches the process for real clock reads. ``install`` it before the code under test is imported."""

    exemptions: tuple[Exemption, ...] = ()
    reads: list[Read] = field(default_factory=list)
    _saved: dict[tuple[Any, str], Any] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _active: bool = False
    _local: threading.local = field(default_factory=threading.local)

    # attribution -------------------------------------------------------------------------------------------------

    def _attribute(self, function: str, frame: FrameType | None) -> Read | None:
        """Who read the clock. None when the reader is the tripwire, the harness, or an exempt read."""
        reader_frame = frame
        while reader_frame is not None and reader_frame.f_globals.get("__name__") in _OWN:
            reader_frame = reader_frame.f_back
        if reader_frame is None:
            return None
        reader = str(reader_frame.f_globals.get("__name__", "?"))
        origin_frame: FrameType | None = reader_frame
        while origin_frame is not None and (_is_stdlib(origin_frame.f_code.co_filename)
                                            or origin_frame.f_globals.get("__name__") in _OWN + _CLOCK):
            origin_frame = origin_frame.f_back
        origin = str(origin_frame.f_globals.get("__name__", "?")) if origin_frame is not None else reader
        if _matches(reader, HARNESS) or (_matches(origin, HARNESS) and origin == reader):
            return None
        where_frame = origin_frame if origin_frame is not None else reader_frame
        read = Read(function, reader, origin, f"{where_frame.f_code.co_filename}:{where_frame.f_lineno}")
        if any(e.matches(read) for e in self.exemptions):
            return None
        return read

    def _record(self, read: Read) -> None:
        with self._lock:
            self.reads.append(read)

    # sys.monitoring: every call, however the name was bound -----------------------------------------------------

    def _on_call(self, code: CodeType, offset: int, target: object, arg0: object) -> object:
        if getattr(self._local, "busy", False):
            return None
        if getattr(self._local, "passing", False):
            self._local.passing = False
            return None
        name = _forbidden_name(target)
        if name is None:
            return None
        self._local.busy = True
        try:
            read = self._attribute(name, sys._getframe(1))
            if read is not None:
                self._record(read)
        finally:
            self._local.busy = False
        return None

    # patched module attributes: raise where the read happens ----------------------------------------------------

    def _wrap(self, module: Any, attr: str, label: str) -> None:
        real = getattr(module, attr)
        self._saved[(module, attr)] = real
        tripwire = self

        if inspect.iscoroutinefunction(real):
            @functools.wraps(real)
            async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                tripwire._raise_or_pass(label, sys._getframe(1))
                return await real(*args, **kwargs)
            setattr(guarded_async, _MARK, True)
            setattr(module, attr, guarded_async)
            return

        @functools.wraps(real)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            tripwire._raise_or_pass(label, sys._getframe(1))
            return real(*args, **kwargs)
        setattr(guarded, _MARK, True)
        setattr(module, attr, guarded)

    def _raise_or_pass(self, label: str, frame: FrameType) -> None:
        if getattr(self._local, "busy", False):
            return
        self._local.busy = True
        try:
            read = self._attribute(label, frame)
        finally:
            self._local.busy = False
        if read is not None:
            self._record(read)
            raise WallClockUse(read)
        self._local.passing = True  # the real call below is the read just judged; the monitor skips it

    # install / uninstall -----------------------------------------------------------------------------------------

    def install(self) -> None:
        if self._active:
            raise RuntimeError("the tripwire is already installed")
        if sys.monitoring.get_tool(_TOOL_ID) is not None:
            raise RuntimeError(f"sys.monitoring tool id {_TOOL_ID} is held by {sys.monitoring.get_tool(_TOOL_ID)}")
        sys.monitoring.use_tool_id(_TOOL_ID, "probity-clock-tripwire")
        try:
            sys.monitoring.register_callback(_TOOL_ID, sys.monitoring.events.CALL, self._on_call)
            sys.monitoring.set_events(_TOOL_ID, sys.monitoring.events.CALL)
            for module_name, names in FORBIDDEN.items():
                module = _REAL_MODULES[module_name]
                for attr in sorted(names):
                    if hasattr(module, attr):  # uuid6 and uuid7 exist from Python 3.14; an absent reader reads nothing
                        self._wrap(module, attr, f"{module_name}.{attr}")
        except BaseException:
            self._release()  # a half-installed tripwire would leave the clock wrapped for every later test
            raise
        self._active = True

    def _release(self) -> None:
        """Put back every wrapped attribute and free the monitoring tool, whatever was installed so far."""
        for (module, attr), real in self._saved.items():
            setattr(module, attr, real)
        self._saved.clear()
        sys.monitoring.set_events(_TOOL_ID, sys.monitoring.events.NO_EVENTS)
        sys.monitoring.register_callback(_TOOL_ID, sys.monitoring.events.CALL, None)
        sys.monitoring.free_tool_id(_TOOL_ID)

    def uninstall(self) -> None:
        if not self._active:
            return
        self._release()
        self._active = False

    def take(self) -> list[Read]:
        """The reads recorded since the last ``take``, removed from the record."""
        with self._lock:
            out, self.reads = self.reads, []
        return out


@contextmanager
def installed(exemptions: Iterable[Exemption] = ()) -> Iterator[Tripwire]:
    """Install a tripwire for the duration of a block."""
    wire = Tripwire(tuple(exemptions))
    wire.install()
    try:
        yield wire
    finally:
        wire.uninstall()


def _report(reads: list[Read]) -> str:
    unique = sorted({str(r) for r in reads})
    return f"{len(reads)} real clock reads ({len(unique)} distinct):\n  " + "\n  ".join(unique)


# pytest plugin ---------------------------------------------------------------------------------------------------

_PLUGIN: Tripwire | None = None
_BETWEEN: list[Read] = []


def _plugin_install() -> Tripwire:
    global _PLUGIN
    if _PLUGIN is None:
        path = os.environ.get("PROBITY_CLOCK_EXEMPT")
        _PLUGIN = Tripwire(load_exemptions(path) if path else ())
        _PLUGIN.install()
    return _PLUGIN


def pytest_load_initial_conftests(early_config: Any, parser: Any, args: list[str]) -> None:
    _plugin_install()


def pytest_configure(config: Any) -> None:
    _plugin_install()


_HOOKWRAPPER: Callable[..., Any] = lambda f: f  # replaced below when pytest is importable
try:
    import pytest as _pytest_api

    _HOOKWRAPPER = _pytest_api.hookimpl(wrapper=True)
except ImportError:  # the module is usable without pytest; the hooks below are then never called
    pass


def _phase() -> Any:
    wire = _plugin_install()
    result = yield
    reads = wire.take()
    if reads:
        raise WallClockUse(reads[0], _report(reads))
    return result


@_HOOKWRAPPER
def pytest_runtest_setup(item: Any) -> Any:
    wire = _plugin_install()
    _BETWEEN.extend(wire.take())  # reads between tests belong to the session, reported at its end
    return (yield from _phase())


@_HOOKWRAPPER
def pytest_runtest_call(item: Any) -> Any:
    return (yield from _phase())


@_HOOKWRAPPER
def pytest_runtest_teardown(item: Any, nextitem: Any) -> Any:
    return (yield from _phase())


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    if _PLUGIN is None:
        return
    reads = _BETWEEN + _PLUGIN.take()
    if reads:
        sys.stderr.write("clock tripwire: reads outside any test call\n" + _report(reads) + "\n")
        session.exitstatus = 1
