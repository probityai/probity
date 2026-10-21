"""Parent-compare replay of sealed pytest ids: the verifier runs and counts the sealed tests.

A sealed pytest command (:mod:`.pytest_plugins`) runs the test bodies in the process that
imports the agent's code, so that code can read the plugin's key, rewrite its outcome table or
register a hook of its own: the exit status and the pass counts are both what the worker says.
Here the SEALED test files run under pytest in the verifier's own interpreter, and the agent's
code never enters it:

- the test root holds only sealed bytes: the protected test files, ``conftest.py`` files and
  pytest configuration the contract sealed (``<heldout>/pytest-root``), with the held-out tree
  overlaid for a held-out command, read with the sealed configuration (``-c``);
- every module under a name the contract seals as remote (the working tree's top-level
  packages) is served by a finder placed ahead of the path finder: importing it, reading a
  plain-data attribute of it and calling a function of it cross to an isolated child that
  holds the agent's tree, as the type-tagged canonical text of :mod:`.replay`. Only plain data
  comes back; a function comes back as a handle whose calls cross the same way;
- the outcomes are counted by a plugin object in this process, each test run ``repeats``
  times; every answer on one request must be identical, and each distinct request is asked
  again of a fresh child, in an order seeded from the grader and recorded, as in :mod:`.replay`.

A replay counts only ids :mod:`.pytest_proof` proves: tests that reduce to ``assert <one call
the child answers> == <sealed literal>``. The parent checks the proof again and runs the sealed
test function pytest compiled, with each call's answer handed to it as a :class:`Sealed` value:
the k-th answer can only be compared, once and before the next call, with the k-th assertion's
sealed value, type-strict (:func:`.replay.strict_eq`), and every comparison must have run
before the test may count as passed. A plain value the candidate gives anywhere else (at
import, in a fixture, in a hook) fails the replay: nothing the candidate chooses reaches the
parent except as the left side of a sealed comparison. An id that is not proven, or a test that
needs anything else of the candidate, fails here on the reference too, so the compiler leaves
it out and only the worker counts it.
"""

from __future__ import annotations

import builtins
import importlib
import importlib.abc
import importlib.machinery
import inspect
import json
import os
import random
import secrets
import sys
import time
import types
from pathlib import Path
from typing import Any

from . import pytest_plugins, pytest_proof
from .replay import Child, ClientFailure, plain, stall, strict_eq, unplain

MODE = "pytest"
# What a stall inside the candidate's own request reads as in a pytest replay: a definitive
# failure (``contradicted`` on a held-out command). Operator ruling of 2026-10-21, "keep
# contradicted."; it covers this mode only, not the LiveCodeBench modes of :mod:`.replay`.
# Recorded in every result and in the grade's isolation record.
STALL_POLICY = "contradicted"
# Builtin exceptions a reply may raise again in the test (``pytest.raises(ValueError)``).
# Anything else the candidate raised, and every protocol failure, is :class:`CandidateFailed`.
EXCEPTIONS = {name: value for name, value in vars(builtins).items()
              if isinstance(value, type) and issubclass(value, Exception)}

CHILD_LOOP = '''
def _serve(codec_source):
    # Local to this call, like the replay child: the agent's modules find nothing of the
    # protocol in __main__ to rebind.
    import importlib, json, os, sys
    codec = {}
    exec(codec_source, codec)
    plain, unplain = codec["plain"], codec["unplain"]
    proto = os.fdopen(os.dup(1), "w")
    os.dup2(2, 1)
    sys.path.insert(0, os.getcwd())
    # A src layout: its packages import from src/, as the task's own install makes them.
    source = os.path.join(os.getcwd(), "src")
    if os.path.isdir(source) and not os.path.exists(os.path.join(source, "__init__.py")):
        sys.path.insert(1, source)
    dumps, loads, load = json.dumps, json.loads, importlib.import_module
    module_type, is_callable, text = type(sys), callable, str
    def send(message):
        proto.write(dumps(message) + "\\n")
        proto.flush()
    def raised(error):
        kind = type(error)
        try:
            args = plain(tuple(error.args))
        except BaseException:
            args = None
        return {"raised": [text(kind.__module__), text(kind.__qualname__)], "args": args}
    def value_reply(value):
        if isinstance(value, module_type):
            return {"module": text(value.__name__)}
        if is_callable(value):
            return {"callable": True}
        try:
            return {"ok": plain(value)}
        except BaseException:
            return {"error": "unplain"}
    for line in sys.stdin:
        nonce = None
        try:
            request = loads(line)
            nonce = request["nonce"]
            op, module = request["op"], load(request["module"])
            if op == "import":
                reply = {"ok": ["none"]}
            elif op == "attr":
                reply = value_reply(getattr(module, request["name"]))
            else:
                function = getattr(module, request["name"])
                reply = value_reply(function(*unplain(request["args"]),
                                             **unplain(request["kwargs"])))
                if "ok" not in reply:
                    reply = {"error": "unplain"}
        except BaseException as error:
            try:
                reply = raised(error)
            except BaseException:
                reply = {"error": "unreportable"}
        reply["nonce"] = nonce
        send(reply)
'''


def child_source() -> str:
    """The child program: one reply line per request line, the codec kept out of ``__main__``."""
    codec = ("from __future__ import annotations\nimport json\nfrom typing import Any\n"
             + inspect.getsource(plain) + inspect.getsource(unplain))
    return CHILD_LOOP + f"_serve({codec!r})\n"


OUTSIDE = "candidate data outside a sealed comparison"


class CandidateFailed(BaseException):
    """The candidate gave no plain answer: a protocol failure, a value that cannot cross, or an
    exception that is not a builtin one. A ``BaseException``, so that no test's ``except
    Exception`` or ``pytest.raises(Exception)`` turns a failure to answer into a pass."""


class Unsupported(BaseException):
    """The test asked of a remote module what a replay cannot give (setting an attribute)."""


def _key(request: dict[str, Any]) -> str:
    return json.dumps([request["op"], request["module"], request.get("name"),
                       request.get("args"), request.get("kwargs")], separators=(",", ":"))


def _answer(reply: dict[str, Any]) -> str:
    return json.dumps(reply, separators=(",", ":"), sort_keys=True)


def exchange(child: Child, request: dict[str, Any], timeout: float | None = None
             ) -> dict[str, Any]:
    """Ask ``request`` of ``child`` under a fresh nonce; a reply that does not carry it back is
    a protocol error. The nonce is not part of the request's key or of its recorded answer.
    ``timeout``, when given, shortens the child's own call limit (the replay's deadline).

    It catches a reply stream out of step with the requests (a line the candidate wrote at
    import, or a second line for one request). It does not authenticate the serve loop: code
    in the child can read each request and echo its nonce."""
    nonce = secrets.token_hex(16)
    message = {**request, "nonce": nonce}
    reply = child.ask(message) if timeout is None else child.ask(message, timeout)
    if isinstance(reply, ClientFailure):
        # The client's own failure (a time-out, an exited child): a type no line the child
        # writes can decode to, so a child that writes the client's words is not one.
        return reply
    if not isinstance(reply, dict) or reply.get("nonce") != nonce:
        # The child writes the protocol stream, so its shape is checked before any field is
        # read: no malformed reply may raise an exception a test could expect.
        return ClientFailure("child-protocol")
    return {key: item for key, item in reply.items() if key != "nonce"}


# The reply to an attribute read that the candidate's module does not have.
ABSENT = ["builtins", "AttributeError"]


def handle(request: dict[str, Any], reply: dict[str, Any]) -> bool:
    """Whether a reply carries nothing the candidate chose but a handle: an import that
    succeeded, or an attribute that is a function or a module of the candidate, or that the
    module does not have (its ``AttributeError``, whose arguments are never read).

    The absent attribute is what ``from pkg import submodule`` asks first: the import system
    imports ``pkg.submodule`` only when ``hasattr`` says the package lacks it, and ``hasattr``
    catches only ``AttributeError``."""
    if request["op"] == "import":
        return reply == {"ok": ["none"]}
    return (request["op"] == "attr" and "ok" not in reply
            and (reply.get("callable") is True or isinstance(reply.get("module"), str)
                 or reply.get("raised") == ABSENT))


class Session:
    """The one child of a pytest replay, and every answer it gave, by request.

    ``phase`` is the run of a proven test being made, or ``None``. Only a call made in it may
    answer with plain data, and that answer reaches the test as a :class:`Sealed` value. Any
    other reply that is more than a handle (:func:`handle`) never reaches the sealed code: it
    is recorded in ``outside``, which fails the replay, and the code gets
    :class:`CandidateFailed` in its place. So a value the candidate chose can never steer
    sealed code (into a path it opens, say) on the verifier's host."""

    def __init__(self, child: Child, remote: frozenset[str],
                 deadline: float | None = None) -> None:
        self.child = child
        self.remote = remote
        # The replay's own deadline (``time.monotonic``), or ``None``; :attr:`spent` once a
        # request stalled on it rather than on the call's limit.
        self.deadline = deadline
        self.spent = False
        self.answers: dict[str, list[str]] = {}
        self.requests: dict[str, dict[str, Any]] = {}
        self.phase: Phase | None = None
        self.outside: list[str] = []

    def left(self) -> float | None:
        """Seconds to the replay's deadline, or ``None`` when it has none."""
        return None if self.deadline is None else max(0.0, self.deadline - time.monotonic())

    def ask(self, request: dict[str, Any]) -> dict[str, Any]:
        key = _key(request)
        left = self.left()
        reply = exchange(self.child, request, left)
        if left is not None and left < getattr(self.child, "timeout", float("inf")) and stall(reply):
            self.spent = True
        self.answers.setdefault(key, []).append(_answer(reply))
        self.requests[key] = request
        if self.phase is None or request["op"] != "call":
            if not handle(request, reply):
                if key not in self.outside:
                    self.outside.append(key)
                # A failure of the client itself carries nothing the candidate chose.
                if not isinstance(reply, ClientFailure):
                    reply = {"error": OUTSIDE}
        return reply

    def counted(self) -> tuple[int, int]:
        """Calls and attribute reads answered, and how many distinct ones (imports are not
        counted: a test that only imports the candidate never consulted it)."""
        keys = [key for key, request in self.requests.items() if request["op"] != "import"]
        return sum(len(self.answers[key]) for key in keys), len(keys)


def raise_for(reply: dict[str, Any]) -> None:
    """Raise what a reply that carries no value stands for in the test."""
    raised = reply.get("raised")
    if raised is not None:
        if not (isinstance(raised, list) and len(raised) == 2
                and all(isinstance(part, str) for part in raised)):
            raise CandidateFailed("malformed raise")
        module, name = raised
        kind = EXCEPTIONS.get(name) if module == "builtins" else None
        if kind is None:
            raise CandidateFailed(f"raised {module}.{name}")
        try:
            args = unplain(reply["args"]) if reply.get("args") is not None else ()
            if type(args) is not tuple:
                raise TypeError("arguments are not a tuple")
            error = kind(*args)
        except BaseException:
            raise CandidateFailed(f"raised {module}.{name}") from None
        raise error
    raise CandidateFailed(str(reply.get("error", "no answer")))


def value(session: Session, reply: dict[str, Any], module: str, name: str,
          call: bool = False) -> Any:
    """The parent's value for a reply: plain data, a remote function or a remote module.

    A call answers with plain data only. A function it returns would come back as a handle
    named by the module and name of the function that made it, so calling that handle would
    call the factory again, not the function it returned; such a reply fails instead."""
    if "ok" in reply:
        try:
            return unplain(reply["ok"])
        except Exception:
            raise CandidateFailed("malformed value") from None
    if call:
        raise_for(reply)
    if reply.get("callable") is True:
        return RemoteFunction(session, module, name)
    found = reply.get("module")
    if isinstance(found, str):
        # Only a module the replay serves: a name of this process's own would run the
        # verifier's code where the test expects the candidate's.
        if (not all(part.isidentifier() for part in found.split("."))
                or found.split(".", 1)[0] not in session.remote):
            raise CandidateFailed(f"module outside the candidate: {found}")
        return importlib.import_module(found)
    if reply.get("raised") == ABSENT:
        # Built here: the candidate's own arguments for it never reach the sealed code.
        raise AttributeError(name)
    raise_for(reply)


class RemoteFunction:
    """A function of the candidate: every call goes to the child as plain data."""

    def __init__(self, session: Session, module: str, name: str) -> None:
        self._session, self._module, self._name = session, module, name

    def __repr__(self) -> str:
        return f"<remote {self._module}.{self._name}>"

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        try:
            args_tagged, kwargs_tagged = plain(tuple(args)), plain(dict(kwargs))
        except TypeError as error:
            raise CandidateFailed(f"argument is not plain data: {error}") from None
        reply = self._session.ask({"op": "call", "module": self._module, "name": self._name,
                                   "args": args_tagged, "kwargs": kwargs_tagged})
        found = value(self._session, reply, self._module, self._name, call=True)
        phase = self._session.phase
        if phase is None:
            # Unreachable while the session refuses data outside a run; kept so that no
            # answer ever reaches sealed code unsealed.
            raise CandidateFailed(OUTSIDE)
        return phase.wrap(found)


class Phase:
    """One run of a proven test. The k-th call it makes must be compared, once and before
    the next call, with the k-th assertion's sealed value."""

    def __init__(self, proof: pytest_proof.Proof, expected: list[Any]) -> None:
        self.proof, self.expected = proof, expected
        self.calls = 0
        self.compared: list[int] = []
        self.booleans: dict[str, set[bool]] = {}

    def wrap(self, answer: Any) -> Sealed:
        index = self.calls
        if index >= len(self.expected) or len(self.compared) != index:
            raise CandidateFailed("a call outside the sealed comparisons")
        self.calls += 1
        return Sealed(self, index, answer)

    def compare(self, index: int, answer: Any, other: Any) -> bool:
        if index != self.calls - 1 or len(self.compared) != index:
            raise CandidateFailed("a sealed comparison out of its order")
        expected = self.expected[index]
        if not strict_eq(other, expected):
            raise CandidateFailed("compared with a value that is not the sealed one")
        self.compared.append(index)
        for key, leaf in pytest_proof.boolean_leaves(self.proof.sites[index].callee, expected):
            self.booleans.setdefault(key, set()).add(leaf)
        return strict_eq(answer, expected)

    def complete(self) -> bool:
        return self.calls == len(self.expected) == len(self.compared)


class Sealed:
    """A call's answer inside a proven test: it can be compared once with its sealed value,
    with the same builtin type at every level, and shown in a failure message. Nothing else
    of it reaches the test."""

    __slots__ = ("_phase", "_index", "_answer")
    __hash__ = None  # type: ignore[assignment]

    def __init__(self, phase: Phase, index: int, answer: Any) -> None:
        self._phase, self._index, self._answer = phase, index, answer

    def __eq__(self, other: object) -> bool:
        return self._phase.compare(self._index, self._answer, other)

    def __ne__(self, other: object) -> bool:
        raise CandidateFailed("a sealed comparison is ==")

    def __bool__(self) -> bool:
        raise CandidateFailed("a sealed answer is only compared")

    def __repr__(self) -> str:
        return repr(self._answer)


class RemoteModule(types.ModuleType):
    """A module of the candidate's tree: a missing attribute is read from the child."""

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        session = self.__dict__["__probity_session__"]
        return value(session, session.ask({"op": "attr", "module": self.__name__,
                                           "name": name}), self.__name__, name)

    def __setattr__(self, name: str, item: Any) -> None:
        # The import system binds a submodule on its parent; nothing else may be set, since
        # the child would never see it.
        if (name.startswith("__") and name.endswith("__")) or isinstance(item, RemoteModule):
            super().__setattr__(name, item)
            return
        raise Unsupported(f"cannot set {self.__name__}.{name} in a replay")


class RemoteLoader(importlib.abc.Loader):
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> types.ModuleType:
        module = RemoteModule(spec.name)
        module.__dict__["__probity_session__"] = self.session
        return module

    def exec_module(self, module: types.ModuleType) -> None:
        reply = self.session.ask({"op": "import", "module": module.__name__})
        if "ok" not in reply:
            raise ImportError(f"the candidate's {module.__name__} did not import: "
                              f"{reply.get('raised', reply.get('error'))}", name=module.__name__)


IMPORT_MACHINERY = (importlib.__file__,)


class RemoteFinder(importlib.abc.MetaPathFinder):
    """Serves every module under one of the session's remote top-level names from the child,
    to sealed code only.

    The import must come from a file under the sealed test root, or from :func:`value`
    following a module the candidate named. An import the verifier's own code makes (pytest
    importing an optional module late, after :func:`refused` looked) is left to the path
    finder, so the candidate never serves the verifier's own modules."""

    def __init__(self, session: Session, root: str = "") -> None:
        self.session = session
        self.loader = RemoteLoader(session)
        self.root = os.path.realpath(root) + os.sep if root else ""

    def sealed_importer(self) -> bool:
        frame = sys._getframe(2)
        while frame is not None:
            code = frame.f_code
            if code.co_filename.startswith("<frozen importlib") or (
                    code.co_filename in IMPORT_MACHINERY):
                frame = frame.f_back
                continue
            if code is value.__code__:
                return True
            return bool(self.root) and os.path.realpath(code.co_filename).startswith(self.root)
        return False

    def find_spec(self, fullname: str, path: Any = None, target: Any = None
                  ) -> importlib.machinery.ModuleSpec | None:
        if fullname.split(".", 1)[0] not in self.session.remote or not self.sealed_importer():
            return None
        return importlib.machinery.ModuleSpec(fullname, self.loader, is_package=True)


class Count:
    """The parent's pytest plugin object: run each test ``repeats`` times, count outcomes.

    A test counts as passed on a run only when :meth:`call` ran the proven function to the
    end on that run with every sealed comparison made; a passed report without that (a hook
    that ran something else, or rewrote the report) counts as failed."""

    def __init__(self, repeats: int, sources: pytest_proof.Sources | None = None,
                 session: Session | None = None, root: str = "") -> None:
        self.repeats = max(1, repeats)
        self.items: dict[str, dict[str, int]] = {}
        self.sources, self.session = sources, session
        self.root = os.path.realpath(root) if root else ""
        self.verified: set[str] = set()
        self.unproven: dict[str, str] = {}
        self.booleans: dict[str, set[bool]] = {}
        self.boolean_items: dict[str, set[str]] = {}

    def proof(self, item: Any) -> pytest_proof.Proof | str:
        """The proof of a collected test, read again from the sealed file pytest imported."""
        import pytest

        if self.sources is None:
            return "no sealed source"
        if type(item) is not pytest.Function or item.cls is not None:
            return "not a module-level test function"
        path = os.path.realpath(str(item.path))
        if not path.startswith(self.root + os.sep):
            return "the test file is not sealed"
        relative = os.path.relpath(path, self.root).replace(os.sep, "/")
        return self.sources.proof(f"{relative}::{item.originalname}")

    def call(self, item: Any) -> bool:
        """Run a proven test: the function pytest collected from the sealed file, holding each
        call's answer to its sealed comparison, every one of which must have run."""
        proof = self.proof(item)
        if isinstance(proof, str):
            self.unproven[item.nodeid] = proof
            raise CandidateFailed(f"not a sealed comparison: {proof}")
        session = self.session
        assert session is not None
        function = item.obj
        code = getattr(function, "__code__", None)
        first = min([proof.node.lineno, *(node.lineno for node in proof.node.decorator_list)])
        if (code is None or getattr(function, "__name__", None) != proof.node.name
                or os.path.realpath(code.co_filename) != os.path.realpath(str(item.path))
                or code.co_firstlineno != first):
            raise CandidateFailed("the collected test is not the sealed function")
        phase = Phase(proof, proof.expected(item.funcargs))
        session.phase = phase
        try:
            function(**{name: item.funcargs[name] for name in proof.params})
        finally:
            session.phase = None
        if not phase.complete():
            raise CandidateFailed("a sealed comparison did not run")
        for key, values in phase.booleans.items():
            self.booleans.setdefault(key, set()).update(values)
            self.boolean_items.setdefault(item.nodeid, set()).add(key)
        self.verified.add(item.nodeid)
        return True

    def degenerate(self) -> list[str]:
        """Withdraw the passes of tests whose boolean comparison was only ever made one way
        on its function in this run; returns their ids."""
        weak = {key for key, values in self.booleans.items() if values != {True, False}}
        found = sorted(nodeid for nodeid, keys in self.boolean_items.items() if keys & weak)
        for nodeid in found:
            counts = self.items.setdefault(nodeid, {"passed": 0, "failed": 0, "skipped": 0})
            counts["failed"] = counts.get("failed", 0) + counts.get("passed", 0)
            counts["passed"] = 0
        return found

    def pytest_runtest_protocol(self, item: Any, nextitem: Any) -> bool:
        from _pytest.runner import runtestprotocol

        item.ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
        for index in range(self.repeats):
            if index:
                item._initrequest()
            last = index == self.repeats - 1
            runtestprotocol(item, nextitem=nextitem if last else item.parent, log=True)
        item.ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
        return True

    def pytest_runtest_logreport(self, report: Any) -> None:
        if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
            outcome = report.outcome
            if report.when == "call":
                if outcome == "passed" and report.nodeid not in self.verified:
                    outcome = "failed"
                self.verified.discard(report.nodeid)
            counts = self.items.setdefault(report.nodeid, {"passed": 0, "failed": 0, "skipped": 0})
            counts[outcome] = counts.get(outcome, 0) + 1


def refused(remote: frozenset[str], root: str) -> str | None:
    """Why ``remote`` cannot be served, or ``None``: a remote name must be an identifier and
    may not name a standard-library module, a module this process already holds, or a module
    the sealed root itself holds."""
    for name in sorted(remote):
        if (not name.isidentifier() or name in sys.stdlib_module_names or name in sys.modules
                or os.path.exists(os.path.join(root, name))
                or os.path.exists(os.path.join(root, name + ".py"))):
            return f"remote module name not allowed: {name}"
    return None


def _run(request: dict[str, Any], session: Session, counter: Count) -> int:
    import pytest

    class Calls:
        """Runs each test through :meth:`Count.call`, before any other implementation."""

        @pytest.hookimpl(tryfirst=True)
        def pytest_pyfunc_call(self, pyfuncitem: Any) -> bool:
            return counter.call(pyfuncitem)

    args = ["-p", "no:cacheprovider", "-q", "--rootdir", request["test_root"]]
    if request.get("config"):
        args += ["-c", request["config"]]
    finder = RemoteFinder(session, request["test_root"])
    sys.meta_path.insert(0, finder)
    cwd, path = os.getcwd(), list(sys.path)
    os.chdir(request["test_root"])
    try:
        return int(pytest.main([*args, "--", *request["ids"]], plugins=[counter, Calls()]))
    finally:
        os.chdir(cwd)
        sys.path[:] = path
        sys.meta_path.remove(finder)
        # The remote modules and the sealed test modules hold this run's session; neither
        # outlives it, so a later run in the same process imports both afresh.
        root = os.path.realpath(request["test_root"]) + os.sep
        for name, module in list(sys.modules.items()):
            origin = getattr(module, "__file__", None)
            if name.split(".", 1)[0] in session.remote or (
                    isinstance(origin, str) and os.path.realpath(origin).startswith(root)):
                del sys.modules[name]


def fresh_mismatches(request: dict[str, Any], session: Session, order: list[str],
                     timeout: float) -> list[str]:
    """The requests, asked again one per fresh child in ``order``, whose answer differs from
    the session's first answer: an answer that depended on what the child was asked before.

    The fresh children share the replay's deadline; the first request that reaches it is a
    mismatch and ends the pass, so no further child is started past it."""
    found = []
    for key in order:
        left = session.left()
        with Child(request["child_argv"], request.get("child_cwd"), timeout) as fresh:
            reply = exchange(fresh, session.requests[key], left)
        if _answer(reply) != session.answers[key][0]:
            found.append(key)
        if left is not None and left < timeout and stall(reply):
            session.spent = True
            break
    return found


# What the parent keeps of the command's limit for itself: closing the children, the count
# and writing the result. A quarter of a short limit, at most a minute of a long one.
DEADLINE_MARGIN = 60.0


def deadline(run_timeout: Any, started: float) -> float | None:
    """The replay's own deadline on ``time.monotonic``: the command's limit less the margin,
    from ``started``. Every request, fresh children included, is asked inside it, so the parent
    writes its result before the runner stops it, whatever pace the candidate answers at."""
    if run_timeout is None:
        return None
    limit = float(run_timeout)
    return started + limit - min(DEADLINE_MARGIN, limit / 4)


def pytest_replay(request: dict[str, Any]) -> dict[str, Any]:
    """Run the sealed ids under pytest in this process, the remote modules served by a child."""
    # pytest and its own modules are imported before the remote names are checked, so none
    # of them can be a name the child serves.
    import _pytest.runner  # noqa: F401
    import pytest  # noqa: F401

    remote = frozenset(request["remote"])
    base: dict[str, Any] = {"passed": False, "mode": MODE, "items": {}, "calls_intercepted": 0,
                            "distinct_calls": 0, "impure": [], "fresh_mismatch": [],
                            "fresh_order": [], "unproven": {}, "outside": [], "degenerate": [],
                            "deadline_reached": False,
                            "stall_policy": STALL_POLICY}
    problem = refused(remote, request["test_root"])
    if problem is not None:
        return {**base, "failure": problem}
    # Plugin autoloading is off in the parent's environment (``runner.parent_env``), which is
    # the scrubbed one: no variable of the verifier's reaches pytest or a sealed conftest.
    timeout = float(request["call_timeout"])
    sources = pytest_proof.Sources([Path(request["test_root"])], remote)
    ends = deadline(request.get("run_timeout"), float(request.get("started", time.monotonic())))
    with Child(request["child_argv"], request.get("child_cwd"), timeout) as child:
        session = Session(child, remote, ends)
        counter = Count(int(request["repeats"]), sources, session, request["test_root"])
        code = _run(request, session, counter)
    degenerate = counter.degenerate()
    impure = sorted(key for key, answers in session.answers.items() if len(set(answers)) != 1)
    order = sorted(session.answers)
    random.Random(request["order_seed"]).shuffle(order)
    calls, distinct = session.counted()
    failure = None
    if session.outside:
        failure = OUTSIDE
    elif code != 0:
        failure = f"pytest exit {code}"
    elif not calls:
        # Tests that pass without consulting the candidate pass on every tree; a replay that
        # never reached it fails, so the compiler drops it rather than seal a vacuous count.
        failure = "no call reached the candidate"
    elif degenerate:
        failure = "a boolean comparison its function never makes the other way"
    elif pytest_plugins.passed(counter.items, request["ids"]) != len(request["ids"]):
        failure = "a sealed id did not pass"
    elif impure:
        failure = "answers differ on one request"
    # The fresh children are asked only of a run that holds no failure yet: nothing they
    # answer can change a failed replay.
    fresh_mismatch = [] if failure else fresh_mismatches(request, session, order, timeout)
    if fresh_mismatch:
        failure = "a fresh child answered differently"
    # Every failure here is definitive, a stall inside one of the candidate's own requests
    # included, and so is a run that spent the replay's whole deadline: each answer came at
    # the candidate's own pace, and the parent stops asking in time to write this result. Only
    # a parent the runner stops before its own deadline, with no result written, reads as no
    # answer (``timed_out``).
    return {**base, "passed": failure is None, "failure": failure, "exit": code,
            "definitive": failure is not None and STALL_POLICY == "contradicted",
            "deadline_reached": session.spent,
            "items": counter.items, "calls_intercepted": calls, "distinct_calls": distinct,
            "impure": impure, "fresh_mismatch": fresh_mismatch, "fresh_order": order,
            "unproven": counter.unproven, "outside": session.outside, "degenerate": degenerate}
