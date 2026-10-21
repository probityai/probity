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

A test that needs anything else of the candidate (an instance of its class, an exception class
it defines, an attribute the test sets) fails here on the reference too, so the compiler drops
its id from the replay and only the worker counts it.
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
import sys
import types
from typing import Any

from .replay import Child, plain, unplain

MODE = "pytest"
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
        try:
            request = loads(line)
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
        send(reply)
'''


def child_source() -> str:
    """The child program: one reply line per request line, the codec kept out of ``__main__``."""
    codec = ("from __future__ import annotations\nimport json\nfrom typing import Any\n"
             + inspect.getsource(plain) + inspect.getsource(unplain))
    return CHILD_LOOP + f"_serve({codec!r})\n"


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


class Session:
    """The one child of a pytest replay, and every answer it gave, by request."""

    def __init__(self, child: Child, remote: frozenset[str]) -> None:
        self.child = child
        self.remote = remote
        self.answers: dict[str, list[str]] = {}
        self.requests: dict[str, dict[str, Any]] = {}

    def ask(self, request: dict[str, Any]) -> dict[str, Any]:
        key = _key(request)
        reply = self.child.ask(request)
        self.answers.setdefault(key, []).append(_answer(reply))
        self.requests[key] = request
        return reply

    def counted(self) -> tuple[int, int]:
        """Calls and attribute reads answered, and how many distinct ones (imports are not
        counted: a test that only imports the candidate never consulted it)."""
        keys = [key for key, request in self.requests.items() if request["op"] != "import"]
        return sum(len(self.answers[key]) for key in keys), len(keys)


def raise_for(reply: dict[str, Any]) -> None:
    """Raise what a reply that carries no value stands for in the test."""
    if "raised" in reply:
        module, name = reply["raised"]
        kind = EXCEPTIONS.get(name) if module == "builtins" else None
        if kind is None:
            raise CandidateFailed(f"raised {module}.{name}")
        try:
            error = kind(*(unplain(reply["args"]) if reply.get("args") is not None else ()))
        except BaseException:
            raise CandidateFailed(f"raised {module}.{name}") from None
        raise error
    raise CandidateFailed(str(reply.get("error", "no answer")))


def value(session: Session, reply: dict[str, Any], module: str, name: str) -> Any:
    """The parent's value for a reply: plain data, a remote function or a remote module."""
    if "ok" in reply:
        try:
            return unplain(reply["ok"])
        except Exception:
            raise CandidateFailed("malformed value") from None
    if reply.get("callable") is True:
        return RemoteFunction(session, module, name)
    found = reply.get("module")
    if isinstance(found, str):
        # Only a module the replay serves: a name of this process's own would run the
        # verifier's code where the test expects the candidate's.
        if found.split(".", 1)[0] not in session.remote:
            raise CandidateFailed(f"module outside the candidate: {found}")
        return importlib.import_module(found)
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
        if "ok" not in reply:
            raise_for(reply)
        return value(self._session, reply, self._module, self._name)


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


class RemoteFinder(importlib.abc.MetaPathFinder):
    """Serves every module under one of the session's remote top-level names from the child."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.loader = RemoteLoader(session)

    def find_spec(self, fullname: str, path: Any = None, target: Any = None
                  ) -> importlib.machinery.ModuleSpec | None:
        if fullname.split(".", 1)[0] not in self.session.remote:
            return None
        return importlib.machinery.ModuleSpec(fullname, self.loader, is_package=True)


class Count:
    """The parent's pytest plugin object: run each test ``repeats`` times, count outcomes."""

    def __init__(self, repeats: int) -> None:
        self.repeats = max(1, repeats)
        self.items: dict[str, dict[str, int]] = {}

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
            counts = self.items.setdefault(report.nodeid, {"passed": 0, "failed": 0, "skipped": 0})
            counts[report.outcome] = counts.get(report.outcome, 0) + 1


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

    args = ["-p", "no:cacheprovider", "-q", "--rootdir", request["test_root"]]
    if request.get("config"):
        args += ["-c", request["config"]]
    finder = RemoteFinder(session)
    sys.meta_path.insert(0, finder)
    cwd, path = os.getcwd(), list(sys.path)
    os.chdir(request["test_root"])
    try:
        return int(pytest.main([*args, "--", *request["ids"]], plugins=[counter]))
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
    the session's first answer: an answer that depended on what the child was asked before."""
    found = []
    for key in order:
        with Child(request["child_argv"], request.get("child_cwd"), timeout) as fresh:
            reply = fresh.ask(session.requests[key])
        if _answer(reply) != session.answers[key][0]:
            found.append(key)
    return found


def pytest_replay(request: dict[str, Any]) -> dict[str, Any]:
    """Run the sealed ids under pytest in this process, the remote modules served by a child."""
    remote = frozenset(request["remote"])
    base: dict[str, Any] = {"passed": False, "mode": MODE, "items": {}, "calls_intercepted": 0,
                            "distinct_calls": 0, "impure": [], "fresh_mismatch": [],
                            "fresh_order": []}
    problem = refused(remote, request["test_root"])
    if problem is not None:
        return {**base, "failure": problem}
    previous = os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD")
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    timeout = float(request["call_timeout"])
    counter = Count(int(request["repeats"]))
    try:
        with Child(request["child_argv"], request.get("child_cwd"), timeout) as child:
            session = Session(child, remote)
            code = _run(request, session, counter)
    finally:
        if previous is None:
            os.environ.pop("PYTEST_DISABLE_PLUGIN_AUTOLOAD", None)
        else:
            os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = previous
    impure = sorted(key for key, answers in session.answers.items() if len(set(answers)) != 1)
    order = sorted(session.answers)
    random.Random(request["order_seed"]).shuffle(order)
    fresh_mismatch = fresh_mismatches(request, session, order, timeout)
    calls, distinct = session.counted()
    failure = None
    if code != 0:
        failure = f"pytest exit {code}"
    elif not calls:
        # Tests that pass without consulting the candidate pass on every tree; a replay that
        # never reached it fails, so the compiler drops it rather than seal a vacuous count.
        failure = "no call reached the candidate"
    elif impure:
        failure = "answers differ on one request"
    elif fresh_mismatch:
        failure = "a fresh child answered differently"
    return {**base, "passed": failure is None, "failure": failure, "exit": code,
            "items": counter.items, "calls_intercepted": calls, "distinct_calls": distinct,
            "impure": impure, "fresh_mismatch": fresh_mismatch, "fresh_order": order}
