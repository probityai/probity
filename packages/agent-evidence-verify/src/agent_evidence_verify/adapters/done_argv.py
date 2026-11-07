"""One argv model for an acceptance command, shared by the claim parser and the verifier.

A sealed acceptance command and a run of it can be spelled many ways that run the same
tests: ``pytest -q tests`` and ``pytest tests -q``, ``python -m pytest -q tests``, ``pytest -q
tests -x``. Matching them by exact argv refused honest agents by spelling (review 5, R5-1),
so both sides compare an :class:`Invocation` instead:

- the **program**: a Python entry point run as ``<interpreter> -m <module>`` is that module
  (``python -m pytest`` is ``pytest``); otherwise the program named by ``argv[0]``;
- for **pytest**, the set of targets (``posixpath.normpath`` of every positional argument)
  and the options that choose or change what runs (selecting and overriding flags with their
  values, sorted); options that only change what is printed or when a failing run stops are
  dropped, because they cannot turn a failing suite into a passing one;
- for **any other program**, the arguments in order, a leading ``./`` removed.

Two invocations match when the program and that canonical argument form are equal. An
option this module does not know is kept as a selecting option, so an unknown flag never
makes two different runs match.

:func:`unwrap` takes a command line an agent printed to the command it runs: leading
``NAME=value`` words, ``env``, ``timeout``, ``uv run``, ``poetry run``, ``pipx run``, ``sh
-c`` (and ``bash -c``, ``-lc``), ``cd <dir> &&`` or ``cd <dir>;``, a trailing ``2>&1`` and a
trailing ``| tee <file>``. The verifier never unwraps: the observer records the exec of the
inner command itself, with its own working directory.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass

INTERPRETER = re.compile(r"(python|pypy)[0-9.]*$")
# Interpreter options that take a value in the next word.
_INTERPRETER_VALUES = {"-W", "-X", "--check-hash-based-pycs"}
# pytest options that change only what is printed, or stop a failing run early.
_REPORTING = {"-q", "--quiet", "-v", "--verbose", "-s", "-x", "--exitfirst", "--no-header",
              "--no-summary", "-l", "--showlocals", "--capture=no", "--disable-warnings",
              "--disable-pytest-warnings", "--strict-markers", "-ra", "-rA", "-rf", "-rs",
              "-rx", "-rX", "-rE", "-rp", "-rP", "-rN"}
_REPORTING_PREFIX = ("--tb=", "--color=", "--durations=", "--maxfail=", "--capture=",
                     "--code-highlight=")
_REPORTING_VALUE = {"--tb", "--color", "--durations", "--maxfail", "--capture"}
_SELECTING_VALUE = {"-k", "-m", "-W", "--deselect", "-c", "-o", "--override-ini", "--rootdir",
                    "--confcutdir", "-p", "--ignore", "--ignore-glob", "--basetemp",
                    "--import-mode"}
_SHELLS = {"sh", "bash", "dash", "zsh"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_RUNNERS = {("uv", "run"), ("poetry", "run"), ("pipx", "run")}


@dataclass(frozen=True)
class Invocation:
    """The program and its canonical arguments; see the module docstring."""

    program: str
    args: tuple


def _plain(word: str) -> str:
    return word[2:] if word.startswith("./") and len(word) > 2 else word


def _module_run(argv: list[str]) -> tuple[str, list[str]] | None:
    """``(module, rest)`` for ``<interpreter> [options] -m <module> rest``."""
    words = argv[1:]
    while words and words[0].startswith("-") and words[0] != "-":
        option = words.pop(0)
        if option == "-m":
            return (words[0], words[1:]) if words else None
        if option.startswith("-m") and len(option) > 2:
            return option[2:], words
        if option in _INTERPRETER_VALUES and words:
            words.pop(0)
    return None


def _pytest_args(args: list[str]) -> tuple:
    targets: set[str] = set()
    selecting: list[tuple[str, ...]] = []
    words = list(args)
    while words:
        word = words.pop(0)
        if word == "--":
            targets.update(posixpath.normpath(_plain(item)) for item in words)
            break
        if not word.startswith("-") or word == "-":
            targets.add(posixpath.normpath(_plain(word)))
        elif word in _REPORTING or word.startswith(_REPORTING_PREFIX):
            continue
        elif word in _REPORTING_VALUE:
            if words:
                words.pop(0)
        elif word in _SELECTING_VALUE:
            selecting.append((word, words.pop(0) if words else ""))
        else:
            selecting.append((word,))
    return (tuple(sorted(targets)), tuple(sorted(selecting)))


def invocation(argv: list[str], exe: str | None = None) -> Invocation:
    """The invocation an argv runs (``exe``, when given, names the file the kernel ran)."""
    name = posixpath.basename(exe or argv[0])
    program, args = posixpath.basename(argv[0]), list(argv[1:])
    if INTERPRETER.match(name) or INTERPRETER.match(program):
        module = _module_run(argv)
        if module is not None:
            program, args = module
    if program == "pytest" or program == "py.test":
        return Invocation("pytest", _pytest_args(args))
    return Invocation(program, tuple(_plain(word) for word in args))


def _split(line: str) -> list[str] | None:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return None


def unwrap(argv: list[str], cwd: str | None = None) -> tuple[list[str], str | None] | None:
    """The command an agent-printed command line runs and the directory it runs in, or None
    when the line uses shell syntax beyond the forms in the module docstring."""
    words = list(argv)
    while words:
        if _ASSIGNMENT.match(words[0]):
            words.pop(0)
        elif words[0] == "env":
            words.pop(0)
            while words and (_ASSIGNMENT.match(words[0]) or words[0] in ("-i", "-")):
                words.pop(0)
        elif words[0] == "timeout":
            words.pop(0)
            while words and words[0].startswith("-"):
                option = words.pop(0)
                if option in ("-s", "-k", "--signal", "--kill-after") and words:
                    words.pop(0)
            if words:
                words.pop(0)
        elif len(words) > 1 and (words[0], words[1]) in _RUNNERS:
            words = words[2:]
            while words and words[0].startswith("-"):
                words.pop(0)
        elif (len(words) == 3 and posixpath.basename(words[0]) in _SHELLS
              and words[1] in ("-c", "-lc")):
            return _line(words[2], cwd)
        else:
            break
    return (words, cwd) if words else None


_CD = re.compile(r"\s*cd\s+(\S+)\s*(?:&&|;)\s*(.+)", re.DOTALL)
_TEE = re.compile(r"(.+?)\s*\|\s*tee(?:\s+-a)?\s+\S+\s*", re.DOTALL)
_STDERR = re.compile(r"(.+?)\s+2>&1\s*", re.DOTALL)


def _line(line: str, cwd: str | None) -> tuple[list[str], str | None] | None:
    """:func:`unwrap` of one shell command line."""
    text = line.strip()
    moved = _CD.fullmatch(text)
    if moved:
        directory = moved.group(1)
        if cwd is not None and not directory.startswith("/"):
            directory = posixpath.join(cwd, directory)
        return _line(moved.group(2), posixpath.normpath(directory))
    for pattern in (_TEE, _STDERR):
        trimmed = pattern.fullmatch(text)
        if trimmed:
            return _line(trimmed.group(1), cwd)
    if set(text) & set("|&;<>()$`"):
        return None
    words = _split(text)
    return unwrap(words, cwd) if words else None
