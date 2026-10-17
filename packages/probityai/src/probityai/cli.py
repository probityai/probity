"""``probity <subcommand> [arguments]``.

The launcher holds no list of subcommands. A distribution adds one by declaring
an entry point in the ``probityai.cli_subcommands`` group. The entry point's name
is the subcommand; its value is a callable ``register(subparsers) -> None`` that
adds a parser of that name and attaches its handler with :func:`register_leaf`.
A distribution may register several subcommands, one entry point each.

Every failure of a registration is an error that names the entry point. Nothing
is skipped silently: a hidden subcommand looks the same as one never installed.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable
from importlib.metadata import EntryPoint, entry_points, version
from typing import Any

PROG = "probity"
GROUP = "probityai.cli_subcommands"
_DISPATCH = "_probity_handler"


class PluginError(Exception):
    """A registered subcommand failed to load, collided or registered nothing."""


def register_leaf(parser: argparse.ArgumentParser, *, handler: Callable[[argparse.Namespace], int]) -> None:
    """Attach ``handler`` as the function ``probity`` calls for this subcommand parser."""
    parser.set_defaults(**{_DISPATCH: handler})


def _owner(point: Any) -> str:
    dist = getattr(point, "dist", None)
    return f"{point.value} ({dist.name})" if dist is not None else point.value


def _register_all(subparsers: Any, points: Iterable[Any]) -> None:
    for point in sorted(points, key=lambda p: (p.name, p.value)):
        before = dict(subparsers.choices)
        if point.name in before:
            raise PluginError(f"subcommand {point.name!r} from {_owner(point)} is already registered")
        try:
            register = point.load()
            register(subparsers)
        except Exception as exc:  # every plugin failure is reported with the plugin's name
            raise PluginError(f"subcommand {point.name!r} from {_owner(point)} failed to register: {exc}") from exc
        replaced = [name for name, parser in before.items() if subparsers.choices.get(name) is not parser]
        if replaced:
            raise PluginError(f"{_owner(point)} replaced the registered subcommand(s) {', '.join(replaced)}")
        if point.name not in subparsers.choices:
            raise PluginError(f"{_owner(point)} did not register a subcommand named {point.name!r}")


def _build(points: Iterable[Any] | None) -> tuple[argparse.ArgumentParser, Any]:
    parser = argparse.ArgumentParser(prog=PROG, description="One command line for the evidence tools.")
    parser.add_argument("--version", action="version", version=f"{PROG} {version('probityai')}")
    subparsers = parser.add_subparsers(title="commands", metavar="<command>")
    _register_all(subparsers, entry_points(group=GROUP) if points is None else points)
    return parser, subparsers


def build_parser(points: Iterable[Any] | None = None) -> argparse.ArgumentParser:
    """Return the ``probity`` parser with every registered subcommand attached."""
    return _build(points)[0]


def main(argv: list[str] | None = None, points: Iterable[EntryPoint] | None = None) -> int:
    """Run ``probity``. Exit 2 for a usage error or a broken registration."""
    try:
        parser, subparsers = _build(points)
    except PluginError as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return 2
    args = parser.parse_args(argv)
    handler = getattr(args, _DISPATCH, None)
    if handler is None:
        parser.print_usage(sys.stderr)
        if not subparsers.choices:
            print(f"{PROG}: error: no commands are installed", file=sys.stderr)
        else:
            print(f"{PROG}: error: a command is required; run '{PROG} --help' for the list", file=sys.stderr)
        return 2
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
