#!/usr/bin/env python3
"""Replay a verdict bundle with the pinned probity-verify and fail on a bad one.

Two modes, one decision rule.

    verify_bundle.py BUNDLE.zip [--allow supported[,not_established]]
    verify_bundle.py --hook [--allow ...]      (hook JSON on stdin)

The bundle is the ZIP written by ``probity-bundle create``. ``probity-bundle
replay`` rechecks every artifact binding and recomputes the decision; this script
adds the gate on top: the replay must succeed and the recomputed decision must be
one of the allowed ones (default: ``supported``).

Exit codes of the direct mode:
  0  replay succeeded and the decision is allowed
  1  replay succeeded and the decision is not allowed (for example contradicted)
  2  the bundle could not be replayed: tampered, malformed, missing, or the
     verifier could not run. Failing closed is deliberate: a check that did not
     run is not a pass.

In hook mode the script finds bundle paths in the hook payload (any string that
names an existing file matching PROBITY_BUNDLE_GLOBS), checks each, prints the
reason on stderr and exits 2 on the first failure so Claude Code feeds it back
to the agent. A payload that names no bundle exits 0 without output.

Environment:
  PROBITY_BUNDLE_CMD    command line of the replay tool, replacing the default
  PROBITY_BUNDLE_ALLOW  comma list of allowed decisions (same as --allow)
  PROBITY_BUNDLE_GLOBS  comma list of file name patterns that count as bundles
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator

PINNED = "probity-verify==0.3.0"
DECISIONS = ("supported", "contradicted", "not_established")
DEFAULT_GLOBS = "*.decision.zip,*.verdict.zip,decision.zip,verdict.zip"
REPLAY_TIMEOUT_SECONDS = 120


class Refused(Exception):
    """The bundle could not be replayed; carries the message to show."""


def replay_command() -> list[str]:
    """The command line that runs ``probity-bundle``, pinned to one version."""
    override = os.environ.get("PROBITY_BUNDLE_CMD")
    if override:
        return shlex.split(override)
    if shutil.which("probity-bundle"):
        return ["probity-bundle"]
    if shutil.which("uvx"):
        return ["uvx", "--from", PINNED, "probity-bundle"]
    raise Refused(
        f"probity-bundle is not installed and uvx is not available; "
        f"run: pip install {PINNED}"
    )


def replay(bundle: Path) -> dict[str, Any]:
    """Replay one bundle and return the decision packet as a dict."""
    if not bundle.is_file():
        raise Refused(f"{bundle}: no such file")
    command = [*replay_command(), "replay", str(bundle), "--json"]
    try:
        done = subprocess.run(
            command, capture_output=True, timeout=REPLAY_TIMEOUT_SECONDS, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused(f"{bundle}: the replay did not run: {exc}") from exc
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip() or f"exit {done.returncode}"
        raise Refused(f"{bundle}: replay refused the bundle: {detail}")
    try:
        packet = json.loads(done.stdout)
    except ValueError as exc:
        raise Refused(f"{bundle}: replay printed no decision packet: {exc}") from exc
    if not isinstance(packet, dict) or packet.get("decision") not in DECISIONS:
        raise Refused(f"{bundle}: replay printed an unreadable decision")
    return packet


def parse_allow(text: str) -> frozenset[str]:
    """Turn ``supported,not_established`` into a checked set of decisions."""
    wanted = frozenset(part.strip() for part in text.split(",") if part.strip())
    unknown = wanted - set(DECISIONS)
    if not wanted or unknown:
        raise Refused(f"--allow takes some of {', '.join(DECISIONS)}; got {text!r}")
    return wanted


def check(bundle: Path, allowed: frozenset[str]) -> tuple[int, str]:
    """Return the exit code and one line describing the verdict on a bundle."""
    try:
        packet = replay(bundle)
    except Refused as exc:
        return 2, f"FAIL {exc}"
    decision, reason = packet["decision"], packet.get("reason", "")
    if decision in allowed:
        return 0, f"OK {bundle}: {decision} ({reason})"
    return 1, f"FAIL {bundle}: decision is {decision} ({reason}); allowed: {', '.join(sorted(allowed))}"


def strings(node: Any) -> Iterator[str]:
    """Every string inside a decoded JSON value."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


def bundle_paths(payload: Any, globs: list[str], cwd: Path) -> list[Path]:
    """Existing files named in a hook payload whose names match a bundle pattern."""
    found: list[Path] = []
    for text in strings(payload):
        for token in text.replace('"', " ").replace("'", " ").split():
            if not any(fnmatch.fnmatch(Path(token).name, glob) for glob in globs):
                continue
            path = Path(token) if os.path.isabs(token) else cwd / token
            if path.is_file() and path not in found:
                found.append(path)
    return found


def run_hook(allowed: frozenset[str]) -> int:
    """Hook mode: gate every bundle the payload names."""
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0  # not a hook payload: nothing named a bundle
    globs = [g.strip() for g in os.environ.get("PROBITY_BUNDLE_GLOBS", DEFAULT_GLOBS).split(",")]
    cwd = Path(payload.get("cwd") or os.getcwd()) if isinstance(payload, dict) else Path.cwd()
    status = 0
    for path in bundle_paths(payload, [g for g in globs if g], cwd):
        code, line = check(path, allowed)
        print(line, file=sys.stderr if code else sys.stdout)
        status = max(status, code)
    return 2 if status else 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for both modes."""
    parser = argparse.ArgumentParser(prog="verify_bundle", description=__doc__.split("\n\n")[0])
    parser.add_argument("bundle", nargs="?", type=Path)
    parser.add_argument("--hook", action="store_true", help="read a hook payload on stdin")
    parser.add_argument("--allow", default=os.environ.get("PROBITY_BUNDLE_ALLOW", "supported"))
    args = parser.parse_args(argv)
    try:
        allowed = parse_allow(args.allow)
    except Refused as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    if args.hook:
        return run_hook(allowed)
    if args.bundle is None:
        parser.error("name a bundle or pass --hook")
    code, line = check(args.bundle, allowed)
    print(line, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
