"""Materialize the original eight reviewed source selections for a clean host.

This is trusted installation setup, not candidate execution. Repository names,
exact revisions and every tracked-file hash come from the original fixed public
selection. Candidate bytes cannot select a repository, revision or build script.
"""

from __future__ import annotations

import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from trust import SOURCE_SHA256, read_json, refuse, sha256, validate_sources, write_json

PROFILE = Path(__file__).resolve().parent


def checkout(name: str, component: dict[str, Any], root: Path, logs: Path) -> None:
    """Clone and detach one selected public source, preserving raw Git streams."""
    target = root / name
    commands = [
        ["git", "clone", "--quiet", "https://github.com/" + component["repository"] + ".git", str(target)],
        # A selected head may now sit only behind a closed pull request after a
        # history rewrite, where a plain clone no longer carries it.
        ["git", "-C", str(target), "fetch", "--quiet", "origin", component["head"]],
        ["git", "-C", str(target), "checkout", "--detach", component["head"]],
    ]
    for index, command in enumerate(commands):
        try:
            result = subprocess.run(command, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired:
            refuse(refusal_reason(name, component, index, command, None, b"timed out after 180 seconds"))
        prefix = logs / (name + "-" + str(index))
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        write_json(prefix.with_suffix(".process.json"), {"command": command, "returnCode": result.returncode})
        if result.returncode != 0:
            refuse(refusal_reason(name, component, index, command, result.returncode, result.stderr))


def refusal_reason(
    name: str, component: dict[str, Any], index: int, command: list[str], return_code: int | None, stderr: bytes
) -> str:
    """Name the failing source, step and Git error so a refusal states its cause.

    The inputs are the fixed public selection and Git's own output, never
    candidate bytes, so the text is safe to put in the refusal.
    """
    detail = stderr.decode("utf-8", "replace").strip()[-2000:] or "no Git output"
    step = command[3] if command[1] == "-C" else command[1]
    return (
        "selected public source materialization failed: source " + name
        + " repository " + component["repository"]
        + " commit " + component["head"]
        + " step " + str(index) + " (git " + step + ")"
        + " returned " + ("timeout" if return_code is None else str(return_code))
        + ": " + detail
    )


def main() -> None:
    """Prepare all frozen sources in parallel, then verify all tracked bytes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    args = parser.parse_args()
    if sha256((PROFILE / "SOURCE-SELECTION.json").read_bytes()) != SOURCE_SHA256:
        refuse("original component source selection differs")
    args.output.mkdir()
    args.logs.mkdir()
    selection = read_json(PROFILE / "SOURCE-SELECTION.json")
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(checkout, name, component, args.output.resolve(), args.logs.resolve())
                   for name, component in selection["components"].items()]
        for future in futures:
            future.result()
    validate_sources(PROFILE, args.output)
    write_json(args.logs / "source-byte-verification.json", {
        "sourceSelectionSha256": SOURCE_SHA256,
        "components": {name: {"head": component["head"], "verifiedFiles": len(component["files"])}
                       for name, component in selection["components"].items()},
    })


if __name__ == "__main__":
    main()
