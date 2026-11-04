"""Verify the retained native APS refund captures with public code only.

Runs the installed public reader, with the profile verifier and a Node
runtime, over every retained capture and requires its exit status, stdout and
stderr to equal the bytes retained with the capture. Needs the locked npm
package installed in this directory (``npm ci --ignore-scripts``).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RETAINED = HERE / "retained"
NATIVE_CASES = ("restart", "cross-instance", "after-intent", "inside-effect-transaction", "lost-ack",
                "approval-reissue", "different-action-first", "different-action")


def read(case: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the public reader on one capture under the policy pin its bytes select.

    The reader reports the capture directory's own name, so a capture whose
    retained output names a different directory is read from a copy under that name.
    """
    stdout = case / "consumer-stdout.bin"
    named = json.loads(stdout.read_bytes()).get("case") if stdout.is_file() and stdout.stat().st_size else None
    if named is not None and named != case.name:
        with tempfile.TemporaryDirectory() as scratch:
            copy = Path(scratch) / named
            shutil.copytree(case, copy)
            return run_reader(copy)
    return run_reader(case)


def run_reader(case: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the installed public reader CLI on one capture directory."""
    pin = hashlib.sha256((case / "host-policy.json").read_bytes()).hexdigest()
    node = shutil.which("node")
    if node is None:
        raise SystemExit("node is required to run the retained reader")
    command = [sys.executable, "-I", "-B", "-m", "probity_aps_refund.reader", str(case),
               "--policy-sha256", pin, "--node", str(Path(node).resolve()),
               "--verifier", str(HERE / "verify-aps.mjs")]
    return subprocess.run(command, capture_output=True, timeout=60, check=False)


def native_failures() -> list[str]:
    """Return native captures whose reader output differs from the retained output."""
    failures = []
    for name in NATIVE_CASES:
        result = read(RETAINED / "native" / name)
        if result.returncode != 0 or result.stderr or result.stdout != (RETAINED / (name + "-reader.json")).read_bytes():
            failures.append("native/" + name)
    return failures


def control_failures(directory: str, record_name: str, exit_key: str) -> list[str]:
    """Return hostile or temporal captures whose consumer outcome differs from the record."""
    failures = []
    root = RETAINED / directory
    inventory = json.loads((root / "inventory.json").read_bytes())
    for kind in sorted(inventory["cases"]):
        case = root / kind
        record = json.loads((case / record_name).read_bytes())
        result = read(case)
        if (result.returncode != record[exit_key] or result.stdout != (case / "consumer-stdout.bin").read_bytes()
                or result.stderr != (case / "consumer-stderr.txt").read_bytes()):
            failures.append(directory + "/" + kind)
    return failures


def main() -> int:
    """Exit zero only when every retained capture reads exactly as retained."""
    failures = (native_failures() + control_failures("public-hostile-controls", "consumer-check.json", "exit")
                + control_failures("public-temporal-controls", "temporal-check.json", "readerExit"))
    for failure in failures:
        print("retained capture differs: " + failure, file=sys.stderr)
    if failures:
        return 1
    print("retained APS refund captures verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
