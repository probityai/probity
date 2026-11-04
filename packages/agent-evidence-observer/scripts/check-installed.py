"""Verify a retained broker packet with the installed offline verifier."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import probity_observer

source = Path(__file__).resolve().parents[1]
installed = Path(probity_observer.__file__).resolve()
if installed.is_relative_to(source):
    raise ValueError("consumer imported the source checkout")
packet = Path(__file__).resolve().parent / "fixtures" / "broker-packet"
command = str(Path(sys.executable).parent / "agent-evidence-observer")
expected = {"noDetectedGap": "true", "status": "verified", "witnessScope": "PEER"}


def tree_digest(directory: Path) -> dict[str, str]:
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob("*")) if p.is_file()}


with tempfile.TemporaryDirectory(prefix="observer-installed-") as output:
    root = Path(output)
    before = tree_digest(packet)
    done = subprocess.run([command, "verify", str(packet)], cwd=root, capture_output=True, check=False)
    if done.returncode != 0 or done.stderr or json.loads(done.stdout) != expected:
        raise ValueError(f"installed verifier rejected the retained packet: {done.returncode}, {done.stderr!r}")
    if tree_digest(packet) != before:
        raise ValueError("verification must not change the retained packet")
    altered_copy = root / "altered-packet"
    shutil.copytree(packet, altered_copy)
    result = altered_copy / "workspace/result.txt"
    result.write_bytes(result.read_bytes() + b"altered\n")
    altered = subprocess.run([command, "verify", str(altered_copy)], cwd=root, capture_output=True, check=False)
    if altered.returncode == 0 or altered.stdout:
        raise ValueError("altered retained effects must not produce a verified result")
print(json.dumps({"installed_module": str(installed), "results": [expected],
                  "altered_effect_exit_code": altered.returncode}, sort_keys=True))
