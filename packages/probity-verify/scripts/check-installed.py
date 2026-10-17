"""Exercise the installed sample API and CLI from outside the source checkout."""

from __future__ import annotations

import hashlib
from importlib import resources
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import probity_verify
from probity_verify import adjudicate


def check() -> None:
    source = Path(__file__).resolve().parents[1]
    installed = Path(probity_verify.__file__).resolve()
    if installed.is_relative_to(source):
        raise ValueError("consumer imported the source checkout")
    bindings = {}
    with tempfile.TemporaryDirectory(prefix="verify-installed-") as output:
        root = Path(output)
        for item in resources.files("probity_verify.samples").iterdir():
            if item.name.endswith((".json", ".html", ".txt")):
                raw = item.read_bytes()
                (root / item.name).write_bytes(raw)
                bindings[item.name] = hashlib.sha256(raw).hexdigest()
        command = str(Path(sys.executable).parent / "probity-verify")
        results = []
        for case, policy, decision, reason in [
            ("case.json", "policy-june.json", "contradicted", "selected_span_missing_from_record"),
            ("case.json", "policy-april.json", "not_established", "witness_outside_source_window"),
            ("case-complete.json", "policy-complete.json", "supported", "all_selected_spans_present"),
        ]:
            expected = adjudicate(json.loads((root / case).read_bytes()),
                                  json.loads((root / policy).read_bytes()), root)
            result = subprocess.run([command, str(root / case), "--policy", str(root / policy), "--json"],
                                    cwd=root, capture_output=True, check=False)
            if result.returncode != 0 or result.stderr or json.loads(result.stdout) != expected:
                raise ValueError(f"installed API and CLI differ: {case}, {policy}")
            if (expected["decision"], expected["reason"]) != (decision, reason):
                raise ValueError(f"installed sample decision changed: {case}, {policy}")
            results.append({"decision": decision, "reason": reason, "exit_code": result.returncode})
        malformed = root / "malformed.json"
        malformed.write_bytes(b"{")
        refused = subprocess.run([command, str(malformed), "--policy", str(root / "policy-june.json"), "--json"],
                                 cwd=root, capture_output=True, check=False)
        if refused.returncode != 2 or refused.stdout or not refused.stderr.startswith(b"probity-verify:"):
            raise ValueError("malformed input must exit 2 without a verdict")
    print(json.dumps({"installed_module": str(installed), "sample_bindings": bindings,
                      "decisions": results, "malformed_exit_code": refused.returncode}, sort_keys=True))


if __name__ == "__main__":
    check()
