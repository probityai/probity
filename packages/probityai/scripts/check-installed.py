"""Run the installed ``probityai`` command from outside the source checkout.

python-build.yml runs this in a fresh virtual environment after installing the built wheel, and
again after installing the wheel rebuilt from the source distribution. It checks the release
promise: one command named ``probityai`` (no other console script), a ``--version`` that names the
installed version, a ``verify`` subcommand supplied by probity-verify, and a sample claim decided.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from importlib import resources
from importlib.metadata import distribution, version
from pathlib import Path

import probityai


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def check() -> dict[str, object]:
    source = Path(__file__).resolve().parents[1]
    if Path(probityai.__file__).resolve().is_relative_to(source):
        raise SystemExit("consumer imported the source checkout")
    scripts = sorted(ep.name for ep in distribution("probityai").entry_points if ep.group == "console_scripts")
    if scripts != ["probityai"]:
        raise SystemExit(f"console scripts are {scripts}, expected exactly ['probityai']")
    command = Path(sys.executable).parent / "probityai"
    if not command.exists():
        raise SystemExit(f"{command} is missing")
    if shutil.which("probity", path=str(command.parent)):
        raise SystemExit("a 'probity' command is installed beside 'probityai'")
    shown = _run(str(command), "--version")
    expected = f"probityai {version('probityai')}"
    if shown.returncode != 0 or shown.stdout.strip() != expected:
        raise SystemExit(f"--version printed {shown.stdout!r} (exit {shown.returncode}), expected {expected!r}")
    helped = _run(str(command), "--help")
    if helped.returncode != 0 or "verify" not in helped.stdout:
        raise SystemExit(f"--help does not list verify: {helped.stdout!r}")
    samples = resources.files("probity_verify") / "samples"
    with tempfile.TemporaryDirectory(prefix="probityai-installed-") as out:
        for item in samples.iterdir():
            if item.name.endswith((".json", ".html", ".txt")):
                (Path(out) / item.name).write_bytes(item.read_bytes())
        ran = _run(str(command), "verify", f"{out}/case.json", "--policy", f"{out}/policy-june.json", "--json")
    if ran.returncode != 0:
        raise SystemExit(f"probityai verify exited {ran.returncode}: {ran.stderr}")
    result = json.loads(ran.stdout)
    if (result["decision"], result["reason"]) != ("contradicted", "selected_span_missing_from_record"):
        raise SystemExit(f"unexpected decision {result['decision']!r} / {result['reason']!r}")
    return {"command": "probityai", "version": version("probityai"), "console_scripts": scripts,
            "sample_decision": result["decision"], "sample_reason": result["reason"]}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2, sort_keys=True))
