"""Run the installed ``agent-evidence-a2a`` command from outside the source checkout.

python-build.yml runs this in a fresh virtual environment after installing the built wheel, and
again after installing the wheel rebuilt from the source distribution. It checks the release
promise: one console script, the shipped corpora read from the installed package with the verdicts
the README states, and the TLS probe judging a plaintext endpoint without opening a connection.
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.metadata import distribution, version
from pathlib import Path

import agent_evidence_a2a

NAME = "agent-evidence-a2a"


def _run(*args: str) -> tuple[int, object]:
    done = subprocess.run(args, capture_output=True, text=True, check=False)
    try:
        return done.returncode, json.loads(done.stdout)
    except json.JSONDecodeError:
        raise SystemExit(f"{' '.join(args)} printed no JSON (exit {done.returncode}): {done.stderr}") from None


def _expect(label: str, got: object, want: object) -> None:
    if got != want:
        raise SystemExit(f"{label}: got {got!r}, expected {want!r}")


def check() -> dict[str, object]:
    source = Path(__file__).resolve().parents[1]
    if Path(agent_evidence_a2a.__file__).resolve().is_relative_to(source):
        raise SystemExit("consumer imported the source checkout")
    _expect("__version__", agent_evidence_a2a.__version__, version(NAME))
    scripts = sorted(ep.name for ep in distribution(NAME).entry_points if ep.group == "console_scripts")
    _expect("console scripts", scripts, [NAME])
    command = str(Path(sys.executable).parent / NAME)

    code, corpus = _run(command, "corpus")
    assert isinstance(corpus, dict)
    _expect("corpus exit", code, 0)
    _expect("corpus", (corpus["detected"], corpus["missed"], corpus["false_rejects"], len(corpus["pending"])),
            (28, [], [], 4))

    code, ssrf = _run(command, "ssrf")
    assert isinstance(ssrf, dict)
    _expect("ssrf exit", code, 0)
    _expect("ssrf", (ssrf["caught"], ssrf["missed"], ssrf["false_flags"]), (30, [], []))

    code, canon = _run(command, "canonicaliser")
    assert isinstance(canon, dict)
    _expect("canonicaliser", (code, canon["total"], canon["passed"]), (0, 57, 57))

    code, tls = _run(command, "tls", "http://agent.example.com/a2a")
    assert isinstance(tls, list)
    _expect("tls exit", code, 1)
    _expect("tls", [(r["id"], r["outcome"]) for r in tls[0]["results"]],
            [("AUTH-TLS-001", "violated"), ("AUTH-TLS-002", "not-applicable"), ("AUTH-SERVER-001", "not-applicable")])

    return {"command": NAME, "version": version(NAME), "console_scripts": scripts,
            "cards_detected": corpus["detected"], "cards_pending": len(corpus["pending"]),
            "ssrf_caught": ssrf["caught"], "vectors_passed": canon["passed"]}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2, sort_keys=True))
