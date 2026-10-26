"""Check that the latest published releases of the package family install together.

    python3 scripts/family_resolves.py lint      # no in-family requirement uses `==`
    python3 scripts/family_resolves.py resolve   # install the latest of all, pip check, import each

The family is pre-1.0, so an exact pin of one family member by another makes the
latest releases unresolvable as a set (measured 2026-10-26). In-family requirements
use compatible-release ranges (`~=X.Y.Z`); third-party pins stay exact. Standard
library only for `lint`; `resolve` needs `uv` on PATH.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# distribution -> (install spec, import name)
FAMILY = {
    "agent-evidence-vocabulary": ("agent-evidence-vocabulary", "agent_evidence_vocabulary"),
    "agent-evidence-admission": ("agent-evidence-admission", "agent_evidence_admission"),
    "agent-evidence-vectors": ("agent-evidence-vectors", "agent_evidence_vectors"),
    "agent-evidence-observer": ("agent-evidence-observer[done,witness]", "probity_observer"),
    "agent-evidence-mcp": ("agent-evidence-mcp", "agent_evidence_mcp"),
    "probity-verify": ("probity-verify", "probity_verify"),
    "probity-ratchet": ("probity-ratchet", "ratchet"),
    "probity-ratchet-cases": ("probity-ratchet-cases", "ratchet_cases"),
    "jcs-admit": ("jcs-admit", "jcs_admit"),
}
_EXACT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*===?\s*\S")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(data: dict) -> list[str]:
    project = data.get("project", {})
    out = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        out += extra
    for group in data.get("dependency-groups", {}).values():
        out += [item for item in group if isinstance(item, str)]
    return out


def lint(root: Path = ROOT) -> list[str]:
    """Every pyproject under packages/ whose in-family requirement is an exact pin."""
    family = {_norm(name) for name in FAMILY}
    problems = []
    for path in sorted(root.glob("packages/**/pyproject.toml")):
        # interop/ holds dated, frozen experiments that pin the release they were run against
        if {".venv", "node_modules", "interop"} & set(path.parts):
            continue
        for req in _requirements(tomllib.loads(path.read_text(encoding="utf-8"))):
            match = _EXACT.match(req.split(";")[0])
            if match and _norm(match.group(1)) in family:
                problems.append(f"{path.relative_to(root)}: in-family requirement {req!r} must be a range (~=X.Y.Z)")
    return problems


def resolve() -> int:
    specs = [spec for spec, _ in FAMILY.values()]
    with tempfile.TemporaryDirectory() as tmp:
        venv = Path(tmp, "venv")
        python = venv / "bin" / "python"
        subprocess.run(["uv", "venv", "--python", "3.12", str(venv)], check=True)
        installed = subprocess.run(["uv", "pip", "install", "--python", str(python), *specs], check=False)
        if installed.returncode:
            print("FAIL: the latest releases of the family do not install together", file=sys.stderr)
            return 1
        subprocess.run(["uv", "pip", "freeze", "--python", str(python)], check=True)
        if subprocess.run(["uv", "pip", "check", "--python", str(python)], check=False).returncode:
            print("FAIL: uv pip check found a broken requirement", file=sys.stderr)
            return 1
        code = "import importlib,sys\nfor n in sys.argv[1:]: importlib.import_module(n)\nprint('imported', len(sys.argv) - 1)"
        if subprocess.run([str(python), "-c", code, *(imp for _, imp in FAMILY.values())], check=False).returncode:
            print("FAIL: a family package does not import", file=sys.stderr)
            return 1
    print(f"OK: {len(FAMILY)} family packages install together, pass pip check and import")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["lint"]:
        problems = lint()
        print("\n".join(problems) or "OK: no in-family exact pin")
        return 1 if problems else 0
    if argv[1:] == ["resolve"]:
        return resolve()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
