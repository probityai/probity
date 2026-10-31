"""Check that the latest published releases of the package family install together.

    python3 scripts/family_resolves.py lint      # no in-family requirement uses `==`
    python3 scripts/family_resolves.py resolve   # install the latest of all, pip check, import each

`resolve` pins every member to its latest version on PyPI. Bare names would let
the resolver fall back to an older release of one member to satisfy another,
which is the failure this check exists to catch (on 2026-10-26 uv "resolved"
verify 0.2.0 with vocabulary 0.7.0 only by silently installing verify 0.1.1).

The family is pre-1.0, so an exact pin of one family member by another makes the
latest releases unresolvable as a set (measured 2026-10-26). Third-party pins stay exact.
Standard library only for `lint`; `resolve` needs `uv` on PATH.

Range policy for a requirement on a member of this workspace. A compatible-release range
(`~=0.3.0`) stops at the next minor, so the day that member released 0.4 the published
dependents could no longer install beside it (probity-verify 0.3.0 on 2026-10-30 broke
probityai, probity-ratchet and agent-evidence-observer, and family-resolves went red until
three patch releases shipped). The range is therefore a window, `>=F,<C`: F is a release
the dependent was tested against (not above the member's version in this tree), and C is the
end of the NEXT release series, meaning minor+2 for 0.x and the next major from 1.0. The window
always admits the member's current release and the one after it, so a release of the member
never strands a published dependent, and a release of the member after that is held back by
the lint: the pull request that bumps the member must move every dependent's window in the same
change, where the workspace tests run the dependents against the new version before it ships.
Requirements on family members that live outside this workspace stay `~=`, because their next
release is not known here; family-resolves reads PyPI daily and catches those.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.request
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
_WINDOW = re.compile(r"\s*>=\s*(\d+)\.(\d+)\.(\d+)\s*,\s*<\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?\s*")
_NAME = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)")
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


def _manifests(root: Path) -> list[tuple[Path, dict]]:
    out = []
    for path in sorted(root.glob("packages/**/pyproject.toml")):
        # interop/ holds dated, frozen experiments that pin the release they were run against
        if {".venv", "node_modules", "interop"} & set(path.parts):
            continue
        out.append((path, tomllib.loads(path.read_text(encoding="utf-8"))))
    return out


def workspace_versions(root: Path = ROOT) -> dict[str, tuple[int, int, int]]:
    """Name and version of every family distribution whose source is in this tree."""
    family = {_norm(name) for name in FAMILY}
    out = {}
    for _, data in _manifests(root):
        project = data.get("project", {})
        name, version = _norm(project.get("name", "")), project.get("version", "")
        parts = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
        if name in family and parts:
            out[name] = (int(parts[1]), int(parts[2]), int(parts[3]))
    return out


def window_ceiling(version: tuple[int, int, int]) -> tuple[int, int]:
    """The end of the next release series: minor+2 below 1.0, the next major from 1.0."""
    major, minor, _ = version
    return (0, minor + 2) if major == 0 else (major + 1, 0)


def _window_problem(spec: str, version: tuple[int, int, int]) -> str | None:
    """Why `spec` is not the window for a member at `version`, or None when it is."""
    match = _WINDOW.fullmatch(spec)
    if not match:
        return "must be a window >=F,<C"
    floor, ceiling = tuple(map(int, match.group(1, 2, 3))), (int(match.group(4)), int(match.group(5) or 0))
    if floor > version:
        return f"floor {floor} is above the {version} in this tree"
    if match.group(6) not in (None, "0") or ceiling != window_ceiling(version):
        want = ".".join(map(str, window_ceiling(version)))
        return f"ceiling must be <{want}, the end of the series after {'.'.join(map(str, version))}"
    return None


def lint(root: Path = ROOT) -> list[str]:
    """Every in-family requirement under packages/ that breaks the policy in the module docstring."""
    family = {_norm(name) for name in FAMILY}
    members = workspace_versions(root)
    problems = []
    for path, data in _manifests(root):
        for req in _requirements(data):
            body = req.split(";")[0]
            where = f"{path.relative_to(root)}: in-family requirement {req!r}"
            match = _NAME.fullmatch(body)
            name = _norm(match.group(1)) if match else ""
            if name not in family:
                continue
            if _EXACT.match(body):
                problems.append(f"{where} must be a range, not an exact pin")
            elif name in members and (why := _window_problem(match.group(2).strip(), members[name])):
                problems.append(f"{where} {why}")
    return problems


def latest_versions() -> dict[str, str]:
    """The newest release of every family member, read from the PyPI JSON API."""
    out = {}
    for name in FAMILY:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as resp:
            out[name] = json.load(resp)["info"]["version"]
    return out


def pinned_specs(latest: dict[str, str]) -> list[str]:
    """Install specs that hold each member at its latest release, extras kept."""
    return [f"{spec}=={latest[name]}" for name, (spec, _) in FAMILY.items()]


def resolve() -> int:
    latest = latest_versions()
    print("latest on PyPI:", ", ".join(f"{name} {ver}" for name, ver in latest.items()), flush=True)
    specs = pinned_specs(latest)
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
