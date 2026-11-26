"""Check that the latest published releases of the package family install together.

    python3 scripts/family_resolves.py lint              # no in-family requirement uses `==`
    python3 scripts/family_resolves.py resolve           # install the latest of all, pip check, import each
    python3 scripts/family_resolves.py candidate DIST    # refuse a built release that strands the family

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
admits the member's current release and the one after it, and the lint holds the tree to it: the
pull request that bumps the member must move every dependent's window in the same change, where
the workspace tests run the dependents against the new version before it ships.
Requirements on family members that live outside this workspace stay `~=`, because their next
release is not known here; family-resolves reads PyPI daily and catches those.

Moving a window in the tree does not move the window of the release already on PyPI. So a
member's second minor release after a dependent's last release strands that dependent: on
2026-11-24 agent-evidence-verify 0.10.0 was published while PyPI's agent-evidence-mcp 0.2.7 still
required verify<0.10 (main had allowed <0.12 since the 0.9.0 bump), and the same shape broke the
family on 2026-10-26, 2026-10-28, 2026-10-30 and 2026-11-21. `candidate` is the gate that refuses
such a release before it is uploaded. The release workflow runs it on the files it built, and
every publish job needs it. It fails when:
  1. the latest PyPI release of any family member or any distribution published from this
     workspace requires the candidate's distribution in a range that excludes the candidate's
     version (release that dependent first; its tree window already admits the new version);
  2. the candidate requires a family member, or a distribution of this workspace, in a range
     that excludes that member's latest PyPI release (the candidate would be stranded at birth);
  3. the candidate, installed beside the latest release of every other family member, fails to
     install, `uv pip check` or import, while the latest releases alone pass. When the latest
     releases are already broken without the candidate, checks 1 and 2 decide, so the release that
     repairs one break is never held back by another.
A registry read that fails is an error, never a pass. Checks 1 and 2 read every requirement on
the distribution, extras and environment markers included, so a requirement that applies only to
one extra or one platform still counts.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
import zipfile
from email.parser import HeaderParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# distribution -> (install spec, import name)
FAMILY = {
    "agent-evidence-vocabulary": ("agent-evidence-vocabulary", "agent_evidence_vocabulary"),
    "agent-evidence-admission": ("agent-evidence-admission", "agent_evidence_admission"),
    "agent-evidence-vectors": ("agent-evidence-vectors", "agent_evidence_vectors"),
    "agent-evidence-observer": ("agent-evidence-observer[done,witness]", "probity_observer"),
    "agent-evidence-mcp": ("agent-evidence-mcp", "agent_evidence_mcp"),
    "agent-evidence-verify": ("agent-evidence-verify", "agent_evidence_verify"),
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


_IMPORT = "import importlib,sys\nfor n in sys.argv[1:]: importlib.import_module(n)\nprint('imported', len(sys.argv) - 1)"


def install_set(specs: list[str], imports: list[str]) -> str | None:
    """Install `specs` into one fresh environment, run `uv pip check` and import each of `imports`.

    Returns None when all three pass, else the step that failed: "install", "check" or "import".
    """
    with tempfile.TemporaryDirectory() as tmp:
        venv = Path(tmp, "venv")
        python = venv / "bin" / "python"
        subprocess.run(["uv", "venv", "--python", "3.12", str(venv)], check=True)
        if subprocess.run(["uv", "pip", "install", "--python", str(python), *specs], check=False).returncode:
            return "install"
        subprocess.run(["uv", "pip", "freeze", "--python", str(python)], check=True)
        if subprocess.run(["uv", "pip", "check", "--python", str(python)], check=False).returncode:
            return "check"
        if subprocess.run([str(python), "-c", _IMPORT, *imports], check=False).returncode:
            return "import"
    return None


_FAILED = {
    "install": "the latest releases of the family do not install together",
    "check": "uv pip check found a broken requirement",
    "import": "a family package does not import",
}


def resolve() -> int:
    latest = latest_versions()
    print("latest on PyPI:", ", ".join(f"{name} {ver}" for name, ver in latest.items()), flush=True)
    failed = install_set(pinned_specs(latest), [imp for _, imp in FAMILY.values()])
    if failed:
        print(f"FAIL: {_FAILED[failed]}", file=sys.stderr)
        return 1
    print(f"OK: {len(FAMILY)} family packages install together, pass pip check and import")
    return 0


# --- the pre-publication gate -------------------------------------------------------------

_CLAUSE = re.compile(r"\s*(===|==|!=|<=|>=|~=|<|>)\s*(\S+?)\s*")
_PLAIN = re.compile(r"\d+(?:\.\d+)*")
_REQUIREMENT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)")


def _release(text: str) -> tuple[int, ...]:
    if not _PLAIN.fullmatch(text):
        raise ValueError(f"{text!r} is not a plain release number")
    return tuple(int(part) for part in text.split("."))


def _padded(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def admits(specifier: str, version: str) -> bool:
    """Whether the PEP 440 `specifier` admits the plain release `version` (an empty one admits all).

    Raises ValueError for a clause this reader cannot judge (a pre-release bound, a URL), so an
    unreadable range is reported, never read as admitting.
    """
    have = _release(version)
    for clause in filter(str.strip, specifier.split(",")):
        match = _CLAUSE.fullmatch(clause)
        if not match:
            raise ValueError(f"cannot read the clause {clause.strip()!r}")
        op, text = match.groups()
        if op == "===":
            ok = text == version
        elif op in ("==", "!=") and text.endswith(".*"):
            prefix = _release(text[:-2])
            ok = (have + (0,) * len(prefix))[: len(prefix)] == prefix
            ok = ok if op == "==" else not ok
        else:
            want = _release(text)
            a, b = _padded(have, want)
            if op == "~=":
                if len(want) < 2:
                    raise ValueError(f"{clause.strip()!r} needs at least two release parts")
                ok = a >= b and a[: len(want) - 1] == want[:-1]
            else:
                ok = {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        if not ok:
            return False
    return True


def split_requirement(requirement: str) -> tuple[str, str]:
    """The normalised distribution name and the version specifier of a Requires-Dist line."""
    match = _REQUIREMENT.fullmatch(requirement.split(";")[0])
    if not match:
        raise ValueError(f"cannot read the requirement {requirement!r}")
    spec = match.group(2).strip()
    if spec.startswith("(") and spec.endswith(")"):
        spec = spec[1:-1].strip()
    return _norm(match.group(1)), spec


def pypi_project(name: str) -> dict | None:
    """The PyPI JSON of `name`, or None when PyPI answers 404. Any other failure raises."""
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return None
        raise


def read_wheel(dist: Path) -> tuple[Path, str, str, list[str]]:
    """The one wheel in `dist` (a directory or the wheel itself): path, normalised name, version, Requires-Dist."""
    wheels = sorted(dist.glob("*.whl")) if dist.is_dir() else [dist]
    if len(wheels) != 1:
        raise ValueError(f"expected exactly one wheel in {dist}, found {len(wheels)}")
    with zipfile.ZipFile(wheels[0]) as archive:
        metadata = [n for n in archive.namelist() if n.count("/") == 1 and n.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise ValueError(f"{wheels[0].name} holds {len(metadata)} METADATA files")
        message = HeaderParser().parsestr(archive.read(metadata[0]).decode("utf-8"))
    return wheels[0], _norm(message["Name"]), message["Version"], message.get_all("Requires-Dist") or []


def gate_names(root: Path = ROOT) -> set[str]:
    """The family and every distribution whose source is in this workspace: whose releases must install together."""
    names = {_norm(name) for name in FAMILY}
    for _, data in _manifests(root):
        if name := data.get("project", {}).get("name"):
            names.add(_norm(name))
    return names


def stranded_dependents(name: str, version: str, registry: dict[str, dict | None]) -> list[str]:
    """Check 1: every latest release in `registry` whose requirement on `name` excludes `version`."""
    problems = []
    for other, project in sorted(registry.items()):
        if other == name or project is None:
            continue
        latest = project["info"]["version"]
        for requirement in project["info"].get("requires_dist") or []:
            dependency, spec = split_requirement(requirement)
            if dependency != name:
                continue
            try:
                ok = admits(spec, version)
            except ValueError as err:
                problems.append(f"{other} {latest} requires {requirement!r}, which this check cannot judge: {err}")
                continue
            if not ok:
                problems.append(
                    f"{other} {latest}, its latest release on PyPI, requires {requirement!r}, which excludes "
                    f"{name} {version}: release {other} with a range that admits {version} first"
                )
    return problems


def stranded_candidate(name: str, version: str, requires: list[str], registry: dict[str, dict | None]) -> list[str]:
    """Check 2: every requirement of the candidate on a gated distribution that excludes that one's latest release."""
    problems = []
    for requirement in requires:
        dependency, spec = split_requirement(requirement)
        if dependency == name or dependency not in registry:
            continue
        project = registry[dependency]
        if project is None:
            problems.append(f"{name} {version} requires {requirement!r}, and {dependency} has no release on PyPI")
            continue
        latest = project["info"]["version"]
        try:
            ok = admits(spec, latest)
        except ValueError as err:
            problems.append(f"{name} {version} requires {requirement!r}, which this check cannot judge: {err}")
            continue
        if not ok:
            problems.append(
                f"{name} {version} requires {requirement!r}, which excludes {dependency} {latest}, its latest release on PyPI"
            )
    return problems


def candidate(dist: Path, root: Path = ROOT, fetch=pypi_project, install=install_set) -> int:
    """Refuse a built release that would leave the latest releases unable to install together."""
    wheel, name, version, requires = read_wheel(dist)
    names = sorted(gate_names(root) | {name})
    registry = {other: fetch(other) for other in names}
    unpublished = [other for other, project in registry.items() if project is None]
    print(f"candidate {name} {version} from {wheel.name}; read {len(names) - len(unpublished)} of {len(names)} "
          f"distributions from PyPI, not published: {', '.join(unpublished) or 'none'}", flush=True)
    problems = stranded_dependents(name, version, registry) + stranded_candidate(name, version, requires, registry)
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    family = {_norm(other): other for other in FAMILY}
    missing = [other for other in family if other != name and registry[other] is None]
    if missing:
        print(f"FAIL: family members with no release on PyPI: {', '.join(missing)}", file=sys.stderr)
        return 1
    latest = {family[other]: registry[other]["info"]["version"] for other in family if registry[other] is not None}
    imports = [imp for _, imp in FAMILY.values()]
    extras = re.sub(r"^[^\[]*", "", FAMILY[family[name]][0]) if name in family else ""
    with_candidate = [f"{name}{extras} @ {wheel.resolve().as_uri()}"]
    with_candidate += [f"{s}=={latest[other]}" for other, (s, _) in FAMILY.items() if _norm(other) != name]
    failed = install(with_candidate, imports)
    if failed is None:
        print(f"OK: {name} {version} installs beside the latest release of every other family member, "
              f"passes pip check and imports; no published release requires a range that excludes it")
        return 0
    baseline = install([f"{s}=={latest[other]}" for other, (s, _) in FAMILY.items() if other in latest],
                       [imp for other, (_, imp) in FAMILY.items() if other in latest])
    if baseline is None:
        print(f"FAIL: with {name} {version}, {_FAILED[failed]}; the latest releases alone pass", file=sys.stderr)
        return 1
    print(f"WARNING: the latest releases already fail without {name} {version} ({_FAILED[baseline]}); "
          f"checks 1 and 2 found no conflict this release adds, so it is not held back", file=sys.stderr)
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["lint"]:
        problems = lint()
        print("\n".join(problems) or "OK: no in-family exact pin")
        return 1 if problems else 0
    if argv[1:] == ["resolve"]:
        return resolve()
    if len(argv) == 3 and argv[1] == "candidate":
        return candidate(Path(argv[2]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
