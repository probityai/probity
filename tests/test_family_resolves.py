"""The in-family lint, and the pre-publication gate that refuses a release which would strand the family."""

import importlib.util
import io
import re
import urllib.error
import zipfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("family_resolves", Path(__file__).resolve().parents[1] / "scripts" / "family_resolves.py")
fr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fr)


def project(tmp_path: Path, deps: str) -> Path:
    d = tmp_path / "packages" / "x"
    d.mkdir(parents=True)
    (d / "pyproject.toml").write_text(f'[project]\nname="x"\nversion="1"\ndependencies={deps}\n', encoding="utf-8")
    return tmp_path


def test_exact_in_family_pin_is_refused(tmp_path: Path) -> None:
    assert fr.lint(project(tmp_path, '["agent-evidence-verify==0.1.1"]'))


def test_underscore_spelling_and_extras_are_refused(tmp_path: Path) -> None:
    assert fr.lint(project(tmp_path, '["agent_evidence_observer[done]==0.1.0"]'))


def test_ranges_and_third_party_pins_pass(tmp_path: Path) -> None:
    assert fr.lint(project(tmp_path, '["agent-evidence-verify>=0.2.1,<0.4", "mcp==2.3.0", "jcs-admit>=0.1"]')) == []


def test_frozen_interop_experiments_may_pin(tmp_path: Path) -> None:
    d = tmp_path / "packages" / "observer" / "interop" / "run-2026-10-03"
    d.mkdir(parents=True)
    (d / "pyproject.toml").write_text('[project]\nname="y"\nversion="1"\ndependencies=["agent-evidence-observer==0.1.0"]\n', encoding="utf-8")
    assert fr.lint(tmp_path) == []


def test_resolve_pins_every_member_to_its_latest_release() -> None:
    latest = {name: f"9.{i}.0" for i, name in enumerate(fr.FAMILY)}
    specs = fr.pinned_specs(latest)
    assert len(specs) == len(fr.FAMILY)
    assert all(spec.endswith(f"=={latest[name]}") for spec, name in zip(specs, fr.FAMILY, strict=True))
    assert "agent-evidence-observer[done,witness]==9.3.0" in specs


def members(tmp_path: Path, verify: str, deps: str) -> Path:
    """A tree holding agent-evidence-verify at `verify` and one dependent with `deps`."""
    for name, version, dependencies in (("agent-evidence-verify", verify, "[]"), ("probityai", "0.1.0", deps)):
        d = tmp_path / "packages" / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "pyproject.toml").write_text(
            f'[project]\nname="{name}"\nversion="{version}"\ndependencies={dependencies}\n', encoding="utf-8"
        )
    return tmp_path


def test_window_ceiling_is_the_end_of_the_next_series() -> None:
    assert fr.window_ceiling((0, 3, 0)) == (0, 5)
    assert fr.window_ceiling((0, 3, 7)) == (0, 5)
    assert fr.window_ceiling((1, 4, 2)) == (2, 0)


def test_window_over_the_current_and_next_series_passes(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["agent-evidence-verify>=0.3.0,<0.5"]')) == []


def test_a_compatible_release_range_on_a_member_is_refused(tmp_path: Path) -> None:
    """The failure this policy exists for: ~=0.3.0 excluded 0.4 the day verify released it."""
    problems = fr.lint(members(tmp_path, "0.3.0", '["agent-evidence-verify~=0.3.0"]'))
    assert problems and "window" in problems[0]


def test_a_window_that_does_not_move_with_the_member_is_refused(tmp_path: Path) -> None:
    """Verify at 0.4.0 makes <0.5 stale: the bump must move every dependent in the same change."""
    problems = fr.lint(members(tmp_path, "0.4.0", '["agent-evidence-verify>=0.3.0,<0.5"]'))
    assert problems and "<0.6" in problems[0]


def test_a_window_wider_than_the_next_series_is_refused(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["agent-evidence-verify>=0.3.0,<1"]'))
    assert fr.lint(members(tmp_path, "0.3.0", '["agent-evidence-verify>=0.3.0"]'))


def test_a_floor_above_the_tree_is_refused(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["agent-evidence-verify>=0.4.0,<0.5"]'))


def test_a_member_from_one_point_zero_spans_one_major(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "1.2.0", '["agent-evidence-verify>=1.0.0,<2"]')) == []
    assert fr.lint(members(tmp_path, "1.2.0", '["agent-evidence-verify>=1.0.0,<3"]'))


def test_a_family_member_outside_the_tree_keeps_the_compatible_release(tmp_path: Path) -> None:
    assert fr.lint(members(tmp_path, "0.3.0", '["agent-evidence-vectors~=0.30.0"]')) == []


def test_the_real_tree_passes() -> None:
    assert fr.lint() == []


# --- the pre-publication gate ---------------------------------------------------------------

@pytest.mark.parametrize(
    ("spec", "version", "want"),
    [
        ("", "0.10.0", True),
        (">=0.5.0,<0.10", "0.10.0", False),
        (">=0.5.0,<0.10", "0.9.4", True),
        ("<0.10,>=0.5.0", "0.4.9", False),
        (">=0.5.0,<0.12", "0.10.0", True),
        ("<1", "0.39.0", True),
        ("<1.0", "1.0.0", False),
        ("~=0.1.0", "0.1.9", True),
        ("~=0.1.0", "0.2.0", False),
        ("~=0.32.1", "0.39.0", False),
        ("~=1.2", "1.9.0", True),
        ("~=1.2", "2.0.0", False),
        ("==0.2.7", "0.2.7", True),
        ("==0.2", "0.2.0", True),
        ("==0.2.*", "0.2.9", True),
        ("==0.2.*", "0.3.0", False),
        ("!=0.2.*", "0.3.0", True),
        ("!=0.2.7", "0.2.7", False),
        ("<=0.2.7", "0.2.7", True),
        (">0.2.7", "0.2.7", False),
        ("===0.2.7", "0.2.7", True),
        (" >= 0.5.0 , < 0.12 ", "0.11.3", True),
    ],
)
def test_admits_reads_the_ranges_the_family_publishes(spec: str, version: str, want: bool) -> None:
    assert fr.admits(spec, version) is want


@pytest.mark.parametrize("spec", [">=1.0rc1", "~=1", "@ https://example.org/x.whl", ">>1"])
def test_a_range_the_gate_cannot_judge_raises_instead_of_admitting(spec: str) -> None:
    with pytest.raises(ValueError):
        fr.admits(spec, "1.0.0")


@pytest.mark.parametrize(
    ("line", "want"),
    [
        ("agent-evidence-verify<0.10,>=0.5.0", ("agent-evidence-verify", "<0.10,>=0.5.0")),
        ('jcs-admit~=0.1.0; extra == "witness"', ("jcs-admit", "~=0.1.0")),
        ("Agent_Evidence.Vectors[x] (>=0.30,<1)", ("agent-evidence-vectors", ">=0.30,<1")),
        ("mcp==2.3.0", ("mcp", "==2.3.0")),
    ],
)
def test_split_requirement_normalises_the_name_and_keeps_the_range(line: str, want: tuple[str, str]) -> None:
    assert fr.split_requirement(line) == want


def published(version: str, *requires: str) -> dict:
    return {"info": {"version": version, "requires_dist": list(requires) or None}}


# The registry as PyPI served it on 2026-11-25, reduced to what the gate reads.
REGISTRY_1125 = {
    "agent-evidence-mcp": published(
        "0.2.7",
        "agent-evidence-verify<0.10,>=0.5.0",
        "agent-evidence-vectors<1,>=0.30.0",
        "agent-evidence-vocabulary<1,>=0.8.0",
        "agent-evidence-admission<1,>=0.2.0",
        "jcs-admit<1,>=0.1.0",
    ),
    "agent-evidence-verify": published("0.9.0", "agent-evidence-vocabulary<0.10,>=0.8.0"),
    "agent-evidence-vocabulary": published("0.9.0"),
    "agent-evidence-vectors": published("0.39.0"),
    "agent-evidence-admission": published("0.3.0"),
    "jcs-admit": published("0.1.1"),
    "agent-evidence-observer": published("0.2.0", 'jcs-admit~=0.1.0; extra == "witness"'),
    "probity-records": published("0.9.0", "agent-evidence-verify<0.12,>=0.9.0"),
    "probity-ratchet": published("0.4.0", "jcs-admit~=0.1.0", "probity-ratchet-cases~=0.2.0"),
    "probity-ratchet-cases": published("0.2.1"),
}


def test_the_verify_release_of_24_november_is_refused_for_stranding_mcp() -> None:
    """agent-evidence-verify 0.10.0 left PyPI's agent-evidence-mcp 0.2.7, capped at <0.10, unable to install beside it."""
    problems = fr.stranded_dependents("agent-evidence-verify", "0.10.0", REGISTRY_1125)
    assert len(problems) == 1
    assert problems[0].startswith("agent-evidence-mcp 0.2.7,") and "release agent-evidence-mcp" in problems[0]


def test_a_release_inside_every_published_range_strands_nobody() -> None:
    assert fr.stranded_dependents("agent-evidence-verify", "0.9.1", REGISTRY_1125) == []
    assert fr.stranded_dependents("agent-evidence-mcp", "0.2.8", REGISTRY_1125) == []


def test_a_requirement_carried_only_by_an_extra_still_counts() -> None:
    problems = fr.stranded_dependents("jcs-admit", "0.2.0", REGISTRY_1125)
    assert sorted(p.split(" ")[0] for p in problems) == ["agent-evidence-mcp", "agent-evidence-observer", "probity-ratchet"]


def test_an_unpublished_dependent_is_skipped_and_the_candidate_itself_is_not_its_own_dependent() -> None:
    registry = {**REGISTRY_1125, "agent-evidence-a2a": None}
    assert fr.stranded_dependents("agent-evidence-mcp", "0.2.8", registry) == []


def test_a_candidate_that_excludes_the_latest_release_of_a_member_is_refused() -> None:
    """The second half of the class: a release born stranded, such as mcp still capping verify at <0.10."""
    registry = {**REGISTRY_1125, "agent-evidence-verify": published("0.10.0")}
    requires = ["agent-evidence-verify<0.10,>=0.5.0", "mcp==2.3.0"]
    problems = fr.stranded_candidate("agent-evidence-mcp", "0.2.7", requires, registry)
    assert len(problems) == 1 and "excludes agent-evidence-verify 0.10.0" in problems[0]
    widened = ["agent-evidence-verify>=0.5.0,<0.12", "mcp==2.3.0"]
    assert fr.stranded_candidate("agent-evidence-mcp", "0.2.8", widened, registry) == []


def test_a_candidate_that_needs_a_member_never_published_is_refused() -> None:
    registry = {**REGISTRY_1125, "agent-evidence-a2a": None}
    problems = fr.stranded_candidate("x", "1.0.0", ["agent-evidence-a2a>=0.1.0,<0.3"], registry)
    assert problems and "has no release on PyPI" in problems[0]


def wheel(tmp_path: Path, name: str, version: str, *requires: str) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}", *(f"Requires-Dist: {r}" for r in requires)]
    path = dist / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{name.replace('-', '_')}-{version}.dist-info/METADATA", "\n".join(lines) + "\n\n")
    return dist


def test_read_wheel_takes_name_version_and_requirements_from_the_metadata(tmp_path: Path) -> None:
    dist = wheel(tmp_path, "agent-evidence-mcp", "0.2.8", "agent-evidence-verify>=0.5.0,<0.12", "mcp==2.3.0")
    path, name, version, requires = fr.read_wheel(dist)
    assert (path.parent, name, version) == (dist, "agent-evidence-mcp", "0.2.8")
    assert requires == ["agent-evidence-verify>=0.5.0,<0.12", "mcp==2.3.0"]


def test_read_wheel_refuses_a_directory_without_exactly_one_wheel(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        fr.read_wheel(tmp_path)


class Installs:
    """A stand-in for install_set that records each call and answers from a list."""

    def __init__(self, *answers: str | None) -> None:
        self.answers, self.calls = list(answers), []

    def __call__(self, specs: list[str], imports: list[str]) -> str | None:
        self.calls.append(specs)
        return self.answers.pop(0)


def registry_fetch(registry: dict) -> object:
    family = {fr._norm(n): published("1.0.0") for n in fr.FAMILY}
    full = {**family, **registry}
    return lambda name: full.get(name)


def test_candidate_refuses_the_24_november_release_before_installing_anything(tmp_path: Path, capsys) -> None:
    dist = wheel(tmp_path, "agent-evidence-verify", "0.10.0", "agent-evidence-vocabulary<0.10,>=0.8.0")
    installs = Installs()
    assert fr.candidate(dist, fetch=registry_fetch(REGISTRY_1125), install=installs) == 1
    assert installs.calls == []
    assert "FAIL: agent-evidence-mcp 0.2.7, its latest release on PyPI" in capsys.readouterr().err


def test_candidate_installs_the_wheel_beside_the_latest_of_every_other_member(tmp_path: Path) -> None:
    dist = wheel(tmp_path, "agent-evidence-mcp", "0.2.8", "agent-evidence-verify>=0.5.0,<0.12")
    registry = {**REGISTRY_1125, "agent-evidence-verify": published("0.10.0")}
    installs = Installs(None)
    assert fr.candidate(dist, fetch=registry_fetch(registry), install=installs) == 0
    (specs,) = installs.calls
    assert specs[0].startswith("agent-evidence-mcp @ file://") and specs[0].endswith(".whl")
    assert "agent-evidence-verify==0.10.0" in specs and not any(s.startswith("agent-evidence-mcp==") for s in specs)
    assert "agent-evidence-observer[done,witness]==0.2.0" in specs


def test_candidate_keeps_the_extras_of_a_family_member(tmp_path: Path) -> None:
    dist = wheel(tmp_path, "agent-evidence-observer", "0.3.0", 'jcs-admit~=0.1.0; extra == "witness"')
    installs = Installs(None)
    assert fr.candidate(dist, fetch=registry_fetch(REGISTRY_1125), install=installs) == 0
    assert installs.calls[0][0].startswith("agent-evidence-observer[done,witness] @ file://")


def test_candidate_refuses_a_set_that_breaks_only_with_the_new_release(tmp_path: Path, capsys) -> None:
    dist = wheel(tmp_path, "agent-evidence-mcp", "0.2.8")
    installs = Installs("check", None)
    assert fr.candidate(dist, fetch=registry_fetch(REGISTRY_1125), install=installs) == 1
    assert len(installs.calls) == 2 and "agent-evidence-mcp==0.2.7" in installs.calls[1]
    assert "the latest releases alone pass" in capsys.readouterr().err


def test_candidate_does_not_hold_back_a_release_when_the_family_was_already_broken(tmp_path: Path, capsys) -> None:
    """Two separate breaks must not each block the release that repairs the other."""
    dist = wheel(tmp_path, "agent-evidence-mcp", "0.2.8")
    installs = Installs("install", "install")
    assert fr.candidate(dist, fetch=registry_fetch(REGISTRY_1125), install=installs) == 0
    assert "WARNING: the latest releases already fail without" in capsys.readouterr().err


def test_a_registry_read_that_fails_is_an_error_never_a_pass(tmp_path: Path) -> None:
    dist = wheel(tmp_path, "agent-evidence-mcp", "0.2.8")

    def down(name: str) -> dict:
        raise urllib.error.HTTPError(f"https://pypi.org/pypi/{name}/json", 503, "unavailable", {}, io.BytesIO())

    with pytest.raises(urllib.error.HTTPError):
        fr.candidate(dist, fetch=down, install=Installs())


def test_pypi_project_reads_404_as_unpublished_and_raises_on_anything_else(monkeypatch) -> None:
    def answer(code: int):
        def urlopen(url: str, timeout: int):
            raise urllib.error.HTTPError(url, code, "x", {}, io.BytesIO())

        return urlopen

    monkeypatch.setattr(fr.urllib.request, "urlopen", answer(404))
    assert fr.pypi_project("never-published") is None
    monkeypatch.setattr(fr.urllib.request, "urlopen", answer(500))
    with pytest.raises(urllib.error.HTTPError):
        fr.pypi_project("anything")


def test_main_routes_candidate_to_the_gate(monkeypatch, tmp_path: Path) -> None:
    seen = []
    monkeypatch.setattr(fr, "candidate", lambda dist: seen.append(dist) or 0)
    assert fr.main(["x", "candidate", str(tmp_path)]) == 0 and seen == [tmp_path]
    assert fr.main(["x", "candidate"]) == 2


def test_every_publish_job_needs_the_gate() -> None:
    """A publish job that does not need family-candidate could upload a release the gate refused."""
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    jobs = re.findall(r"^  (publish-[a-z0-9-]+):\n    needs: \[([^\]]*)\]", workflow, re.MULTILINE)
    assert len(jobs) == len(re.findall(r"^  publish-", workflow, re.MULTILINE)) >= 11
    assert all("family-candidate" in needs.split(", ") for _, needs in jobs), jobs
    gate = re.search(r"^  family-candidate:\n(.*?)(?=^  \S)", workflow, re.MULTILINE | re.DOTALL)
    assert gate and "scripts/family_resolves.py candidate release-artifacts/dist" in gate.group(1)
