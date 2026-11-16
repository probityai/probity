"""Conformance output names the verifier that produced it, and the release manifest stays current."""

import json
import runpy
from pathlib import Path

import pytest
from agent_evidence_verify.cli import main
from agent_evidence_verify.core import REFERENCE_VERIFIER_ID, adjudicate

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/source-coverage"
EXPECTED_ID = "https://probityai.github.io/probity/verifiers/agent-evidence-verify"
MANIFEST_SCRIPT = runpy.run_path(str(ROOT / "scripts/build-release-manifest.py"))


def _decision():
    case = json.loads((EXAMPLE / "case.json").read_text())
    policy = json.loads((EXAMPLE / "policy-june.json").read_text())
    return adjudicate(case, policy, EXAMPLE)


def test_decision_carries_reference_verifier_id():
    verifier = _decision()["reference"]["verifier"]
    assert verifier["id"] == EXPECTED_ID
    assert set(verifier) == {"id", "version", "package_sha256"}
    assert REFERENCE_VERIFIER_ID == EXPECTED_ID


def test_the_package_digest_is_the_files_that_run(tmp_path):
    """The digest a decision carries equals the digest of a wheel holding the same files."""
    import hashlib
    import zipfile

    from agent_evidence_verify import identity

    package = Path(identity.__file__).resolve().parent
    wheel = tmp_path / "agent_evidence_verify-0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in sorted(package.rglob("*")):
            if path.is_file():
                archive.write(path, f"agent_evidence_verify/{path.relative_to(package).as_posix()}")
        archive.writestr("agent_evidence_verify-0.dist-info/RECORD", "")
    expected = identity.wheel_digest(wheel)
    assert _decision()["reference"]["verifier"]["package_sha256"] == expected
    assert len(expected) == 64 and expected != hashlib.sha256(b"").hexdigest()
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("agent_evidence_verify/injected.py", "x = 1\n")
    assert identity.wheel_digest(wheel) != expected
    assert identity.main([str(wheel)]) == 0


def test_cli_json_and_packet_name_the_reference_verifier(capsys, tmp_path):
    argv = [str(EXAMPLE / "case.json"), "--policy", str(EXAMPLE / "policy-june.json")]
    assert main(argv + ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["reference"]["verifier"]["id"] == EXPECTED_ID
    assert main(argv) == 0
    packet = capsys.readouterr().out
    assert f"Reference verifier: {EXPECTED_ID}" in packet
    assert "Verifier package SHA-256: " in packet


def test_release_manifest_is_current_and_names_the_verifier():
    recorded = json.loads((ROOT / "docs/release-manifest.json").read_text())
    assert recorded == MANIFEST_SCRIPT["build"]()
    assert recorded["reference"]["verifier"]["id"] == EXPECTED_ID
    assert len(recorded["expectations_digest"]) == 64
    assert {item["suite"] for item in recorded["corpora"]} == {
        "done-checks/v1", "operand-lineage/v1", "source-text-coverage/v1"}


def test_release_manifest_check_fails_when_stale(tmp_path, monkeypatch):
    module = dict(MANIFEST_SCRIPT)
    stale = tmp_path / "release-manifest.json"
    stale.write_text("{}\n")
    module["main"].__globals__["OUTPUT"] = stale
    try:
        monkeypatch.setattr("sys.argv", ["build-release-manifest.py", "--check"])
        assert module["main"]() == 1
    finally:
        module["main"].__globals__["OUTPUT"] = ROOT / "docs/release-manifest.json"


@pytest.mark.parametrize("path", ["docs/release-manifest.json"])
def test_manifest_matches_pyproject_version(path):
    import tomllib
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert json.loads((ROOT / path).read_text())["version"] == version


class _FakeDist:
    """Just the metadata ``identity.release_of`` reads."""

    version = "9.9.9"

    def __init__(self, site: Path, files: list[str], direct_url: str | None = None) -> None:
        from importlib.metadata import PackagePath

        self._site, self._direct = site, direct_url
        self.files = [PackagePath(name) for name in files]

    def locate_file(self, path):
        return self._site / str(path)

    def read_text(self, name: str):
        return self._direct if name == "direct_url.json" else None


def test_a_source_tree_ahead_of_the_wheel_does_not_borrow_its_version(tmp_path):
    """Break-it counter-example: PYTHONPATH=<checkout>/src with an older wheel installed.

    The decision carried the wheel's version beside a digest of the checkout's files, so it named
    a release whose bytes did not run.
    """
    from agent_evidence_verify import identity

    site, checkout = tmp_path / "site-packages", tmp_path / "checkout/src/agent_evidence_verify"
    for root in (site / "agent_evidence_verify", checkout):
        root.mkdir(parents=True)
        (root / "identity.py").write_text("")
    wheel = _FakeDist(site, ["agent_evidence_verify/identity.py"])
    assert identity.release_of(wheel, site / "agent_evidence_verify/identity.py") == "9.9.9"
    assert identity.release_of(wheel, checkout / "identity.py") is None
    editable = _FakeDist(site, ["__editable__.pth"], json.dumps(
        {"url": (tmp_path / "checkout").as_uri(), "dir_info": {"editable": True}}))
    assert identity.release_of(editable, checkout / "identity.py") == "9.9.9"
    elsewhere = _FakeDist(site, ["__editable__.pth"], json.dumps(
        {"url": (tmp_path / "other").as_uri(), "dir_info": {"editable": True}}))
    assert identity.release_of(elsewhere, checkout / "identity.py") is None
    assert identity.release_of(_FakeDist(site, [], "{not json"), checkout / "identity.py") is None


def test_a_wheel_member_under_purelib_counts_toward_the_package_digest(tmp_path):
    """PEP 427 ``<dist>.data/purelib`` members install into the package; the digest must see them."""
    import zipfile

    from agent_evidence_verify import identity

    plain, data = tmp_path / "a-0-py3-none-any.whl", tmp_path / "b-0-py3-none-any.whl"
    with zipfile.ZipFile(plain, "w") as archive:
        archive.writestr("agent_evidence_verify/__init__.py", "")
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("agent_evidence_verify/__init__.py", "")
        archive.writestr("agent_evidence_verify-0.data/purelib/agent_evidence_verify/core.py", "x = 1\n")
    assert identity.wheel_digest(plain) != identity.wheel_digest(data)
    assert identity.wheel_digest(data) == identity.package_digest(
        [("agent_evidence_verify/__init__.py", b""), ("agent_evidence_verify/core.py", b"x = 1\n")])
