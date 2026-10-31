"""Portable bundle tests across the three shipped claim adapters."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import tempfile
import tomllib
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from probity_verify.bundle import create_bundle, main, replay_bundle
from probity_verify.common import CaseError
from probity_verify.core import REFERENCE_VERIFIER_ID, canonical_json

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _make_bundle(tmp_path: Path, example: str = "source-coverage") -> Path:
    files = {
        "source-coverage": ("case.json", "policy-june.json"),
        "source-april": ("case.json", "policy-april.json"),
        "operand-lineage": ("case.json", "policy.json"),
        "authority-anchor": ("case.json", "policy.json"),
    }
    case, policy = files[example]
    root = EXAMPLES / ("source-coverage" if example == "source-april" else example)
    output = tmp_path / "decision.zip"
    create_bundle(root / case, root / policy, output)
    return output


def _rewrite_bundle(path: Path, changes: dict[str, bytes]) -> None:
    """Replace members while preserving all other archive members."""
    with zipfile.ZipFile(path) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    members.update(changes)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data, compress_type=zipfile.ZIP_STORED)


class TestBundle:
    """Shared builder for passing and failing replay cases."""

    @staticmethod
    def create(tmp_path: Path, example: str = "source-coverage") -> Path:
        return _make_bundle(tmp_path, example)


class TestPassingCases(TestBundle):
    @pytest.mark.parametrize("example,decision", [
        ("source-coverage", "contradicted"),
        ("source-april", "not_established"),
        ("operand-lineage", "supported"),
        ("authority-anchor", "supported"),
    ])
    def test_replay_every_adapter(self, tmp_path: Path, example: str, decision: str) -> None:
        bundle = self.create(tmp_path, example)
        result = replay_bundle(bundle)
        assert result["decision"] == decision
        with zipfile.ZipFile(bundle) as archive:
            assert archive.read("decision.json") == (
                json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                + "\n"
            ).encode("utf-8")

    def test_deterministic_bytes_and_cli(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        root = EXAMPLES / "source-coverage"
        first = self.create(tmp_path)
        second = tmp_path / "second.zip"
        create_bundle(root / "case.json", root / "policy-june.json", second)
        assert first.read_bytes() == second.read_bytes()
        assert main(["replay", str(first)]) == 0
        assert "Decision: contradicted" in capsys.readouterr().out

    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", min_size=1, max_size=80))
    @settings(max_examples=20, deadline=None)
    def test_report_bytes_replay_from_bundle(self, suffix: str) -> None:
        root = EXAMPLES / "source-coverage"
        case = json.loads((root / "case.json").read_text())
        policy = json.loads((root / "policy-june.json").read_text())
        report = ("The initial incident.\nSeveral channels were rem\n" + suffix).encode()
        digest = hashlib.sha256(report).hexdigest()
        case["artifacts"]["report"].update(sha256=digest, length=len(report))
        policy["assessments"]["source-coverage-demo"]["record_sha256"] = digest
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "source.html").write_bytes((root / "source.html").read_bytes())
            (work / "report.txt").write_bytes(report)
            (work / "case.json").write_text(json.dumps(case), encoding="utf-8")
            (work / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
            bundle = work / "decision.zip"
            created = create_bundle(work / "case.json", work / "policy.json", bundle)
            assert replay_bundle(bundle) == created


class TestFailingCases(TestBundle):
    def test_changed_artifact_fails_replay(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        _rewrite_bundle(bundle, {"artifacts/report.txt": b"changed"})
        with pytest.raises(CaseError, match="artifact binding_mismatch"):
            replay_bundle(bundle)

    def test_unselected_artifact_binding_is_still_checked(self, tmp_path: Path) -> None:
        root = EXAMPLES / "source-coverage"
        case = json.loads((root / "case.json").read_text())
        spare = b"an unused but declared witness"
        case["artifacts"]["spare"] = {
            "path": "spare.bin", "sha256": hashlib.sha256(spare).hexdigest(),
            "length": len(spare),
        }
        (tmp_path / "source.html").write_bytes((root / "source.html").read_bytes())
        (tmp_path / "report.txt").write_bytes((root / "report.txt").read_bytes())
        (tmp_path / "spare.bin").write_bytes(spare)
        (tmp_path / "case.json").write_text(json.dumps(case), encoding="utf-8")
        bundle = tmp_path / "decision.zip"
        create_bundle(tmp_path / "case.json", root / "policy-june.json", bundle)
        _rewrite_bundle(bundle, {"artifacts/spare.bin": b"changed"})
        with pytest.raises(CaseError, match="artifacts.spare: artifact binding_mismatch"):
            replay_bundle(bundle)

    def test_changed_policy_fails_replay(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        with zipfile.ZipFile(bundle) as archive:
            policy = json.loads(archive.read("policy.json"))
        policy["assessments"]["source-coverage-demo"]["source_window"]["start"] = (
            "2019-06-26T08:00:00Z"
        )
        _rewrite_bundle(bundle, {"policy.json": canonical_json(policy)})
        with pytest.raises(CaseError, match="bundled decision differs from replay"):
            replay_bundle(bundle)

    def test_unlisted_member_and_traversal_are_refused(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        _rewrite_bundle(bundle, {"../escape": b"not extracted"})
        with pytest.raises(CaseError, match="bundle members do not match case artifacts"):
            replay_bundle(bundle)
        assert not (tmp_path / "escape").exists()

    def test_duplicate_archive_member_is_refused(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        with zipfile.ZipFile(bundle, "a") as archive, pytest.warns(
            UserWarning, match="Duplicate name"
        ):
            archive.writestr("case.json", b"{}")
        with pytest.raises(CaseError, match="bundle has duplicate or missing control members"):
            replay_bundle(bundle)

    def test_symlink_member_is_refused(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        with zipfile.ZipFile(bundle) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        with zipfile.ZipFile(bundle, "w") as archive:
            for name, data in members.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (
                    (stat.S_IFLNK if name == "artifacts/report.txt" else stat.S_IFREG) | 0o644
                ) << 16
                archive.writestr(info, data)
        with pytest.raises(CaseError, match="unsafe or oversized bundle member"):
            replay_bundle(bundle)

    def test_unbound_artifact_cannot_be_packaged(self, tmp_path: Path) -> None:
        root = EXAMPLES / "source-coverage"
        case = json.loads((root / "case.json").read_text())
        case["artifacts"]["report"]["sha256"] = "0" * 64
        path = tmp_path / "case.json"
        path.write_text(json.dumps(case), encoding="utf-8")
        with pytest.raises(
            CaseError, match=re.escape("artifacts.report: artifact binding_mismatch")
        ):
            create_bundle(path, root / "policy-june.json", tmp_path / "decision.zip",
                          artifact_root=root)
        assert not (tmp_path / "decision.zip").exists()

    def test_existing_bundle_is_not_overwritten(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        original = bundle.read_bytes()
        root = EXAMPLES / "source-coverage"
        with pytest.raises(CaseError, match="bundle already exists"):
            create_bundle(root / "case.json", root / "policy-june.json", bundle)
        assert bundle.read_bytes() == original


RELEASED = Path(__file__).resolve().parent / "data" / "bundles"
RELEASED_BUNDLES = [
    ("source-coverage-0.2.2.zip", "contradicted"),
    ("operand-lineage-0.2.2.zip", "supported"),
    ("source-coverage-0.2.4.zip", "contradicted"),
    ("operand-lineage-0.2.4.zip", "supported"),
]


def _copy_released(tmp_path: Path, name: str) -> Path:
    bundle = tmp_path / name
    bundle.write_bytes((RELEASED / name).read_bytes())
    return bundle


def _forge_decision(bundle: Path) -> None:
    """Flip the bundled verdict while keeping every other byte of the archive."""
    with zipfile.ZipFile(bundle) as archive:
        decision = json.loads(archive.read("decision.json"))
    decision.update(decision="supported", reason="all_selected_spans_present")
    _rewrite_bundle(bundle, {"decision.json": canonical_json(decision)})


def _producer(bundle: Path) -> dict:
    with zipfile.ZipFile(bundle) as archive:
        return json.loads(archive.read("bundle.json"))


class TestReleaseSkew(TestBundle):
    """Bundles written by earlier releases replay; altered ones are still refused."""

    @pytest.mark.parametrize("name,decision", RELEASED_BUNDLES)
    def test_bundle_written_by_a_published_release_replays(
        self, tmp_path: Path, name: str, decision: str
    ) -> None:
        bundle = _copy_released(tmp_path, name)
        assert replay_bundle(bundle)["decision"] == decision
        assert main(["replay", str(bundle)]) == 0

    @pytest.mark.parametrize("name", ["source-coverage-0.2.2.zip", "source-coverage-0.2.4.zip"])
    def test_forged_decision_in_a_released_bundle_is_refused(self, tmp_path: Path, name: str) -> None:
        bundle = _copy_released(tmp_path, name)
        _forge_decision(bundle)
        with pytest.raises(CaseError, match="bundled decision differs from replay: "
                                            "the bundle names no verifier release"):
            replay_bundle(bundle)
        assert main(["replay", str(bundle)]) == 2

    def test_new_bundle_records_this_release(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        source = tomllib.loads((EXAMPLES.parent / "pyproject.toml").read_text())["project"]["version"]
        assert _producer(bundle) == {
            "schema_version": "probity-bundle/v1",
            "verifier": {"id": REFERENCE_VERIFIER_ID, "version": source},
        }

    def test_forged_decision_under_this_release_is_refused_as_altered(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        _forge_decision(bundle)
        with pytest.raises(CaseError, match=r"^bundled decision differs from replay$"):
            replay_bundle(bundle)

    def test_decision_from_another_release_names_both_releases(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        record = _producer(bundle)
        record["verifier"]["version"] = "0.2.9"
        _rewrite_bundle(bundle, {"bundle.json": canonical_json(record)})
        assert replay_bundle(bundle)["decision"] == "contradicted"
        _forge_decision(bundle)
        with pytest.raises(CaseError, match="written by probity-verify 0.2.9 and this is "):
            replay_bundle(bundle)

    def test_bundle_without_release_record_in_the_current_shape_replays(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        with zipfile.ZipFile(bundle) as archive:
            members = {name: archive.read(name) for name in archive.namelist()
                       if name != "bundle.json"}
        with zipfile.ZipFile(bundle, "w") as archive:
            for name, data in members.items():
                archive.writestr(name, data, compress_type=zipfile.ZIP_STORED)
        assert replay_bundle(bundle)["decision"] == "contradicted"

    @pytest.mark.parametrize("change,message", [
        (lambda r: r["verifier"].update(id="https://example.invalid/other"), "written by another verifier"),
        (lambda r: r["verifier"].update(version="0.3"), "release number"),
        (lambda r: r["verifier"].update(version=3), "release number"),
        (lambda r: r.update(extra=True), "expected probity-bundle/v1"),
        (lambda r: r.update(schema_version="probity-bundle/v2"), "expected probity-bundle/v1"),
        (lambda r: r["verifier"].pop("version"), "expected probity-bundle/v1"),
    ])
    def test_malformed_release_record_is_refused(self, tmp_path: Path, change, message: str) -> None:
        bundle = self.create(tmp_path)
        record = _producer(bundle)
        change(record)
        _rewrite_bundle(bundle, {"bundle.json": canonical_json(record)})
        with pytest.raises(CaseError, match=message):
            replay_bundle(bundle)

    def test_noncanonical_release_record_is_refused(self, tmp_path: Path) -> None:
        bundle = self.create(tmp_path)
        _rewrite_bundle(bundle, {"bundle.json": json.dumps(_producer(bundle), indent=1).encode()})
        with pytest.raises(CaseError, match="bundle.json: must use canonical JSON"):
            replay_bundle(bundle)
