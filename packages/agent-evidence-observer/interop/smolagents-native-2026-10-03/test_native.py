"""Fault controls over the retained, source-pinned smolagents packet and the separately installed reader."""
from __future__ import annotations

import copy
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from probity_observer.crypto import SigningKey
from probity_smolagents import reader, source
from probity_smolagents.contract import CASES, encode, load, sha

RETAINED = Path(__file__).resolve().parent / "retained"


def withheld_sources():
    """Return the retained digests of source files withheld from the packet, keyed by manifest path."""
    held = load(RETAINED / "WITHHELD-SOURCES.json")
    return {name.removeprefix("native/packet/source/"): digest for name, digest in held.items()
            if name.startswith("native/packet/source/")}


def verify_saved(root, policy):
    """Read a packet with the retained withheld-source digests."""
    return reader.verify_saved(root, policy, withheld_sources())


def publish_saved(root, policy, destination):
    """Publish from a packet with the retained withheld-source digests."""
    return reader.publish_saved(root, policy, destination, withheld_sources())


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    """Copy the retained native run and restore its empty target directories."""
    output = tmp_path_factory.mktemp("native") / "capture"
    shutil.copytree(RETAINED / "native", output)
    for history in (output / "packet").rglob("history.jsonl"):
        (history.parent / "work").mkdir(exist_ok=True)
    return output, load(output / "host-policy.json")


@pytest.fixture
def selected(original, tmp_path):
    """Copy retained actual bytes; keep the host selection outside the packet."""
    output, policy = original
    destination = tmp_path / "selected"
    shutil.copytree(output, destination)
    return destination / "packet", copy.deepcopy(policy)


def reselect_native(root, policy, case, mutate):
    """Update a host-selected native artifact after a semantic mutation."""
    path = root / case / "native.json"
    native = load(path)
    mutate(native)
    path.write_bytes(encode(native))
    policy["cases"][case]["artifacts"]["native.json"] = sha(path.read_bytes())


def change_action(native, index, field, value):
    """Change callback and memory together to reach the semantic checker."""
    action = [row for row in native["callbacks"] if row["kind"] == "ActionStep"][index]["data"]
    action[field] = value
    native["memoryActions"][index][field] = copy.deepcopy(value)


def refused(root, policy, destination, reason, caplog):
    """A semantically invalid selected record must not create publication."""
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="probity_smolagents"):
        with pytest.raises(ValueError, match="^" + reason + "$"):
            publish_saved(root, policy, destination)
    assert reason in caplog.text
    assert not destination.exists()


def withheld_path(root):
    """Write the retained withheld-source digests beside a packet copy."""
    path = root.parent / "withheld-sources.json"
    path.write_bytes(encode(withheld_sources()))
    return path


def reader_command(root, policy_path, digest, destination=None):
    """Invoke only the independently installed reader environment."""
    command = [
        os.environ.get("SMOLAGENTS_READER_PYTHON", sys.executable), "-I", "-B", "-m",
        "probity_smolagents.reader", str(root), "--host-policy", str(policy_path),
        "--policy-sha256", digest, "--withheld", str(withheld_path(root)),
    ]
    if destination:
        command += ["--publish", str(destination)]
    return command


class TestNativePopulation:
    class TestPassingCases:
        def test_native_counts_and_actual_closure(self, original):
            output, policy = original
            report = verify_saved(output / "packet", policy)
            assert (report["modelCalls"], report["toolCalls"], report["committedEffects"]) == (14, 7, 5)
            assert report["modelInferenceCalls"] == 0
            assert report["independentCustody"] is False
            records = {row["case"]: row for row in report["records"]}
            assert set(records) == set(CASES)
            assert [row["case"] for row in report["records"] if row["publicationDecision"] == "RELEASE"] == ["permit"]
            assert {row["witnessScope"] for row in report["records"]} == {"PEER"}
            native = [load(output / "packet" / case / "native.json") for case in CASES]
            assert sum(row["kind"] == "ActionStep" for record in native for row in record["callbacks"]) == 14
            assert sum(row["kind"] == "FinalAnswerStep" for record in native for row in record["callbacks"]) == 6

        def test_committed_writes_survive_terminal_failures(self, original):
            output, policy = original
            report = verify_saved(output / "packet", policy)
            records = {row["case"]: row for row in report["records"]}
            for case in ("error-after", "max-steps", "model-error-after", "incomplete-after"):
                assert records[case]["committedEffects"] == 1
                assert records[case]["publicationDecision"] == "WITHHOLD"

        def test_publish_only_permit(self, selected, tmp_path):
            root, policy = selected
            destination = tmp_path / "publication"
            result = publish_saved(root, policy, destination)
            assert [row["case"] for row in result["records"]] == ["permit"]
            assert load(destination / "published.json") == result
            assert result["selectionSha256"] == sha(encode(policy))

        def test_reader_runs_without_framework_and_repeats_bytes(self, selected, tmp_path):
            root, policy = selected
            executable = os.environ.get("SMOLAGENTS_READER_PYTHON", sys.executable)
            check = subprocess.run(
                [executable, "-I", "-B", "-c",
                 "import importlib.util; assert importlib.util.find_spec('smolagents') is None"],
                check=True, capture_output=True, text=True,
            )
            assert check.returncode == 0
            policy_path = tmp_path / "selected-policy.json"
            policy_path.write_bytes(encode(policy))
            digest = sha(policy_path.read_bytes())
            first = subprocess.run(reader_command(root, policy_path, digest), check=True, capture_output=True)
            second = subprocess.run(reader_command(root, policy_path, digest), check=True, capture_output=True)
            assert first.stdout == second.stdout
            assert json.loads(first.stdout) == verify_saved(root, policy)
            publication = tmp_path / "installed-publication"
            published = subprocess.run(
                reader_command(root, policy_path, digest, publication),
                check=True, capture_output=True,
            )
            assert json.loads(published.stdout) == load(publication / "published.json")

    class TestFailingCases:
        @pytest.mark.parametrize("case", list(CASES))
        def test_changed_original_digest(self, selected, tmp_path, caplog, case):
            root, policy = selected
            path = root / case / "native.json"
            path.write_bytes(path.read_bytes() + b" ")
            refused(root, policy, tmp_path / "publication", "artifact digest differs from host selection", caplog)

        @pytest.mark.parametrize(
            "case,field,value,reason",
            [
                ("permit", "is_final_answer", True, "native final-answer flag differs"),
                ("error-after", "error", None, "native action error differs"),
                ("max-steps", "error", None, "native action error differs"),
                ("permit", "tool_calls", [], "native processed tool population differs"),
                ("permit", "step_number", True, "native step identity differs"),
                ("permit", "model_input_messages", [], "native action input differs"),
            ],
        )
        def test_reselected_action_semantics(self, selected, tmp_path, caplog, case, field, value, reason):
            root, policy = selected
            index = 1 if case == "max-steps" else 0
            reselect_native(root, policy, case, lambda native: change_action(native, index, field, value))
            refused(root, policy, tmp_path / "publication", reason, caplog)

        def test_reselected_final_before_action(self, selected, tmp_path, caplog):
            root, policy = selected
            reselect_native(root, policy, "permit", lambda native: native["callbacks"].insert(0, native["callbacks"].pop()))
            refused(root, policy, tmp_path / "publication", "native callback order differs", caplog)

        def test_reselected_incomplete_forged_closure(self, selected, tmp_path, caplog):
            root, policy = selected
            reselect_native(root, policy, "incomplete-after", lambda native: native["callbacks"].append(
                {"kind": "FinalAnswerStep", "data": {"output": "done"}}
            ))
            refused(root, policy, tmp_path / "publication", "final callback population differs", caplog)

        def test_reselected_model_error_concealed(self, selected, tmp_path, caplog):
            root, policy = selected
            reselect_native(root, policy, "model-error-after", lambda native: native["modelCalls"][1].update(error=None))
            refused(root, policy, tmp_path / "publication", "model error differs", caplog)

        def test_reselected_native_terminal_changed(self, selected, tmp_path, caplog):
            root, policy = selected
            reselect_native(root, policy, "error-after", lambda native: native["terminal"].update(state="failed"))
            refused(root, policy, tmp_path / "publication", "native terminal state differs", caplog)

        @pytest.mark.parametrize(
            "field,value,reason",
            [
                ("content", "different actual forward", "native forward or effect boundary differs"),
                ("committed", 1, "tool committed type differs"),
                ("exception", None, "native forward or effect boundary differs"),
            ],
        )
        def test_reselected_actual_forward_changed(self, selected, tmp_path, caplog, field, value, reason):
            root, policy = selected
            reselect_native(root, policy, "error-after", lambda native: native["toolCalls"][0].update({field: value}))
            refused(root, policy, tmp_path / "publication", reason, caplog)

        @pytest.mark.parametrize("role", ("issuerKey", "observerKey", "witnessKey"))
        def test_host_key_changed(self, selected, tmp_path, caplog, role):
            root, policy = selected
            policy["cases"]["permit"][role] = SigningKey.generate().public_hex
            reason = "grant verification refused" if role == "issuerKey" else "signed effect verification refused"
            refused(root, policy, tmp_path / "publication", reason, caplog)

        def test_actual_work_bytes_changed(self, selected, tmp_path, caplog):
            root, policy = selected
            (root / "permit" / "work" / "result.txt").write_text("later replacement")
            refused(root, policy, tmp_path / "publication", "signed effect verification refused", caplog)

        @pytest.mark.parametrize("mode", ("missing", "extra"))
        def test_planned_population_changed(self, selected, tmp_path, caplog, mode):
            root, policy = selected
            if mode == "missing":
                del policy["cases"]["permit"]
            else:
                policy["cases"]["unselected"] = copy.deepcopy(policy["cases"]["permit"])
            refused(root, policy, tmp_path / "publication", "planned population differs", caplog)

        @pytest.mark.parametrize("owner,reason", [
            ("sdk", "selected source population or bytes differ"),
            ("retained", "retained source population differs"),
        ])
        def test_reselected_source_population_changed(self, selected, tmp_path, caplog, owner, reason):
            root, policy = selected
            manifest_path = root / "source-before-run.json"
            manifest = load(manifest_path)
            sdk = source.sdk_hashes()
            del manifest[next(name for name in sorted(manifest) if (name in sdk) == (owner == "sdk"))]
            manifest_path.write_bytes(encode(manifest))
            policy["sourceManifestSha256"] = sha(manifest_path.read_bytes())
            refused(root, policy, tmp_path / "publication", reason, caplog)

        def test_withheld_source_digest_must_match_the_manifest(self, selected, tmp_path, caplog):
            root, policy = selected
            held = withheld_sources()
            assert held
            name = sorted(held)[0]
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="probity_smolagents"):
                with pytest.raises(ValueError, match="^withheld source digest differs from manifest$"):
                    reader.verify_saved(root, policy, {**held, name: "00" * 32})

        def test_unlisted_missing_source_is_refused(self, selected, caplog):
            root, policy = selected
            held = withheld_sources()
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="probity_smolagents"):
                with pytest.raises(ValueError, match="^retained source population differs$"):
                    reader.verify_saved(root, policy, dict(list(held.items())[1:]))

        def test_present_withheld_source_must_match_its_digest(self, selected, caplog):
            root, policy = selected
            held = withheld_sources()
            (root / "source" / sorted(held)[0]).write_bytes(b"different bytes\n")
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="probity_smolagents"):
                with pytest.raises(ValueError, match="^artifact digest differs from host selection$"):
                    reader.verify_saved(root, policy, held)

        def test_reselected_sdk_yaml_bytes_changed(self, selected, tmp_path, caplog):
            root, policy = selected
            name = "smolagents/prompts/toolcalling_agent.yaml"
            source_path = root / "source" / name
            source_path.write_bytes(source_path.read_bytes() + b"\n# changed prompt\n")
            manifest_path = root / "source-before-run.json"
            manifest = load(manifest_path)
            manifest[name] = sha(source_path.read_bytes())
            manifest_path.write_bytes(encode(manifest))
            policy["sourceManifestSha256"] = sha(manifest_path.read_bytes())
            refused(root, policy, tmp_path / "publication", "selected source population or bytes differ", caplog)

        def test_artifact_symlink(self, selected, tmp_path, caplog):
            root, policy = selected
            path = root / "permit" / "native.json"
            target = tmp_path / "linked-native.json"
            path.rename(target)
            path.symlink_to(target)
            refused(root, policy, tmp_path / "publication", "artifact must be a regular file", caplog)

        def test_source_parent_symlink(self, selected, tmp_path, caplog):
            root, policy = selected
            path = root / "source" / "smolagents" / "prompts"
            target = tmp_path / "linked-prompts"
            path.rename(target)
            path.symlink_to(target, target_is_directory=True)
            refused(root, policy, tmp_path / "publication", "retained source is not regular", caplog)

        def test_publication_inside_packet(self, selected, caplog):
            root, policy = selected
            refused(root, policy, root / "publication", "publication destination must be outside packet", caplog)

        def test_existing_publication_is_preserved(self, selected, tmp_path, caplog):
            root, policy = selected
            destination = tmp_path / "publication"
            destination.mkdir()
            original = b"previous host output"
            (destination / "published.json").write_bytes(original)
            with caplog.at_level(logging.WARNING, logger="probity_smolagents"):
                with pytest.raises(ValueError, match="^publication destination already exists$"):
                    publish_saved(root, policy, destination)
            assert "publication destination already exists" in caplog.text
            assert (destination / "published.json").read_bytes() == original

        @pytest.mark.parametrize("failure", ("pin", "inside", "native"))
        def test_installed_reader_refuses_without_output(self, selected, tmp_path, failure):
            root, policy = selected
            policy_path = tmp_path / "host-policy.json"
            if failure == "native":
                reselect_native(root, policy, "permit", lambda native: native["modelCalls"][0].update(output=None))
            if failure == "inside":
                policy_path = root / "host-policy.json"
            policy_path.write_bytes(encode(policy))
            digest = "0" * 64 if failure == "pin" else sha(policy_path.read_bytes())
            destination = tmp_path / "publication"
            result = subprocess.run(reader_command(root, policy_path, digest, destination), capture_output=True, text=True)
            assert result.returncode != 0
            assert not result.stdout
            assert not destination.exists()
            expected = {
                "pin": "host policy pin differs", "inside": "host policy must be outside packet",
                "native": "model reply differs",
            }[failure]
            assert expected in result.stderr


class TestSelectedSource:
    class TestPassingCases:
        def test_selection_covers_complete_sdk_python_and_yaml(self):
            selected = source.sdk_selection()
            assert len(source.sdk_hashes()) == len(selected["files"]) == 21
            assert len([name for name in selected["files"] if name.endswith(".yaml")]) == 3


class TestStrictInput:
    class TestPassingCases:
        def test_finite_utf8_json(self, tmp_path):
            path = tmp_path / "input.json"
            selected = {"message": "native \u03b1", "count": 1, "closed": True, "timing": 0.5}
            path.write_bytes(encode(selected))
            assert load(path) == selected

    class TestFailingCases:
        @pytest.mark.parametrize(
            "raw,reason",
            [
                (b'{"case":1,"case":2}', "duplicate JSON member"),
                (b'{"value":NaN}', "non-finite JSON number"),
                (b'{"value":Infinity}', "non-finite JSON number"),
                (b'{"value":1e999}', "non-finite JSON number"),
                (b'{"value":-1e999}', "non-finite JSON number"),
            ],
        )
        def test_duplicate_and_nonfinite_json(self, tmp_path, caplog, raw, reason):
            path = tmp_path / "input.json"
            path.write_bytes(raw)
            with caplog.at_level(logging.WARNING, logger="probity_smolagents"):
                with pytest.raises(ValueError, match="^" + reason + "$"):
                    load(path)
            assert reason in caplog.text

        # The log buffer is explicitly cleared for every generated example.
        @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
        @given(st.sampled_from([True, False]), st.integers(min_value=0, max_value=1))
        def test_boolean_is_not_native_integer(self, caplog, boolean, integer):
            from probity_smolagents.contract import exact
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger="probity_smolagents"):
                with pytest.raises(ValueError, match="^native identity type differs$"):
                    exact(boolean, integer, "native identity type differs")
            assert "native identity type differs" in caplog.text
