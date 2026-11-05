"""Semantic mutations and authenticated effect refusals over the retained Haystack packet."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from probity_haystack import reader
from probity_haystack.contract import CASES, encode, load, sha

RETAINED = Path(__file__).resolve().parent / "retained"


def withheld_sources():
    """Return the retained digests of source files withheld from the packet, keyed by manifest path."""
    held = load(RETAINED / "WITHHELD-SOURCES.json")
    return {name.removeprefix("packet/source/"): digest for name, digest in held.items()
            if name.startswith("packet/source/")}


def verify_saved(root, policy):
    """Read a packet with the retained withheld-source digests."""
    return reader.verify_saved(root, policy, withheld_sources())


def publish_saved(root, policy, destination):
    """Publish from a packet with the retained withheld-source digests."""
    return reader.publish_saved(root, policy, destination, withheld_sources())


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    """Copy the retained packet and restore its empty target directories."""
    root = tmp_path_factory.mktemp("native") / "packet"
    shutil.copytree(RETAINED / "packet", root)
    for history in root.rglob("history.jsonl"):
        (history.parent / "work").mkdir(exist_ok=True)
    return root, load(root / "host-policy.json")


def test_native_originals_and_repeat(original):
    root, policy = original
    report = verify_saved(root, policy)
    assert report == verify_saved(root, policy)
    assert len(report["records"]) == 7
    assert report["modelCalls"] == 11
    assert report["toolCalls"] == 6
    assert report["committedEffects"] == 4
    assert [row["case"] for row in report["records"] if row["publicationDecision"] == "RELEASE"] == ["permit"]
    assert report["modelInferenceCalls"] == 0
    assert all(row["witnessScope"] == "PEER" for row in report["records"])


@pytest.mark.parametrize("mutation", ["open-span", "omit-tool", "omit-model", "false-effect", "invent-effect", "invent-terminal", "wrong-tool-span", "wrong-parent", "tool-error-as-success", "tool-exception", "terminal-exception", "tool-result-origin", "model-arguments"])
def test_reselected_semantic_mutants(original, tmp_path, mutation):
    root, policy = original
    changed = tmp_path / "changed"
    shutil.copytree(root, changed)
    policy = copy.deepcopy(policy)
    case = "unhandled-after" if mutation == "terminal-exception" else "handled-after" if mutation in {"invent-terminal", "tool-error-as-success"} else "wrong-content" if mutation == "invent-effect" else "permit"
    path = changed / case / "native.json"
    record = load(path)
    if mutation == "open-span":
        record["spans"][0]["closed"] = False
    elif mutation == "omit-tool":
        record["toolCalls"].clear()
    elif mutation == "omit-model":
        record["modelCalls"].pop()
    elif mutation == "false-effect":
        record["toolCalls"][0]["committed"] = False
    elif mutation == "invent-effect":
        record["toolCalls"][0]["committed"] = True
    elif mutation == "invent-terminal":
        record["terminal"]["exitReason"] = "length"
    elif mutation == "wrong-tool-span":
        next(s for s in record["spans"] if s["operation"] == "haystack.agent.step.tool")["tags"]["haystack.tool.name"] = "other"
    elif mutation == "wrong-parent":
        next(s for s in record["spans"] if s["operation"] == "haystack.agent.step.tool")["parent"] = 0
    elif mutation == "tool-error-as-success":
        for message in record["messages"]:
            for content in message["content"]:
                if "tool_call_result" in content:
                    content["tool_call_result"]["error"] = False
    elif mutation == "tool-exception":
        record["toolCalls"][0]["exception"] = "RuntimeError"
    elif mutation == "terminal-exception":
        record["terminal"]["exception"] = "InventedError"
    elif mutation == "tool-result-origin":
        for message in record["messages"]:
            for content in message["content"]:
                if "tool_call_result" in content:
                    content["tool_call_result"]["origin"]["id"] = "other-call"
    elif mutation == "model-arguments":
        record["modelCalls"][0]["output"]["content"][0]["tool_call"]["arguments"]["content"] = "other bytes"
    path.write_bytes(encode(record))
    policy["cases"][case]["artifacts"]["native.json"] = sha(path.read_bytes())
    with pytest.raises((ValueError, KeyError, TypeError)):
        verify_saved(changed, policy)


@pytest.mark.parametrize("mutation", ["missing-case", "extra-case", "source", "observer-key", "issuer-key", "witness-key", "action-content", "artifact-digest"])
def test_host_selection_refusals(original, mutation):
    root, policy = original
    policy = copy.deepcopy(policy)
    if mutation == "missing-case":
        policy["cases"].pop("permit")
    elif mutation == "extra-case":
        policy["cases"]["unknown"] = policy["cases"]["permit"]
    elif mutation == "source":
        policy["sdkSource"] = "0" * 40
    elif mutation.endswith("-key"):
        policy["cases"]["permit"][mutation.split("-")[0] + "Key"] = "0" * 64
    elif mutation == "action-content":
        policy["cases"]["permit"]["request"]["content_sha256"] = "0" * 64
    elif mutation == "artifact-digest":
        policy["cases"]["permit"]["artifacts"]["native.json"] = "0" * 64
    with pytest.raises((ValueError, KeyError, TypeError)):
        verify_saved(root, policy)


def test_changed_durable_bytes_refused(original, tmp_path):
    root, policy = original
    changed = tmp_path / "changed"
    shutil.copytree(root, changed)
    (changed / "permit/work/result.txt").write_bytes(b"changed")
    with pytest.raises(ValueError):
        verify_saved(changed, policy)


def test_duplicate_json_refused(tmp_path):
    file = tmp_path / "duplicate.json"
    file.write_bytes(b'{"a":1,"a":2}')
    with pytest.raises(ValueError, match="duplicate"):
        load(file)


def test_installed_reader_has_no_framework(original, tmp_path):
    python = os.environ.get("HAYSTACK_READER_PYTHON", sys.executable)
    root, policy = original
    policy_path = root / "host-policy.json"
    held = tmp_path / "withheld.json"
    held.write_bytes(encode(withheld_sources()))
    result = subprocess.run([python, "-I", "-B", "-m", "probity_haystack.reader", str(root), "--host-policy", str(policy_path), "--policy-sha256", sha(policy_path.read_bytes()), "--withheld", str(held)], cwd=tmp_path, capture_output=True, check=True, text=True)
    assert json.loads(result.stdout) == verify_saved(root, policy)
    assert result.stdout.encode() == (RETAINED / "reader-report.json").read_bytes()
    subprocess.run([python, "-I", "-c", "import importlib.util; assert importlib.util.find_spec('haystack') is None"], cwd=tmp_path, check=True)


def test_unselected_policy_refused(original, tmp_path):
    root, _ = original
    result = subprocess.run([os.environ.get("HAYSTACK_READER_PYTHON", sys.executable), "-I", "-m", "probity_haystack.reader", str(root), "--host-policy", str(root / "host-policy.json"), "--policy-sha256", "0" * 64], cwd=tmp_path, capture_output=True)
    assert result.returncode != 0 and b"host policy pin differs" in result.stderr


def test_selected_source_byte_change_refused(original, tmp_path):
    root, policy = original
    changed = tmp_path / "changed"
    shutil.copytree(root, changed)
    (changed / "source/probity_haystack/reader.py").write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest"):
        verify_saved(changed, policy)


def test_present_withheld_source_must_match_its_digest(original, tmp_path):
    root, policy = original
    changed = tmp_path / "changed"
    shutil.copytree(root, changed)
    target = changed / "source" / "probity_observer" / "authorization.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest"):
        verify_saved(changed, policy)


def test_unlisted_missing_source_refused(original, tmp_path):
    root, policy = original
    changed = tmp_path / "changed"
    shutil.copytree(root, changed)
    (changed / "source/probity_haystack/reader.py").unlink()
    with pytest.raises(ValueError, match="regular"):
        verify_saved(changed, policy)


def test_withheld_digest_must_match_the_manifest(original):
    root, policy = original
    held = withheld_sources()
    assert "probity_observer/authorization.py" in held
    with pytest.raises(ValueError, match="withheld source digest differs from manifest"):
        reader.verify_saved(root, policy, {**held, "probity_observer/authorization.py": "0" * 64})


def test_parent_symlink_refused(original, tmp_path):
    root, policy = original
    changed = tmp_path / "changed"
    shutil.copytree(root, changed)
    source = changed / "source/probity_haystack"
    moved = tmp_path / "outside"
    source.rename(moved)
    source.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError, match="regular"):
        verify_saved(changed, policy)


def test_publish_only_verified_permit(original, tmp_path):
    root, policy = original
    dest = tmp_path / "publication"
    result = publish_saved(root, policy, dest)
    assert [row["case"] for row in result["records"]] == ["permit"]
    assert load(dest / "published.json") == result
    with pytest.raises(FileExistsError):
        publish_saved(root, policy, dest)


def test_refusal_leaves_no_publication(original, tmp_path):
    root, policy = original
    policy = copy.deepcopy(policy)
    policy["cases"]["permit"]["artifacts"]["native.json"] = "0" * 64
    dest = tmp_path / "publication"
    with pytest.raises(ValueError):
        publish_saved(root, policy, dest)
    assert not dest.exists()
