"""The sealed manifest for Inspect logs: canonical digests, covers and the manifest builder.

Needs only the core dependencies. The runs that need Inspect itself and probity-verify are in
``interop/inspect-sealed-manifest-2026-11-03/test_real_run.py``."""

from __future__ import annotations

import ast
import copy
import hashlib
import math
from pathlib import Path
from typing import Any

import pytest

from probity_observer import inspect_binding as binding

# Raised inside inspect_ai's own retry module on every model call; nothing here can change it.
pytestmark = pytest.mark.filterwarnings("ignore:The 'initial' parameter is deprecated:DeprecationWarning")


def _log(score: float = 1.0, image: str = "sha256:aaa") -> dict[str, Any]:
    return {
        "status": "success",
        "eval": {
            "eval_id": "E1", "run_id": "R1", "created": "2026-11-03T00:00:00+00:00", "task": "demo",
            "task_id": "T1", "model": "mockllm/model", "eval_set_id": "S1", "tags": ["one"],
            "metadata": {"note": "as written"}, "packages": {"inspect_ai": "0.3.287"},
            "sandbox": {"type": "docker", "config": image}, "scorers": [{"name": "match"}],
        },
        "results": {"total_samples": 1},
        "metadata": {"top": "level"},
        "samples": [{
            "id": "s1", "epoch": 1, "uuid": "u1", "files": ["x.txt"], "scores": {"match": {"value": score}},
            "messages": [{"role": "user", "content": "hi"}],
        }],
    }


# canonical form and digests


def test_digest_is_stable_across_key_order() -> None:
    assert binding.digest_value({"a": 1, "b": [1.5, "é"]}) == binding.digest_value({"b": [1.5, "é"], "a": 1})
    assert binding.digest_value({}) == "sha256:" + hashlib.sha256(b"{}").hexdigest()


@pytest.mark.parametrize("value", [math.nan, math.inf, 2**60])
def test_a_value_with_no_canonical_form_is_refused(value: Any) -> None:
    with pytest.raises(binding.SealError):
        binding.digest_value({"x": value})


# covers


def test_execution_cover_leaves_out_what_downstream_tools_rewrite() -> None:
    cover = binding.execution_cover(_log())
    assert set(cover["eval"]) == {"eval_id", "run_id", "created", "task", "task_id", "model", "packages",
                                  "sandbox"}
    assert set(cover["samples"][0]) == {"id", "epoch", "uuid", "files"}
    assert "scores" not in cover["samples"][0]


def test_every_excluded_and_uncaptured_item_carries_a_reason() -> None:
    assert binding.EXCLUDED_AND_WHY and binding.NOT_CAPTURED
    assert all(reason.strip() for reason in (*binding.EXCLUDED_AND_WHY.values(), *binding.NOT_CAPTURED.values()))


def test_an_import_restamp_and_an_enrichment_do_not_move_the_execution_digest() -> None:
    restamped = _log()
    restamped["eval"]["eval_set_id"] = "adopted"
    restamped["eval"]["tags"] = ["two"]
    restamped["eval"]["metadata"] = {"env_versions": {"image_digest": "repo@sha256:ccc"}}
    restamped["metadata"] = {"imported": True}
    assert binding.digest_value(binding.execution_cover(_log())) == binding.digest_value(
        binding.execution_cover(restamped))
    assert binding.digest_value(binding.results_cover(_log())) == binding.digest_value(
        binding.results_cover(restamped))


def test_a_changed_environment_moves_the_execution_digest_only() -> None:
    changed = _log(image="other.yaml")
    assert binding.digest_value(binding.execution_cover(_log())) != binding.digest_value(
        binding.execution_cover(changed))
    assert binding.digest_value(binding.results_cover(_log())) == binding.digest_value(
        binding.results_cover(changed))


def test_a_regrade_moves_the_results_digest_and_not_the_execution_digest() -> None:
    regraded = _log(score=0.0)
    assert binding.digest_value(binding.execution_cover(_log())) == binding.digest_value(
        binding.execution_cover(regraded))
    assert binding.digest_value(binding.results_cover(_log())) != binding.digest_value(
        binding.results_cover(regraded))


def test_a_sample_error_is_part_of_the_results_cover() -> None:
    errored = _log()
    errored["samples"][0]["error"] = {"message": "boom"}
    assert binding.digest_value(binding.results_cover(_log())) != binding.digest_value(
        binding.results_cover(errored))


def test_sample_order_does_not_change_a_cover() -> None:
    one = _log()
    two = copy.deepcopy(one)
    extra = {**copy.deepcopy(one["samples"][0]), "id": "s2", "uuid": "u2"}
    one["samples"].append(extra)
    two["samples"].insert(0, extra)
    assert binding.digest_value(binding.execution_cover(one)) == binding.digest_value(
        binding.execution_cover(two))


# a real run


# verification after handling


# probity-verify, the published release, judges the digests with its own canonicalizer


# manifest builder


def test_the_manifest_names_its_reader_covers_counts_and_what_it_does_not_show() -> None:
    log = _log()
    log["eval"]["dataset"] = {"samples": 1}
    log["eval"]["config"] = {"epochs": 1}
    manifest = binding.build_manifest("logs/run.eval", log, sealed_at="2026-11-03T00:00:00+00:00")

    assert manifest["schema"] == binding.SCHEMA
    assert manifest["log_file"] == "run.eval" and manifest["log_format"] == "eval"
    assert manifest["log_inspect_ai"] == "0.3.287"
    assert manifest["read_with"]["reader"] == "inspect_ai.log.read_eval_log"
    assert manifest["counts"] == {"samples_in_log": 1, "samples_with_error": 0, "dataset_samples": 1,
                                  "epochs": 1}
    assert manifest["execution_digest"] == binding.digest_value(binding.execution_cover(log))
    assert manifest["results_digest"] == binding.digest_value(binding.results_cover(log))
    assert set(manifest["not_captured"]) == {"container_observation", "input_file_digests",
                                             "grading_artifact_digests"}
    assert "execution-truth" in manifest["doesNotAssert"]


def test_a_remote_location_is_left_unsealed() -> None:
    assert binding.seal("s3://bucket/run.eval") is None
    assert binding.main(["seal", "s3://bucket/run.eval"]) == 2


def test_the_hook_never_assigns_into_event_data() -> None:
    source = Path(binding.__file__).with_name("inspect_hook.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(
            node, (ast.AugAssign, ast.AnnAssign)) else []
        for target in targets:
            root = target
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            assert not (isinstance(root, ast.Name) and root.id == "data"), ast.dump(target)
