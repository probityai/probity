"""Seal a finished Inspect log into a detached manifest of two digests.

A digest over a whole ``.eval`` file does not survive ordinary handling. An importer
restamps ``eval.eval_set_id`` and the ``metadata`` blocks in place, and an enrichment step
resolves image digests into ``eval.metadata`` and rewrites the log. A binding that broke on
either would be switched off within a week.

The manifest therefore covers a canonical subset of the log, read only through
``inspect_ai.log.read_eval_log``, in two parts that answer different questions:

``execution_digest``
    Run identity, declared environment and each sample's identity and declared sandbox.
    It survives a restamp, a metadata enrichment, a tag edit and a regrade.
``results_digest``
    Status, scorers, results, reductions and each sample's scores, errors and limit.
    A regrade moves it, so a reader can say "same execution, different grading".

The manifest records what it does not cover. The Inspect hooks API exposes no container
observation, no input-file bytes and no grader artifact, so the manifest lists them as not
captured and never as empty. The digest lives beside the log and never inside it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Literal

import rfc8785

SCHEMA = "agent-evidence-observer/inspect-sealed-manifest/v1"
EXECUTION_COVER = "agent-evidence-observer/inspect-execution-cover/v1"
RESULTS_COVER = "agent-evidence-observer/inspect-results-cover/v1"
# Not .json or .eval: Inspect lists any such name that starts like a log as a log.
MANIFEST_SUFFIX = ".sealed"

EXECUTION_EVAL_FIELDS: tuple[str, ...] = (
    "eval_id", "run_id", "created", "task", "task_id", "task_version", "task_file",
    "task_registry_name", "solver", "model", "model_base_url", "dataset", "packages",
    "revision", "sandbox",
)
EXECUTION_SAMPLE_FIELDS: tuple[str, ...] = ("id", "epoch", "uuid", "sandbox", "files", "setup")
RESULTS_LOG_FIELDS: tuple[str, ...] = ("status", "results", "reductions")
RESULTS_EVAL_FIELDS: tuple[str, ...] = ("eval_id", "scorers")
RESULTS_SAMPLE_FIELDS: tuple[str, ...] = ("id", "epoch", "uuid", "scores", "error", "limit")

EXCLUDED_AND_WHY: dict[str, str] = {
    "eval.eval_set_id": "restamped in place by importers that adopt a log into their own eval set",
    "eval.metadata": "an untyped surface that downstream tools write into after the eval ends",
    "metadata": "the same surface at the top level of the log",
    "eval.tags": "editable through the log-editing API",
    "tags": "editable through the log-editing API",
    "invalidated": "set and cleared through the log-editing API",
    "eval.config": "carries operational overrides an eval-set worker may apply",
    "eval.task_args": "an arbitrary caller payload outside the environment claim",
    "eval.model_args": "an arbitrary caller payload that can carry credentials",
    "eval.model_generate_config": "a generation setting outside the environment claim",
    "eval.solver_args": "an arbitrary caller payload outside the environment claim",
    "stats": "wall-clock and token counters that no re-check can reproduce",
    "samples[].events": "the transcript, condensed and rewritten by attachment handling",
    "samples[].messages": "rewritten by image and attachment condensation",
    "samples[].attachments": "content-addressed by the condenser, not by this cover",
}

NOT_CAPTURED: dict[str, str] = {
    "container_observation": "Inspect's hooks API does not expose the container runtime's account of a sandbox",
    "input_file_digests": "Inspect's hooks API does not expose the bytes a sample was given",
    "grading_artifact_digests": "Inspect's hooks API does not expose the artifacts a scorer graded against",
}

DOES_NOT_ASSERT: tuple[str, ...] = (
    "execution-truth", "container-isolation", "input-bytes", "grader-bytes", "operator-independence",
)

DigestAlgorithm = "sha256"


class SealError(ValueError):
    """A log cannot be sealed or checked, and the reason is in the message."""


def canonical_bytes(value: Any) -> bytes:
    """RFC 8785 canonical JSON; refuses NaN, infinity and integers beyond 2**53."""
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise SealError(f"value has no canonical JSON form: {exc}") from exc


def digest_value(value: Any) -> str:
    """``sha256:<hex>`` over the canonical form of a JSON value."""
    return f"{DigestAlgorithm}:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


def _subset(source: Mapping[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    """Take the covered fields that are present; an absent field is omitted, never null."""
    return {name: source[name] for name in fields if source.get(name) is not None}


def _sample_key(sample: Mapping[str, Any]) -> tuple[str, int]:
    return (str(sample.get("id")), int(sample.get("epoch") or 0))


def execution_cover(log: Mapping[str, Any]) -> dict[str, Any]:
    """The execution cover of a decoded log."""
    spec = log.get("eval") or {}
    samples = sorted(log.get("samples") or [], key=_sample_key)
    return {
        "cover": EXECUTION_COVER,
        "eval": _subset(spec, EXECUTION_EVAL_FIELDS),
        "samples": [_subset(sample, EXECUTION_SAMPLE_FIELDS) for sample in samples],
    }


def results_cover(log: Mapping[str, Any]) -> dict[str, Any]:
    """The graded-outcome cover of a decoded log."""
    spec = log.get("eval") or {}
    samples = sorted(log.get("samples") or [], key=_sample_key)
    return {
        "cover": RESULTS_COVER,
        "log": _subset(log, RESULTS_LOG_FIELDS),
        "eval": _subset(spec, RESULTS_EVAL_FIELDS),
        "samples": [_subset(sample, RESULTS_SAMPLE_FIELDS) for sample in samples],
    }


def decode_log(location: str) -> dict[str, Any]:
    """Read a log through Inspect's own reader and return the fields the file carried.

    ``exclude_unset`` drops fields the file did not hold, so a field a later Inspect adds
    with a default does not change a digest taken earlier.
    """
    from inspect_ai.log import read_eval_log

    log = read_eval_log(location)
    return log.model_dump(mode="json", exclude_unset=True, exclude_none=True)


def is_local(location: str) -> bool:
    """Whether a log location is a plain local path this module can seal."""
    return "://" not in location or location.startswith("file://")


def _local_path(location: str) -> Path:
    return Path(location[len("file://"):] if location.startswith("file://") else location)


def manifest_path(location: str) -> Path:
    """The manifest filename for a log: the log's own name plus a suffix."""
    return Path(f"{_local_path(location)}{MANIFEST_SUFFIX}")


def _installed(distribution: str) -> str | None:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


def build_manifest(location: str, log: Mapping[str, Any], sealed_at: str | None = None) -> dict[str, Any]:
    """The manifest for a decoded log."""
    path = _local_path(location)
    spec = log.get("eval") or {}
    samples = log.get("samples") or []
    log_format: Literal["eval", "json"] = "eval" if path.suffix == ".eval" else "json"
    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "digest_algorithm": DigestAlgorithm,
        "canonicalization": "rfc8785",
        "sealed_at": sealed_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "log_file": path.name,
        "log_format": log_format,
        "read_with": {
            "reader": "inspect_ai.log.read_eval_log",
            "inspect_ai": _installed("inspect-ai"),
            "agent_evidence_observer": _installed("agent-evidence-observer"),
        },
        "log_inspect_ai": (spec.get("packages") or {}).get("inspect_ai"),
        "eval_id": spec.get("eval_id"),
        "run_id": spec.get("run_id"),
        "task_id": spec.get("task_id"),
        "status": log.get("status"),
        "execution_cover": EXECUTION_COVER,
        "execution_digest": digest_value(execution_cover(log)),
        "results_cover": RESULTS_COVER,
        "results_digest": digest_value(results_cover(log)),
        "counts": {
            "samples_in_log": len(samples),
            "samples_with_error": sum(1 for sample in samples if sample.get("error") is not None),
            "dataset_samples": (spec.get("dataset") or {}).get("samples"),
            "epochs": (spec.get("config") or {}).get("epochs"),
        },
        "covered_fields": {
            "execution": {"eval": list(EXECUTION_EVAL_FIELDS), "samples": list(EXECUTION_SAMPLE_FIELDS)},
            "results": {
                "log": list(RESULTS_LOG_FIELDS),
                "eval": list(RESULTS_EVAL_FIELDS),
                "samples": list(RESULTS_SAMPLE_FIELDS),
            },
        },
        "excluded": dict(EXCLUDED_AND_WHY),
        "not_captured": dict(NOT_CAPTURED),
        "doesNotAssert": list(DOES_NOT_ASSERT),
    }
    return {key: value for key, value in manifest.items() if value is not None}


def seal(location: str) -> dict[str, Any] | None:
    """Seal a finished log into ``<log>.sealed`` beside it and return the manifest.

    Returns None for a remote location, which is left unsealed: no manifest means nothing
    was captured. Raises on a local log it cannot read or a manifest it cannot write.
    """
    if not is_local(location):
        return None
    manifest = build_manifest(location, decode_log(location))
    target = manifest_path(location)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, target)
    return manifest


def read_manifest(location: str) -> dict[str, Any] | None:
    """A log's manifest, or None when it has none."""
    target = manifest_path(location)
    if not target.exists():
        return None
    manifest = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise SealError(f"{target} is not a {SCHEMA} manifest")
    return manifest


@dataclass(frozen=True)
class Verification:
    """The outcome of checking a manifest against a log."""

    execution_match: bool
    results_match: bool
    expected_execution_digest: str
    actual_execution_digest: str
    expected_results_digest: str
    actual_results_digest: str

    @property
    def established(self) -> bool:
        """Both covers reproduce."""
        return self.execution_match and self.results_match

    @property
    def summary(self) -> str:
        if self.established:
            return "execution and grading both reproduce"
        if self.execution_match:
            return "same execution, different grading"
        if self.results_match:
            return "same grading, different execution"
        return "neither execution nor grading reproduces"


def verify(location: str) -> Verification | None:
    """Check a log against its manifest; None when the log has no manifest."""
    manifest = read_manifest(location)
    if manifest is None:
        return None
    log = decode_log(location)
    actual_execution = digest_value(execution_cover(log))
    actual_results = digest_value(results_cover(log))
    return Verification(
        execution_match=actual_execution == manifest.get("execution_digest"),
        results_match=actual_results == manifest.get("results_digest"),
        expected_execution_digest=str(manifest.get("execution_digest")),
        actual_execution_digest=actual_execution,
        expected_results_digest=str(manifest.get("results_digest")),
        actual_results_digest=actual_results,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m probity_observer.inspect_binding seal|verify LOG``."""
    parser = argparse.ArgumentParser(prog="python -m probity_observer.inspect_binding")
    parser.add_argument("command", choices=("seal", "verify"))
    parser.add_argument("log")
    args = parser.parse_args(argv)
    if args.command == "seal":
        manifest = seal(args.log)
        if manifest is None:
            print(f"{args.log}: not a local file, left unsealed", file=sys.stderr)
            return 2
        print(f"sealed {manifest['log_file']} execution {manifest['execution_digest']} "
              f"results {manifest['results_digest']}")
        return 0
    result = verify(args.log)
    if result is None:
        print(f"{args.log}: no manifest, nothing was sealed", file=sys.stderr)
        return 2
    print(result.summary)
    return 0 if result.established else 1


if __name__ == "__main__":
    raise SystemExit(main())
