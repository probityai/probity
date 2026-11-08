"""Corpus mode: one verdict line per corpus member, in the shared verdict-line format.

``agent-evidence-verify corpus DIR [DIR ...]`` reads each corpus directory's
``MANIFEST.json`` and prints one JSON object per member, in the format
agent-evidence-vectors publishes as ``vectors/verdict-line.schema.json``
(schema identifier below). Several verifiers' lines over the same corpora are
compared member by member by that package's checker.

Three suites are answered here by this package's own implementations:

* ``adversarial-execution-evidence-conformance``, by ``execution_evidence.verify``
  with no consumer key policy (validity, the result token, and the first code);
* ``uncertain-effect/v1``, by the uncertain-effect adapter's domain checks and
  ordered checks;
* ``approval-binding/v1``, by the approval-binding adapter's ordered checks.

Every member of any other suite is answered ``not-applicable``, member by member,
so the output always covers the whole manifest and never reads as a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from . import execution_evidence as aee
from .adapters import approval_binding, uncertain_effect
from .json_input import parse_json

SCHEMA_ID = "https://probityai.github.io/agent-evidence-vectors/schema/verdict-line/v1"
AEE_SUITE = "adversarial-execution-evidence-conformance"
UNCERTAIN_SUITE = "uncertain-effect/v1"
NAME = "agent-evidence-verify"


def version() -> str:
    """The installed distribution's version, or a marker for an uninstalled tree."""
    try:
        return metadata.version(NAME)
    except metadata.PackageNotFoundError:
        return "uninstalled"


def _uncertain(record_path: Path) -> tuple[str, str]:
    record = parse_json(record_path.read_bytes(), max_bytes=uncertain_effect.MAX_RECORD_BYTES,
                        max_depth=32, max_nodes=32768)
    if not isinstance(record, dict):
        raise ValueError("record: expected a JSON object")
    uncertain_effect.check_domains(record)
    failure = uncertain_effect.first_failure(record)
    return ("accept", uncertain_effect.ACCEPTED) if failure is None else ("reject", failure)


def _answer(suite: str, root: Path, entry: dict[str, Any]) -> tuple[str, str | None, str | None]:
    """(verdict, reason, result) for one member."""
    if suite == AEE_SUITE:
        report = aee.verify((root / entry["file"]).read_bytes())
        if report.verdict == aee.VALID:
            return "accept", None, report.result
        return "reject", report.primary_code, None
    if suite == UNCERTAIN_SUITE:
        verdict, reason = _uncertain(root / entry["path"] / "record.json")
        return verdict, reason, None
    if suite == approval_binding.SUITE:
        decision, reason = approval_binding.judge(root / entry["path"] / "record.json")
        return ("accept" if decision == approval_binding.ALLOW else "reject"), reason, None
    return "not-applicable", "suite-not-implemented", None


def lines(root: Path) -> list[dict[str, Any]]:
    """The verdict line of every member of the corpus at ``root``."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    suite, digest, entries = manifest.get("suite"), manifest.get("corpusDigest"), manifest.get("vectors")
    if not isinstance(suite, str) or not isinstance(digest, str) or not isinstance(entries, list):
        raise ValueError(f"{root}/MANIFEST.json names no suite, corpusDigest or vectors list")
    verifier = {"name": NAME, "version": version()}
    out = []
    for entry in entries:
        try:
            verdict, reason, result = _answer(suite, root, entry)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            verdict, reason, result = "error", f"{type(exc).__name__}: {exc}", None
        line: dict[str, Any] = {"schema": SCHEMA_ID, "suite": suite, "corpusDigest": digest,
                                "vector": entry["id"], "verdict": verdict, "reason": reason,
                                "verifier": verifier}
        if result is not None:
            line["result"] = result
        out.append(line)
    return out


def main(argv: list[str] | None = None) -> int:
    """Print verdict lines for every corpus named; 2 when one cannot be read."""
    parser = argparse.ArgumentParser(
        prog="agent-evidence-verify corpus",
        description="print one verdict line per member of each corpus directory")
    parser.add_argument("corpus", nargs="+", type=Path, metavar="DIR")
    args = parser.parse_args(argv)
    try:
        rendered = [json.dumps(line, sort_keys=True, separators=(",", ":"))
                    for root in args.corpus for line in lines(root)]
    except (OSError, ValueError) as exc:
        print(f"agent-evidence-verify corpus: NOT RUN: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write("".join(text + "\n" for text in rendered))
    return 0
