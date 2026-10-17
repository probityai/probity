"""Generate pinned operand-lineage fixtures and their expected decisions."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


SOURCE = {"values": {"checking": "15.20", "savings": "12"}}
TRACE = {
    "steps": [
        {"id": "difference", "operation": "subtract", "operands": [
            {"kind": "source", "ref": "checking", "value": "15.20"},
            {"kind": "source", "ref": "savings", "value": "12"},
        ], "result": "3.20"},
        {"id": "total", "operation": "multiply", "operands": [
            {"kind": "step", "ref": "difference", "value": "3.20"},
            {"kind": "constant", "ref": "multiplier", "value": "2"},
        ], "result": "6.40"},
    ],
    "figure": "6.40",
}


def _vectors() -> list[dict]:
    cases = []

    def add(name: str, decision: str, reason: str, *, source: dict | None = None,
            trace: dict | None = None, constants: dict | None = None,
            omit_execution: bool = False, stale_source_pin: bool = False) -> None:
        cases.append({"id": name, "expected": {"decision": decision, "reason": reason},
                      "source": copy.deepcopy(SOURCE if source is None else source),
                      "trace": copy.deepcopy(TRACE if trace is None else trace),
                      "constants": copy.deepcopy({"multiplier": "2"} if constants is None else constants),
                      "omit_execution": omit_execution, "stale_source_pin": stale_source_pin})

    add("complete", "supported", "lineage_recomputed")

    compensating = copy.deepcopy(TRACE)
    compensating["steps"][0]["operands"][0]["value"] = "15.30"
    compensating["steps"][0]["operands"][1]["value"] = "12.10"
    add("compensating-operands", "contradicted", "operand_unresolved", trace=compensating)

    wrong_result = copy.deepcopy(TRACE)
    wrong_result["steps"][0]["result"] = "3.30"
    wrong_result["steps"][1]["operands"][0]["value"] = "3.30"
    wrong_result["steps"][1]["result"] = "6.60"
    wrong_result["figure"] = "6.60"
    add("incorrect-intermediate", "contradicted", "result_mismatch", trace=wrong_result)

    wrong_figure = copy.deepcopy(TRACE)
    wrong_figure["figure"] = "6.50"
    add("incorrect-figure", "contradicted", "figure_mismatch", trace=wrong_figure)

    dead_step = copy.deepcopy(TRACE)
    dead_step["steps"].insert(1, {
        "id": "unused", "operation": "add", "operands": [
            {"kind": "source", "ref": "checking", "value": "15.20"},
            {"kind": "source", "ref": "savings", "value": "12"},
        ], "result": "27.20",
    })
    add("dead-step", "contradicted", "step_not_in_final_lineage", trace=dead_step)
    add("unused-constant", "contradicted", "declared_constant_unused",
        constants={"multiplier": "2", "unused": "1"})

    missing_ref = copy.deepcopy(TRACE)
    missing_ref["steps"][0]["operands"][0]["ref"] = "absent"
    add("missing-source-reference", "not_established", "reference_missing", trace=missing_ref)

    division = {"steps": [{
        "id": "quotient", "operation": "divide", "operands": [
            {"kind": "source", "ref": "one", "value": "1"},
            {"kind": "source", "ref": "three", "value": "3"},
        ], "result": "0.333",
    }], "figure": "0.333"}
    add("rounding-unspecified", "not_established", "rounding_rule_missing",
        source={"values": {"one": "1", "three": "3"}}, trace=division, constants={})

    add("execution-absent", "not_established", "witness_unavailable_or_unbound",
        omit_execution=True)
    add("self-hashed-source-swap", "not_established", "witness_unavailable_or_unbound",
        source={"values": {"checking": "15.30", "savings": "12"}}, stale_source_pin=True)
    return cases


def generate(root: Path = ROOT) -> dict:
    entries = []
    original_source_pin = _sha(_json(SOURCE))
    for vector in _vectors():
        name = vector["id"]
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        source = _json(vector["source"])
        execution = _json(vector["trace"])
        case_id = f"operand-lineage-{name}"
        case = {"schema_version": "probity-case/v1", "case_id": case_id,
                "artifacts": {
                    "source": {"path": "source.json", "sha256": _sha(source), "length": len(source)},
                    "execution": {"path": "execution.json", "sha256": _sha(execution),
                                  "length": len(execution)},
                }}
        policy = {"schema_version": "probity-policy/v1", "witnesses": {
            "source": {"artifact": "source", "sha256": original_source_pin if vector["stale_source_pin"] else _sha(source),
                       "authority": "consumer-pinned synthetic source"},
            "execution": {"artifact": "execution", "sha256": _sha(execution),
                          "authority": "consumer-pinned synthetic trace"},
        }, "assessments": {case_id: {
            "claim_type": "operand_lineage/v1", "source_witness": "source",
            "execution_witness": "execution", "final_step":
                "quotient" if name == "rounding-unspecified" else "total",
            "constants": vector["constants"],
        }}}
        files = {"source.json": source, "case.json": _json(case), "policy.json": _json(policy)}
        if not vector["omit_execution"]:
            files["execution.json"] = execution
        else:
            (directory / "execution.json").unlink(missing_ok=True)
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({"id": name, "path": f"cases/{name}",
                        "files": {filename: _sha(data) for filename, data in sorted(files.items())},
                        "expected": vector["expected"]})
    manifest = {"suite": "operand-lineage/v1", "vectors": entries,
                "verifierContract": "probity-verify case.json --policy policy.json --json"}
    manifest["corpusDigest"] = _sha(_json(entries))
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
