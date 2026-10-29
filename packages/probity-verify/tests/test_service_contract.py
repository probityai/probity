"""A service that follows the contract returns the command line's bytes."""

import base64
import json
import tempfile
from pathlib import Path, PurePosixPath

from probity_verify.cli import main
from probity_verify.core import CaseError, adjudicate, canonical_json

DOCS = Path(__file__).resolve().parents[1] / "docs"
EXAMPLE = Path(__file__).resolve().parents[1] / "examples/source-coverage"
SCHEMA = json.loads((DOCS / "verifier-service-request.schema.json").read_text())


def build_request(case_name: str, policy_name: str) -> dict:
    case = json.loads((EXAMPLE / case_name).read_text())
    artifacts = {}
    for item in case["artifacts"].values():
        raw = (EXAMPLE / item["path"]).read_bytes()
        artifacts[item["path"]] = {"encoding": "base64", "bytes": base64.b64encode(raw).decode()}
    return {"contract": "probity-verify-service/v1", "case": case,
            "policy": json.loads((EXAMPLE / policy_name).read_text()),
            "artifacts": artifacts}


def handle(request: dict) -> tuple[int, bytes]:
    """Reference handler: the whole of what a conforming service does."""
    if request.get("contract") != SCHEMA["properties"]["contract"]["const"]:
        return 400, canonical_json({"error": "unsupported contract"})
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, blob in request["artifacts"].items():
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                return 422, canonical_json({"error": f"artifact path {name} leaves the root"})
            target = root.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(blob["bytes"], validate=True))
        try:
            decision = adjudicate(request["case"], request["policy"], root,
                                  require_witness_scope=request.get("require_witness_scope", "PEER"))
        except CaseError as exc:
            return 422, canonical_json({"error": str(exc)})
    return 200, canonical_json(decision)


def cli_bytes(case_name: str, policy_name: str, capsys) -> bytes:
    argv = [str(EXAMPLE / case_name), "--policy", str(EXAMPLE / policy_name), "--json"]
    assert main(argv) == 0
    return capsys.readouterr().out.encode()


def test_body_equals_the_command_line_bytes(capsys):
    for case_name, policy_name in (("case.json", "policy-june.json"),
                                   ("case.json", "policy-april.json"),
                                   ("case-complete.json", "policy-complete.json")):
        status, body = handle(build_request(case_name, policy_name))
        assert status == 200
        assert body == cli_bytes(case_name, policy_name, capsys)


def test_a_tampered_artifact_changes_the_decision_and_still_matches_the_cli(tmp_path, capsys):
    request = build_request("case.json", "policy-june.json")
    original = handle(request)[1]
    blob = request["artifacts"]["source.html"]
    blob["bytes"] = base64.b64encode(base64.b64decode(blob["bytes"]) + b" ").decode()
    status, body = handle(request)
    assert status in (200, 422)
    assert body != original
    if status == 200:
        for name, entry in request["artifacts"].items():
            (tmp_path / name).write_bytes(base64.b64decode(entry["bytes"]))
        (tmp_path / "case.json").write_text(json.dumps(request["case"]))
        (tmp_path / "policy.json").write_text(json.dumps(request["policy"]))
        assert main([str(tmp_path / "case.json"), "--policy", str(tmp_path / "policy.json"), "--json"]) == 0
        assert body == capsys.readouterr().out.encode()


def test_a_path_that_climbs_out_is_refused():
    request = build_request("case.json", "policy-june.json")
    request["artifacts"]["../escape.txt"] = {"encoding": "base64", "bytes": ""}
    status, body = handle(request)
    assert status == 422
    assert json.loads(body)["error"].startswith("artifact path")


def test_request_example_matches_the_schema_members():
    request = build_request("case.json", "policy-june.json")
    assert set(request) <= set(SCHEMA["properties"])
    assert set(SCHEMA["required"]) <= set(request)
