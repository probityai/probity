"""Reproduce the retained synthetic vantage examples without changing their bytes."""

import argparse
import hashlib
import json
from pathlib import Path


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def build():
    scope = {"id": "run-1", "start": "2026-09-01T00:00:00Z",
             "end": "2026-09-01T00:01:00Z"}
    files = {}
    for name in ("covered", "observed-write", "self-reported-write"):
        producer = "agent-1" if name == "self-reported-write" else "host-broker"
        vantage = "self_reported" if name == "self-reported-write" else "independent"
        capability = {"schema_version": "probity-capabilities/v1", "claim_id": name,
                      "invocation_id": "call-1", "producer": producer,
                      "visible_event_types": ["write"]}
        observation = {"schema_version": "probity-observation/v1", "claim_id": name,
                       "invocation_id": "call-1", "producer": producer,
                       "vantage": vantage, "scope": scope, "coverage": "complete", "events": []}
        if name != "covered":
            observation["events"] = [{"id": "write-1", "type": "write",
                                       "time": "2026-09-01T00:00:50Z"}]
        if name == "observed-write":
            observation["coverage"] = "incomplete"
            observation["gaps"] = [{"start": "2026-09-01T00:00:20Z",
                                     "end": "2026-09-01T00:00:40Z"}]
        case = {"schema_version": "probity-case/v1", "case_id": name, "artifacts": {}}
        policy = {"schema_version": "probity-policy/v1", "witnesses": {},
                  "assessments": {name: {"claim_type": "event_absence/v2", "event_type": "write",
                      "invocation_id": "call-1", "scope": scope, "observed_party": "agent-1",
                      "capability_witness": "capability", "observation_witness": "observation"}}}
        for role, value in (("capability", capability), ("observation", observation)):
            raw = encoded(value)
            digest = hashlib.sha256(raw).hexdigest()
            files[f"{name}/{role}.json"] = raw
            case["artifacts"][role] = {"path": role + ".json", "length": len(raw), "sha256": digest}
            policy["witnesses"][role] = {"artifact": role, "authority": "synthetic fixture", "sha256": digest}
            if role == "observation":
                policy["witnesses"][role].update(producer=producer, vantage=vantage)
        files[f"{name}/case.json"] = encoded(case)
        files[f"{name}/policy.json"] = encoded(policy)
    members = [{"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
               for name, raw in sorted(files.items())]
    files["MANIFEST.json"] = encoded({"schema": "probity.vantage-fixtures/v1",
        "source_commit": "a489590aa537b46f54caddb552b4f6d1464c2565",
        "operator": "authored synthetic records", "members": members})
    return files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    for name, raw in build().items():
        path = root / name
        if args.check:
            if not path.is_file() or path.read_bytes() != raw:
                raise SystemExit("vantage fixture bytes differ: " + name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    print("vantage fixture bytes and bindings pass" if args.check else "vantage fixtures reproduced")
