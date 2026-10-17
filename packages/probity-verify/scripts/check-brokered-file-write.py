"""Check real hard-exit captures with an independently installed Verify CLI.

This controller imports neither Observer nor Verify. It retains actual process
streams, original evidence and consumer-authored assertions separately.
"""

import argparse
import hashlib
import json
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ORIGINAL_SHA = "2b4f04dcc0c0d5e7c1a4a68288fd92457676db50da3da631a348ba0d4940605e"
ROOT = Path(__file__).resolve().parents[1]


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def file_binding(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def command(root, name, argv):
    started = time.time()
    with (root / (name + ".stdout")).open("xb") as stdout, (root / (name + ".stderr")).open("xb") as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr, check=False, timeout=120)
    record = {"argv": argv, "exit": result.returncode, "started_epoch": started, "ended_epoch": time.time(),
              "stdout": {"path": name + ".stdout", **file_binding(root / (name + ".stdout"))},
              "stderr": {"path": name + ".stderr", **file_binding(root / (name + ".stderr"))}}
    (root / (name + ".process.json")).write_bytes(encode(record))
    return result.returncode


def select(root, public, *, completion, sealed):
    """Author a new typed report and consumer selection; originals stay intact."""
    authority = public["authority"]
    report = {"schema_version": "brokered-file-write-report/v1", "interval_id": authority["intervalId"],
              "request_id": public["request_id"], "path": public["path"],
              "content_sha256": public["content_sha256"], "completion_recorded": completion}
    label = "assert-true" if completion else "assert-false"
    (root / (label + ".report.json")).write_bytes(encode(report))
    roles = {"report": label + ".report.json", "history": "history.jsonl", "ledger": "ledger.jsonl", "head": "head.json"}
    if sealed:
        roles["packet"] = "packet.json"
    if (root / "work/result.txt").is_file():
        roles["target"] = "work/result.txt"
    artifacts = {role: {"path": path, "length": file_binding(root / path)["bytes"],
                        "sha256": file_binding(root / path)["sha256"]} for role, path in roles.items()}
    selector = lambda role: {"artifact": role, "sha256": artifacts[role]["sha256"]}
    case = {"schema_version": "probity-case/v1", "case_id": label, "artifacts": artifacts}
    record = {"state": "sealed" if sealed else "missing_terminal",
              **{role: selector(role) for role in roles if role not in {"report", "target"}}}
    context = {"interval_id": authority["intervalId"], "request_id": public["request_id"], "path": public["path"],
               "authority_scope": authority["scope"], "intended_content_sha256": public["content_sha256"]}
    policy = {"schema_version": "probity-policy/v1", "witnesses": {"broker": {
              "observer_key": public["observer_key"], "witness_key": public["witness_key"],
              "witness_scope": "PEER", "record": record}}, "assessments": {label: {
              "claim_type": "brokered_file_write/v1", "report": selector("report"), "broker_witness": "broker",
              "context": context, "retained_target": {**selector("target"), "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
              if "target" in roles else None}}}
    (root / (label + ".case.json")).write_bytes(encode(case))
    (root / (label + ".policy.json")).write_bytes(encode(policy))
    return label


def consume(root, verifier, public, *, sealed):
    rows = []
    for completion in (True, False):
        label = select(root, public, completion=completion, sealed=sealed)
        argv = [verifier, str(root / (label + ".case.json")), "--policy", str(root / (label + ".policy.json")), "--json"]
        code = command(root, label, argv)
        expected = ("supported" if completion else "contradicted") if sealed else "not_established"
        raw = (root / (label + ".stdout")).read_bytes()
        answer = json.loads(raw) if code == 0 else None
        valid = code == 0 and answer["decision"] == expected and answer["scope"]["witness_scope"] == "PEER"
        rows.append({"assertion": completion, "expected": expected, "exit": code,
                     "actual": answer["decision"] if answer else None, "valid": valid})
    return rows


def original_capture(path, output, verifier):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ORIGINAL_SHA:
        raise ValueError("original public capture digest differs")
    original = output / "original-capture"
    original.mkdir()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("duplicate ZIP members")
        policy_raw = archive.read("native/host-policy.json")
        (original / "host-policy.json").write_bytes(policy_raw)
        policy = json.loads(policy_raw)
        inventory = []
        # Read and bind every original member, without executing archive code.
        for item in archive.infolist():
            name = PurePosixPath(item.filename)
            if name.is_absolute() or ".." in name.parts or item.is_dir():
                raise ValueError("unexpected original ZIP path")
            data = archive.read(item)
            inventory.append({"path": item.filename, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        (original / "members.json").write_bytes(encode(inventory))
        for source, digest in policy["source"].items():
            if hashlib.sha256(archive.read("native/packet/source/" + source)).hexdigest() != digest:
                raise ValueError("original source binding differs")
        rows = []
        for name, selected in sorted(policy["cases"].items()):
            root = original / name
            root.mkdir()
            for relative, digest in selected["files"].items():
                data = archive.read("native/packet/" + name + "/" + relative)
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError("original selected evidence binding differs")
                target = root / relative
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(data)
            request = selected["request"]
            public = {"authority": {"intervalId": name, "scope": "/work", "operation": "write-file"},
                      "observer_key": selected["observerKey"], "witness_key": selected["witnessKey"],
                      "request_id": request["request_id"], "path": request["target_path"],
                      "content_sha256": request["content_sha256"]}
            results = consume(root, verifier, public, sealed=selected["signedTerminal"])
            rows.append({"case": name, "original_expected_exit": selected["expectedExit"],
                         "original_expected_state": selected["expectedState"], "results": results})
        return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer-python", required=True)
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-capture", type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for mode in ("completed", "after-seal", "before-terminal"):
        root = output / mode
        argv = [args.producer_python, str(ROOT / "scripts/brokered-file-write-producer.py"), "--output", str(root), "--mode", mode]
        code = command(output, mode, argv)
        expected_exit = 0 if mode == "completed" else 74
        if code != expected_exit:
            raise ValueError(f"producer {mode} actual exit {code}, expected {expected_exit}")
        public = json.loads((root / "public-selection.json").read_bytes())
        target = (root / "work/result.txt").read_bytes()
        if hashlib.sha256(target).hexdigest() != public["content_sha256"]:
            raise ValueError("actual target differs from declared native content")
        results = consume(root, args.verifier, public, sealed=mode != "before-terminal")
        rows.append({"mode": mode, "actual_process_exit": code, "target": file_binding(root / "work/result.txt"), "results": results})
    originals = original_capture(args.original_capture, output, args.verifier) if args.original_capture else []
    valid = all(result["valid"] for row in rows + originals for result in row["results"])
    result = {"schema": "probity-brokered-file-write-native-controls/v1", "operator": "author-operated",
              "witness_scope": "PEER", "native": rows, "original_replays": originals,
              "original_capture": file_binding(args.original_capture) if args.original_capture else None,
              "valid": valid, "does_not_establish": ["independent custody", "maintainer acceptance", "outside adoption", "registered study result"]}
    (output / "RESULTS.json").write_bytes(encode(result))
    print(json.dumps(result, indent=2))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
