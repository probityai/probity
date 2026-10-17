"""Build exact invented spend fixtures and their consumer-held pins."""

import argparse
import copy
import hashlib
import json
from pathlib import Path


def sha(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def build():
    prices = [{"provider": "fixture", "model": "loop", "target": "tool",
               "unit": "fixture-credit", "valid_from": 100, "expires_at": 400,
               "input_rate": 2, "output_rate": 3, "fixed_cost": 1}]
    budget = {"schema_version": "probity-spend-policy/v1", "budget_id": "budget-1",
              "unit": "fixture-credit", "limit": 100, "valid_from": 100,
              "expires_at": 500, "prices_sha256": sha(prices)}
    call = {"call_id": "call-1", "attempt": 1, "provider": "fixture", "model": "loop",
            "target": "tool", "args_sha256": "a" * 64, "input_limit": 10,
            "output_limit": 2, "price_sha256": sha(prices[0])}
    identity = sha({"budget_id": "budget-1", "call_id": "call-1", "attempt": 1})
    accepted = [
        {"sequence": 1, "kind": "reserve", "at": 101, "reservation": identity,
         "call": copy.deepcopy(call), "maximum": 27, "remaining_before": 100, "remaining_after": 73},
        {"sequence": 2, "kind": "dispatch", "at": 102, "reservation": identity,
         "call": copy.deepcopy(call), "maximum": 27, "remaining_after": 73},
        {"sequence": 3, "kind": "settle", "at": 103, "reservation": identity,
         "actual": 12, "bound_exceeded": False, "remaining_after": 88},
        {"sequence": 4, "kind": "refund", "at": 103, "reservation": identity,
         "amount": 15, "reason": "unused-reservation", "remaining_after": 88}]
    oversized = {**call, "input_limit": 50}
    cases = {"accepted": accepted, "pending": accepted[:2], "refused-overshoot": [
        {"sequence": 1, "kind": "deny", "at": 101, "call": oversized,
         "reason": "insufficient-budget", "remaining_after": 100}]}
    files = {}
    manifest = []
    for name, events in cases.items():
        trace = {"schema_version": "probity-spend-trace/v1", "budget_id": "budget-1",
                 "policy_sha256": sha(budget), "events": events}
        case = {"schema_version": "probity-case/v1", "case_id": name, "artifacts": {}}
        policy = {"schema_version": "probity-policy/v1", "witnesses": {}, "assessments": {name: {
            "claim_type": "spend_reservation/v1", "budget_id": "budget-1",
            "budget_policy_witness": "budget", "price_table_witness": "prices", "trace_witness": "trace"}}}
        for role, value in (("budget", budget), ("prices", prices), ("trace", trace)):
            raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
            digest = hashlib.sha256(raw).hexdigest()
            files[f"{name}/{role}.json"] = raw
            case["artifacts"][role] = {"path": role + ".json", "sha256": digest, "length": len(raw)}
            policy["witnesses"][role] = {"artifact": role, "sha256": digest,
                                        "authority": "consumer-selected synthetic fixture"}
        for role, value in (("case", case), ("policy", policy)):
            files[f"{name}/{role}.json"] = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    for name, raw in sorted(files.items()):
        manifest.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    files["MANIFEST.json"] = (json.dumps({"schema": "probity.spend-fixtures.v1",
        "operator": "authored synthetic controls", "providerBillingExecuted": False,
        "members": manifest}, indent=2) + "\n").encode()
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
                raise SystemExit("fixture bytes differ: " + name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    print("spend fixture bytes and bindings pass" if args.check else "spend fixtures generated")
