"""Generate independent support examples and their exact byte bindings."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    checks = ["action_binding", "recipient", "plan", "discount", "tenure",
              "draft_rendering", "report", "manager_authorization"]
    files, members = {}, []
    variants = (
        ("routine", 1200, False, "supported", "routine_action_supported", "APPROVE"),
        ("green-over-limit", 2400, False, "contradicted", "discount_exceeds_maximum", "BLOCK"),
        ("needs-manager", 1600, False, "not_established", "artifact_unavailable_or_unbound", "HOLD_FOR_REVIEW"),
        ("exact-manager", 1600, True, "supported", "manager_action_supported", "APPROVE"),
    )
    for name, discount, approved, decision, reason, permission in variants:
        action = {"schema_version": "support-discount-action/v1", "action_id": f"offer-{name}",
                  "request_id": "request-42", "recipient": "customer@example.test",
                  "plan": "Professional", "discount_bps": discount}
        raw = {
            "action": encoded(action),
            "draft": f"Your {discount // 100}% loyalty discount applies to the Professional plan.\n".encode(),
            "customer": encoded({"customer_id": "customer-42", "recipient": action["recipient"],
                                 "plan": action["plan"], "tenure_months": 18}),
            "company_policy": encoded({"policy_id": "loyalty-2026-10", "plan": action["plan"],
                                       "routine_discount_bps": 1200, "maximum_discount_bps": 1800,
                                       "minimum_tenure_months": 12}),
            "report": encoded({"schema_version": "synthetic-quality-report/v1", "status": "GREEN", "score": 94}),
        }
        if approved:
            raw["manager_approval"] = encoded({
                "approval_id": "grant-42", "approver_id": "manager-42",
                **{key: action[key] for key in ("action_id", "request_id", "recipient", "plan", "discount_bps")},
                "action_sha256": hashlib.sha256(raw["action"]).hexdigest(),
                "draft_sha256": hashlib.sha256(raw["draft"]).hexdigest(),
                "not_before": "2026-10-10T19:00:00Z", "expires_at": "2026-10-10T21:00:00Z",
            })
            raw["approval_uses"] = encoded({"consumed_approval_ids": []})
        artifacts = {}
        for role, data in raw.items():
            path = f"{role}.txt" if role == "draft" else f"{role}.json"
            files[f"cases/{name}/{path}"] = data
            artifacts[role] = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}
        case = {"schema_version": "customer-support-action-case/v1", "case_id": name, "artifacts": artifacts}
        policy = {"schema_version": "customer-support-action-policy/v1", "assessments": {name: {
            "claim_type": "customer_support_action/v1", "bindings": {role: meta["sha256"] for role, meta in artifacts.items()},
            "required_checks": checks, "clock": "2026-10-10T20:00:00Z",
            "manager_ids": ["manager-42"], "manager_approval_id": "grant-42",
        }}}
        files[f"cases/{name}/case.json"] = encoded(case)
        files[f"cases/{name}/policy.json"] = encoded(policy)
        members.append({"case": f"cases/{name}/case.json", "policy": f"cases/{name}/policy.json",
                        "expected": {"decision": decision, "reason": reason, "action": permission}})
    manifest = {"schema_version": "customer-support-example/v1", "members": members,
                "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "length": len(data)}
                          for name, data in sorted(files.items())]}
    files["MANIFEST.json"] = encoded(manifest)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    for name, raw in build().items():
        path = root / name
        if args.check:
            if not path.is_file() or path.read_bytes() != raw:
                parser.exit(1, f"generated example differs: {name}\n")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
