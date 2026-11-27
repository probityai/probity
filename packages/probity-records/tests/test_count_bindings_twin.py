"""The two readers count an approval's people the same way: OpenID Connect sign-ins and revoked approver keys.

``quorum.count_bindings`` counts an approver who signed in at a pinned identity provider and refuses an approver
whose key the auditor's revocation lists revoked at or before the record's time. The TypeScript twin's
``countBindings`` must give the same people and the same problems. The fixture holds each case's inputs (policy,
embedded bindings, record time, provider pins, signed revocation lists) and this reader's result; this file checks
the fixture is this reader's result, and ``node/probity-records-verify/test/count-bindings.test.ts`` checks the
twin returns it.

Regenerate after an intended change: ``uv run python packages/probity-records/tests/test_count_bindings_twin.py``.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

from probity_records import (
    RevocationState,
    build_approval_binding,
    embed_approval_binding,
    sign_approval,
    sign_revocations,
)
from probity_records.quorum import count_bindings

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import gen_shared_vectors as g
import test_oidc_approval as o

FIXTURE = (Path(__file__).resolve().parents[3] / "node" / "probity-records-verify" / "test" / "fixtures"
           / "count-bindings.json")
BOB, ROOT = g.key("count-bindings/bob"), g.key("count-bindings/revocation-root")
POLICY = {"policyId": "acme-wires", "threshold": 2,
          "approvers": {"dave": o.POLICY["approvers"]["dave"],
                        "bob": base64.b64encode(BOB.public.public_bytes_raw()).decode()}}


def keyed(**over: Any) -> dict[str, Any]:
    approval = o.body("bob", BOB.key_id, **over)
    signed = sign_approval(BOB, approval)
    record, payload = build_approval_binding(approval, o.USE, o.PAYLOAD, [], {"bob": BOB.key_id}, o.DECIDED,
                                             o.RELEASE, issued=["req-1"], enforcement="enforce")
    return embed_approval_binding(record, payload, signed["sig"])


def revoked(at: str) -> dict[str, Any]:
    """The auditor's pinned lists: one list revoking bob's key at ``at``."""
    entry = {"kind": "key", "id": BOB.key_id, "revokedAt": at, "reason": "left"}
    lists = [sign_revocations(ROOT, list_id="rl", seq=1, issued_at="2026-11-11T00:00:00Z", entries=[entry])]
    return {"rootKeyIds": [ROOT.key_id], "lists": lists}


def cases() -> dict[str, dict[str, Any]]:
    good = o.body()
    edited = o.oidc(good)
    edited["record"]["approval"] = {**good, "payloadSha256": "0" * 64}
    pins = o.PINS
    return {
        "oidc and key approvals both count": {"bindings": [o.oidc(good), keyed()], "pins": pins},
        "no provider pinned: the sign-in does not count": {"bindings": [o.oidc(good), keyed()], "pins": {}},
        "the body was edited after the sign-in": {"bindings": [edited, keyed()], "pins": pins},
        "a session from before the request": {"bindings": [o.oidc(good, auth_offset=-3600)], "pins": pins},
        "a token another provider key signed": {"bindings": [o.oidc(good, signer=o._key("another-idp"))],
                                                "pins": pins},
        "a sign-in as someone the policy does not pin": {"bindings": [o.oidc(good, sub="someone-else")],
                                                         "pins": pins},
        "an approval key id that is not the principal": {"bindings": [o.oidc(o.body(key="f" * 64))], "pins": pins},
        "one person signs in twice": {"bindings": [o.oidc(good), o.oidc(good)], "pins": pins},
        "the key approval carries a token": {"bindings": [{**keyed(), "approvalToken": "x.y.z"}], "pins": pins},
        "bob's key revoked before the decision": {"bindings": [o.oidc(good), keyed()], "pins": pins,
                                                  "revocations": revoked("2026-11-10T09:00:00Z")},
        "bob's key revoked after the decision": {"bindings": [o.oidc(good), keyed()], "pins": pins,
                                                 "revocations": revoked("2026-11-10T09:05:00Z")},
    }


def result(case: dict[str, Any]) -> list[Any]:
    docs = case.get("revocations")
    state = None if docs is None else RevocationState.from_lists(docs["lists"], docs["rootKeyIds"])
    key_revoked = None if state is None else state.key_revoked
    counted, problems = count_bindings(POLICY, case["bindings"], o.DECIDED, key_revoked, oidc_pins=case["pins"])
    return [sorted(counted), problems]


def build() -> dict[str, Any]:
    rows = [{"id": name, **case, "revocations": case.get("revocations"), "expected": result(case)}
            for name, case in cases().items()]
    return {"policy": POLICY, "at": o.DECIDED, "cases": rows}


def test_the_fixture_is_this_readers_count() -> None:
    fixture = json.loads(FIXTURE.read_text())
    assert fixture == build()
    for case in fixture["cases"]:
        assert result(case) == case["expected"], case["id"]


def test_the_cases_reach_both_paths_and_the_revocation() -> None:
    expected = {c["id"]: c["expected"] for c in json.loads(FIXTURE.read_text())["cases"]}
    assert expected["oidc and key approvals both count"] == [["bob", "dave"], []]
    assert expected["bob's key revoked before the decision"] == [["dave"], ["binding_1:approver_key_revoked"]]
    assert expected["bob's key revoked after the decision"] == [["bob", "dave"], []]


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(build(), indent=1, sort_keys=True) + "\n")
