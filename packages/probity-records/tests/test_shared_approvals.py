"""The approval vectors in vectors/shared/approvals.json are this package's verdicts under the installed reader.

The TypeScript twin (node/probity-records-verify) is held to these expected reports, so a reader release that changes a
verdict must change the file in the same commit; this test is what notices when it did not.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from probity_records import BINDING_MALFORMED, judge_approval_binding, verify_journal
from probity_records.authority import Trust

SHARED = Path(__file__).resolve().parents[1] / "vectors" / "shared"
ROWS = json.loads((SHARED / "approvals.json").read_text())


@pytest.mark.parametrize("row", ROWS, ids=[row["id"] for row in ROWS])
def test_shared_approval_vector_is_this_packages_verdict(row: dict, tmp_path: Path) -> None:
    (tmp_path / "journal.jsonl").write_text("".join(line + "\n" for line in row["journal"]))
    doc = row["trust"]
    trust = Trust(grant_root_key_ids=frozenset(doc["grantRootKeyIds"]), quorum_policies=doc["quorumPolicies"])
    report = verify_journal(tmp_path, [k.encode() for k in row["keys"]], row["checkpoint"], trust=trust)
    assert {k: report[k] for k in row["expected"]} == row["expected"]


def _reasons() -> set[str]:
    """The reader's reason for every approval binding embedded in the vectors' journals."""
    reasons = set()
    for row in ROWS:
        for line in row["journal"]:
            body = json.loads(base64.b64decode(json.loads(line)["payload"]))
            for embedded in body["predicate"].get("approvalBindings") or []:
                payload = base64.b64decode(embedded["payloadB64"])
                reasons.add(judge_approval_binding(embedded["record"], payload)["reason"])
    return reasons


def test_shared_approval_vectors_reach_every_check_the_builder_writes_for() -> None:
    missing = {"bound", "approval_not_issued", "approval_not_granted", "approval_not_enforced",
               "approval_request_completed_twice", "key_retired", BINDING_MALFORMED} - _reasons()
    assert not missing, missing
