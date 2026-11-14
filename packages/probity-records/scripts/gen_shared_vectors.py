"""Write the shared verifier vectors every implementation of the records verifier must agree on.

Each journal case is ``{"id", "description", "journal": [line, ...], "checkpoint", "keys": [pem],
"trust": {...}, "expected": {"verdict", "records", "verified", "failures", "checkpoint"}}``; the
expected block is this package's own ``verify_journal`` result. ``identity.json`` holds the
principal-level vectors of ``identity_vectors``. Run from the package: ``uv run python
scripts/gen_shared_vectors.py vectors/shared``.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from probity_records import (GRANT_ALLOW, QUORUM_ALLOW, TOOL_CALL_RECORD, Journal, Signer, Trust, args_sha256,
                             verify_grant_allow, build_approval_binding, build_uncertain_effect, canonical as jcs,
                             embed_approval_binding, grant_evidence, issue_grant, permit_id, raw_public,
                             sign_approval, tool_call_predicate, verify_journal)
from probity_records.core import _b64, canonical
from probity_records.grants import GRANT_DOMAIN
from probity_records.identity_vectors import vectors as identity_vectors
from probity_records.quorum import approval_policy, count, request_hash, sign_deputy, sign_vote

NB, EXP, AT = "2026-01-01T00:00:00Z", "2099-12-31T00:00:00Z", "2026-06-01T00:00:00Z"
TOOLS = {"refund": {"approval": "none", "when": ["args.amount_cents < 3000 || args.currency == 'USD'"], "args": {
    "amount_cents": {"type": "range", "min": 1, "max": 4000},
    "currency": {"type": "cel", "expr": "value in ['USD', 'EUR']"},
    "note": {"type": "any", "of": [{"type": "pattern", "pattern": "ticket-*"}, {"type": "exact", "value": None}]}}}}
CTX = {"workflowId": "refunds-42", "runId": "r1"}
WF = {"workflowId": {"type": "pattern", "pattern": "refunds-*"}}


def key(name: str) -> Signer:
    return Signer(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"probity-shared-vectors/{name}".encode()).digest()))


GATE, ROOT, AGENT, SUB = key("gate"), key("root"), key("agent"), key("sub")


def chain(**root_kw) -> list[dict]:
    root_kw.setdefault("context", WF)
    parent = issue_grant(ROOT, grant_id="g-root", holder_key=raw_public(AGENT), tools=TOOLS, max_depth=1,
                         not_before=NB, expires_at=EXP, **root_kw)
    budget = root_kw.get("budget")
    child = issue_grant(AGENT, grant_id="g-child", holder_key=raw_public(SUB), tools=TOOLS, parent=parent,
                        not_before=NB, expires_at=EXP, context=root_kw["context"], budget=budget)
    return [parent, child]


def grant_case(directory: Path, grants: list[dict], calls: list[dict], *, intent_grant: str | None = None,
               ctx: dict | None = None) -> Journal:
    j = Journal(directory, GATE)
    for n, args in enumerate(calls):
        pid = permit_id("p", f"c{n}", args_sha256(args))
        common = {"run_id": "r1", "tool_call_id": f"c{n}", "tool": "refund", "args_sha256_hex": args_sha256(args),
                  "permit_id": pid}
        verdict = verify_grant_allow(grants, "refund", args, AT, {ROOT.key_id}, ctx=ctx or CTX)
        digest = verdict["grantDigest"] or "00" * 32
        j.append(TOOL_CALL_RECORD, f"tool-call:c{n}", args_sha256(args), tool_call_predicate(
            phase="authorize", decision="allow", reason=GRANT_ALLOW, authority=grant_evidence(grants, args, ctx or CTX),
            grant_digest=digest, **common))
        j.append(TOOL_CALL_RECORD, f"tool-call:c{n}", args_sha256(args), tool_call_predicate(
            phase="intent", grant_digest=intent_grant or digest, **common))
    return j


def forged_wide() -> list[dict]:
    parent, child = chain()
    wide = {**child["body"], "tools": {"refund": {**TOOLS["refund"], "args": {
        **TOOLS["refund"]["args"], "amount_cents": {"type": "range", "min": 1, "max": 400000}}}}}
    return [parent, {"body": wide, "sig": _b64(AGENT.sign(GRANT_DOMAIN + canonical(wide)))}]


QNAMES = ("alice", "bob", "carol", "dave")
QKEYS = {n: key(f"approver-{n}") for n in QNAMES}
POLICY = {"approvers": {n: raw_public(QKEYS[n]) for n in QNAMES[:3]}, "policyId": "pay", "proposerBound": True,
          "roles": {"finance": {"members": ["bob", "carol"], "min": 1}, "security": {"members": ["alice", "bob"],
                                                                                     "min": 1}},
          "threshold": 2}
QARGS = {"amount_cents": 90000}
QPID = permit_id("p", "q1", args_sha256(QARGS))
QREQ = request_hash("pay", args_sha256(QARGS), QPID, proposer="dave", history="ab" * 32)
W = {"issued_at": "2026-05-01T00:00:00Z", "expires_at": EXP}


def vote(who: str, role: str, **kw) -> dict:
    return sign_vote(QKEYS[who], approver=who, policy_id="pay", request=QREQ, role=role, **W, **kw)


def quorum_case(directory: Path, votes: list[dict], proposer: str = "dave") -> Journal:
    result = count(POLICY, QREQ, votes, AT, proposer=proposer)
    evidence = result.evidence(POLICY, QREQ, proposer=proposer, history="ab" * 32)
    evidence["votes"] = list(votes)
    j = Journal(directory, GATE)
    j.append(TOOL_CALL_RECORD, "tool-call:q1", args_sha256(QARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason=QUORUM_ALLOW, authority=evidence, run_id="r1",
        tool_call_id="q1", tool="pay", args_sha256_hex=args_sha256(QARGS), permit_id=QPID))
    return j


# ---- constraint edge cases: IPv6 CIDR, shell quoting, int vs float ----

def solo_chain(tools: dict) -> list[dict]:
    return [issue_grant(ROOT, grant_id="g-solo", holder_key=raw_public(AGENT), tools=tools, not_before=NB,
                        expires_at=EXP)]


def solo_case(directory: Path, tools: dict, tool: str, calls: list[dict]) -> Journal:
    """One recorded allow per call. A call the grant refuses is recorded as an allow all the same, so the
    verifier's own judgement of the grant is what the vector pins."""
    j = Journal(directory, GATE)
    grants = solo_chain(tools)
    for n, args in enumerate(calls):
        verdict = verify_grant_allow(grants, tool, args, AT, {ROOT.key_id}, ctx={})
        j.append(TOOL_CALL_RECORD, f"tool-call:s{n}", args_sha256(args), tool_call_predicate(
            phase="authorize", decision="allow", reason=GRANT_ALLOW, authority=grant_evidence(grants, args, {}),
            grant_digest=verdict["grantDigest"] or "00" * 32, run_id="r1", tool_call_id=f"s{n}", tool=tool,
            args_sha256_hex=args_sha256(args), permit_id=permit_id("p", f"s{n}", args_sha256(args))))
    return j


def one_arg(constraint: dict) -> dict:
    return {"probe": {"approval": "none", "args": {"x": constraint}}}


def constraint_rows() -> list[tuple[str, str, object]]:
    def row(vid: str, description: str, constraint: dict, values: list) -> tuple[str, str, object]:
        return vid, description, lambda d: solo_case(d, one_arg(constraint), "probe", [{"x": v} for v in values])
    v6 = {"type": "cidr", "network": "2001:db8::/32"}
    return [
        row("CV1", "IPv6 CIDR: an address inside, one outside, an IPv4 address, text that is no address",
            v6, ["2001:db8::1", "2001:db8:ffff::", "2001:dc8::1", "192.0.2.1", "not-an-ip"]),
        row("CV2", "IPv6 CIDR spellings: compressed, expanded, mixed dotted quad, uppercase, zone id",
            {"type": "cidr", "network": "::ffff:0:0/96"},
            ["::ffff:192.0.2.1", "0:0:0:0:0:ffff:c000:201", "::FFFF:C000:201", "::ffff:c000:201%eth0", "::fffe:c000:201"]),
        row("CV3", "IPv4 CIDR spellings: prefix, netmask, hostmask, leading zeros, a single host",
            {"type": "cidr", "network": "10.0.0.0/255.0.0.0"}, ["10.1.2.3", "11.0.0.1", "010.1.2.3", "10.1.2"]),
        row("CV4", "single-host IPv6 network", {"type": "cidr", "network": "2001:db8::7"}, ["2001:db8::7", "2001:db8::8"]),
        row("CV5", "shlex allowlist: quoted command word, joined quoting, empty word, open quote",
            {"type": "shlex", "allow": ["git", "ls"]},
            ["git status", "'git' status", 'gi"t" log', "'git status'", "git 'open", "''", "  ls   -la", "ls\t-la", "rm -rf /",
             "git $(id)", "ls; id"]),
        row("CV6", "exact: 3 against 3.0 written as a float in the grant", {"type": "exact", "value": 3.0}, [3, 3.5, 4]),
        row("CV7", "one_of: a float 3.0 and an int 4 in the grant", {"type": "one_of", "values": [3.0, 4]}, [3, 4, 5]),
        row("CV8", "range with float bounds accepts ints and floats", {"type": "range", "min": 1.0, "max": 3.0}, [1, 2, 3, 3.5, 0]),
        row("CV9", "not_one_of treats 3 and 3.0 as equal", {"type": "not_one_of", "values": [3.0]}, [3, 4]),
        row("CV10", "cel on a float-valued grant constant", {"type": "cel", "expr": "value == 3.0"}, [3, 3.5]),
        row("CV11", "url_safe: global and private IPv6 and IPv4 literals",
            {"type": "url_safe", "schemes": ["http"]},
            ["http://[2001:4860:4860::8888]/", "http://[::1]/", "http://[fe80::1]/", "http://[2001:db8::1]/",
             "http://[::ffff:10.0.0.1]/", "http://[::ffff:8.8.8.8]/", "http://8.8.8.8/", "http://224.0.0.1/",
             "http://100.64.0.1/", "http://192.0.0.9/", "http://198.18.0.1/", "http://localhost/"]),
    ]


# ---- approval-binding and uncertain-effect records ----

OPS, LEAD, FORGER = key("approver-ops"), key("approver-lead"), key("approver-forger")
WHO = {"ops": "human:ops", "lead": "human:lead"}
APOL = {"refunds1": approval_policy("refunds1", {WHO["ops"]: OPS.public_pem()}, 1),
        "refunds2": approval_policy("refunds2", {WHO["ops"]: OPS.public_pem(), WHO["lead"]: LEAD.public_pem()}, 2)}
AARGS = {"amount_cents": 4000, "customer_id": "alice", "payee_account": "acct-alice"}
RELEASE = {"releaseId": "r1", "lookup": "ok", "graceSeconds": 300, "firstServedAt": "2026-01-01T00:00:00Z",
           "lastServedAt": "2099-01-01T00:00:00Z"}


def binding(signer: Signer, who: str, *, payload: dict | None = None, consumed: tuple = (), approval: dict | None = None,
            use: dict | None = None, record: dict | None = None, trusted_key: str | None = None,
            release: dict | None = None, payload_file: str | None = None) -> dict:
    approval_body = {"approvalId": "appr-1", "approver": who, "event": "tools/call", "expiresAt": "2099-01-01T00:00:00Z",
                     "issuedAt": "2026-01-01T00:00:00Z", "keyId": signer.key_id, "payloadSha256": args_sha256(AARGS),
                     "phase": "pre-execution", "principal": "customer:alice", "target": "acct-alice",
                     "tool": "refund_payment", **(approval or {})}
    use_body = {k: approval_body[k] for k in ("approvalId", "event", "phase", "principal", "target", "tool")}
    use_body["usedAt"] = "2026-06-01T00:00:00Z"
    use_body.update(use or {})
    rec, raw = build_approval_binding(approval_body, use_body, jcs(payload if payload is not None else AARGS), list(consumed),
                                      {who: trusted_key or signer.key_id}, "2026-06-01T00:00:00Z", release or RELEASE)
    rec.update(record or {})
    if payload_file is not None:
        rec["use"]["payloadFile"] = payload_file
    return embed_approval_binding(rec, raw, sign_approval(signer, rec["approval"])["sig"])


def approval_case(directory: Path, bindings: list[dict], *, decision: str = "allow", reason: str = "bound",
                  threshold: int | None = 1, policy: str | None = "refunds1") -> Journal:
    j = Journal(directory, GATE)
    j.append(TOOL_CALL_RECORD, "tool-call:a1", args_sha256(AARGS), tool_call_predicate(
        phase="authorize", decision=decision, reason=reason, approval_bindings=bindings, threshold=threshold,
        approval_policy=policy, run_id="run", tool_call_id="a1", tool="refund_payment", args_sha256_hex=args_sha256(AARGS),
        permit_id=permit_id("pause", "a1", args_sha256(AARGS))))
    return j


def approval_rows() -> list[tuple[str, str, object]]:
    ops = lambda **kw: binding(OPS, WHO["ops"], **kw)  # noqa: E731
    lead = lambda **kw: binding(LEAD, WHO["lead"], **kw)  # noqa: E731
    two = {"policy": "refunds2", "threshold": 2}
    renew = {"transitions": [{"status": "accepted", "mode": "exclusive-replacement", "predecessorApprovalId": "appr-0",
                              "successorApprovalId": "appr-1", "predecessorDecisionId": "d0", "successorDecisionId": "d1",
                              "acceptedAt": "2026-05-01T00:00:00Z"}],
             "presentedApprovals": []}
    old = {"approvalId": "appr-0", "approver": WHO["ops"], "event": "tools/call", "expiresAt": "2099-01-01T00:00:00Z",
           "issuedAt": "2026-01-01T00:00:00Z", "keyId": OPS.key_id, "payloadSha256": args_sha256(AARGS),
           "phase": "pre-execution", "principal": "customer:alice", "target": "acct-alice", "tool": "refund_payment",
           "decisionId": "d0"}
    return [
        ("AV1", "one approval under a 1-of-1 policy", lambda d: approval_case(d, [ops()])),
        ("AV2", "two distinct approvers under a 2-of-2 policy", lambda d: approval_case(d, [ops(), lead()], **two)),
        ("AV3", "one approval where the pinned policy needs two", lambda d: approval_case(d, [ops()], **two)),
        ("AV4", "a second approval signed by a key the policy does not pin",
         lambda d: approval_case(d, [ops(), binding(FORGER, WHO["lead"])], **two)),
        ("AV5", "the same approver twice counts once", lambda d: approval_case(d, [ops(), ops()], **two)),
        ("AV6", "the authority writes threshold 1 where the auditor pinned 2",
         lambda d: approval_case(d, [ops(), lead()], policy="refunds2", threshold=1)),
        ("AV7", "threshold written as the float 3.0 where the auditor pinned 2",
         lambda d: approval_case(d, [ops(), lead()], policy="refunds2", threshold=3.0)),
        ("AV8", "threshold written as the float 2.0 equals the pinned 2",
         lambda d: approval_case(d, [ops(), lead()], policy="refunds2", threshold=2.0)),
        ("AV9", "a replayed approval recorded as an allow", lambda d: approval_case(d, [ops(consumed=("appr-1",))])),
        ("AV10", "a replayed approval recorded as a deny with the reader's reason",
         lambda d: approval_case(d, [ops(consumed=("appr-1",))], decision="deny", reason="approval_replayed")),
        ("AV11", "a deny recorded with a reason the reader does not give",
         lambda d: approval_case(d, [ops(consumed=("appr-1",))], decision="deny", reason="payload_mismatch")),
        ("AV12", "the used payload is not the approved payload",
         lambda d: approval_case(d, [ops(payload={**AARGS, "amount_cents": 400000})])),
        ("AV13", "used after the approval expired", lambda d: approval_case(d, [ops(use={"usedAt": "2100-01-01T00:00:00Z"})])),
        ("AV14", "the policy release was not served at the decision time",
         lambda d: approval_case(d, [ops(release={**RELEASE, "firstServedAt": "2026-07-01T00:00:00Z"})])),
        ("AV15", "the policy release lookup failed",
         lambda d: approval_case(d, [ops(release={**RELEASE, "lookup": "unavailable"})])),
        ("AV16", "grace seconds written as a float extends the release window",
         lambda d: approval_case(d, [ops(release={**RELEASE, "lastServedAt": "2026-05-31T23:58:00Z", "graceSeconds": 300.0})])),
        ("AV17", "a renewal naming an accepted transition from a presented predecessor",
         lambda d: approval_case(d, [ops(approval={"decisionId": "d1"}, use={"authorityForm": "renewed"},
                                         record={**renew, "presentedApprovals": [old]})])),
        ("AV18", "a renewal with no accepted transition",
         lambda d: approval_case(d, [ops(approval={"decisionId": "d1"}, use={"authorityForm": "renewed"})])),
        ("AV19", "a renewal whose predecessor is not among the presented approvals",
         lambda d: approval_case(d, [ops(approval={"decisionId": "d1"}, use={"authorityForm": "renewed"}, record=renew)])),
        ("AV20", "an approval replaced before the use",
         lambda d: approval_case(d, [ops(record={"transitions": [{"status": "accepted", "mode": "exclusive-replacement",
                                                                  "predecessorApprovalId": "appr-1",
                                                                  "successorApprovalId": "appr-2",
                                                                  "predecessorDecisionId": "d1",
                                                                  "successorDecisionId": "d2",
                                                                  "acceptedAt": "2026-05-01T00:00:00Z"}]})])),
        ("AV21", "the effect the use names is already closed",
         lambda d: approval_case(d, [ops(use={"effectKey": "e1"}, record={"effectRegistry": {"e1": "CONSUMED"}})])),
        ("AV22", "the pinned key for the approver is another key",
         lambda d: approval_case(d, [ops(trusted_key="ff" * 32)])),
        ("AV23", "two different approvals share one identifier",
         lambda d: approval_case(d, [ops(record={"presentedApprovals": [{"approvalId": "appr-1", "approver": "human:x"}]})])),
        ("AV24", "the payload file name leaves the record's directory",
         lambda d: approval_case(d, [ops(payload_file="../payload.bin")])),
        ("AV25", "an allow naming a quorum policy the auditor never pinned",
         lambda d: approval_case(d, [ops()], policy="not-pinned")),
        ("AV26", "an allow with no approval binding and no policy reason", lambda d: approval_case(d, [])),
        ("AV27", "the contract identifier is not the approval-binding contract",
         lambda d: approval_case(d, [ops(record={"contractId": "https://example.invalid/other"})])),
        ("AV28", "the approving principal is not the user who made the call",
         lambda d: approval_case(d, [ops(use={"principal": "customer:mallory"})])),
    ]


E_ARGS = {"amount_cents": 1200, "customer_id": "bob"}
E_DIGEST = args_sha256(E_ARGS)


def effect_record(outcome: str, replies: list[str], owner_effects: int = 1, token: int | None = None, **kw) -> dict:
    extra = {} if token is None else {"worker": "w1", "fencingToken": token}
    attempts = [{"dispatchedAt": f"2026-06-01T00:00:{n * 10 + 1:02d}+00:00", "reply": r, **extra}
                for n, r in enumerate(replies)]
    return build_uncertain_effect(record_id="r", action="refund_payment", operation_id="op", idempotency_key="k",
                                  args_sha256_hex=E_DIGEST, attempts=attempts, owner_id="bank",
                                  owner_effects=owner_effects, outcome=outcome, as_of="2026-06-01T00:01:00+00:00", **kw)


def effect_case(directory: Path, record: dict | None, *, outcome: str | None = None, args: str = E_DIGEST,
                intent: bool = True) -> Journal:
    j = Journal(directory, GATE)
    pid = permit_id("pause", "e1", args)
    common = {"run_id": "run", "tool_call_id": "e1", "tool": "refund_payment", "args_sha256_hex": args, "permit_id": pid}
    j.append(TOOL_CALL_RECORD, "tool-call:e1", args, tool_call_predicate(
        phase="authorize", decision="allow", reason="no_approval_required", **common))
    if intent:
        j.append(TOOL_CALL_RECORD, "tool-call:e1", args, tool_call_predicate(phase="intent", **common))
    j.append(TOOL_CALL_RECORD, "tool-call:e1", args, tool_call_predicate(
        phase="effect", outcome=outcome if outcome is not None else (record or {}).get("reported", {}).get("outcome"),
        uncertain_effect=record, **common))
    return j


def effect_rows() -> list[tuple[str, str, object]]:
    def case(vid: str, description: str, record: dict | None, **kw) -> tuple[str, str, object]:
        return vid, description, lambda d: effect_case(d, record, **kw)
    lease = lambda token, a, b: {"worker": "w1", "fencingToken": token, "acquiredAt": a, "expiresAt": b}  # noqa: E731
    base = effect_record("committed", ["confirmed"])
    return [
        case("EV1", "a confirmed effect reported committed", base),
        case("EV2", "committed reported after a lost reply with no owner answer",
             effect_record("committed", ["connection_lost"])),
        case("EV3", "a lost reply honestly reported unknown", effect_record("unknown", ["connection_lost"])),
        case("EV4", "the owner reports two effects", effect_record("committed", ["confirmed"], owner_effects=2)),
        case("EV5", "the owner's count written as the float 2.0", {**base, "ownerEffects": 2.0}),
        case("EV6", "a retry after a timeout with no deduplication",
             effect_record("committed", ["timeout", "confirmed"])),
        case("EV7", "a retry the owner deduplicates by key within its retention",
             effect_record("committed", ["timeout", "confirmed"], deduplicates_by_key=True, key_retention_seconds=600)),
        case("EV8", "a retry after the owner's key retention ran out",
             effect_record("committed", ["timeout", "confirmed"], deduplicates_by_key=True, key_retention_seconds=5)),
        case("EV9", "a retry after the owner's final answer that the effect is absent",
             effect_record("committed", ["timeout", "confirmed"],
                           reconciliations=[{"at": "2026-06-01T00:00:05+00:00", "result": "absent", "final": True}])),
        case("EV10", "reported not_run after a final absent answer",
             effect_record("not_run", ["timeout"],
                           reconciliations=[{"at": "2026-06-01T00:00:05+00:00", "result": "absent", "final": True}])),
        case("EV11", "reported not_run where the owner said present",
             effect_record("not_run", ["timeout"],
                           reconciliations=[{"at": "2026-06-01T00:00:05+00:00", "result": "present", "final": True}])),
        case("EV12", "the outcome field differs from the record's reported outcome", base, outcome="unknown"),
        case("EV13", "the record's arguments are not the call's arguments", base, args=args_sha256({"amount_cents": 1})),
        case("EV14", "an effect record carrying no uncertain-effect record", None, outcome="committed"),
        case("EV15", "a dispatch outside every lease",
             {**effect_record("committed", ["confirmed"], token=1), "leases": [lease(1, "2026-05-01T00:00:00Z", "2026-05-01T01:00:00Z")]}),
        case("EV16", "a dispatch inside its lease",
             {**effect_record("committed", ["confirmed"], token=1), "leases": [lease(1, "2026-06-01T00:00:00+00:00", "2026-06-01T01:00:00+00:00")]}),
        case("EV17", "a dispatch after a newer fencing token took over",
             {**effect_record("committed", ["confirmed"], token=1), "leases": [
                 lease(1, "2026-06-01T00:00:00+00:00", "2026-06-01T01:00:00+00:00"),
                 lease(2, "2026-06-01T00:00:00+00:00", "2026-06-01T01:00:00+00:00")]}),
        case("EV18", "an unknown outcome whose reservation was released",
             {**effect_record("unknown", ["connection_lost"]), "reservation": {"charged": False}}),
        case("EV19", "an unknown outcome whose reservation is still charged",
             {**effect_record("unknown", ["connection_lost"]), "reservation": {"charged": True}}),
        case("EV20", "an owner commit after the stop was acknowledged, reported quiescent",
             {**base, "stop": {"revokedAt": "2026-06-01T00:00:00+00:00", "acknowledgedAt": "2026-06-01T00:00:02+00:00",
                               "reported": "quiescent", "ownerCommit": {"notBefore": "2026-06-01T00:00:03+00:00",
                                                                        "notAfter": "2026-06-01T00:00:04+00:00"}}}),
        case("EV21", "an owner commit straddling the acknowledgement, reported settled",
             {**base, "stop": {"revokedAt": "2026-06-01T00:00:00+00:00", "acknowledgedAt": "2026-06-01T00:00:02+00:00",
                               "reported": "effect_after_stop", "ownerCommit": {"notBefore": "2026-06-01T00:00:01+00:00",
                                                                                "notAfter": "2026-06-01T00:00:04+00:00"}}}),
        case("EV22", "an authority check accepted after the revocation",
             {**base, "stop": {"revokedAt": "2026-06-01T00:00:00+00:00", "acknowledgedAt": "2026-06-01T00:00:02+00:00",
                               "reported": "quiescent",
                               "authorityChecks": [{"at": "2026-06-01T00:00:01+00:00", "result": "accepted"}]}}),
        case("EV23", "the contract identifier is not the uncertain-effect contract",
             {**base, "contractId": "https://example.invalid/other"}),
        case("EV24", "an attempt with no idempotency key", {**base, "attempts": [{**base["attempts"][0], "idempotencyKey": ""}]}),
        case("EV25", "the key reused with different arguments",
             {**base, "attempts": [{**base["attempts"][0], "argsDigest": "sha256:" + "00" * 32}]}),
    ]


def trust_doc() -> dict:
    return {"grantRootKeyIds": [ROOT.key_id], "quorumPolicies": {"pay": POLICY, **APOL}}


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    usd = {"amount_cents": 3500, "currency": "USD", "note": "ticket-9"}
    eur = {"amount_cents": 2000, "currency": "EUR", "note": None}
    deputy = sign_deputy(QKEYS["bob"], delegator="bob", deputy="erin", deputy_key=raw_public(key("deputy-erin")),
                         policy_id="pay", roles=["finance"], not_before="2026-05-01T00:00:00Z", expires_at=EXP)
    erin = sign_vote(key("deputy-erin"), approver="erin", policy_id="pay", request=QREQ, role="finance",
                     deputy_for=deputy, **W)
    cases = {
        "grants": [
            ("GV1", "two-grant chain, CEL constraint and condition, context: every record holds",
             lambda d: grant_case(d, chain(), [usd, eur])),
            ("GV2", "forged child that widens a range, signed by the parent holder", lambda d: grant_case(
                d, forged_wide(), [usd])),
            ("GV3", "budget of two uses on the root, three calls under the child",
             lambda d: grant_case(d, chain(budget={"uses": 2}), [usd, eur, usd])),
            ("GV4", "intent names a different grant than its permit",
             lambda d: grant_case(d, chain(), [usd], intent_grant="cd" * 32)),
            ("GV5", "recorded allow that breaks the CEL condition (EUR over 3000)",
             lambda d: grant_case(d, chain(), [{"amount_cents": 3500, "currency": "EUR", "note": None}])),
            ("GV6", "recorded allow from a workflow outside the grant's context",
             lambda d: grant_case(d, chain(), [usd], ctx={"workflowId": "payroll-1", "runId": "r1"})),
        ],
        "quorum": [
            ("QV1", "two approvers fill the two roles; the proposer does not vote",
             lambda d: quorum_case(d, [vote("carol", "finance"), vote("alice", "security")])),
            ("QV2", "one approval where two are required", lambda d: quorum_case(d, [vote("carol", "finance")])),
            ("QV3", "one person votes in both roles", lambda d: quorum_case(
                d, [vote("bob", "finance"), vote("bob", "security")])),
            ("QV4", "a deputy votes for bob in finance, alice in security", lambda d: quorum_case(
                d, [erin, vote("alice", "security")])),
            ("QV5", "the record drops the proposer to let the proposer vote", lambda d: quorum_case(
                d, [vote("carol", "finance"), vote("alice", "security")], proposer=None)),
        ],
    }
    cases["constraints"] = constraint_rows()
    cases["approvals"] = approval_rows()
    cases["effects"] = effect_rows()
    trust = Trust(grant_root_key_ids=frozenset({ROOT.key_id}), quorum_policies={"pay": POLICY, **APOL})
    for family, rows in cases.items():
        out_rows = []
        for vid, description, build in rows:
            with tempfile.TemporaryDirectory() as tmp:
                j = build(Path(tmp))
                checkpoint = j.checkpoint()
                lines = [line for line in j.path.read_text().splitlines() if line.strip()]
                report = verify_journal(tmp, [GATE.public_pem()], checkpoint, trust=trust)
            out_rows.append({"id": vid, "description": description, "journal": lines, "checkpoint": checkpoint,
                             "keys": [GATE.public_pem().decode()], "trust": trust_doc(),
                             "expected": {k: report[k] for k in ("verdict", "records", "verified", "failures",
                                                                 "checkpoint")}})
        (out / f"{family}.json").write_text(json.dumps(out_rows, indent=2, sort_keys=True) + "\n")
    (out / "identity.json").write_text(json.dumps(identity_vectors(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
