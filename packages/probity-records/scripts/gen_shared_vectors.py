"""Write the shared verifier vectors every implementation of the records verifier must agree on.

Each journal case is ``{"id", "description", "journal": [line, ...], "checkpoint", "keys": [pem],
"trust": {...}, "expected": {"verdict", "records", "verified", "failures", "checkpoint"}}``; the
expected block is this package's own ``verify_journal`` result. ``identity.json`` holds the
principal-level vectors of ``identity_vectors`` (autonomous blocks included), ``standing_grants.json`` its standing
grant chains, ``canonical_identity.json`` the canonical identity
strings of ``canonical_identity_vectors``, ``identity_digests.json`` the identity digests of
``digests_vectors``. ``canonical.json`` holds bytes and the canonical
bytes or typed refusal both twins must report for them; ``received.json`` holds journals whose
signed bytes have no canonical form. Run from the package: ``uv run python
scripts/gen_shared_vectors.py vectors/shared``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from probity_records import (
    GRANT_ALLOW,
    QUORUM_ALLOW,
    REVOCATION_KINDS,
    TOOL_CALL_RECORD,
    Journal,
    RevocationState,
    Signer,
    Trust,
    args_sha256,
    build_approval_binding,
    build_uncertain_effect,
    embed_approval_binding,
    grant_evidence,
    issue_grant,
    permit_id,
    raw_public,
    sign_approval,
    sign_revocations,
    tool_call_predicate,
    verify_grant_allow,
    verify_journal,
)
from probity_records import canonical as jcs
from probity_records.canonical_identity_vectors import (
    vectors as canonical_identity_vectors,
)
from probity_records.clock import FixedClock, SystemClock, from_datetime
from probity_records.core import (
    IN_TOTO_PAYLOAD_TYPE,
    STATEMENT_TYPE,
    _b64,
    canonical,
    canonical_of_received,
    pae,
)
from probity_records.digests_vectors import vectors as digest_vectors
from probity_records.grants import GRANT_DOMAIN, grant_digest
from probity_records.identity_vectors import (
    autonomous_record_parts,
    standing_grant_vectors,
)
from probity_records.identity_vectors import vectors as identity_vectors
from probity_records.possession import cnf_for_signer
from probity_records.quorum import (
    approval_policy,
    count,
    request_hash,
    sign_deputy,
    sign_vote,
)
from probity_records.revocation import DIGEST_KINDS, REVOCATION_DOMAIN

SYSTEM_CLOCK = SystemClock()  # these cases judge windows against the host's time

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
    parent = issue_grant(ROOT, grant_id="g-root", holder_key=raw_public(AGENT), cnf=cnf_for_signer(AGENT), tools=TOOLS, max_depth=1,
                         not_before=NB, expires_at=EXP, **root_kw)
    budget = root_kw.get("budget")
    child = issue_grant(AGENT, grant_id="g-child", holder_key=raw_public(SUB), cnf=cnf_for_signer(SUB), tools=TOOLS, parent=parent,
                        not_before=NB, expires_at=EXP, context=root_kw["context"], budget=budget)
    return [parent, child]


def grant_case(directory: Path, grants: list[dict], calls: list[dict], *, intent_grant: str | None = None,
               ctx: dict | None = None, possession: list[dict] | None = None) -> Journal:
    """One authorize and one intent record per call; ``possession`` gives each allow the proof it rested on."""
    j = Journal(directory, GATE, clock=SYSTEM_CLOCK)
    for n, args in enumerate(calls):
        pid = permit_id("p", f"c{n}", args_sha256(args))
        common = {"run_id": "r1", "tool_call_id": f"c{n}", "tool": "refund", "args_sha256_hex": args_sha256(args),
                  "permit_id": pid}
        verdict = verify_grant_allow(grants, "refund", args, AT, {ROOT.key_id}, ctx=ctx or CTX)
        digest = verdict["grantDigest"] or "00" * 32
        j.append(TOOL_CALL_RECORD, f"tool-call:c{n}", args_sha256(args), tool_call_predicate(
            phase="authorize", decision="allow", reason=GRANT_ALLOW,
            authority=grant_evidence(grants, args, ctx or CTX, possession[n] if possession else None),
            grant_digest=digest, **common))
        j.append(TOOL_CALL_RECORD, f"tool-call:c{n}", args_sha256(args), tool_call_predicate(
            phase="intent", grant_digest=intent_grant or digest, **common))
    return j


def autonomous_case(directory: Path, *, authority: str = "standing", intent: str = "standing",
                    ctx: dict | None = None, tool: str = "refund", args: dict | None = None) -> Journal:
    """One autonomous call (authorize allow, then intent) at the identity vectors' instant; its block names the
    standing grant. The allow rests on ``authority``: "standing", "plain" (a broad grant the same agent key holds,
    with no sponsor or review date) or "policy" (no grant at all); the intent names ``intent``'s grant."""
    parts = autonomous_record_parts()
    block = parts["principals"]
    args = {"amount_cents": 40} if args is None else args
    ctx = {"agent": block["agent"]["clientId"], "session": block["session"]["id"]} if ctx is None else ctx
    digest = args_sha256(args)
    common = {"run_id": "r1", "tool_call_id": "c0", "tool": tool, "args_sha256_hex": digest,
              "permit_id": permit_id("p", "c0", digest), "principals": block}
    j = Journal(directory, GATE, clock=FixedClock(from_datetime(datetime.fromisoformat(parts["at"]))))
    if authority == "policy":
        allow = tool_call_predicate(phase="authorize", decision="allow", reason="no_approval_required", **common)
    else:
        chain = [parts[authority]]
        allow = tool_call_predicate(phase="authorize", decision="allow", reason=GRANT_ALLOW,
                                    authority=grant_evidence(chain, args, ctx),
                                    grant_digest=grant_digest(chain[-1]["body"]), **common)  # fmt: skip
    j.append(TOOL_CALL_RECORD, "tool-call:c0", digest, allow)
    named = None if authority == "policy" else grant_digest(parts[intent]["body"])
    j.append(TOOL_CALL_RECORD, "tool-call:c0", digest, tool_call_predicate(phase="intent", grant_digest=named, **common))
    return j


def autonomous_trust() -> tuple[Trust, dict]:
    """The auditor of the autonomous family: identity pins, the sponsor registry, the grant root, the standing grant
    (pinned, so a record that names it while resting on something else is judged on that, not on an unknown grant),
    strict."""
    parts = autonomous_record_parts()
    sponsors = {agent: [tuple(s) for s in refs] for agent, refs in parts["sponsors"].items()}
    trust = Trust(grant_root_key_ids=frozenset({parts["root"]}), identity_profile="strict",
                  identity_issuers={url: frozenset(t) for url, t in parts["pins"].items()},
                  agent_sponsors={agent: frozenset(refs) for agent, refs in sponsors.items()},
                  standing_grants=((parts["standing"],),))  # fmt: skip
    doc = {"grantRootKeyIds": [parts["root"]], "identityProfile": "strict", "identityIssuers": parts["pins"],
           "agentSponsors": {agent: [list(s) for s in refs] for agent, refs in sponsors.items()},
           "standingGrants": [[parts["standing"]]]}
    return trust, doc


def forged_wide() -> list[dict]:
    parent, child = chain()
    wide = {**child["body"], "tools": {"refund": {**TOOLS["refund"], "args": {
        **TOOLS["refund"]["args"], "amount_cents": {"type": "range", "min": 1, "max": 400000}}}}}
    return [parent, {"body": wide, "sig": _b64(AGENT.sign(GRANT_DOMAIN + canonical(wide)))}]


def dpop_use(jti: str, holder: Signer = SUB) -> dict:
    """The possession record of a DPoP proof by ``holder`` (the leaf grant's cnf key by default), made now, so
    the journal's own record times fall inside its lifetime."""
    return {"iat": int(time.time()), "jkt": cnf_for_signer(holder)["jkt"], "jti": jti, "method": "dpop"}


def bearer_grant() -> list[dict]:
    """A root grant with no ``cnf``, signed by the trusted root: a bearer token, refused by every verifier."""
    body = {k: v for k, v in chain()[0]["body"].items() if k != "cnf"}
    return [{"body": body, "sig": _b64(ROOT.sign(GRANT_DOMAIN + canonical(body)))}]


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
    j = Journal(directory, GATE, clock=SYSTEM_CLOCK)
    j.append(TOOL_CALL_RECORD, "tool-call:q1", args_sha256(QARGS), tool_call_predicate(
        phase="authorize", decision="allow", reason=QUORUM_ALLOW, authority=evidence, run_id="r1",
        tool_call_id="q1", tool="pay", args_sha256_hex=args_sha256(QARGS), permit_id=QPID))
    return j


# ---- constraint edge cases: IPv6 CIDR, shell quoting, int vs float ----

def solo_chain(tools: dict) -> list[dict]:
    return [issue_grant(ROOT, grant_id="g-solo", holder_key=raw_public(AGENT), cnf=cnf_for_signer(AGENT), tools=tools, not_before=NB,
                        expires_at=EXP)]


def solo_case(directory: Path, tools: dict, tool: str, calls: list[dict]) -> Journal:
    """One recorded allow per call. A call the grant refuses is recorded as an allow all the same, so the
    verifier's own judgement of the grant is what the vector pins."""
    j = Journal(directory, GATE, clock=SYSTEM_CLOCK)
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
    j = Journal(directory, GATE, clock=SYSTEM_CLOCK)
    j.append(TOOL_CALL_RECORD, "tool-call:a1", args_sha256(AARGS), tool_call_predicate(
        phase="authorize", decision=decision, reason=reason, approval_bindings=bindings, threshold=threshold,
        approval_policy=policy, run_id="run", tool_call_id="a1", tool="refund_payment", args_sha256_hex=args_sha256(AARGS),
        permit_id=permit_id("pause", "a1", args_sha256(AARGS))))
    return j


def approval_rows() -> list[tuple[str, str, object]]:
    ops = lambda **kw: binding(OPS, WHO["ops"], **kw)
    lead = lambda **kw: binding(LEAD, WHO["lead"], **kw)
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
    j = Journal(directory, GATE, clock=SYSTEM_CLOCK)
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
    lease = lambda token, a, b: {"worker": "w1", "fencingToken": token, "acquiredAt": a, "expiresAt": b}
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


#: (id, description, path, input bytes). "received" admits the bytes raw, then canonicalizes
#: (canonical_of_received); "value" parses them with json.loads and canonicalizes the value. The
#: first five are agent-evidence-vectors vectors-a2a-jcs-v01 A3-REJECT-011/012 and
#: A4-REJECT-013/014/015, which the TypeScript twin canonicalized until both twins went through
#: jcs-admit.
CANONICAL_ROWS: list[tuple[str, str, str, bytes]] = [
    ("CV1", "A3-REJECT-011: lone high surrogate escape in a key", "received", b'{"b\\ud800key": 1, "a": 2}'),
    ("CV2", "A3-REJECT-012: lone low surrogate escape in a key", "received", b'{"b\\udc00key": 1, "a": 2}'),
    ("CV3", "A4-REJECT-013: lone low surrogate escape in a value", "received", b'{"name": "broken \\udc00 value"}'),
    ("CV4", "A4-REJECT-014: lone low surrogate escape mid-value", "received", b'{"name": "before\\udc00after"}'),
    ("CV5", "A4-REJECT-015: high surrogate escape then a plain letter", "received", b'{"name": "\\ud800x"}'),
    ("CV6", "A3-REJECT-011 parsed first, then canonicalized", "value", b'{"b\\ud800key": 1, "a": 2}'),
    ("CV7", "A3-REJECT-012 parsed first, then canonicalized", "value", b'{"b\\udc00key": 1, "a": 2}'),
    ("CV8", "A4-REJECT-013 parsed first, then canonicalized", "value", b'{"name": "broken \\udc00 value"}'),
    ("CV9", "A4-REJECT-014 parsed first, then canonicalized", "value", b'{"name": "before\\udc00after"}'),
    ("CV10", "A4-REJECT-015 parsed first, then canonicalized", "value", b'{"name": "\\ud800x"}'),
    ("CV11", "a duplicate member", "received", b'{"a":1,"a":2}'),
    ("CV12", "a duplicate member a first-wins reader would read differently", "received",
     b'{"name":"Good","name":"Evil"}'),
    ("CV13", "a surrogate encoded as UTF-8 bytes", "received", b'{"a":"\xed\xa0\x80"}'),
    ("CV14", "a byte that is never UTF-8", "received", b'{"a":"\xff"}'),
    ("CV15", "an integer past 2**53 that rounds onto 2**53", "received", b'{"n":9007199254740993}'),
    ("CV16", "2**53 itself, parsed first", "value", b'{"n":9007199254740992}'),
    ("CV17", "minus 2**53", "received", b'{"n":-9007199254740992}'),
    ("CV18", "the largest exact integer", "received", b'{"n":9007199254740991}'),
    ("CV19", "an integral float past 2**53 stays a float", "received", b'{"n":1e21}'),
    ("CV20", "a surrogate pair", "received", b'{"a":"\\ud83d\\ude00"}'),
    ("CV21", "keys sorted, escapes and raw UTF-8 normalized", "received", b'{"b":1,"a":"\xc3\xa9\\u00e9","c":[1.0,1.5e-7,-0]}'),
]


def canonical_rows() -> list[dict]:
    rows = []
    for vid, description, path, raw in CANONICAL_ROWS:
        try:
            out = canonical_of_received(raw) if path == "received" else canonical(json.loads(raw))
            expected: dict[str, str] = {"canonicalHex": out.hex()}
        except ValueError as exc:
            expected = {"refused": str(exc)}
        rows.append({"id": vid, "description": description, "path": path, "inputB64": _b64(raw),
                     "expected": expected})
    return rows


def received_line(payload: bytes) -> str:
    """One journal line: the gate's DSSE envelope over exactly ``payload``."""
    sig = GATE.sign(pae(IN_TOTO_PAYLOAD_TYPE, payload))
    return json.dumps({"payload": _b64(payload), "payloadType": IN_TOTO_PAYLOAD_TYPE,
                       "signatures": [{"keyid": GATE.key_id, "sig": _b64(sig)}]}, sort_keys=True,
                      separators=(",", ":"))


def received_rows() -> list[dict]:
    """Journals whose signed bytes have no canonical form: both twins refuse them at the parse."""
    head = b'{"_type":"' + STATEMENT_TYPE.encode() + b'","predicateType":"' + TOOL_CALL_RECORD.encode() + b'",'
    pred = b'"predicate":{"prev":"' + b"0" * 64 + b'","seq":1'
    good, other = head + pred + b"}}", head + pred + b',"tool":"other"}}'
    swapped = json.loads(received_line(other))
    rows = [
        ("RV1", "the signed payload repeats its predicate member",
         [received_line(head + pred + b'},' + pred + b',"tool":"shadow"}}')]),
        ("RV2", "the signed payload carries a byte that is never UTF-8", [received_line(head + pred + b',"tool":"\xff"}}')]),
        ("RV3", "the signed payload carries a lone surrogate escape", [received_line(head + pred + b',"tool":"\\ud800"}}')]),
        ("RV4", "the envelope line repeats its payload member; the last one is signed",
         ['{"payload":"' + _b64(good) + '","payload":"' + swapped["payload"] + '","payloadType":"'
          + IN_TOTO_PAYLOAD_TYPE + '","signatures":' + json.dumps(swapped["signatures"], separators=(",", ":"))
          + "}"]),
        ("RV5", "control: the same record with one predicate member", [received_line(good)]),
    ]
    out = []
    for vid, description, lines in rows:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "journal.jsonl").write_text("".join(line + "\n" for line in lines))
            report = verify_journal(tmp, [GATE.public_pem()], None)
        out.append({"id": vid, "description": description, "journal": lines, "checkpoint": None,
                    "keys": [GATE.public_pem().decode()], "trust": None,
                    "expected": {k: report[k] for k in ("verdict", "records", "verified", "failures", "checkpoint")}})
    return out


# -- revocation lists ------------------------------------------------------------------------------------------------

RL_ROOT, RL_NEXT, RL_OUTSIDER = key("revocation-root"), key("revocation-successor"), key("revocation-outsider")
#: A successor whose key id sorts after RL_ROOT's (RL_NEXT's sorts before it): a reader that walked the entries in
#: order would give the two cases different roots.
RL_NEXT_LATE = key("revocation-successor-1")
T0, T1, T2, T3 = "2026-06-01T00:00:00Z", "2026-06-02T00:00:00Z", "2026-06-03T00:00:00Z", "2026-06-04T00:00:00Z"
DIGEST_A = hashlib.sha256(b"grant-a").hexdigest()


def rl(seq: int, entries: list, previous: dict | None = None, *, at: str = T0, signer: Signer = RL_ROOT,
       list_id: str = "probity-revocations") -> dict:
    return sign_revocations(signer, list_id=list_id, seq=seq, issued_at=at, entries=entries, previous=previous)


def rl_entry(kind: str, ident: str, at: str = T0, **extra) -> dict:
    return {"kind": kind, "id": ident, "revokedAt": at, **extra}


def rl_resign(body: dict, signer: Signer = RL_ROOT) -> dict:
    """Sign a body the issuer would refuse, so a reader sees a malformed list with a valid signature."""
    try:
        message = REVOCATION_DOMAIN + canonical(body)
    except ValueError:
        return {"body": body, "sig": _b64(bytes(64))}
    return {"body": body, "sig": _b64(signer.sign(message))}


def loosen(char: str) -> str:
    """The same base64 digit with its lowest (unused, so non-canonical) bit set."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return alphabet[alphabet.index(char) | 1]


def rl_edit(signed: dict, **members) -> dict:
    return rl_resign({**signed["body"], **members})


def revocation_rows() -> list[dict]:
    """Cases every reader of the one revocation list must agree on."""
    one = rl(1, [])
    two = rl(2, [rl_entry("agent", "agent:alpha", T1), rl_entry("stream", "stream-7", T1)], one, at=T1)
    every = [rl_entry(k, DIGEST_A if k in DIGEST_KINDS else f"{k}:one", T2, reason="test") for k in REVOCATION_KINDS]
    three = rl(3, sorted(two["body"]["entries"] + every, key=lambda e: (e["kind"], e["id"])), two, at=T2)
    rotate = rl(1, [rl_entry("key", RL_ROOT.key_id, reason="rotation", successor=raw_public(RL_NEXT))])
    by_next = rl(2, rotate["body"]["entries"], rotate, at=T1, signer=RL_NEXT)
    killed = rl(1, [rl_entry("key", RL_ROOT.key_id, reason="compromised")])
    both_early = rl(1, [rl_entry("key", RL_ROOT.key_id, reason="rotation", successor=raw_public(RL_NEXT)),
                        rl_entry("key", RL_NEXT.key_id, reason="compromised")])
    both_late = rl(1, [rl_entry("key", RL_ROOT.key_id, reason="rotation", successor=raw_public(RL_NEXT_LATE)),
                       rl_entry("key", RL_NEXT_LATE.key_id, reason="compromised")])
    assert RL_NEXT.key_id < RL_ROOT.key_id < RL_NEXT_LATE.key_id
    sig = base64.b64decode(one["sig"])
    loose_sig = one["sig"][:-3] + loosen(one["sig"][-3]) + "=="
    loose_key = one["body"]["issuerKey"][:-2] + loosen(one["body"]["issuerKey"][-2]) + "="
    accept, refuse = "accept", "refuse"
    cases: list[tuple[str, str, list, str, str | None, int | None]] = [
        ("RL01", "an empty first list is in force", [one], accept, None, None),
        ("RL02", "a chain of three lists naming every kind", [one, two, three], accept, None, None),
        ("RL03", "a root rotates to its successor, which signs the next list", [rotate, by_next], accept, None, None),
        ("RL04", "a reason outside the BMP canonicalises the same in every reader",
         [rl(1, [rl_entry("sponsor", "sponsor:acme", reason="key on a lost laptop \U0001F4BB\u2028")])],
         accept, None, None),
        ("RL05", "an unknown kind is refused even when signed",
         [rl_edit(one, entries=[rl_entry("tenant", "tenant:x")])], refuse, "revocation_list_shape", 0),
        ("RL06", "entries out of order are refused",
         [rl_edit(one, entries=[rl_entry("stream", "s"), rl_entry("agent", "a")])], refuse,
         "revocation_list_shape", 0),
        ("RL07", "a duplicate entry is refused",
         [rl_edit(one, entries=[rl_entry("agent", "a"), rl_entry("agent", "a")])], refuse,
         "revocation_list_shape", 0),
        ("RL08", "a non-ASCII identifier is refused",
         [rl_edit(one, entries=[rl_entry("agent", "agent:\u00e9")])], refuse, "revocation_list_shape", 0),
        ("RL09", "an identifier with a space is refused",
         [rl_edit(one, entries=[rl_entry("agent", "agent one")])], refuse, "revocation_list_shape", 0),
        ("RL10", "an identifier of 513 characters is refused",
         [rl_edit(one, entries=[rl_entry("agent", "a" * 513)])], refuse, "revocation_list_shape", 0),
        ("RL11", "an extra body member is refused", [rl_edit(one, extra="x")], refuse, "revocation_list_shape", 0),
        ("RL12", "a boolean seq is refused", [rl_edit(one, seq=True)], refuse, "revocation_list_shape", 0),
        ("RL13", "a seq beyond 2^53-1 is refused", [rl_edit(one, seq=2**53, previous="sha256:" + "00" * 32)],
         refuse, "revocation_list_shape", 0),
        ("RL14", "a timestamp with an offset is refused", [rl_edit(one, issuedAt="2026-06-01T00:00:00+00:00")],
         refuse, "revocation_list_shape", 0),
        ("RL15", "a timestamp that is not a calendar day is refused", [rl_edit(one, issuedAt="2026-02-30T00:00:00Z")],
         refuse, "revocation_list_shape", 0),
        ("RL16", "an issuer key in non-canonical base64 is refused", [rl_edit(one, issuerKey=loose_key)], refuse,
         "revocation_list_shape", 0),
        ("RL17", "an upper-case grant digest is refused",
         [rl_edit(one, entries=[rl_entry("grant", DIGEST_A.upper())])], refuse, "revocation_list_shape", 0),
        ("RL18", "a successor on an agent entry is refused",
         [rl_edit(one, entries=[rl_entry("agent", "a", successor=raw_public(RL_NEXT))])], refuse,
         "revocation_list_shape", 0),
        ("RL19", "a signed list with an extra top-level member is refused", [{**one, "issuer": "x"}], refuse,
         "revocation_list_shape", 0),
        ("RL20", "another type is refused", [rl_edit(one, type="https://example.org/revocations")], refuse,
         "revocation_list_shape", 0),
        ("RL21", "a list from a key that is not a pinned root is refused", [rl(1, [], signer=RL_OUTSIDER)], refuse,
         "revocation_list_signer_not_a_root", 0),
        ("RL22", "a list whose entries were edited after signing is refused",
         [{"body": {**two["body"], "entries": [], "previous": None, "seq": 1}, "sig": two["sig"]}], refuse,
         "revocation_list_signature_unverified", 0),
        ("RL23", "a pinned issuer key over another key's signature is refused",
         [{"body": one["body"], "sig": rl_resign(one["body"], RL_OUTSIDER)["sig"]}], refuse,
         "revocation_list_signature_unverified", 0),
        ("RL24", "a signature with one bit flipped is refused",
         [{**one, "sig": _b64(bytes([sig[0] ^ 1]) + sig[1:])}], refuse, "revocation_list_signature_unverified", 0),
        ("RL25", "a signature in non-canonical base64 is refused", [{**one, "sig": loose_sig}], refuse,
         "revocation_list_signature_unverified", 0),
        ("RL26", "a list from another chain is refused", [one, rl(2, [], one, at=T1, list_id="other")], refuse,
         "revocation_list_other_chain", 1),
        ("RL27", "the list in force replayed is refused", [one, two, two], refuse, "revocation_list_rollback", 2),
        ("RL28", "a rollback to an earlier list is refused", [one, two, one], refuse, "revocation_list_rollback", 2),
        ("RL29", "a list from the future (a seq gap) is refused", [one, three], refuse, "revocation_list_gap", 1),
        ("RL30", "a fresh reader refuses a first list past seq 1", [two], refuse, "revocation_list_gap", 0),
        ("RL31", "a fork (seq right, previous wrong) is refused",
         [one, two, rl(3, two["body"]["entries"], one, at=T2)], refuse, "revocation_list_previous_mismatch", 2),
        ("RL32", "a list issued before the list in force is refused",
         [one, two, rl(3, two["body"]["entries"], two, at=T0)], refuse, "revocation_list_time_reversed", 2),
        ("RL33", "an entry revoked after the list's issue time is refused",
         [rl_edit(one, entries=[rl_entry("agent", "a", T1)])], refuse, "revocation_entry_from_future", 0),
        ("RL34", "a list that drops an entry (shrinks) is refused", [one, two, rl(3, [], two, at=T2)], refuse,
         "revocation_list_drops_entry", 2),
        ("RL35", "a list that edits an entry is refused",
         [one, two, rl(3, [{**two["body"]["entries"][0], "reason": "changed"}, two["body"]["entries"][1]], two,
                       at=T2)], refuse, "revocation_list_drops_entry", 2),
        ("RL36", "after rotation the old root's next list is refused",
         [rotate, rl(2, rotate["body"]["entries"], rotate, at=T1)], refuse, "revocation_list_signer_not_a_root", 1),
        ("RL37", "a root revoked without a successor ends the chain",
         [killed, rl(2, killed["body"]["entries"], killed, at=T1)], refuse, "revocation_list_signer_not_a_root", 1),
        ("RL38", "a root revoked with a successor that the same list revokes ends the chain (successor id sorts before)",
         [both_early, rl(2, both_early["body"]["entries"], both_early, at=T1, signer=RL_NEXT)], refuse,
         "revocation_list_signer_not_a_root", 1),
        ("RL39", "a root revoked with a successor that the same list revokes ends the chain (successor id sorts after)",
         [both_late, rl(2, both_late["body"]["entries"], both_late, at=T1, signer=RL_NEXT_LATE)], refuse,
         "revocation_list_signer_not_a_root", 1),
    ]
    rows = []
    for vid, description, lists, verdict, code, index in cases:
        expected: dict
        if verdict == accept:
            state = RevocationState(roots=frozenset({RL_ROOT.key_id}))
            for signed in lists:
                state = state.apply(signed)
            expected = {"state": state.summary()}
        else:
            expected = {"index": index, "refused": code}
        rows.append({"description": description, "expected": expected, "id": vid, "lists": lists,
                     "roots": [RL_ROOT.key_id]})
    return rows


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
            ("GV7", "a grant that names no holder confirmation key (cnf): a bearer grant",
             lambda d: grant_case(d, bearer_grant(), [usd])),
            ("GV8", "one DPoP proof spent by two permits inside its lifetime: a replay",
             lambda d: grant_case(d, chain(), [usd, eur], possession=[dpop_use("proof-1"), dpop_use("proof-1")])),
            ("GV9", "an allow whose possession record names the parent's key, not the leaf grant's cnf",
             lambda d: grant_case(d, chain(), [usd], possession=[dpop_use("proof-1", AGENT)])),
            ("GV10", "two permits, each with its own DPoP proof by the leaf grant's key: every record holds",
             lambda d: grant_case(d, chain(), [usd, eur], possession=[dpop_use("proof-1"), dpop_use("proof-2")])),
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
    cases["autonomous"] = [
        ("AV1", "an autonomous call that rests on the standing grant its block names: identity holds",
         lambda d: autonomous_case(d)),
        ("AV2", "the allow rests on a broad plain grant the agent key also holds, the block names the standing grant",
         lambda d: autonomous_case(d, authority="plain", intent="plain", tool="wire", args={"to": "acct-9"})),
        ("AV3", "the allow rests on no grant at all, the block names the standing grant",
         lambda d: autonomous_case(d, authority="policy", tool="wire", args={"to": "acct-9"})),
        ("AV4", "the intent names another grant than its block",
         lambda d: autonomous_case(d, intent="plain")),
        ("AV5", "the grant evidence states another agent than the block for the grant's context",
         lambda d: autonomous_case(d, ctx={"agent": "agent-other", "session": "run-2026-11-08-nightly"})),
        ("AV6", "a call outside the standing grant's constraint", lambda d: autonomous_case(d, args={"amount_cents": 9000})),
    ]
    cases["constraints"] = constraint_rows()
    cases["approvals"] = approval_rows()
    cases["effects"] = effect_rows()
    trust = Trust(grant_root_key_ids=frozenset({ROOT.key_id}), quorum_policies={"pay": POLICY, **APOL})
    family_trust = {"autonomous": autonomous_trust()}
    for family, rows in cases.items():
        out_rows = []
        auditor, auditor_doc = family_trust.get(family, (trust, trust_doc()))
        for vid, description, build in rows:
            with tempfile.TemporaryDirectory() as tmp:
                j = build(Path(tmp))
                checkpoint = j.checkpoint()
                lines = [line for line in j.path.read_text().splitlines() if line.strip()]
                report = verify_journal(tmp, [GATE.public_pem()], checkpoint, trust=auditor)
            out_rows.append({"id": vid, "description": description, "journal": lines, "checkpoint": checkpoint,
                             "keys": [GATE.public_pem().decode()], "trust": auditor_doc,
                             "expected": {k: report[k] for k in ("verdict", "records", "verified", "failures",
                                                                 "checkpoint")}})
        (out / f"{family}.json").write_text(json.dumps(out_rows, indent=2, sort_keys=True) + "\n")
    (out / "identity.json").write_text(json.dumps(identity_vectors(), indent=2, sort_keys=True) + "\n")
    (out / "standing_grants.json").write_text(json.dumps(standing_grant_vectors(), indent=2, sort_keys=True) + "\n")
    (out / "canonical_identity.json").write_text(json.dumps(canonical_identity_vectors(), indent=2, sort_keys=True)
                                                 + "\n")
    (out / "identity_digests.json").write_text(json.dumps(digest_vectors(), indent=2, sort_keys=True) + "\n")
    (out / "canonical.json").write_text(json.dumps(canonical_rows(), indent=2, sort_keys=True) + "\n")
    (out / "received.json").write_text(json.dumps(received_rows(), indent=2, sort_keys=True) + "\n")
    (out / "revocation.json").write_text(json.dumps(revocation_rows(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
