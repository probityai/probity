"""A hash-chained journal of DSSE-signed in-toto statements, its signed checkpoint, and the
offline verifier an outsider runs over both.

Each line is one envelope. Its statement's predicate carries ``seq`` (1, 2, ...), ``prev`` (SHA-256
of the previous line's bytes, 64 zeros for the first) and ``at``. A checkpoint is a signed statement
of the line count and the last line's hash: pinned by an outsider, it exposes a truncated or
rewritten journal.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import threading
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .authority import Trust, check_authority
from .quorum import count_bindings
from .governance import GOVERNANCE_STEP, check_step
from .core import load_public, open_envelope, sign_envelope, statement
from .grants import grant_digest, spend_of
from .identity import act_grade, check_principals
from .signing import Delegation, verify_delegation
from .records import TOOL_CALL_RECORD, judge_approval_binding, judge_uncertain_effect

GENESIS = "0" * 64
CHECKPOINT_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/tool-call-journal-checkpoint"
JOURNAL_FILE = "journal.jsonl"
#: Root-signed certificates for the session keys that signed lines of the journal (``signing.delegate``).
KEYS_FILE = "keys.jsonl"


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(base64.b64decode(envelope["payload"]))


class Journal:
    """Append-only signed journal in ``directory``.

    Appends are serialised by a file lock and fsynced, so a record that returned is on disk before the
    caller acts on it. The head (line count, last hash, byte offset) is cached per instance and
    refreshed only from bytes other writers appended since: an append costs the same at line one
    million as at line one. Concurrent appenders in one process share fsyncs (group commit): a writer
    whose bytes an earlier fsync already covered does not fsync again.
    """

    def __init__(self, directory: str | os.PathLike[str], signer: Any) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / JOURNAL_FILE
        self.signer = signer
        self._offset, self._seq, self._head = 0, 0, GENESIS
        self._synced = 0
        self._sync_lock = threading.Lock()
        self._certify(signer)

    def _certify(self, signer: Any) -> None:
        """Record a delegated session key's certificate before the key signs its first line."""
        certificate = getattr(signer, "certificate", None)
        if certificate is None:
            return
        keys = self.directory / KEYS_FILE
        line = json.dumps(certificate, sort_keys=True, separators=(",", ":"))
        lock = self.directory / (JOURNAL_FILE + ".lock")
        with lock.open("w") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            if keys.exists() and line in keys.read_text().splitlines():
                return
            fd = os.open(keys, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line.encode() + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)

    def rotate(self, signer: Any) -> None:
        """Sign later lines with ``signer`` (a fresh delegated session key, typically)."""
        self._certify(signer)
        self.signer = signer

    def _refresh(self) -> tuple[int, str]:
        """Bring the cached head up to the file's current end, reading only the new bytes."""
        size = self.path.stat().st_size if self.path.exists() else 0
        if size < self._offset:  # the file was replaced or truncated under us: rescan from the start
            self._offset, self._seq, self._head = 0, 0, GENESIS
        if size > self._offset:
            with self.path.open("rb") as fh:
                fh.seek(self._offset)
                for line in fh:
                    if not line.endswith(b"\n"):
                        break  # a torn tail from a crashed writer is not a line
                    self._offset += len(line)
                    body = line.rstrip(b"\n")
                    if body.strip():
                        self._seq = int(_payload(json.loads(body))["predicate"]["seq"])
                        self._head = _line_hash(body)
        return self._seq, self._head

    def _tail(self) -> tuple[int, str]:
        return self._refresh()

    def _sync(self, fd: int, end: int) -> None:
        with self._sync_lock:
            if self._synced >= end:
                return
            os.fsync(fd)
            self._synced = end

    def append(self, predicate_type: str, subject_name: str, subject_digest: str,
               predicate: Mapping[str, Any]) -> dict[str, Any]:
        """Sign and append one statement; returns the envelope written, durable on return."""
        lock = self.directory / (JOURNAL_FILE + ".lock")
        # "a", never "w": O_TRUNC dirties the lock file's inode on every append, and the journal fsync
        # then commits that metadata too (measured on ext4 burst boxes as part of the p95 cost).
        with lock.open("a") as guard:
            fcntl.flock(guard, fcntl.LOCK_EX)
            seq, head = self._refresh()
            body = statement(subject_name, subject_digest, predicate_type,
                             {**dict(predicate), "at": now(), "prev": head, "seq": seq + 1})
            envelope = sign_envelope(self.signer, json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
            line = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line)
                self._offset += len(line)
                self._seq, self._head = seq + 1, _line_hash(line.rstrip(b"\n"))
                end = self._offset
                fcntl.flock(guard, fcntl.LOCK_UN)  # order is fixed; durability may be shared
                self._sync(fd, end)
            finally:
                os.close(fd)
        return envelope

    def statements(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [_payload(json.loads(line)) for line in self.path.read_text().splitlines() if line.strip()]

    def checkpoint(self) -> dict[str, Any]:
        """A signed statement of the line count and head, for an outsider to pin."""
        seq, head = self._refresh()
        body = statement("tool-call-journal", head, CHECKPOINT_TYPE,
                         {"at": now(), "count": seq, "head": head,
                          "keyProvenance": dict(getattr(self.signer, "provenance", {"backend": "unstated"}))})
        return sign_envelope(self.signer, json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


def _keys(public_pems: Iterable[bytes]) -> list[Any]:
    keys = [load_public(pem) for pem in public_pems]
    if not keys:
        raise ValueError("verify_journal needs at least one trusted public key")
    return keys


def _delegations(directory: Path, roots: list[Any], failures: list[str]) -> dict[str, Delegation]:
    """Session keys certified by a pinned root; a certificate no pinned root signed is a failure."""
    found: dict[str, Delegation] = {}
    path = directory / KEYS_FILE
    if not path.exists():
        return found
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            d = verify_delegation(json.loads(line), roots)
        except (ValueError, TypeError) as exc:
            failures.append(f"keys_line_{n}:{exc}")
            continue
        found[d.session_key_id] = d
    return found


NO_APPROVAL_REQUIRED = "no_approval_required"
#: A fresh permit for a call whose earlier permit was used, issued only after the effect owner gave a
#: final "absent" answer, which the record carries (``context.reconciliation``); valid only when an
#: earlier allow for the same permit exists (checked below).
RECONCILED_RETRY = "reconciled_absent_retry"
#: A fresh permit for a call whose earlier permit never led to an effect the journal cannot account
#: for: no intent was journalled since the last permit (intent is fsynced before the call leaves, so
#: the call never left), or the last effect record for the permit settled ``not_run``.
NOT_RUN_RETRY = "not_run_retry"
RETRY_REASONS = (RECONCILED_RETRY, NOT_RUN_RETRY)


def _check_approval(pred: dict[str, Any], problems: list[str], where: str, trust: Trust | None) -> None:
    if pred.get("decision") == "allow" and check_authority(pred, trust, problems, where):
        return
    bindings = pred.get("approvalBindings") or []
    if not bindings:
        # An allow with no approval is accepted only as the authority's signed statement that its
        # policy required none for this call; verify_journal counts these apart (policyAllows).
        if pred.get("decision") == "allow" and pred.get("reason") not in (NO_APPROVAL_REQUIRED, *RETRY_REASONS):
            problems.append(f"{where}:allow_without_approval_binding")
        return
    reader_allowed: set[str] = set()
    for n, embedded in enumerate(bindings):
        payload = base64.b64decode(embedded["payloadB64"])
        if hashlib.sha256(payload).hexdigest() != pred.get("argsSha256"):
            problems.append(f"{where}:binding_{n}:approval_payload_is_not_the_call_arguments")
        verdict = judge_approval_binding(embedded["record"], payload)
        if verdict["decision"] == "allow":
            reader_allowed.add(str(embedded["record"].get("approval", {}).get("approver")))
        elif pred.get("decision") == "deny" and verdict["reason"] != pred.get("reason") and len(bindings) == 1:
            problems.append(f"{where}:deny_reason_{pred.get('reason')}_but_reader_says_{verdict['reason']}")
    if pred.get("decision") != "allow":
        return
    # The M of N is re-counted under the quorum policy the AUDITOR pinned: the approver keys and the
    # threshold come from Trust, never from the record the authority wrote.
    if trust is None:
        problems.append(f"{where}:approval_allow_but_no_trust_pinned")
        return
    policy = trust.quorum_policies.get(str(pred.get("approvalPolicyId")))
    if policy is None:
        problems.append(f"{where}:approval_policy_not_pinned")
        return
    if pred.get("threshold") != policy["threshold"]:
        problems.append(f"{where}:threshold_{pred.get('threshold')}_is_not_the_pinned_{policy['threshold']}")
    signed, sig_problems = count_bindings(policy, bindings, str(pred.get("at")), trust.key_revoked,
                                          oidc_pins=trust.identity_issuers)
    problems.extend(f"{where}:{p}" for p in sig_problems)
    counted = signed & reader_allowed
    if len(counted) < policy["threshold"]:
        problems.append(f"{where}:recorded_allow_but_{len(counted)}_of_{policy['threshold']}_approvals_hold")


def _check_effect(pred: dict[str, Any], problems: list[str], where: str) -> str | None:
    record = pred.get("uncertainEffect")
    if not record:
        problems.append(f"{where}:effect_without_uncertain_effect_record")
        return None
    verdict = judge_uncertain_effect(record)
    if verdict["decision"] != "supported":
        problems.append(f"{where}:uncertain_effect_{verdict['decision']}:{verdict['reason']}")
    if record.get("operation", {}).get("argsDigest") != "sha256:" + str(pred.get("argsSha256")):
        problems.append(f"{where}:effect_args_differ_from_call")
    if pred.get("outcome") != verdict.get("reported_outcome"):
        problems.append(f"{where}:outcome_field_differs_from_record")
    return verdict.get("reported_outcome")


def _check_revocations(pred: dict[str, Any], signer_id: str, trust: Trust, problems: list[str], where: str) -> None:
    """A record signed by a key revoked before the record's time, a permit used after its revocation,
    and an approval whose approver key was revoked before the decision all fail."""
    at = str(pred.get("at"))
    if trust.key_revoked(signer_id, at):
        problems.append(f"{where}:signer_key_revoked")
    if pred.get("permitId") and trust.permit_revoked(str(pred["permitId"]), at):
        problems.append(f"{where}:permit_revoked")


def _approval_signers(pred: dict[str, Any]) -> set[str] | None:
    names = {str((b.get("record") or {}).get("approval", {}).get("approver")) for b in pred.get("approvalBindings") or []}
    quorum = (pred.get("authority") or {}).get("quorum") or (pred.get("authority") or {})
    names |= {str(v.get("body", {}).get("onBehalfOf", v.get("body", {}).get("approver")))
              for v in quorum.get("votes") or [] if isinstance(v, dict)}
    return names or None


def _check_identity(pred: dict[str, Any], trust: Trust | None, problems: list[str], where: str) -> None:
    if trust is None:
        problems.append(f"{where}:principals_but_no_trust_pinned")
        return
    found, grade = check_principals(pred["principals"], str(pred.get("at")), trust.identity_issuers,
                                    _approval_signers(pred))
    problems.extend(f"{where}:{p}" for p in found)
    if grade is not None and trust.identity_profile == "strict" and grade != "strict":
        problems.append(f"{where}:principals_below_strict:{act_grade(pred['principals'])}")


def _check_line(i: int, line: str, keys: list[Any], prev: str, trust: Trust | None,
                delegations: Mapping[str, Delegation]) -> tuple[dict[str, Any] | None, list[str]]:
    problems: list[str] = []
    where = f"line_{i}"
    try:
        payload, signer_id = open_envelope(json.loads(line), keys)
        body = json.loads(payload)
    except (ValueError, KeyError, TypeError) as exc:
        return None, [f"{where}:{exc}"]
    pred = body.get("predicate", {})
    delegation = delegations.get(signer_id)
    if delegation is not None and not delegation.covers(str(pred.get("at"))):
        problems.append(f"{where}:session_key_used_outside_its_certified_window")
    if trust is not None:
        _check_revocations(pred, signer_id, trust, problems, where)
        if delegation is not None and trust.key_revoked(delegation.root_key_id, str(pred.get("at"))):
            problems.append(f"{where}:signer_root_key_revoked")
    if pred.get("seq") != i:
        problems.append(f"{where}:seq_{pred.get('seq')}_not_{i}")
    if pred.get("prev") != prev:
        problems.append(f"{where}:chain_broken")
    if body.get("predicateType") == TOOL_CALL_RECORD and pred.get("principals") is not None:
        _check_identity(pred, trust, problems, where)
    if body.get("predicateType") == TOOL_CALL_RECORD:
        if pred.get("phase") == "authorize":
            _check_approval(pred, problems, where, trust)
        elif pred.get("phase") == "effect":
            _check_effect(pred, problems, where)
    elif body.get("predicateType") == GOVERNANCE_STEP:
        policies = trust.quorum_policies if trust else None
        revoked = trust.key_revoked if trust else None
        problems.extend(f"{where}:{p}" for p in check_step(pred, policies, str(pred.get("at")), revoked))
    return body, problems


def _grant_charges(pred: dict[str, Any]) -> list[tuple[str, dict[str, Any] | None, Any]]:
    """(grant digest, budget, call args) for every grant in the chain an allow rests on."""
    evidence = pred.get("authority")
    if not isinstance(evidence, Mapping) or evidence.get("kind") != "grant":
        return []
    try:
        args = json.loads(base64.b64decode(evidence.get("argsB64", ""))) if evidence.get("argsB64") else None
        return [(grant_digest(g["body"]), g["body"].get("budget"), args) for g in evidence.get("chain", [])]
    except (ValueError, KeyError, TypeError):
        return []


def _budget_problems(bodies: list[tuple[int, dict[str, Any]]]) -> list[str]:
    """Re-count every grant's uses and spend across the journal, charging every ancestor."""
    problems: list[str] = []
    uses: dict[str, int] = {}
    spent: dict[str, float] = {}
    charged: set[str] = set()
    for i, body in bodies:
        pred = body.get("predicate", {})
        if (body.get("predicateType") != TOOL_CALL_RECORD or pred.get("phase") != "authorize"
                or pred.get("decision") != "allow" or pred.get("permitId") in charged):
            continue
        charges = _grant_charges(pred)
        if charges:
            charged.add(pred.get("permitId"))
        for digest, budget, args in charges:
            if not budget:
                continue
            uses[digest] = uses.get(digest, 0) + 1
            spent[digest] = spent.get(digest, 0) + spend_of(budget, args)
            if "uses" in budget and uses[digest] > budget["uses"]:
                problems.append(f"line_{i}:grant_budget_exceeded:{digest[:12]}")
            if "spend" in budget and spent[digest] > budget["spend"]["max"]:
                problems.append(f"line_{i}:grant_spend_exceeded:{digest[:12]}")
    return problems


def _retry_problem(pred: dict[str, Any], since_allow: list[str], last_effect: str | None) -> str | None:
    """Why a re-issued permit is not supported by the journal itself, or ``None`` when it is."""
    if pred.get("reason") == RECONCILED_RETRY:
        answer = (pred.get("context") or {}).get("reconciliation") or {}
        if answer.get("result") != "absent" or answer.get("final") is not True:
            return "reconciled_retry_without_final_absent_answer"
        return None
    # not_run_retry: nothing left the worker since the last permit, or the call settled not_run.
    if "intent" not in since_allow or (since_allow[-1] == "effect" and last_effect == "not_run"):
        return None
    return "not_run_retry_but_an_effect_may_have_happened"


def _cross_checks(bodies: list[tuple[int, dict[str, Any]]]) -> list[str]:
    """Run-level rules: an effect needs an earlier allow for its permit; a re-issued permit needs an
    earlier allow and the journal's own evidence that the earlier call did not take effect; a permit
    whose outcome settled (committed or unknown) gets no later effect record; an intent with no effect
    record is an open operation, reported, never read as success; an intent or effect names the same
    grant as the allow its permit rests on; grant budgets hold."""
    problems: list[str] = _budget_problems(bodies)
    grant_of: dict[str, Any] = {}
    allowed: set[str] = set()
    effects: dict[str, str | None] = {}  # pid -> outcome of its latest effect record
    since_allow: dict[str, list[str]] = {}  # pid -> phases journalled since its latest allow
    intents: dict[str, int] = {}
    for i, body in bodies:
        if body.get("predicateType") != TOOL_CALL_RECORD:
            continue
        pred = body["predicate"]
        pid = pred.get("permitId")
        phase = pred.get("phase")
        if phase == "authorize" and pred.get("decision") == "allow":
            if pred.get("reason") in RETRY_REASONS:
                if pid not in allowed:
                    problems.append(f"line_{i}:retry_without_earlier_permit")
                else:
                    why = _retry_problem(pred, since_allow.get(pid, []), effects.get(pid))
                    if why is not None:
                        problems.append(f"line_{i}:{why}")
            allowed.add(pid)
            since_allow[pid] = []
            grant_of.setdefault(pid, pred.get("grantDigest"))
        elif phase in ("intent", "effect") and pid in grant_of and pred.get("grantDigest") != grant_of[pid]:
            problems.append(f"line_{i}:{phase}_grant_differs_from_permit")
        if phase == "intent":
            if pid not in allowed:
                problems.append(f"line_{i}:intent_without_permit")
            intents.setdefault(pid, i)
            since_allow.setdefault(pid, []).append("intent")
        elif phase == "effect":
            if pid not in allowed:
                problems.append(f"line_{i}:effect_without_permit")
            if effects.get(pid) in ("committed", "unknown"):
                problems.append(f"line_{i}:effect_record_after_settled_outcome")
            effects[pid] = pred.get("outcome")
            since_allow.setdefault(pid, []).append("effect")
    for pid, i in intents.items():
        if pid not in effects:
            problems.append(f"line_{i}:open_intent_no_effect_record:{pid[:12]}")
    return problems


def _check_witnessed(note: str | None, lines: list[str], trust: Trust, failures: list[str]) -> dict[str, Any]:
    """The witnessed checkpoint against the auditor's pinned tlog-policy and the journal's own lines."""
    from . import witness  # noqa: PLC0415 - keeps the policy parser off the import path of plain verifies

    if note is None:
        failures.append("witnessed_checkpoint_required_by_policy")
        return {"status": "missing"}
    try:
        verified = witness.verify_note(note, witness.parse_policy(str(trust.witness_policy)))
    except witness.NoteError as exc:
        failures.append(f"witnessed_checkpoint:{exc}")
        return {"status": "refused"}
    cp = verified.checkpoint
    out = {"status": "verified", "size": cp.size, "of": len(lines), "cosigners": sorted(verified.cosigned_at),
           "origin": cp.origin}
    if cp.size > len(lines):
        failures.append(f"witnessed_checkpoint_size_{cp.size}_journal_has_{len(lines)}")
        out["status"] = "journal_truncated"
        return out
    leaves = [witness.leaf_hash(line.encode()) for line in lines[:cp.size]]
    if witness.root(leaves) != cp.root:
        failures.append("witnessed_checkpoint_root_differs_from_the_journal")
        out["status"] = "root_mismatch"
    elif cp.size < len(lines):
        out["status"] = "tail_unwitnessed"
    return out


def _check_custody(checkpoint_env: Mapping[str, Any] | None, signer_ids: set[str],
                   delegations: Mapping[str, Delegation], trust: Trust, failures: list[str]) -> None:
    """Each signing key the auditor pinned a custody for must name that custody in the checkpoint."""
    if checkpoint_env is None:
        failures.append("key_custody_pinned_but_no_checkpoint")
        return
    try:
        provenance = json.loads(base64.b64decode(checkpoint_env["payload"]))["predicate"].get("keyProvenance") or {}
    except (KeyError, TypeError, ValueError):
        return  # the checkpoint check reports the malformed envelope
    roots = {delegations[k].root_key_id if k in delegations else k for k in signer_ids}
    stated = provenance.get("root", provenance) if provenance.get("backend") == "delegated" else provenance
    for kid in sorted(roots):
        want = trust.key_custody.get(kid)
        if want is not None and stated.get("backend") != want:
            failures.append(f"key_custody_{kid[:12]}_is_{stated.get('backend')}_pinned_{want}")


def verify_journal(path: str | os.PathLike[str], public_pems: Iterable[bytes],
                   checkpoint_env: Mapping[str, Any] | None = None,
                   trust: Trust | None = None, witnessed_checkpoint: str | None = None) -> dict[str, Any]:
    """Verify a journal offline: every signature, the chain, the checkpoint, and both published
    readers re-run on every embedded record. Reports the denominator (``verified`` of ``records``).

    ``path`` is the journal file or the directory holding ``journal.jsonl``. ``trust`` is what the
    auditor pins for records that rest on a grant, a quorum, an exception or a revocation list, the
    custody of each signing key (``key_custody``), and the c2sp.org/tlog-policy whose witnesses must
    have cosigned ``witnessed_checkpoint`` (``witness_policy``): a journal the customer's witness did
    not cosign then fails, offline, whatever else holds.
    """
    roots = _keys(public_pems)
    p = Path(path)
    p = p / JOURNAL_FILE if p.is_dir() else p
    lines = [line for line in p.read_text().splitlines() if line.strip()] if p.exists() else []
    failures: list[str] = []
    delegations = _delegations(p.parent, roots, failures)
    keys = [*roots, *(d.session for d in delegations.values())]
    prev, bodies, verified = GENESIS, [], 0
    signer_ids: set[str] = set()
    outcomes: dict[str, int] = {}
    policy_allows = 0
    for i, line in enumerate(lines, 1):
        body, problems = _check_line(i, line, keys, prev, trust, delegations)
        prev = _line_hash(line.encode())
        failures.extend(problems)
        if body is None:
            continue
        bodies.append((i, body))
        if not problems:
            verified += 1
        pred = body.get("predicate", {})
        if (pred.get("phase") == "authorize" and pred.get("decision") == "allow"
                and pred.get("reason") == NO_APPROVAL_REQUIRED):
            policy_allows += 1
        if pred.get("phase") == "effect" and pred.get("outcome"):
            outcomes[pred["outcome"]] = outcomes.get(pred["outcome"], 0) + 1
    failures.extend(_cross_checks(bodies))
    checkpoint = "not_supplied"
    if checkpoint_env is not None:
        try:
            payload, cp_signer = open_envelope(dict(checkpoint_env), keys)
            signer_ids.add(cp_signer)
            cp = json.loads(payload)["predicate"]
            if cp["count"] != len(lines):
                failures.append(f"checkpoint_count_{cp['count']}_journal_has_{len(lines)}")
                checkpoint = "mismatch"
            elif cp["head"] != prev:
                failures.append("checkpoint_head_mismatch")
                checkpoint = "mismatch"
            else:
                checkpoint = "matches"
        except (ValueError, KeyError, TypeError) as exc:
            failures.append(f"checkpoint:{exc}")
            checkpoint = "invalid"
    witnessed = None
    if trust is not None and trust.witness_policy is not None:
        witnessed = _check_witnessed(witnessed_checkpoint, lines, trust, failures)
    if trust is not None and trust.key_custody:
        _check_custody(checkpoint_env, signer_ids, delegations, trust, failures)
    if failures:
        verdict = "FAIL"
    elif witnessed is not None and witnessed["status"] != "verified":
        verdict = "NOT_ESTABLISHED"  # the tail past the witnessed size rests on the authority alone
    elif checkpoint != "matches":
        verdict = "NOT_ESTABLISHED"  # every line holds, but truncation cannot be ruled out
    else:
        verdict = "PASS"
    return {"verdict": verdict, "records": len(lines), "verified": verified, "failures": failures,
            "checkpoint": checkpoint, "witnessed": witnessed, "outcomes": outcomes, "policyAllows": policy_allows,
            "statements": [body for _, body in bodies]}
