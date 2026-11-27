"""A hash-chained journal of DSSE-signed in-toto statements, its signed checkpoint, and the
offline verifier an outsider runs over both.

Each line is one envelope. Its statement's predicate carries ``seq`` (1, 2, ...), ``prev`` (SHA-256
of the previous line's bytes, 64 zeros for the first) and ``at``, taken from the journal's ``Clock`` and never
earlier than the ``at`` of any line already in the file, so a writer whose clock stepped back keeps the chain in
order. A checkpoint is a signed statement
of the line count and the last line's hash: pinned by an outsider, it exposes a truncated or
rewritten journal.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .authority import GRANT_ALLOW, Trust, check_authority
from .clock import Clock, from_datetime, to_datetime
from .core import (
    admitted_loads,
    call_args_of,
    load_public,
    open_envelope,
    sign_envelope,
    statement,
    unb64,
    value_key,
)
from .governance import GOVERNANCE_STEP, check_step
from .grants import body_problem, chain_digests, grant_digest, spend_of
from .identifiers import identifier, same_identifier
from .identity import AUTONOMOUS, check_principals, sponsor_id, strict_shortfall
from .possession import DEFAULT_SKEW, duplicate_proofs
from .quorum import count_bindings
from .records import TOOL_CALL_RECORD, judge_approval_binding, judge_uncertain_effect
from .signing import Delegation, verify_delegation

GENESIS = "0" * 64
CHECKPOINT_TYPE = identifier("agent-evidence-vectors/predicate/v1/tool-call-journal-checkpoint")
#: A producer's signed statement that ``dropped`` records it made never reached the journal, after line ``afterSeq``.
GAP_TYPE = identifier("agent-evidence-vectors/predicate/v1/tool-call-journal-gap")
#: A writer's signed statement that it removed a torn last line (``bytes`` long, ``tornSha256``) after ``afterSeq``.
TORN_TAIL_TYPE = identifier("agent-evidence-vectors/predicate/v1/tool-call-journal-torn-tail")
JOURNAL_SUBJECT = "tool-call-journal"
JOURNAL_FILE = "journal.jsonl"
#: Root-signed certificates for the session keys that signed lines of the journal (``signing.delegate``).
KEYS_FILE = "keys.jsonl"


def timestamp(ns: int) -> str:
    """The journal's form of a wall time given in nanoseconds: RFC 3339, UTC, microseconds, ``Z``."""
    return to_datetime(ns).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _at_ns(text: object) -> int | None:
    if not isinstance(text, str):
        return None
    try:
        return from_datetime(datetime.fromisoformat(text))
    except ValueError:
        return None


def _line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _payload(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return admitted_loads(unb64(envelope["payload"]))


def _whole_lines(path: Path) -> tuple[list[bytes], int]:
    """The lines of an append-only file up to its last newline, and the byte count of the torn tail after it.

    Each line is written with its newline in one append, durable on return, so bytes after the last newline are an
    append a killed writer never finished and nothing acted on: they are not a line. Every reader stops before them.
    """
    if not path.exists():
        return [], 0
    data = path.read_bytes()
    end = data.rfind(b"\n") + 1
    return data[:end].split(b"\n")[:-1], len(data) - end


def _cut_torn_tail(fd: int, end: int) -> None:
    """Cut the file open at ``fd`` back to ``end``, the end of its last whole line, durably, before a line is
    appended: written after a torn tail, the new line would be glued onto it and the file would stay unreadable."""
    if os.fstat(fd).st_size > end:
        os.ftruncate(fd, end)
        os.fsync(fd)


class Journal:
    """Append-only signed journal in ``directory``.

    Appends are serialised by a file lock and fsynced, so a record that returned is on disk before the
    caller acts on it. The head (line count, last hash, byte offset) is cached per instance and
    refreshed only from bytes other writers appended since: an append costs the same at line one
    million as at line one. Concurrent appenders in one process share fsyncs (group commit): a writer
    whose bytes an earlier fsync already covered does not fsync again.
    """

    def __init__(self, directory: str | os.PathLike[str], signer: Any, *, clock: Clock, run: str | None = None) -> None:
        self.directory = Path(directory)
        self.run = run
        self._torn: bytes | None = None
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / JOURNAL_FILE
        self.signer = signer
        self.clock = clock
        self._offset, self._seq, self._head = 0, 0, GENESIS
        self._last_at = 0
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
            present = _whole_lines(keys)[0]
            if line.encode() in present:
                return
            fd = os.open(keys, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                _cut_torn_tail(fd, sum(len(row) + 1 for row in present))
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
            self._offset, self._seq, self._head, self._last_at = 0, 0, GENESIS, 0
        self._torn = None
        if size > self._offset:
            with self.path.open("rb") as fh:
                fh.seek(self._offset)
                for line in fh:
                    if not line.endswith(b"\n"):
                        self._torn = line  # a torn tail from a crashed writer is not a line; append removes it
                        break
                    self._offset += len(line)
                    body = line.rstrip(b"\n")
                    if body.strip():
                        predicate = _payload(admitted_loads(body))["predicate"]
                        self._seq = int(predicate["seq"])
                        self._head = _line_hash(body)
                        at = _at_ns(predicate.get("at"))
                        self._last_at = max(self._last_at, at if at is not None else 0)
        return self._seq, self._head

    def _tail(self) -> tuple[int, str]:
        return self._refresh()

    def _stamp(self) -> str:
        """Now, held at the latest ``at`` already in the file (call after a refresh)."""
        self._last_at = max(self.clock.now(), self._last_at)
        return timestamp(self._last_at)

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
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                if self._torn is not None:
                    seq, head = self._remove_torn_tail(fd, seq)
                envelope, line = self._line(predicate_type, subject_name, subject_digest, predicate, seq, head)
                os.write(fd, line)
                self._offset += len(line)
                self._seq, self._head = seq + 1, _line_hash(line.rstrip(b"\n"))
                end = self._offset
                fcntl.flock(guard, fcntl.LOCK_UN)  # order is fixed; durability may be shared
                self._sync(fd, end)
            finally:
                os.close(fd)
        return envelope

    def _line(self, predicate_type: str, subject_name: str, subject_digest: str, predicate: Mapping[str, Any],
              seq: int, head: str) -> tuple[dict[str, Any], bytes]:
        body = statement(subject_name, subject_digest, predicate_type,
                         {**dict(predicate), "at": self._stamp(), "prev": head, "seq": seq + 1})
        envelope = sign_envelope(self.signer, json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
        return envelope, json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode() + b"\n"

    def _remove_torn_tail(self, fd: int, seq: int) -> tuple[int, str]:
        """Cut the torn bytes a crashed writer left and append the signed line that says so, durable before the
        caller's line: a torn tail leaves the file only with a statement of its length and digest."""
        torn = self._torn or b""
        os.ftruncate(fd, self._offset)
        os.fsync(fd)
        _, line = self._line(TORN_TAIL_TYPE, JOURNAL_SUBJECT, hashlib.sha256(torn).hexdigest(),
                             {"afterSeq": seq, "bytes": len(torn), "tornSha256": hashlib.sha256(torn).hexdigest()},
                             seq, self._head)
        os.write(fd, line)
        os.fsync(fd)
        self._offset += len(line)
        self._synced = max(self._synced, self._offset)
        self._seq, self._head, self._torn = seq + 1, _line_hash(line.rstrip(b"\n")), None
        return self._seq, self._head

    def gap(self, *, dropped: int, after_seq: int, reason: str) -> dict[str, Any]:
        """Append the signed statement that ``dropped`` records the producer made never reached the journal, lost
        after line ``after_seq``. The producer states the loss it knows of; the journal never infers one."""
        seq, _ = self._refresh()
        if (isinstance(dropped, bool) or not isinstance(dropped, int) or dropped < 1
                or isinstance(after_seq, bool) or not isinstance(after_seq, int) or not 0 <= after_seq <= seq
                or not isinstance(reason, str) or not reason):  # fmt: skip
            raise ValueError("journal_gap_invalid: dropped >= 1, 0 <= afterSeq <= the last line, a reason")
        return self.append(GAP_TYPE, JOURNAL_SUBJECT, hashlib.sha256(reason.encode()).hexdigest(),
                           {"afterSeq": after_seq, "dropped": dropped, "reason": reason})

    def statements(self) -> list[dict[str, Any]]:
        """The statements of every whole line; a torn tail from a writer killed mid-append is not one."""
        return [_payload(admitted_loads(line)) for line in _whole_lines(self.path)[0] if line.strip()]

    def checkpoint(self) -> dict[str, Any]:
        """A signed statement of the line count and head, for an outsider to pin."""
        seq, head = self._refresh()
        predicate = {"at": self._stamp(), "count": seq, "head": head,
                     "keyProvenance": dict(getattr(self.signer, "provenance", {"backend": "unstated"}))}
        if self.run is not None:
            predicate["run"] = self.run
        body = statement(JOURNAL_SUBJECT, head, CHECKPOINT_TYPE, predicate)
        return sign_envelope(self.signer, json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


def _keys(public_pems: Iterable[bytes]) -> list[Any]:
    keys = [load_public(pem) for pem in public_pems]
    if not keys:
        raise ValueError("verify_journal needs at least one trusted public key")
    return keys


def _delegations(directory: Path, roots: list[Any], failures: list[str]) -> dict[str, Delegation]:
    """Session keys certified by a pinned root; a certificate no pinned root signed is a failure."""
    found: dict[str, Delegation] = {}
    for n, line in enumerate(_whole_lines(directory / KEYS_FILE)[0], 1):
        if not line.strip():
            continue
        try:
            d = verify_delegation(admitted_loads(line), roots)
        except (ValueError, TypeError) as exc:
            failures.append(f"keys_line_{n}:session_key_delegation_invalid:{exc}")
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


#: What an authorize record's approvals give its principals: (nameable, counted). ``nameable`` is who an approver
#: principal may name, None when no approval admitted the call; ``counted`` is who the approval counted, every one of
#: whom strict names. An allow's two are one set; a deny counts nobody, so its ``counted`` is empty.
Approvers = tuple[set[str] | None, set[str] | None]


def _same(counted: set[str] | None) -> Approvers:
    return counted, counted


def _check_approval(pred: dict[str, Any], problems: list[str], where: str, trust: Trust | None) -> Approvers:
    """Check the approvals an authorize record rests on, and return (nameable, counted). For an allow both are the
    approvers it COUNTS: those whose binding the reader allowed and whose signature verified under the pinned
    policy, or the approving voters of a quorum that held. For a deny, nameable is every approver whose binding it
    carries and counted is empty: a deny counts nobody, so strict does not need each of them named. (None, None)
    when no approval admitted the call (no approval, or none that holds)."""
    if pred.get("decision") == "allow":
        before = len(problems)
        if check_authority(pred, trust, problems, where):
            return _same((_vote_signers(pred) or None) if len(problems) == before else None)
    bindings = pred.get("approvalBindings") or []
    if not bindings:
        # An allow with no approval is accepted only as the authority's signed statement that its
        # policy required none for this call; verify_journal counts these apart (policyAllows).
        if pred.get("decision") == "allow" and pred.get("reason") not in (NO_APPROVAL_REQUIRED, *RETRY_REASONS):
            problems.append(f"{where}:allow_without_approval_binding")
        return None, None
    reader_allowed: set[str] = set()
    for n, embedded in enumerate(bindings):
        payload = unb64(embedded["payloadB64"])  # core.unb64, as the TypeScript reader reads it
        if hashlib.sha256(payload).hexdigest() != pred.get("argsSha256"):
            problems.append(f"{where}:binding_{n}:approval_payload_is_not_the_call_arguments")
        verdict = judge_approval_binding(embedded["record"], payload)
        if verdict["decision"] == "allow":
            reader_allowed.add(str(embedded["record"].get("approval", {}).get("approver")))
        elif pred.get("decision") == "deny" and verdict["reason"] != pred.get("reason") and len(bindings) == 1:
            problems.append(f"{where}:deny_reason_mismatch:{pred.get('reason')}:{verdict['reason']}")
    if pred.get("decision") != "allow":
        # A deny counts nobody; its approver principal may name any approver whose binding it carries.
        return {str((b.get("record") or {}).get("approval", {}).get("approver")) for b in bindings}, set()
    # The M of N is re-counted under the quorum policy the AUDITOR pinned: the approver keys and the
    # threshold come from Trust, never from the record the authority wrote.
    if trust is None:
        problems.append(f"{where}:authority_trust_not_pinned:approval")
        return None, None
    policy = trust.quorum_policies.get(str(pred.get("approvalPolicyId")))
    if policy is None:
        problems.append(f"{where}:approval_policy_not_pinned")
        return None, None
    if pred.get("threshold") != policy["threshold"]:
        problems.append(f"{where}:threshold_not_pinned:{pred.get('threshold')}:{policy['threshold']}")
    signed, sig_problems = count_bindings(policy, bindings, str(pred.get("at")), trust.key_revoked,
                                          oidc_pins=trust.identity_issuers)
    problems.extend(f"{where}:{p}" for p in sig_problems)
    counted = signed & reader_allowed
    if len(counted) < policy["threshold"]:
        problems.append(f"{where}:approvals_below_threshold:{len(counted)}:{policy['threshold']}")
    return _same(counted or None)


def _check_effect(pred: dict[str, Any], problems: list[str], where: str) -> str | None:
    record = pred.get("uncertainEffect")
    if not record:
        problems.append(f"{where}:effect_without_uncertain_effect_record")
        return None
    verdict = judge_uncertain_effect(record)
    if verdict["decision"] != "supported":
        problems.append(f"{where}:uncertain_effect_not_supported:{verdict['decision']}:{verdict['reason']}")
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


def _vote_signers(pred: dict[str, Any]) -> set[str]:
    """The approving voters of the quorum an allow's authority carries (a deputy votes on behalf of its delegator).
    Called only once that quorum held, and a quorum with an invalid vote does not hold, so each was counted."""
    quorum = (pred.get("authority") or {}).get("quorum") or (pred.get("authority") or {})
    votes = quorum.get("votes")
    return {str(v.get("body", {}).get("onBehalfOf", v.get("body", {}).get("approver")))
            for v in (votes if isinstance(votes, list) else [])  # the votes are a list; any other value holds none
            if isinstance(v, dict) and v.get("body", {}).get("decision") == "approve"}


def _authority_chain(pred: Mapping[str, Any]) -> list[Any] | None:
    evidence = pred.get("authority")
    if isinstance(evidence, Mapping) and isinstance(evidence.get("chain"), list):
        return list(evidence["chain"])
    return None


def _standing_grants(pred: Mapping[str, Any], trust: Trust,
                     seen: Mapping[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:  # fmt: skip
    """Every grant body an autonomous block may name: from chains the auditor pins, the record's own authority chain
    and the authority chains of earlier lines of this journal (``seen``), each verified against the pinned grant
    roots first. Nothing the record says selects a key."""
    chains = [list(c) for c in trust.standing_grants]
    own = _authority_chain(pred)
    if own is not None:
        chains.append(own)
    found: dict[str, dict[str, Any]] = dict(seen)
    for chain in chains:
        found.update(chain_digests(chain, set(trust.grant_root_key_ids)))
    return found


def _standing_problems(pred: Mapping[str, Any], block: Mapping[str, Any]) -> list[str]:
    """An autonomous call runs on the standing grant its block names, and the record shows it: an allow rests on that
    grant (a grant allow whose leaf it is, so the reader re-runs the call under it), judged in the block's own agent
    and session; every intent and effect names that grant. A refusal may name any tool: the grant admitted nothing."""
    named = block["standingGrant"]
    phase = pred.get("phase")
    if phase in ("intent", "effect"):
        return [] if pred.get("grantDigest") == named else ["principals_standing_grant_not_the_authority"]
    if phase != "authorize" or pred.get("decision") != "allow":
        return []
    evidence = pred.get("authority")
    chain = _authority_chain(pred)
    try:
        leaf = grant_digest(chain[-1]["body"]) if chain else None
    except (KeyError, TypeError, ValueError):
        leaf = None
    if (pred.get("reason") != GRANT_ALLOW or not isinstance(evidence, Mapping) or evidence.get("kind") != GRANT_ALLOW
            or leaf != named or pred.get("grantDigest") != named):  # fmt: skip
        return ["principals_standing_grant_not_the_authority"]
    ctx = evidence.get("ctx") or {}
    session = block["session"]
    own = {"agent": block["agent"]["clientId"], "session": session["id"]}
    if not isinstance(ctx, Mapping) or any(key in ctx and ctx[key] != value for key, value in own.items()):
        return ["principals_standing_context_not_the_block"]
    return []


def _revocation_problems(block: Mapping[str, Any], grade: str, at: str, trust: Trust) -> list[str]:
    """A record answering to a subject the auditor's revocation list revoked at or before the record's time: its
    agent (kind ``agent``, its client id), its sponsor (kind ``sponsor``) whenever the block names one, and for an
    autonomous block its standing grant. A suspended sponsor answers for nothing, with or without a person in the
    session."""
    revocations = trust.revocations
    if revocations is None:
        return []
    problems = []
    if revocations.revoked_at("agent", str(block["agent"]["clientId"]), at):
        problems.append("principals_agent_revoked")
    if "sponsor" in block:
        sponsor = block["sponsor"]
        if revocations.revoked_at("sponsor", sponsor_id(sponsor["issuer"], sponsor["subject"]), at):
            problems.append("principals_sponsor_revoked")
    if grade == "autonomous" and revocations.revoked_at("grant", str(block["standingGrant"]), at):
        problems.append("principals_standing_grant_revoked")
    return problems


def _check_identity(pred: dict[str, Any], trust: Trust | None, problems: list[str], where: str,
                    seen: dict[str, dict[str, Any]], approvers: Approvers) -> None:  # fmt: skip
    if trust is None:
        problems.append(f"{where}:principals_but_no_trust_pinned")
        return
    block = pred["principals"]
    at = str(pred.get("at"))
    autonomous = isinstance(block, dict) and bool(set(block) & set(AUTONOMOUS))
    grants = _standing_grants(pred, trust, seen) if autonomous else None
    nameable, counted = approvers
    found, grade = check_principals(block, at, trust.identity_issuers, nameable, counted=counted,
                                    sponsors=trust.agent_sponsors or None, standing_grants=grants)
    problems.extend(f"{where}:{p}" for p in found)
    if grade == "autonomous":
        problems.extend(f"{where}:{p}" for p in _standing_problems(pred, block))
    if grade is not None:
        problems.extend(f"{where}:{p}" for p in _revocation_problems(block, grade, at, trust))
    if grade is not None and trust.identity_profile == "strict" and grade not in ("strict", "autonomous"):
        problems.append(f"{where}:principals_below_strict:{strict_shortfall(block, nameable, counted)}")


def _remember_standing(pred: Mapping[str, Any], trust: Trust | None, seen: dict[str, dict[str, Any]]) -> None:
    """Keep the verified bodies of an allow's authority chain, so later intent and effect lines of the same journal
    resolve the standing grant they name without the auditor pinning it."""
    chain = _authority_chain(pred)
    if trust is not None and chain is not None and pred.get("phase") == "authorize" and pred.get("decision") == "allow":
        seen.update(chain_digests(chain, set(trust.grant_root_key_ids)))


def _check_line(i: int, line: str, keys: list[Any], prev: str, trust: Trust | None,
                delegations: Mapping[str, Delegation], seen: dict[str, dict[str, Any]],
                counted: dict[str, Approvers]) -> tuple[dict[str, Any] | None, list[str]]:  # fmt: skip
    problems: list[str] = []
    where = f"line_{i}"
    try:
        payload, signer_id = open_envelope(admitted_loads(line), keys)
        body = admitted_loads(payload)
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
        problems.append(f"{where}:seq_mismatch:{pred.get('seq')}:{i}")
    if pred.get("prev") != prev:
        problems.append(f"{where}:chain_broken")
    if same_identifier(body.get("predicateType"), TOOL_CALL_RECORD):
        # The approvals are judged first, because an approver principal may name only an approver this record
        # counts; their problems are reported after the identity's, as before.
        approval_problems: list[str] = []
        pid = str(pred.get("permitId"))
        if pred.get("phase") == "authorize":
            approvers = _check_approval(pred, approval_problems, where, trust)
            if pred.get("decision") == "allow":
                counted.setdefault(pid, approvers)
        else:
            # An intent or effect answers to the allow its permit rests on: the approvers that allow counted.
            approvers = counted.get(pid, (None, None))
        if pred.get("principals") is not None:
            _check_identity(pred, trust, problems, where, seen, approvers)
        elif pred.get("phase") == "authorize" and trust is not None and trust.identity_profile == "strict":
            # An auditor that requires strict identity is never satisfied by a decision that omits it.
            problems.append(f"{where}:principals_missing")
        _remember_standing(pred, trust, seen)
        problems.extend(approval_problems)
        if pred.get("phase") == "effect":
            _check_effect(pred, problems, where)
    elif same_identifier(body.get("predicateType"), GAP_TYPE) or same_identifier(body.get("predicateType"),
                                                                                  TORN_TAIL_TYPE):
        problems.extend(f"{where}:{p}" for p in _loss_problems(body, i))
    elif same_identifier(body.get("predicateType"), GOVERNANCE_STEP):
        policies = trust.quorum_policies if trust else None
        revoked = trust.key_revoked if trust else None
        problems.extend(f"{where}:{p}" for p in check_step(pred, policies, str(pred.get("at")), revoked))
    return body, problems


def _count(value: Any, low: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= low


def _loss_problems(body: Mapping[str, Any], line: int) -> list[str]:
    """A gap or torn-tail line holds exactly its members: a count of at least one and a position before itself."""
    pred = body.get("predicate", {})
    if same_identifier(body.get("predicateType"), GAP_TYPE):
        members, code = {"afterSeq", "dropped", "reason", "at", "prev", "seq"}, "journal_gap_invalid"
        shape = _count(pred.get("dropped"), 1) and isinstance(pred.get("reason"), str) and bool(pred.get("reason"))
    else:
        members, code = {"afterSeq", "bytes", "tornSha256", "at", "prev", "seq"}, "journal_torn_tail_invalid"
        digest = pred.get("tornSha256")
        shape = (_count(pred.get("bytes"), 1) and isinstance(digest, str) and len(digest) == 64
                 and all(c in "0123456789abcdef" for c in digest))  # fmt: skip
    if set(pred) != members or not shape or not _count(pred.get("afterSeq"), 0) or pred["afterSeq"] >= line:
        return [code]
    return []


def _loss_report(bodies: list[tuple[int, dict[str, Any]]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The gap and torn-tail lines of a journal, in order, for the report."""
    gaps, torn = [], []
    for i, body in bodies:
        pred = body.get("predicate", {})
        if same_identifier(body.get("predicateType"), GAP_TYPE) and not _loss_problems(body, i):
            gaps.append({"afterSeq": pred["afterSeq"], "dropped": pred["dropped"], "line": i, "reason": pred["reason"]})
        elif same_identifier(body.get("predicateType"), TORN_TAIL_TYPE) and not _loss_problems(body, i):
            torn.append({"afterSeq": pred["afterSeq"], "bytes": pred["bytes"], "line": i})
    return gaps, torn


def _grant_charges(pred: dict[str, Any]) -> list[tuple[str, dict[str, Any] | None, Any]]:
    """(grant digest, budget, call args) for every well-formed grant in the chain an allow rests on. A malformed body
    is skipped: the allow it carries is refused already (``grant_deny``), and its budget has no members to count."""
    evidence = pred.get("authority")
    if not isinstance(evidence, Mapping) or evidence.get("kind") != "grant":
        return []
    try:
        args = call_args_of(evidence)[1]
        return [(grant_digest(g["body"]), g["body"].get("budget"), args) for g in evidence.get("chain", [])
                if body_problem(g["body"]) is None]
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
        if (not same_identifier(body.get("predicateType"), TOOL_CALL_RECORD)
                or pred.get("phase") != "authorize"
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


def _party(p: Any) -> bytes:
    """One party's key: a principal (any object) is its issuer and subject, as an object, so a refreshed credential is
    the same party and a list of two strings that spell the pair is not (a member that is not an object never prints
    as an object). The key is ``value_key``: one JSON value, one key, whatever its member order or number spelling."""
    if isinstance(p, dict):
        return value_key({"issuer": p.get("issuer"), "subject": p.get("subject")})
    return value_key(p)


def _parties(block: Any) -> dict[str, bytes | tuple[bytes, ...]] | None:
    """Who a principals block names, role by role (issuer and subject). A credential may be refreshed between a
    permit's records; the parties may not change. An approver list is the multiset of its members' parties, in no
    order: sorted by key, so the verdict never depends on the order the writer listed them in, and two lists are the
    same parties exactly when each member has one equal member in the other (the TypeScript twin reads the same
    keys)."""
    if not isinstance(block, dict):
        return None
    return {role: tuple(sorted(_party(m) for m in p)) if isinstance(p, list) else _party(p)
            for role, p in block.items()}


def _cross_checks(bodies: list[tuple[int, dict[str, Any]]], skew: int) -> list[str]:
    """Run-level rules: an effect needs an earlier allow for its permit; a re-issued permit needs an
    earlier allow and the journal's own evidence that the earlier call did not take effect; a permit
    whose outcome settled (committed or unknown) gets no later effect record; an intent with no effect
    record is an open operation, reported, never read as success; an intent or effect names the same
    grant, and the same parties (issuer and subject per role), as the allow its permit rests on; grant budgets hold;
    no DPoP proof is spent by two permits inside its lifetime."""
    problems: list[str] = _budget_problems(bodies)
    tool_calls = [(i, b) for i, b in bodies if same_identifier(b.get("predicateType"), TOOL_CALL_RECORD)]
    problems.extend(f"line_{i}:{reason}" for i, reason in duplicate_proofs(tool_calls, skew=skew))
    grant_of: dict[str, Any] = {}
    parties_of: dict[str, Any] = {}  # pid -> who its first allow names, role by role
    allowed: set[str] = set()
    effects: dict[str, str | None] = {}  # pid -> outcome of its latest effect record
    since_allow: dict[str, list[str]] = {}  # pid -> phases journalled since its latest allow
    intents: dict[str, int] = {}
    for i, body in bodies:
        if not same_identifier(body.get("predicateType"), TOOL_CALL_RECORD):
            continue
        pred = body["predicate"]
        pid = pred.get("permitId")
        phase = pred.get("phase")
        later = phase in ("intent", "effect") or (phase == "authorize" and pred.get("decision") == "allow")
        if (later and pid in parties_of and pred.get("principals") is not None
                and _parties(pred["principals"]) != parties_of[pid]):  # fmt: skip
            # A credential may be refreshed between a permit's records; the parties they name may not change. A record
            # that names no parties claims none (the identity profile decides whether it must).
            problems.append(f"line_{i}:principals_differ_from_permit:{phase}")
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
            parties_of.setdefault(pid, _parties(pred.get("principals")))
        elif phase in ("intent", "effect") and pid in grant_of and pred.get("grantDigest") != grant_of[pid]:
            problems.append(f"line_{i}:grant_differs_from_permit:{phase}")
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
    from . import witness

    if note is None:
        failures.append("witnessed_checkpoint_missing")
        return {"status": "missing"}
    try:
        verified = witness.verify_note(note, witness.parse_policy(str(trust.witness_policy)))
    except witness.NoteError as exc:
        failures.append(f"witnessed_checkpoint_invalid:{exc}")
        return {"status": "refused"}
    cp = verified.checkpoint
    out = {"status": "verified", "size": cp.size, "of": len(lines), "cosigners": sorted(verified.cosigned_at),
           "origin": cp.origin}
    if cp.size > len(lines):
        failures.append(f"witnessed_checkpoint_beyond_journal:{cp.size}:{len(lines)}")
        out["status"] = "journal_truncated"
        return out
    leaves = [witness.leaf_hash(line.encode()) for line in lines[:cp.size]]
    if witness.root(leaves) != cp.root:
        failures.append("witnessed_checkpoint_root_mismatch")
        out["status"] = "root_mismatch"
    elif cp.size < len(lines):
        out["status"] = "tail_unwitnessed"
    return out


def _check_custody(checkpoint_env: Mapping[str, Any] | None, signer_ids: set[str],
                   delegations: Mapping[str, Delegation], trust: Trust, failures: list[str]) -> None:
    """Each signing key the auditor pinned a custody for must name that custody in the checkpoint."""
    if checkpoint_env is None:
        failures.append("key_custody_checkpoint_missing")
        return
    try:
        provenance = admitted_loads(unb64(checkpoint_env["payload"]))["predicate"].get("keyProvenance") or {}
    except (KeyError, TypeError, ValueError):
        return  # the checkpoint check reports the malformed envelope
    roots = {delegations[k].root_key_id if k in delegations else k for k in signer_ids}
    stated = provenance.get("root", provenance) if provenance.get("backend") == "delegated" else provenance
    for kid in sorted(roots):
        want = trust.key_custody.get(kid)
        if want is not None and stated.get("backend") != want:
            failures.append(f"key_custody_differs:{kid[:12]}:{stated.get('backend')}:{want}")


def verify_journal(path: str | os.PathLike[str], public_pems: Iterable[bytes],
                   checkpoint_env: Mapping[str, Any] | None = None,
                   trust: Trust | None = None, witnessed_checkpoint: str | None = None,
                   run: str | None = None) -> dict[str, Any]:
    """Verify a journal offline: every signature, the chain, the checkpoint, and both published
    readers re-run on every embedded record. Reports the denominator (``verified`` of ``records``).

    ``path`` is the journal file or the directory holding ``journal.jsonl``. ``trust`` is what the
    auditor pins for records that rest on a grant, a quorum, an exception or a revocation list, the
    custody of each signing key (``key_custody``), and the c2sp.org/tlog-policy whose witnesses must
    have cosigned ``witnessed_checkpoint`` (``witness_policy``): a journal the customer's witness did
    not cosign then fails, offline, whatever else holds.

    Loss is reported, never inferred: ``dropped`` sums the signed gap lines, ``gaps`` and ``tornTails`` list them.
    A record is a whole line, up to its newline, as the writer and the witness tree count it. Bytes after the last
    newline are an append a writer killed mid-write never finished: not a record, reported as ``tornTail`` and
    ``tornTailBytes``, and they keep the verdict from ``PASS``. ``run`` pins the run the checkpoint must name.
    """
    roots = _keys(public_pems)
    p = Path(path)
    p = p / JOURNAL_FILE if p.is_dir() else p
    # the lines a writer and the witness tree count: up to the last newline (a torn tail is reported, not read)
    raw, torn = _whole_lines(p)
    lines = [line.decode() for line in raw if line.strip()]
    failures: list[str] = []
    delegations = _delegations(p.parent, roots, failures)
    keys = [*roots, *(d.session for d in delegations.values())]
    prev, bodies, verified = GENESIS, [], 0
    signer_ids: set[str] = set()
    outcomes: dict[str, int] = {}
    policy_allows = 0
    seen: dict[str, dict[str, Any]] = {}  # grant bodies of the authority chains verified so far, by digest
    counted: dict[str, Approvers] = {}  # permit id -> the approvers its first allow counted
    for i, line in enumerate(lines, 1):
        body, problems = _check_line(i, line, keys, prev, trust, delegations, seen, counted)
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
    failures.extend(_cross_checks(bodies, trust.possession_skew_seconds if trust is not None else DEFAULT_SKEW))
    checkpoint = "not_supplied"
    if checkpoint_env is not None:
        try:
            payload, cp_signer = open_envelope(dict(checkpoint_env), keys)
            signer_ids.add(cp_signer)
            cp = admitted_loads(payload)["predicate"]
            if cp["count"] != len(lines):
                failures.append(f"checkpoint_count_mismatch:{cp['count']}:{len(lines)}")
                checkpoint = "mismatch"
            elif cp["head"] != prev:
                failures.append("checkpoint_head_mismatch")
                checkpoint = "mismatch"
            else:
                checkpoint = "matches"
            if run is not None and cp.get("run") != run:
                failures.append(f"checkpoint_run_mismatch:{cp.get('run')}:{run}")
        except (ValueError, KeyError, TypeError) as exc:
            failures.append(f"checkpoint_invalid:{exc}")
            checkpoint = "invalid"
    witnessed = None
    if trust is not None and trust.witness_policy is not None:
        witnessed = _check_witnessed(witnessed_checkpoint, lines, trust, failures)
    if trust is not None and trust.key_custody:
        _check_custody(checkpoint_env, signer_ids, delegations, trust, failures)
    gaps, torn_lines = _loss_report(bodies)
    torn_tail = {"afterSeq": len(lines), "bytes": torn} if torn else None
    if failures:
        verdict = "FAIL"
    elif torn_tail is not None:
        verdict = "NOT_ESTABLISHED"  # a writer died mid-line: what it was writing is not in the journal
    elif witnessed is not None and witnessed["status"] != "verified":
        verdict = "NOT_ESTABLISHED"  # the tail past the witnessed size rests on the authority alone
    elif checkpoint != "matches":
        verdict = "NOT_ESTABLISHED"  # every line holds, but truncation cannot be ruled out
    else:
        verdict = "PASS"
    return {"verdict": verdict, "records": len(lines), "verified": verified, "failures": failures,
            "checkpoint": checkpoint, "witnessed": witnessed, "outcomes": outcomes, "policyAllows": policy_allows,
            "dropped": sum(g["dropped"] for g in gaps), "gaps": gaps, "tornTails": torn_lines, "tornTail": torn_tail,
            "tornTailBytes": torn, "statements": [body for _, body in bodies]}
