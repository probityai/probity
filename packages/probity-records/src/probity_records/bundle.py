"""The record bundle (``probity-record-bundle/v1``) and the offline verifier a stranger runs with public witness keys.

A bundle carries one decision record and what is needed to check it with no service and no network: the cosigned
checkpoint (c2sp.org/tlog-checkpoint, ``witness``), the log's keys, the record's leaf with its RFC 9162 inclusion
proof, the record and the key it is signed under, and, for a record that answers one stage of one permit, the receipt
map commitment leaf (with its own inclusion proof) and the map proof that the key (issuer, permit id, stage) holds
exactly this record (``receipt_map``).

Which records a public bundle carries (docs/record-bundle.md, "What a public bundle carries"): the evaluator's
control-decision statement (``EVALUATOR_PREDICATE``), the one decision predicate with a public reader. A bundle
naming any other source kind is refused (``bundle_record_kind_unsupported``) unless the verifier passes a reader for that kind (``readers``): the grading,
the proofs and the claims check stay this module's, and only reading the record is the caller's.

What the verifier trusts is what IT holds (``ThirdPartyTrust``), never what the bundle names: the public witness keys
and their list (production or staging), how many distinct external operators it requires, the counterparty receipt
keys it bound to a target identity, and the ML-DSA-44 key of each log whose own post-quantum signature it relies on.
The log's Ed25519 key comes from the bundle: independence comes from the witnesses, and a witness cosigns a checkpoint
only under the log key it pins. The log's ML-DSA-44 line counts only under the key the verifier pins for the origin,
because on the day Ed25519 is forged a post-quantum key the bundle names is the forger's own.

The verdict, per record:
- grade S, "locally tamper-evident, awaiting external witness": no quorum of fresh cosignatures from external
  operators the verifier pins;
- grade W: externally witnessed, with content attested only by the party it describes, or a counterparty receipt
  without a map proof, or a record the bundle presents as a counterparty's under a key the verifier has not bound to
  that target ("tenant-declared counterparty");
- grade I: a counterparty receipt under a key the verifier bound, externally witnessed, with a map proof that its
  (issuer, permit id, stage) holds exactly this record;
- "staging-grade" unless production-list operators alone meet the quorum;
- post-quantum: "PQ-covered (independence)" with the log's own ML-DSA-44 line under the pinned key and a fresh
  ML-DSA-44 cosignature from a counted external witness; "PQ-covered (integrity)" with the pinned log line only;
  "PQ-pending" otherwise, and always for grade S.

The witnessed time is the moment the quorum was met (the quorum-th earliest counted cosignature, one per operator),
never backdated; the admission time is given separately. A bundle may state the grade and post-quantum status it
claims; a claim above what the verifier computes is refused (``bundle_claim_overstated``).

Refusal codes, in the order the checks run: ``bundle_malformed``, ``bundle_checkpoint_refused``,
``bundle_trust_invalid``, ``bundle_log_key_invalid``, ``bundle_leaf_not_included``, ``bundle_leaf_malformed``,
``bundle_record_kind_unsupported``, ``bundle_record_invalid``, ``bundle_record_mismatch``, ``bundle_map_invalid``,
``bundle_map_contradiction``, ``bundle_claim_overstated``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import witness
from .core import JsonRefused, admitted_loads, pae
from .receipt_map import MapError, Proof, check_key, map_key

BUNDLE_FORMAT = "probity-record-bundle/v1"
LEAF_FORMAT = "probity-decision-log-leaf/v2"
COMMITMENT_FORMAT = "probity-receipt-map-commitment/v1"
EVALUATOR_PREDICATE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/control-decision"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
LIST_GRADES = ("production", "staging")
GRADES = ("S", "W", "W+", "I")  # ascending
PQ_STATUSES = ("PQ-pending", "PQ-covered (integrity)", "PQ-covered (independence)")  # ascending
AWAITING = "locally tamper-evident, awaiting external witness"
TENANT_DECLARED = "tenant-declared counterparty"
CANNOT_INFER = ("freshness after the latest counted cosignature", "actions that were never submitted to the log",
                "that the record's content is true")
MAX_INT = 2**53


class BundleRefused(ValueError):
    """A bundle the verifier will not grade; ``code`` is the registered reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def canonical(value: Any) -> bytes:
    """The leaf bytes a decision log writes: sorted members, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _unb64(text: Any) -> bytes:
    if not isinstance(text, str):
        raise BundleRefused("bundle_malformed", "expected base64 text")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleRefused("bundle_malformed", "not base64") from exc


def _hashes(items: Any) -> list[bytes]:
    if not isinstance(items, list):
        raise BundleRefused("bundle_malformed", "a proof is a list of hashes")
    out = [_unb64(h) for h in items]
    if any(len(h) != 32 for h in out):
        raise BundleRefused("bundle_malformed", "a proof hash is 32 bytes")
    return out


# --- reading the record ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceKey:
    """The producer a bundle names: its source id, kind and raw Ed25519 public key."""

    source_id: str
    kind: str
    public_raw: bytes

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.public_raw).hexdigest()


@dataclass(frozen=True)
class RecordFacts:
    """What the leaf states about a record, read from the verified record itself."""

    tenant: str
    sequence: int
    previous: str | None
    digest: str
    receipt: tuple[str, str] | None


#: A reader verifies one record's bytes under its source key and returns the facts its leaf must state; it raises
#: ValueError with the reason when the record is not admissible. It parses the bytes with ``core.admitted_loads``, the
#: package's one reader of untrusted JSON, so hostile bytes are refused rather than raised.
Reader = Callable[[bytes, SourceKey], RecordFacts]


def read_evaluator(raw: bytes, key: SourceKey) -> RecordFacts:
    """A control-decision DSSE envelope signed by ``key``: the payload is the record, its SHA-256 its identity."""
    try:
        envelope = admitted_loads(raw)
        if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
            raise ValueError("not a DSSE in-toto envelope")
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 1 or not isinstance(signatures[0], dict):
            raise ValueError("exactly one signature is required")
        if signatures[0].get("keyid") not in (None, "", key.key_id):
            raise ValueError("the signature names another key than the bundle's source key")
        payload = base64.b64decode(envelope["payload"], validate=True)
        Ed25519PublicKey.from_public_bytes(key.public_raw).verify(
            base64.b64decode(signatures[0]["sig"], validate=True), pae(PAYLOAD_TYPE, payload))
        body = admitted_loads(payload)
    except InvalidSignature as exc:
        raise ValueError("the record's signature does not verify under its source key") from exc
    except (KeyError, TypeError, binascii.Error) as exc:
        raise ValueError(f"the envelope is malformed: {type(exc).__name__}") from exc
    if not isinstance(body, dict) or body.get("_type") != STATEMENT_TYPE or body.get("predicateType") != \
            EVALUATOR_PREDICATE:
        raise ValueError("not a control-decision statement")
    predicate = body.get("predicate")
    runtime = predicate.get("runtime") if isinstance(predicate, dict) else None
    if not isinstance(runtime, dict) or not isinstance(runtime.get("scope"), dict):
        raise ValueError("the runtime block is missing")
    previous = runtime.get("previous")
    if previous is not None and (not isinstance(previous, str) or not previous.startswith("sha256:")):
        raise ValueError("runtime.previous is null or a sha256: digest")
    sequence = runtime.get("sequence")
    if type(sequence) is not int or not 0 <= sequence <= MAX_INT:
        raise ValueError("runtime.sequence is an integer in [0, 2**53]")
    permit, stage = runtime.get("permitId"), runtime.get("stage")
    receipt = None
    if permit is not None or stage is not None:
        try:
            receipt = check_key(permit, stage)
        except MapError as exc:
            raise ValueError(f"the receipt key: {exc}") from exc
    tenant = runtime["scope"].get("tenant_id")
    if not isinstance(tenant, str):
        raise ValueError("runtime.scope.tenant_id is a string")
    return RecordFacts(tenant, sequence, None if previous is None else previous.removeprefix("sha256:"),
                       hashlib.sha256(payload).hexdigest(), receipt)


PUBLIC_READERS: Mapping[str, Reader] = {"evaluator": read_evaluator}


def leaf_entry(source: SourceKey, facts: RecordFacts, admitted_at_ms: int) -> dict[str, Any]:
    """The ``probity-decision-log-leaf/v2`` entry a log writes for a record it admitted at ``admitted_at_ms``."""
    receipt = None if facts.receipt is None else {"issuer": source.key_id, "permit": facts.receipt[0],
                                                   "stage": facts.receipt[1]}
    return {"format": LEAF_FORMAT, "tenant": facts.tenant, "source": source.source_id, "kind": source.kind,
            "sequence": facts.sequence, "previous": facts.previous, "record": facts.digest, "receipt": receipt,
            "admittedAtMs": admitted_at_ms}


# --- what the verifier holds -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicWitness:
    """One public witness key the verifier pins: its vkey (type 0x04 or 0x06), its operator and its list."""

    vkey: str
    operator: str
    list_grade: str


@dataclass(frozen=True)
class ThirdPartyTrust:
    witnesses: tuple[PublicWitness, ...]
    quorum: int = 1  # distinct external operators whose fresh cosignature is required
    max_age: int = 3600  # seconds a cosignature counts for
    max_skew: int = 300
    counterparties: Mapping[str, str] = field(default_factory=dict)  # receipt key id (hex SHA-256) -> target id
    log_pq: Mapping[str, str] = field(default_factory=dict)  # origin -> the log's ML-DSA-44 vkey, pinned

    def policy(self, log_keys: list[witness.VerifierKey]) -> witness.Policy:
        """A tlog-policy over the bundle's log keys and the pinned witnesses with quorum none: the verifier counts
        the external quorum per operator itself, so a stale quorum grades down instead of refusing."""
        lines = [f"log {k.encode()}" for k in log_keys]
        operators: set[str] = set()
        for i, w in enumerate(self.witnesses):
            try:
                key = witness.parse_vkey(w.vkey)
            except witness.NoteError as exc:
                raise BundleRefused("bundle_trust_invalid", str(exc)) from exc
            if key.sig_type not in witness.WITNESS_TYPES or w.list_grade not in LIST_GRADES:
                raise BundleRefused("bundle_trust_invalid", f"{key.name}: a counted witness is a cosignature key on "
                                                            "the production or staging list")
            lines.append(f"witness w{i} {w.vkey}")
            operators.add(w.operator)
        if type(self.quorum) is not int or not 1 <= self.quorum <= len(operators):
            raise BundleRefused("bundle_trust_invalid", "the external quorum is 1 to the number of pinned operators")
        lines.append("quorum none")
        try:
            return witness.parse_policy("\n".join(lines) + "\n")
        except witness.NoteError as exc:
            raise BundleRefused("bundle_trust_invalid", str(exc)) from exc


# --- verifying a bundle ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    grade: str
    independent_of: tuple[str, ...]
    label: str
    pq: str
    assurance: str  # "production", "staging-grade", or "none" when no external quorum
    external_operators: tuple[str, ...]
    externally_witnessed_at: int | None  # the moment the quorum was met, seconds
    admitted_at_ms: int
    receipt: tuple[str, str, str] | None  # (issuer key id, permit id, stage)
    map_status: str  # "proven", "unproven", "unkeyed"
    origin: str
    size: int
    cannot_infer: tuple[str, ...]


def _log_keys(doc: Any, origin: str) -> list[witness.VerifierKey]:
    if not isinstance(doc, dict) or set(doc) != {"vkey", "pqVkey"}:
        raise BundleRefused("bundle_malformed", "log is {vkey, pqVkey}")
    try:
        ed = witness.parse_vkey(doc["vkey"])
        pq = None if doc["pqVkey"] is None else witness.parse_vkey(doc["pqVkey"])
    except (TypeError, AttributeError, witness.NoteError) as exc:
        raise BundleRefused("bundle_log_key_invalid", str(exc)) from exc
    if ed.sig_type != witness.SIG_ED25519 or ed.name != origin:
        raise BundleRefused("bundle_log_key_invalid", "the log key is an Ed25519 key named after the origin")
    if pq is not None and (pq.sig_type != witness.SIG_MLDSA44 or pq.name != origin):
        raise BundleRefused("bundle_log_key_invalid", "the log's post-quantum key is ML-DSA-44, named after the origin")
    return [ed] if pq is None else [ed, pq]


def _included(cp: witness.Checkpoint, part: Any, what: str) -> tuple[int, bytes]:
    if not isinstance(part, dict) or set(part) != {"index", "bytes", "inclusion"}:
        raise BundleRefused("bundle_malformed", f"the {what} is {{index, bytes, inclusion}}")
    index, leaf, proof = part["index"], _unb64(part["bytes"]), _hashes(part["inclusion"])
    if type(index) is not int or not witness.verify_inclusion(index, cp.size, witness.leaf_hash(leaf), proof, cp.root):
        raise BundleRefused("bundle_leaf_not_included", f"the {what} is not in the checkpointed tree")
    return index, leaf


def _record(doc: Any, leaf: bytes, readers: Mapping[str, Reader]) -> tuple[dict[str, Any], str]:
    """The leaf entry, once the record verifies under the key the bundle names and states exactly that leaf."""
    try:
        src = doc["source"]
        key = SourceKey(src["id"], src["kind"], bytes.fromhex(src["publicKey"]))
        raw = _unb64(doc["bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BundleRefused("bundle_malformed", f"record: {type(exc).__name__}") from exc
    if not isinstance(key.source_id, str) or len(key.public_raw) != 32:
        raise BundleRefused("bundle_malformed", "a record source is a string id and a 32-byte Ed25519 key")
    try:
        entry = admitted_loads(leaf)
    except JsonRefused as exc:
        raise BundleRefused("bundle_leaf_malformed", f"the leaf bytes are not admissible JSON: {exc.variant}") from exc
    if not isinstance(entry, dict) or entry.get("format") != LEAF_FORMAT or canonical(entry) != leaf:
        raise BundleRefused("bundle_leaf_malformed", "not a canonical record leaf")
    reader = readers.get(key.kind) if isinstance(key.kind, str) else None
    if reader is None:
        raise BundleRefused("bundle_record_kind_unsupported", f"no reader for source kind {key.kind!r}")
    try:
        facts = reader(raw, key)
    except ValueError as exc:
        raise BundleRefused("bundle_record_invalid", str(exc)) from exc
    admitted = entry.get("admittedAtMs")
    if type(admitted) is not int or not 0 <= admitted <= MAX_INT:
        raise BundleRefused("bundle_leaf_malformed", "admittedAtMs is an integer")
    # Bytes, never values: Python holds True == 1 == 1.0, so a value compare would grade a leaf the log never writes.
    try:
        stated = canonical(leaf_entry(key, facts, admitted))
    except (TypeError, ValueError) as exc:  # a caller's reader returned facts that are not JSON text
        raise BundleRefused("bundle_record_invalid", f"the record's facts do not encode: {type(exc).__name__}") from exc
    if stated != leaf:
        raise BundleRefused("bundle_record_mismatch", "the record does not state its leaf")
    return entry, key.key_id


def _map_status(cp: witness.Checkpoint, doc: Any, entry: dict[str, Any], index: int, leaf: bytes) -> str:
    receipt = entry["receipt"]
    if receipt is None:
        if doc is not None:
            raise BundleRefused("bundle_map_invalid", "a map proof for a record that answers no permit stage")
        return "unkeyed"
    if doc is None:
        return "unproven"
    if not isinstance(doc, dict) or set(doc) != {"commitment", "proof"}:
        raise BundleRefused("bundle_malformed", "map is {commitment, proof}")
    commitment_index, commitment = _included(cp, doc["commitment"], "map commitment leaf")
    try:
        c = admitted_loads(commitment)
        root = bytes.fromhex(c["root"])
        proof = Proof.from_doc(doc["proof"])
    except (ValueError, KeyError, TypeError, MapError) as exc:
        raise BundleRefused("bundle_map_invalid", f"the map commitment or proof is malformed: {exc}") from exc
    covers = c.get("coversSize")
    if c.get("format") != COMMITMENT_FORMAT or canonical(c) != commitment or type(covers) is not int \
            or covers != commitment_index:
        raise BundleRefused("bundle_map_invalid", "not a canonical map commitment leaf for its own position")
    if c.get("tenant") != entry["tenant"] or not index < commitment_index:
        raise BundleRefused("bundle_map_invalid", "the commitment does not cover this record")
    if proof.key != map_key(receipt["issuer"], receipt["permit"], receipt["stage"]):
        raise BundleRefused("bundle_map_invalid", "the map proof is for another key")
    try:
        held = proof.holds(root)
    except MapError as exc:
        raise BundleRefused("bundle_map_invalid", str(exc)) from exc
    if held is None or held.index != index or held.leaf != witness.leaf_hash(leaf):
        raise BundleRefused("bundle_map_contradiction", "the committed map holds another record for this permit stage")
    return "proven"


_MEMBERS = frozenset({"format", "checkpoint", "log", "leaf", "record", "map"})


def verify_bundle(bundle: Any, trust: ThirdPartyTrust, now: int,
                  readers: Mapping[str, Reader] = PUBLIC_READERS) -> Verdict:
    """Grade one bundle offline with the verifier's own trust at ``now`` (seconds); BundleRefused otherwise."""
    if not isinstance(bundle, dict) or bundle.get("format") != BUNDLE_FORMAT \
            or not _MEMBERS <= set(bundle) <= _MEMBERS | {"claims"}:
        raise BundleRefused("bundle_malformed", f"a record bundle has exactly {sorted(_MEMBERS)} and optional claims")
    note_text = bundle["checkpoint"]
    try:
        cp = witness.parse_checkpoint(witness.parse_note(note_text).text)
    except (witness.NoteError, TypeError, AttributeError) as exc:
        raise BundleRefused("bundle_checkpoint_refused", str(exc)) from exc
    log_keys = _log_keys(bundle["log"], cp.origin)
    policy = trust.policy(log_keys)
    try:
        verified = witness.verify_note(note_text, policy, now, trust.max_age, trust.max_skew)
    except witness.NoteError as exc:  # a forged line under a pinned key, or no valid log signature
        raise BundleRefused("bundle_checkpoint_refused", str(exc)) from exc
    index, leaf = _included(cp, bundle["leaf"], "record leaf")
    record = bundle["record"]
    if not isinstance(record, dict) or not {"bytes", "source"} <= set(record) <= {"bytes", "source", "counterparty"}:
        raise BundleRefused("bundle_malformed", "record is {bytes, source} and an optional counterparty")
    entry, issuer = _record(record, leaf, readers)
    map_status = _map_status(cp, bundle["map"], entry, index, leaf)
    claimed = record.get("counterparty")
    if claimed is not None and not isinstance(claimed, str):
        raise BundleRefused("bundle_malformed", "record.counterparty is a target id")
    pinned_pq = trust.log_pq.get(cp.origin)
    log_pq = witness.SIG_MLDSA44 in verified.log_types and bundle["log"]["pqVkey"] == pinned_pq
    verdict = _grade(trust, verified, policy, entry, issuer, claimed, map_status, cp, log_pq)
    _check_claims(bundle.get("claims"), verdict)
    return verdict


def _grade(trust: ThirdPartyTrust, verified: witness.VerifiedCheckpoint, policy: witness.Policy,
           entry: dict[str, Any], issuer: str, claimed: str | None, map_status: str, cp: witness.Checkpoint,
           log_pq: bool) -> Verdict:
    pinned = {f"w{i}": w for i, w in enumerate(trust.witnesses)}
    counted = dict(verified.cosigned_at)
    operators = sorted({pinned[n].operator for n in counted})
    receipt = entry["receipt"]
    key = None if receipt is None else (receipt["issuer"], receipt["permit"], receipt["stage"])
    base: dict[str, Any] = {"admitted_at_ms": entry["admittedAtMs"], "receipt": key, "map_status": map_status,
                            "origin": cp.origin, "size": cp.size}
    if len(operators) < trust.quorum:
        return Verdict("S", (), AWAITING, PQ_STATUSES[0], "none", tuple(operators), None,
                       cannot_infer=CANNOT_INFER, **base)
    pq_external = bool(verified.post_quantum(policy))
    pq = PQ_STATUSES[2] if log_pq and pq_external else PQ_STATUSES[1] if log_pq else PQ_STATUSES[0]
    production = {pinned[n].operator for n in counted if pinned[n].list_grade == "production"}
    staging = len(production) < trust.quorum
    first_by_operator: dict[str, int] = {}
    for n, ts in counted.items():
        op = pinned[n].operator
        first_by_operator[op] = min(ts, first_by_operator.get(op, ts))
    at = sorted(first_by_operator.values())[trust.quorum - 1]  # the moment the quorum was met
    bound = trust.counterparties.get(issuer)
    continuity = ("log operator (continuity)",)
    if claimed is not None and bound != claimed:
        grade, independent_of, label = "W", continuity, TENANT_DECLARED
    elif bound is not None and map_status == "proven":
        grade, independent_of, label = "I", ("tenant",), f"counterparty {bound}: independently attested"
    elif bound is not None:
        grade, independent_of = "W", continuity
        label = f"counterparty {bound}: receipt without a (permit id, stage) map proof"
    else:
        grade, independent_of = "W", continuity
        label = "witnessed commitment, content attested by the party it describes"
    if staging:
        label += " (staging-grade)"
    extra = () if grade == "I" else ("that the content was not written by the party it describes",)
    return Verdict(grade, independent_of, label, pq, "staging-grade" if staging else "production", tuple(operators),
                   at, cannot_infer=CANNOT_INFER + extra, **base)


def _check_claims(claims: Any, verdict: Verdict) -> None:
    """Refuse a bundle whose stated grade or post-quantum status is above what the verifier computed."""
    if claims is None:
        return
    if not isinstance(claims, dict) or not set(claims) <= {"grade", "pq"}:
        raise BundleRefused("bundle_malformed", "claims is {grade, pq}")
    grade, pq = claims.get("grade"), claims.get("pq")
    if grade is not None and (grade not in GRADES or GRADES.index(grade) > GRADES.index(verdict.grade)):
        raise BundleRefused("bundle_claim_overstated", f"claims grade {grade!r}; the verifier computes {verdict.grade}")
    if pq is not None and (pq not in PQ_STATUSES or PQ_STATUSES.index(pq) > PQ_STATUSES.index(verdict.pq)):
        raise BundleRefused("bundle_claim_overstated", f"claims {pq!r}; the verifier computes {verdict.pq!r}")
