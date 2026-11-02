"""``observed_effect/v1``: one signed Observed Effect record against its predicate.

An Observed Effect record states what an observer saw change during one interval, from a vantage
the observed party may or may not control. The claim: this DSSE envelope is a conforming record under
the observer key the consumer pinned. The rules, their order and their refusal codes are a port of
probityai/agent-evidence-vectors at commit 317df600f9a1503f32bcc2742b9f111036bdee32,
``packaging/agent_evidence_vectors/observedeffect.py``, with this package's Ed25519 in place of the
harness's. Rule order is load-bearing: the first refusal is the code a corpus member pins.

``verify`` returns a :class:`Report` with one of three verdicts. ``malformed`` is a defect in the
carried bytes, reached before any trust input; ``invalid`` is a coherent statement whose own rules
refuse its claims. ``adjudicate`` reports a clean record as ``supported`` and either refusal as
``contradicted`` with the code as its reason. The check keeps the verdict, because the corpus
scores a verifier that collapses the two as wrong. ``supported`` says the record conforms; what a
consumer may read from it is in the check (``derived_tier``, ``effects_independently_observed``,
``absence_established``), and the tier there is recomputed, never copied from the record.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import itertools
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..common import CaseError, _digest, _string
from .bound_records import assessment_for, bound, decision

CLAIM_TYPE = "observed_effect/v1"
PREDICATE_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect"
LIMIT = ("Checks the record's rules and signatures under the pinned observer key. It does not "
         "establish who holds that key, that the observer saw everything it claims, or that the "
         "commitment is joined to any invocation: evidence_sufficiency/v1 decides those.")

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# --------------------------------------------------------------------------
# Closed vocabularies. Fail closed on an unknown value: a verifier that ignores
# a value it does not know has read a record it does not understand as one that
# conforms.
# --------------------------------------------------------------------------

TIERS = frozenset({"voluntary", "authoritative"})
MUTATIONS = frozenset({"observed", "none"})
HASH_ALGORITHMS = frozenset({"sha256", "sha1"})
VANTAGES = frozenset({"below-observed", "peer", "self"})
BASE_RESOLUTIONS = frozenset({"supplied", "recorded-parent", "empty-tree"})
READ_STATES = frozenset({"bytes-read", "no-bytes-read", "unavailable"})
AGREEMENTS = frozenset({"agree", "disagree", "one-sided"})
#: How the evidence in this record ARRIVED, which is a different question from
#: where the producer stood. Three values are the sibling vocabulary's;
#: first-hand is this registry's own, for a producer that observed somebody
#: else's execution itself.
ORIGINS = frozenset({"self", "first-hand", "third-party-control-plane", "log-import"})
#: The two origins that hold somebody else's record. An importer has no quote to
#: present, so it may not claim a hardware-rooted runtime.
IMPORT_ORIGINS = frozenset({"third-party-control-plane", "log-import"})

#: A scope carrying one of these is a pattern, and a pattern is resolved by
#: whoever reads it. The universal scope is the literal "/".
GLOB_METACHARACTERS = frozenset("*?[]{}!")
#: I-JSON's safe-integer bound. The producer side refuses to ENCODE past it; a
#: hostile rail does not use our encoder, so the verifier refuses to CONSUME
#: past it too.
IJSON_LIMIT = 2**53
#: RFC 3339, UTC, Z designator, no fractional second. The ordering rules compare
#: strings, which is sound for exactly one grammar. The regular expression fixes
#: the shape and the parse below fixes the calendar, because 2026-13-01T00:00:00Z
#: matches the shape and names no day.
#: [0-9] rather than \d: Python's \d matches every script's decimal digits and
#: strptime reads them as numbers, so 00:00:0\u0665Z parsed here while the Go rail
#: refused it, and it sorts after every ASCII timestamp.
TIMESTAMP_GRAMMAR = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: The object name of the empty tree per hash algorithm: the terminal case of
#: base resolution, and what makes beforeRoot unconditionally required rather
#: than optional-when-unknown. Computed from the preimage rather than stated as a
#: literal, so the corpus check below compares two computations and not a
#: constant against the value that produced it. ``usedforsecurity=False`` is what
#: keeps this importable where the library refuses sha1 outright: the empty
#: tree's object name is an identifier, and nothing here signs with it.
EMPTY_TREE = {
    "sha1": hashlib.sha1(b"tree 0\x00", usedforsecurity=False).hexdigest(),
    "sha256": hashlib.sha256(b"tree 0\x00").hexdigest(),
}

#: The one blob this corpus's read rows point at, restated here rather than read
#: out of the thing being judged. A reader that took the bytes from the corpus
#: would agree with it by construction; stated, the digest check in ``_corpus``
#: says so when the corpus starts narrating different bytes, instead of the
#: range-preimage rule quietly skipping every row for want of a blob.
NARRATED_BLOB = b"port: 8080\nmode: strict\n" * 8


def _pae(payload_type: str, payload: bytes) -> bytes:
    """The DSSE pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(kind), kind, len(payload), payload)


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


class Malformed(Exception):
    """A defect in the carried bytes. Stage one; no trust input reaches it."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Invalid(Exception):
    """A coherent statement whose claims its own rules refuse. Stage two."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Policy:
    """What a consumer brings to a verification.

    Nothing here is read from the record: a record that carried its own expected
    predicate type, or its own key, would be grading its own homework. Blobs are
    the blobs this consumer holds; a verifier holding none treats a range digest
    as an opaque commitment, which is why the predicate calls three of the four
    read bindings checkable rather than four.
    """

    predicate_type: str
    observer_public_key: str
    blobs: dict[str, bytes] = field(default_factory=dict)
    expected_code_digest: str = ""
    """Consumer-pinned SHA-256 for a required code join; empty leaves it unrequested.

    The caller selects this value from its own capability policy, never from the
    effect record. A successful match is not an independent code measurement.
    """
    expected_invocation_binding: str = ""
    """Consumer-pinned call binding for a required invocation join; empty leaves it unrequested.

    The caller computes this value from the request it holds (sha256 over the RFC
    8785 bytes of the request's method and params) or takes it from a decision
    record it has already verified, never from the effect record.
    """


@dataclass
class Report:
    """One verification.

    ``codes`` carries the single first refusal, which is what the corpus pins: a
    verifier reporting every rule a record breaks would make the expectation
    depend on rule order in a second way. ``derived_tier`` is the tier
    RECOMPUTED from the record, never the tier the record claims, and is empty
    where the statement was refused before the recompute could run.
    """

    verdict: str
    codes: list[str]
    derived_tier: str = ""

    vantage: str = ""

    @property
    def effects_independently_observed(self) -> bool:
        """The reads and writes this record carries were seen by somebody other
        than the observed party: it verified, and its vantage is below-observed,
        which stage one admits only from a first-hand observer holding a
        commitment signed before the interval.

        Independent of the tier. A below-observed record naming a blind spot
        inside its own scope recomputes to voluntary, and the writes it did see
        are still witnessed; reading them as self-report would make an observer
        who discloses a gap worth less than one who hides it. Derived, never
        copied from the record.
        """
        return self.verdict == "valid" and self.vantage == "below-observed"

    @property
    def absence_established(self) -> bool:
        """The record establishes that nothing it does not carry happened inside
        pathScope: it verified and the recomputed tier is authoritative. This is
        the reading the predicate forbids for a voluntary record, made
        unbypassable because there is no field to copy one into."""
        return self.verdict == "valid" and self.derived_tier == "authoritative"


@dataclass
class _State:
    """One statement under verification, plus what the recompute filled in."""

    statement: dict[str, Any]
    predicate: dict[str, Any]
    policy: Policy
    derived_tier: str = ""


# --------------------------------------------------------------------------
# Shared readings. Each is a rule's predicate, pulled out only where more than
# one rule states it.
# --------------------------------------------------------------------------


def _no_constant(token: str) -> Any:
    """NaN, Infinity and -Infinity are not JSON; Python's parser accepts them unless told not to."""
    raise Malformed("not-parseable")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a repeated member name at any depth.

    Nothing in the json module refuses one: the last spelling of a repeated key
    wins silently, so two rails reading one set of bytes can disagree about what
    the record says while both report a clean parse.
    """
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise Malformed("duplicate-member")
        seen.add(key)
    return dict(pairs)


def _required(obj: Any, *names: str) -> None:
    """Refuse an absent member, naming it. No member has a default and no
    verifier may supply one, so a shape that cannot carry members at all is the
    same refusal rather than a shape nobody described."""
    for name in names:
        if not isinstance(obj, dict) or name not in obj:
            raise Malformed(f"required-member-absent:{name}")


def _lower_hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value != ""
        and all(character in "0123456789abcdef" for character in value)
    )


def _path_normalized(value: Any, allow_trailing_slash: bool) -> bool:
    """Absolute, with no empty, dot or dot-dot segment.

    Without this, /srv/app/../../../etc/shadow starts with /srv/app/ and a write
    to /etc/shadow travels as in-scope under a scope of /srv/app/.
    """
    if not isinstance(value, str) or not value.startswith("/"):
        return False
    body = value[1:]
    if body.endswith("/"):
        if not allow_trailing_slash:
            return False
        body = body[:-1]
    if body == "":
        return True
    return all(segment not in ("", ".", "..") for segment in body.split("/"))


def _under(path: Any, scope: Any) -> bool:
    """Containment at a segment boundary, never by string prefix.

    /srv/application-secrets/id_ed25519 starts with /srv/app and is not under it.
    """
    if not isinstance(path, str) or not isinstance(scope, str):
        return False
    prefix = scope if scope.endswith("/") else scope + "/"
    return path == scope.rstrip("/") or path.startswith(prefix)


def _in_scope(pred: dict[str, Any], path: Any) -> bool:
    return any(_under(path, scope) for scope in pred["pathScope"])


def _timestamp_ok(value: Any) -> bool:
    if not isinstance(value, str) or not TIMESTAMP_GRAMMAR.match(value):
        return False
    try:
        datetime.datetime.strptime(value, TIMESTAMP_FORMAT)
    except ValueError:
        return False
    return True


def _commitment(pred: dict[str, Any]) -> dict[str, Any] | None:
    """The prior commitment, or None where the record carries none.

    A member that is present and is not an object is read as absent, so the rule
    that requires a commitment refuses it by name instead of a later rule failing
    on a shape nobody described.
    """
    carried = pred["observation"].get("priorCommitment")
    return carried if isinstance(carried, dict) else None


def _canonical_string_map(members: dict[str, str]) -> bytes:
    """RFC 8785 for the one shape this predicate signs over: a flat object of
    string members.

    The prior commitment's preimage is that shape and nothing else here is
    canonicalized, so a general canonicalizer would be surface nothing exercises.
    Member names sort by UTF-16 code unit, which is Section 3.2.3, and the
    strings carry no HTML escaping, because an escaped less-than sign is a
    different byte string and would not verify against a rail that wrote the
    character.
    """
    body = ",".join(
        json.dumps(name, ensure_ascii=False, separators=(",", ":"))
        + ":"
        + json.dumps(members[name], ensure_ascii=False, separators=(",", ":"))
        for name in sorted(members, key=lambda name: name.encode("utf-16-be"))
    )
    return ("{" + body + "}").encode("utf-8")


def _commitment_preimage(state: _State, commitment: dict[str, Any]) -> bytes:
    """The four members the commitment digest and signature are taken over.

    Four, not two: authorityDigest is in it so an observer cannot select a
    permissive authority after the interval closed, and intervalId is in it so
    one signed commitment cannot serve two intervals that share a before-root.
    Both were open while the preimage carried only the before-root and the nonce.
    """
    pred = state.predicate
    return _canonical_string_map(
        {
            "authorityDigest": pred["authorityDigest"],
            "beforeRoot": pred["interval"]["beforeRoot"],
            "intervalId": pred["intervalId"],
            "witnessNonce": commitment["witnessNonce"],
        }
    )


#: The facts a statement determines about ITSELF. For these the observed side of
#: a dual value is not a matter of report and a verifier recomputes it: the
#: member the predicate offers as the one that catches a lying producer was a
#: free string, so a record carrying two writes could declare writes.count
#: observed as 7 and agree with itself.
SELF_DERIVABLE: dict[str, Callable[[dict[str, Any]], str]] = {
    "writes.count": lambda pred: str(len(pred["writes"])),
    "reads.count": lambda pred: str(len(pred["reads"])),
    "pathScope.count": lambda pred: str(len(pred["pathScope"])),
    "interval.beforeRoot": lambda pred: pred["interval"]["beforeRoot"],
    "interval.afterRoot": lambda pred: pred["interval"]["afterRoot"],
    "authorityDigest": lambda pred: pred["authorityDigest"],
}


# --------------------------------------------------------------------------
# The rules. One function per rule the predicate states.
# --------------------------------------------------------------------------


def _over_bound(number: Decimal) -> bool:
    """An integer by value at or past the I-JSON bound, whatever its spelling.

    1e21 and 9007199254740993.0 are integers past the bound. The value is exact
    because the statement is parsed with Decimal, so this rail decides the same
    way as the Go rails, which use exact rationals (attack A33).
    """
    return number == number.to_integral_value() and abs(number) >= IJSON_LIMIT


def _number_over_bound(node: Any) -> bool:
    """True for an integer or an exact decimal that is an integer at or past the bound."""
    if isinstance(node, bool):
        return False
    if isinstance(node, int):
        return abs(node) >= IJSON_LIMIT
    return isinstance(node, Decimal) and _over_bound(node)


def _rule_ijson_integers(state: _State) -> None:
    """No integer at or above 2**53 anywhere in the statement, at any depth.

    Whether a number is an integer is decided by its value, not its spelling:
    1e21 and 9007199254740993.0 are integers at or past the bound, and a double
    reads the second as 2^53, so every number is held to the bound by its value
    (attack A33; a spelling reading let the attack below back in). The producer
    side refuses to encode past the bound and nothing refused it on the way in, so
    a byteRange of 9007199254740993 was accepted and two rails read two different
    numbers out of one set of bytes.
    """

    def walk(node: Any) -> None:
        if _number_over_bound(node):
            raise Malformed("integer-not-ijson-safe")
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(state.statement)


def _rule_predicate_type(state: _State) -> None:
    """The statement says which predicate its fields belong to, and the policy
    says which one this consumer routes. A policy carrying no type refuses every
    statement, because a verifier that accepts any predicate type has stopped
    checking which predicate it is reading.
    """
    expected = state.policy.predicate_type
    if not expected or state.statement.get("predicateType") != expected:
        raise Malformed("predicate-type-unexpected")


def _rule_required_members(state: _State) -> None:
    """No member has a default, and no verifier may supply one."""
    pred = state.predicate
    _required(
        pred,
        "intervalId",
        "tier",
        "mutation",
        "hashAlgorithm",
        "interval",
        "pathScope",
        "authorityDigest",
        "observation",
        "reads",
        "writes",
        "dualValues",
        "doesNotAssert",
        "issuedAt",
    )
    _required(
        pred["interval"], "beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"
    )
    _required(pred["observation"], "vantage", "coverage", "observedSigners", "origin")


def _rule_closed_vocabularies(state: _State) -> None:
    """Fail closed on an unknown value in any closed vocabulary. A tier that is
    the number 3 is refused for carrying an unknown tier, which is where the
    refusal belongs, rather than for a shape nobody described."""
    pred = state.predicate
    for value, known, code in (
        (pred["tier"], TIERS, "tier-unknown"),
        (pred["mutation"], MUTATIONS, "mutation-unknown"),
        (pred["hashAlgorithm"], HASH_ALGORITHMS, "hash-algorithm-unknown"),
        (pred["observation"]["vantage"], VANTAGES, "vantage-unknown"),
        (pred["observation"]["origin"], ORIGINS, "origin-unknown"),
    ):
        if not isinstance(value, str) or value not in known:
            raise Malformed(code)


def _rule_timestamp_grammar(state: _State) -> None:
    """Every timestamp is RFC 3339 UTC with Z and no fractional second.

    The ordering rules below compare strings, and two records defeated that while
    the grammar was open: an offset of -05:00 sorted an hour-late commitment
    before the interval it was meant to precede, and a fractional second sorted
    an identical instant strictly before itself.
    """
    pred = state.predicate
    for member in ("openedAt", "sealedAt"):
        if not _timestamp_ok(pred["interval"][member]):
            raise Malformed(f"timestamp-not-utc-basic:interval.{member}")
    if not _timestamp_ok(pred["issuedAt"]):
        raise Malformed("timestamp-not-utc-basic:issuedAt")
    commitment = _commitment(pred)
    if commitment is not None and "committedAt" in commitment:
        if not _timestamp_ok(commitment["committedAt"]):
            raise Malformed("timestamp-not-utc-basic:priorCommitment.committedAt")


def _rule_interval_order(state: _State) -> None:
    """The ordering the fixed grammar above makes checkable by comparing
    strings, and the one the issuance has to respect: a record cannot be issued
    before the interval it reports was sealed."""
    interval = state.predicate["interval"]
    if interval["openedAt"] >= interval["sealedAt"]:
        raise Malformed("interval-not-ordered")
    if state.predicate["issuedAt"] < interval["sealedAt"]:
        raise Malformed("issued-before-sealed")


def _rule_base_vocabulary(state: _State) -> None:
    """Resolution is ordered -- supplied, then the authority's recorded parent,
    then the empty tree -- and a value outside the three is a fourth resolution
    nobody defined."""
    if state.predicate["interval"]["baseResolution"] not in BASE_RESOLUTIONS:
        raise Malformed("base-resolution-unknown")


def _rule_empty_tree_constant(state: _State) -> None:
    """empty-tree requires the constant for the DECLARED algorithm, not either
    one. The terminal case has a value, so there is no case in which a producer
    may leave the base out."""
    interval = state.predicate["interval"]
    if interval["baseResolution"] != "empty-tree":
        return
    if interval["beforeRoot"] != EMPTY_TREE[state.predicate["hashAlgorithm"]]:
        raise Malformed("empty-tree-constant-wrong-algorithm")


def _rule_path_scope_literal(state: _State) -> None:
    """A scope is a literal path. A pattern is resolved by whoever reads it, so
    two readers of one record can disagree about what it covered."""
    for entry in state.predicate["pathScope"]:
        if not isinstance(entry, str) or not entry.startswith("/"):
            raise Malformed("path-scope-not-absolute")
        if GLOB_METACHARACTERS & set(entry):
            raise Malformed("path-scope-glob-metacharacter")


def _rule_paths_normalized(state: _State) -> None:
    """Every path in the statement is absolute and normalized. A scope may end in
    a separator and a row's path may not, because a row names a file."""
    pred = state.predicate
    for entry in pred["pathScope"]:
        if not _path_normalized(entry, allow_trailing_slash=True):
            raise Malformed("path-scope-not-normalized")
    for row in list(pred["reads"]) + list(pred["writes"]):
        if not isinstance(row, dict) or not _path_normalized(row.get("path"), False):
            raise Malformed("path-not-normalized")


def _rule_mutation_coherence(state: _State) -> None:
    """A record whose own carried evidence refutes its own claim is malformed.

    A verifier that reads the claim and does not recompute over the rows accepts
    a record that says both things at once.
    """
    pred = state.predicate
    interval = pred["interval"]
    if pred["mutation"] == "none":
        if pred["writes"]:
            raise Malformed("mutation-contradicted-by-writes")
        if interval["beforeRoot"] != interval["afterRoot"]:
            raise Malformed("mutation-none-with-moved-root")
    elif not pred["writes"]:
        raise Malformed("mutation-observed-without-writes")


def _rule_write_chain(state: _State) -> None:
    """The ordered composition must carry beforeRoot to afterRoot. A chain that
    stops short is a record whose rows do not add up to its own claim."""
    interval = state.predicate["interval"]
    writes = state.predicate["writes"]
    if not writes:
        return
    cursor = interval["beforeRoot"]
    for row in writes:
        _required(row, "path", "preStateDigest", "postStateDigest", "inScope")
        if row["preStateDigest"] != cursor:
            raise Malformed("write-chain-broken")
        cursor = row["postStateDigest"]
    if cursor != interval["afterRoot"]:
        raise Malformed("write-chain-does-not-reach-after-root")


def _rule_code_digest_shape(state: _State) -> None:
    """Validate the optional signed code identity without inventing a default.

    The digest describes code selected by the producer for this run. It is a
    join key, not an independent code measurement. A sole SHA-256 entry avoids
    algorithm choice by different consumers. See ``_rule_code_digest_policy``
    for matching against a capability selected by consumer policy.
    """
    if "codeDigest" not in state.predicate:
        return
    value = state.predicate["codeDigest"]
    if not isinstance(value, dict) or set(value) != {"sha256"}:
        raise Malformed("code-digest-shape")
    digest = value["sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise Malformed("code-digest-value")


def _rule_code_digest_policy(state: _State) -> None:
    """Require a match only when the caller pins an expected SHA-256 digest.

    Missing/mismatching fields cannot satisfy a required join. Empty policy
    preserves existing readers that do not ask a code-identity question.
    """
    expected = state.policy.expected_code_digest
    if expected == "":
        return
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise Invalid("code-digest-policy-invalid")
    if "codeDigest" not in state.predicate:
        raise Invalid("code-digest-required")
    value = state.predicate["codeDigest"]
    if not isinstance(value, dict) or value.get("sha256") != expected:
        raise Invalid("code-digest-mismatch")


def _rule_invocation_binding_shape(state: _State) -> None:
    """Validate the optional signed call binding without inventing a default.

    The binding names the call this interval answers: sha256 over the RFC 8785
    bytes of the request's method and params. It is a join key, not evidence that
    the call was dispatched. See ``_rule_invocation_binding_policy``.
    """
    if "invocationBinding" not in state.predicate:
        return
    value = state.predicate["invocationBinding"]
    if not isinstance(value, dict) or set(value) != {"sha256"}:
        raise Malformed("invocation-binding-shape")
    digest = value["sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise Malformed("invocation-binding-value")


def _rule_invocation_binding_policy(state: _State) -> None:
    """Require a match only when the caller pins an expected call binding."""
    expected = state.policy.expected_invocation_binding
    if expected == "":
        return
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise Invalid("invocation-binding-policy-invalid")
    if "invocationBinding" not in state.predicate:
        raise Invalid("invocation-binding-required")
    value = state.predicate["invocationBinding"]
    if not isinstance(value, dict) or value.get("sha256") != expected:
        raise Invalid("invocation-binding-mismatch")


def _rule_subject_binding(state: _State) -> None:
    """The subject is the interval's after-state, and nothing else.

    This is the rule whose absence made every other rule optional: a consumer
    gates on the subject digest, and while nothing bound it to the interval a
    record could carry an honest, fully authoritative interval beside a subject
    naming an artifact the interval never produced.
    """
    pred = state.predicate
    subject = state.statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1:
        raise Malformed("subject-not-a-single-member")
    member = subject[0]
    _required(member, "name", "digest")
    digest = member["digest"]
    algorithm = pred["hashAlgorithm"]
    if not isinstance(digest, dict) or set(digest) != {algorithm}:
        raise Malformed("subject-digest-algorithm-mismatch")
    if digest[algorithm] != pred["interval"]["afterRoot"]:
        raise Malformed("subject-not-the-after-root")


def _rule_read_bindings(state: _State) -> None:
    """What a read row carries, and what it may not carry.

    A row that read no bytes carrying a range is a row claiming a reading it says
    it did not take, and a range of zero bytes proves that a path existed while
    reading as proof that its contents were seen.
    """
    for row in state.predicate["reads"]:
        _required(row, "path", "preStateDigest", "blobDigest", "readState")
        if row["readState"] not in READ_STATES:
            raise Malformed("read-state-unknown")
        if row["readState"] != "bytes-read":
            if "byteRange" in row or "rangeDigest" in row:
                raise Malformed("read-state-carries-range")
            continue
        _required(row, "byteRange", "rangeDigest")
        _check_byte_range(row["byteRange"])


def _check_byte_range(span: Any) -> None:
    _required(span, "start", "end")
    start, end = span["start"], span["end"]
    if isinstance(start, bool) or isinstance(end, bool):
        raise Malformed("byte-range-not-integer")
    if not isinstance(start, int) or not isinstance(end, int):
        raise Malformed("byte-range-not-integer")
    if start < 0:
        raise Malformed("byte-range-negative")
    if end <= start:
        raise Malformed("byte-range-empty")


def _rule_range_preimage(state: _State) -> None:
    """rangeDigest binds blob length and both offsets, never the range bytes
    alone.

    A verifier holding the blob recomputes this. One that does not holds the
    range digest as an opaque commitment and cannot check it, which is why the
    predicate calls three of the four read bindings checkable rather than four.
    """
    for row in state.predicate["reads"]:
        if row.get("readState") != "bytes-read":
            continue
        blob = state.policy.blobs.get(row["blobDigest"])
        if blob is None:
            continue
        start, end = row["byteRange"]["start"], row["byteRange"]["end"]
        if end > len(blob):
            raise Malformed("range-digest-preimage-wrong")
        preimage = b"%d\x00%d\x00%d\x00" % (len(blob), start, end) + blob[start:end]
        if row["rangeDigest"] != hashlib.sha256(preimage).hexdigest():
            raise Malformed("range-digest-preimage-wrong")


def _rule_read_chain(state: _State) -> None:
    """A read's pre-state must be a state this interval actually passed
    through, which is the before-root or the post-state of one of its writes."""
    pred = state.predicate
    reachable = {pred["interval"]["beforeRoot"]}
    for row in pred["writes"]:
        reachable.add(row["postStateDigest"])
    for row in pred["reads"]:
        if row["preStateDigest"] not in reachable:
            raise Malformed("read-pre-state-not-in-interval")


def _rule_empty_tree_holds_no_bytes(state: _State) -> None:
    """Nothing can be read out of the empty tree.

    The terminal case of base resolution is the strongest thing a producer can
    claim about the past -- there was nothing before -- and a record that claims
    it and then reads 64 bytes from a file at that root has said both.
    """
    pred = state.predicate
    before = pred["interval"]["beforeRoot"]
    if before != EMPTY_TREE[pred["hashAlgorithm"]]:
        return
    for row in pred["reads"]:
        if row.get("readState") == "bytes-read" and row.get("preStateDigest") == before:
            raise Malformed("bytes-read-from-the-empty-tree")


def _unobserved_spans(coverage: dict[str, Any]) -> list[dict[str, str]]:
    """The spans in ``unobservedIntervals``, each an object of exactly ``from`` and
    ``to``, both in the one timestamp grammar; anything else is malformed."""
    spans = coverage["unobservedIntervals"]
    if not isinstance(spans, list):
        raise Malformed("unobserved-interval-malformed")
    for span in spans:
        if not isinstance(span, dict) or set(span) != {"from", "to"}:
            raise Malformed("unobserved-interval-malformed")
        for bound in ("from", "to"):
            if not _timestamp_ok(span[bound]):
                raise Malformed(
                    f"timestamp-not-utc-basic:coverage.unobservedIntervals.{bound}"
                )
    return spans


def _rule_coverage_unobserved_intervals(state: _State) -> None:
    """The spans an observer was not watching, located in time.

    A monitor that attached after the call began was blind to every path for a
    span it knows exactly, so neither a path gap nor ``notEstablished`` is true of
    it. Each span runs from strictly before to, inside the interval, and the list
    is ordered with each span ending strictly before the next begins.
    """
    pred = state.predicate
    coverage = pred["observation"]["coverage"]
    if "unobservedIntervals" not in coverage:
        return
    spans = _unobserved_spans(coverage)
    interval = pred["interval"]
    for span in spans:
        if span["from"] >= span["to"]:
            raise Malformed("unobserved-interval-not-ordered")
        if span["from"] < interval["openedAt"] or span["to"] > interval["sealedAt"]:
            raise Malformed("unobserved-interval-outside-interval")
    for earlier, later in itertools.pairwise(spans):
        if earlier["to"] >= later["from"]:
            raise Malformed("unobserved-intervals-not-disjoint")


def _rule_coverage_coherence(state: _State) -> None:
    """A record that declares complete coverage and then names a gap inside the
    scope it says it covered, or a span it did not watch, has said both."""
    pred = state.predicate
    coverage = pred["observation"]["coverage"]
    _required(coverage, "scopeComplete", "gaps")
    if not coverage["scopeComplete"]:
        return
    if coverage.get("unobservedIntervals"):
        raise Malformed("coverage-self-contradictory")
    for gap in coverage["gaps"]:
        if _in_scope(pred, gap):
            raise Malformed("coverage-self-contradictory")


def _rule_coverage_gaps_named(state: _State) -> None:
    """An incomplete observation says WHERE it was blind.

    The tier recompute's coverage clause reads "every gap names a path outside
    pathScope", which an empty gaps list satisfies vacuously, so a record could
    admit it did not cover its own scope, name no gap, and still grade
    authoritative. The blind spot is where the writes went.
    """
    coverage = state.predicate["observation"]["coverage"]
    if (
        not coverage["scopeComplete"]
        and not coverage["gaps"]
        and not coverage.get("unobservedIntervals")
        and "notEstablished" not in coverage
    ):
        raise Malformed("coverage-incomplete-without-gaps")


def _rule_coverage_not_established_shape(state: _State) -> None:
    """A coverage the observer could not determine says why, and says only that.

    ``notEstablished`` is the third coverage shape, beside complete and
    incomplete-with-located-gaps. An empty reason is the unnamed gap again under
    another member, and a reason beside a located gap or a claim of completeness
    is a record that has said two things about one coverage.
    """
    coverage = state.predicate["observation"]["coverage"]
    if "notEstablished" not in coverage:
        return
    reason = coverage["notEstablished"]
    if not isinstance(reason, str) or not reason.strip():
        raise Malformed("coverage-not-established-without-reason")
    if coverage["scopeComplete"] or coverage["gaps"] or coverage.get("unobservedIntervals"):
        raise Malformed("coverage-shape-ambiguous")


def _rule_origin_carries_the_vantage(state: _State) -> None:
    """Only a producer that observed the execution itself may claim to have stood
    below it.

    Without the origin member there was no place in the record where an importer
    had to say it imported, so a record assembled from another vendor's exported
    log could be emitted as a first-hand below-observed observation and no field
    contradicted it. The lie was not a false value anywhere; it was a claim the
    format had no slot to refuse.
    """
    observation = state.predicate["observation"]
    if observation["vantage"] == "below-observed" and observation["origin"] != "first-hand":
        raise Malformed("origin-cannot-carry-below-observed-vantage")


def _rule_import_origin_platform(state: _State) -> None:
    """A record holding somebody else's log may not claim a hardware-rooted
    runtime.

    An importer has no quote to present: whatever the exporting platform
    measured, the importing party cannot produce the evidence for it. So an
    origin of third-party-control-plane or log-import declares a software-only
    platform and a verifier refuses anything else, absence included. The sibling
    vocabulary registers this beside the origin enum as a MUST and nothing
    enforced it, so half of the origin rule was a sentence in a registry with no
    verifier behind it.
    """
    observation = state.predicate["observation"]
    if observation["origin"] not in IMPORT_ORIGINS:
        return
    runtime = observation.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("platform") != "software-only":
        raise Malformed("import-origin-requires-software-only-platform")


def _rule_prior_commitment_present(state: _State) -> None:
    """A below-observed vantage requires a prior commitment.

    The Fields section says so and nothing enforced it, so a record could carry
    the independence claim with nothing behind it. Refusing it here is what makes
    the tier recompute's commitment clause unreachable, which is why that clause
    is gone rather than kept as a sentence.
    """
    observation = state.predicate["observation"]
    if observation["vantage"] == "below-observed" and _commitment(state.predicate) is None:
        raise Malformed("prior-commitment-absent-for-vantage")


def _rule_commitment_digest(state: _State) -> None:
    """The commitment digest recomputes from the four members it covers."""
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    _required(commitment, "committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig")
    recomputed = hashlib.sha256(_commitment_preimage(state, commitment)).hexdigest()
    if commitment["commitmentDigest"] != recomputed:
        raise Malformed("commitment-digest-mismatch")


def _rule_keyid_form(state: _State) -> None:
    """One spelling per key identifier, so the disjointness check below cannot be
    dodged by case.

    That check is the predicate's offline discriminator and it is a string
    comparison. An observed party that listed its own key uppercase in
    observedSigners and committed with it lowercase passed the discriminator with
    the same key on both sides.
    """
    observation = state.predicate["observation"]
    for keyid in observation["observedSigners"]:
        if not _lower_hex(keyid):
            raise Malformed("keyid-not-lowercase-hex")
    commitment = _commitment(state.predicate)
    if commitment is not None and not _lower_hex(commitment.get("keyid")):
        raise Malformed("keyid-not-lowercase-hex")


def _rule_commitment_signature_form(state: _State) -> None:
    """The commitment signature has one spelling: 128 lowercase hex characters.

    ``bytes.fromhex`` skips whitespace and accepts uppercase, and Go's
    ``hex.DecodeString`` accepts uppercase and refuses whitespace, so while the
    decoder decided, one signed record read valid here and malformed on the Go
    rail. Fixing the spelling in stage one makes the bytes decide.
    """
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    signature = commitment.get("sig")
    if not (isinstance(signature, str) and _lower_hex(signature) and len(signature) == 128):
        raise Malformed("commitment-signature-malformed")


def _rule_agreement_derivable(state: _State) -> None:
    """The agreement is a function of the two carried values, never a claim."""
    for row in state.predicate["dualValues"]:
        _required(row, "fact", "observedValue", "reportedValue", "agreement")
        if row["agreement"] not in AGREEMENTS:
            raise Malformed("agreement-unknown")
        observed, reported = row["observedValue"], row["reportedValue"]
        if observed == "" and reported == "":
            # Neither side carries a value, so there is no comparison to declare.
            # This read as one-sided and let a record carry any number of dual
            # values that looked like cross-checks and asserted nothing.
            raise Malformed("dual-value-carries-no-value")
        if observed == "" or reported == "":
            derived = "one-sided"
        elif observed == reported:
            derived = "agree"
        else:
            derived = "disagree"
        if row["agreement"] != derived:
            raise Malformed("agreement-not-derivable")


def _rule_dual_value_recomputes(state: _State) -> None:
    """For a fact the statement determines about itself, the observed side is
    that fact and not a report of it."""
    for row in state.predicate["dualValues"]:
        derive = SELF_DERIVABLE.get(row["fact"])
        if derive is None:
            continue
        if row["observedValue"] != derive(state.predicate):
            raise Malformed("dual-value-not-recomputable")


def _rule_commitment_signature(state: _State) -> None:
    """The prior commitment is signed, and the signature is CHECKED.

    Stage two names this gate and nothing implemented it, so sixty-four zero
    bytes in sig produced an authoritative record. Checking it against the key
    the consumer anchored also narrows the two-key attack: the second key a
    self-observer commits with is no longer any key it likes, it is a key the
    consumer has to have anchored.
    """
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    try:
        signature = bytes.fromhex(commitment["sig"])
        public_key = bytes.fromhex(state.policy.observer_public_key)
    except (ValueError, TypeError) as exc:
        raise Malformed("commitment-signature-unreadable") from exc
    if len(public_key) != 32:
        raise Malformed("commitment-signature-unreadable")
    if not _ed25519_verify(public_key, _commitment_preimage(state, commitment), signature):
        raise Invalid("commitment-signature-invalid")


def _rule_commitment_order(state: _State) -> None:
    """The commitment precedes the interval. One made after the fact commits to
    nothing."""
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    if commitment["committedAt"] >= state.predicate["interval"]["openedAt"]:
        raise Invalid("commitment-not-prior")


def _rule_commitment_keyid_disjoint(state: _State) -> None:
    """The offline discriminator. Necessary, and the predicate says not
    sufficient."""
    observation = state.predicate["observation"]
    commitment = _commitment(state.predicate)
    if commitment is None:
        return
    if commitment["keyid"] in observation["observedSigners"]:
        raise Invalid("commitment-keyid-not-disjoint")


def _rule_write_scope(state: _State) -> None:
    """The in-scope label is derived from the path and the scope, never read as
    the producer's opinion of it, and an authoritative record's writes stay
    inside the scope it claims to have covered."""
    pred = state.predicate
    for row in pred["writes"]:
        covered = _in_scope(pred, row["path"])
        if covered != bool(row["inScope"]):
            raise Invalid("write-in-scope-mislabelled")
        if not covered and pred["tier"] == "authoritative":
            raise Invalid("write-outside-path-scope")


def _rule_tier_recompute(state: _State) -> None:
    """tier is recomputed, never read as a claim, and a mismatch is invalid
    rather than a silent downgrade: a caller that selected its own tier and got
    it quietly corrected learns nothing.

    There is no prior-commitment clause and no mutation-shape clause. Both were
    proved UNREACHABLE: a below-observed record with no commitment is already
    refused in stage one, a record whose vantage is anything else fails the
    vantage clause first, and a record whose mutation claim disagrees with its
    write set is already malformed. A clause no input can reach is a sentence,
    not a gate, and worse than absent -- it made the coherence rule look measured
    when nothing measured it.
    """
    pred = state.predicate
    observation = pred["observation"]
    coverage = observation["coverage"]
    clauses = {
        "authoritative-vantage-not-independent": observation["vantage"] == "below-observed",
        "authoritative-empty-path-scope": bool(pred["pathScope"]),
        "authoritative-coverage-incomplete": bool(coverage["scopeComplete"])
        or not any(_in_scope(pred, gap) for gap in coverage["gaps"]),
        "authoritative-coverage-not-established": "notEstablished" not in coverage,
        "authoritative-interval-not-observed": not coverage.get("unobservedIntervals"),
    }
    derived = "authoritative" if all(clauses.values()) else "voluntary"
    state.derived_tier = derived
    if pred["tier"] == derived:
        return
    if pred["tier"] == "authoritative":
        for code, held in clauses.items():
            if not held:
                raise Invalid(code)
    raise Invalid("tier-recompute-mismatch")


def _rule_authoritative_carries_rows(state: _State) -> None:
    """An authoritative record observed something.

    The non-empty path scope clause closed one spelling of the vacuous record. A
    scope of ["/"] with no reads and no writes is the same record, graded the
    strongest tier, asserting that nothing happened anywhere; a mutation of none
    is a positive claim about an interval and it needs a row to be a claim about
    anything.
    """
    pred = state.predicate
    if pred["tier"] != "authoritative":
        return
    if not pred["reads"] and not pred["writes"]:
        raise Invalid("authoritative-without-observed-rows")


Rule = Callable[[_State], None]

#: Ordered, because stage one precedes stage two and because the first refusal is
#: the code the manifest names. The names are the Go rail's, which exports the
#: same list from ``RuleNames()``, so the two orders can be diffed rather than
#: compared by eye.
RULES: tuple[tuple[str, Rule], ...] = (
    ("ijson-integers", _rule_ijson_integers),
    ("predicate-type", _rule_predicate_type),
    ("required-members", _rule_required_members),
    ("closed-vocabularies", _rule_closed_vocabularies),
    ("timestamp-grammar", _rule_timestamp_grammar),
    ("interval-order", _rule_interval_order),
    ("base-vocabulary", _rule_base_vocabulary),
    ("empty-tree-constant", _rule_empty_tree_constant),
    ("path-scope-literal", _rule_path_scope_literal),
    ("paths-normalized", _rule_paths_normalized),
    ("mutation-coherence", _rule_mutation_coherence),
    ("write-chain", _rule_write_chain),
    ("subject-binding", _rule_subject_binding),
    ("code-digest-shape", _rule_code_digest_shape),
    ("invocation-binding-shape", _rule_invocation_binding_shape),
    ("read-bindings", _rule_read_bindings),
    ("range-preimage", _rule_range_preimage),
    ("read-chain", _rule_read_chain),
    ("empty-tree-holds-no-bytes", _rule_empty_tree_holds_no_bytes),
    ("coverage-unobserved-intervals", _rule_coverage_unobserved_intervals),
    ("coverage-coherence", _rule_coverage_coherence),
    ("coverage-not-established-shape", _rule_coverage_not_established_shape),
    ("coverage-gaps-named", _rule_coverage_gaps_named),
    ("origin-carries-the-vantage", _rule_origin_carries_the_vantage),
    ("import-origin-platform", _rule_import_origin_platform),
    ("prior-commitment-present", _rule_prior_commitment_present),
    ("commitment-digest", _rule_commitment_digest),
    ("keyid-form", _rule_keyid_form),
    ("commitment-signature-form", _rule_commitment_signature_form),
    ("agreement-derivable", _rule_agreement_derivable),
    ("dual-value-recomputes", _rule_dual_value_recomputes),
    ("commitment-signature", _rule_commitment_signature),
    ("commitment-order", _rule_commitment_order),
    ("commitment-keyid-disjoint", _rule_commitment_keyid_disjoint),
    ("write-scope", _rule_write_scope),
    ("tier-recompute", _rule_tier_recompute),
    ("authoritative-carries-rows", _rule_authoritative_carries_rows),
    ("code-digest-policy", _rule_code_digest_policy),
    ("invocation-binding-policy", _rule_invocation_binding_policy),
)


def verify(raw: bytes, policy: Policy) -> Report:
    """Judge one DSSE envelope carrying an Observed Effect statement."""
    try:
        envelope = json.loads(
            raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constant
        )
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(
            payload,
            object_pairs_hook=_no_duplicates,
            parse_constant=_no_constant,
            parse_float=Decimal,
        )
    except Malformed as exc:
        return Report("malformed", [exc.code])
    except Exception:
        return Report("malformed", ["not-parseable"])
    if not isinstance(statement, dict):
        return Report("malformed", ["not-parseable"])

    state = _State(statement=statement, predicate={}, policy=policy)
    refused = _apply_rules(state)
    if refused is not None:
        return refused
    return _verify_envelope(envelope, payload, state)


def _apply_rules(state: _State) -> Report | None:
    """Run stage one and stage two. Return a refusal, or None where every rule
    held."""
    try:
        if state.statement.get("_type") != STATEMENT_TYPE:
            raise Malformed("statement-type-unexpected")
        predicate = state.statement.get("predicate")
        if not isinstance(predicate, dict):
            raise Malformed("unhandled-shape:predicate")
        state.predicate = predicate
        for _, rule in RULES:
            rule(state)
    except Malformed as exc:
        return Report("malformed", [exc.code], state.derived_tier)
    except Invalid as exc:
        return Report("invalid", [exc.code], state.derived_tier)
    except (KeyError, TypeError) as exc:
        # A shape no rule named. Reported under its own name rather than crashing
        # the replay, because a rail that dies on one member judges none of the
        # rest and a traceback is not a verdict.
        return Report("malformed", [f"unhandled-shape:{exc.__class__.__name__}"])
    return None


def _verify_envelope(envelope: dict[str, Any], payload: bytes, state: _State) -> Report:
    """The last gate, after every carried-bytes rule held."""
    try:
        signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
        public_key = bytes.fromhex(state.policy.observer_public_key)
    except Exception:
        return Report("malformed", ["envelope-signature-unreadable"], state.derived_tier)
    if len(public_key) != 32 or not isinstance(envelope.get("payloadType"), str):
        return Report("malformed", ["envelope-signature-unreadable"], state.derived_tier)
    message = _pae(envelope["payloadType"], payload)
    if not _ed25519_verify(public_key, message, signature):
        return Report("invalid", ["envelope-signature-invalid"], state.derived_tier)
    vantage = str(state.predicate["observation"]["vantage"])
    return Report("valid", [], state.derived_tier, vantage)


def report_check(report: Report) -> dict[str, Any]:
    """The verdict and the readings a consumer may take from one verification."""
    return {"id": "observed_effect_rules", "status": "pass" if report.verdict == "valid" else "fail",
            "verdict": report.verdict, "codes": report.codes, "derived_tier": report.derived_tier,
            "effects_independently_observed": report.effects_independently_observed,
            "absence_established": report.absence_established}


def _hex_key(value: Any) -> str:
    key = _digest(value, "assessment.observer_public_key")
    return key


def _pinned_blobs(artifacts: dict, artifact_root: Path, names: Any) -> dict[str, bytes] | None:
    """The blobs this consumer holds, by digest; None when a named blob is unavailable."""
    if not isinstance(names, list):
        raise CaseError("assessment.blobs: expected a list of artifact names")
    blobs: dict[str, bytes] = {}
    for name in names:
        data, binding = bound(artifacts, artifact_root, name, "assessment.blobs")
        if data is None:
            return None
        blobs[binding["sha256"]] = data
    return blobs


def _pin(assessment: dict, name: str) -> str:
    return _string(assessment[name], "assessment." + name) if name in assessment else ""


def adjudicate(case: Any, policy: Any, artifact_root: Path) -> dict:
    """Judge one bound Observed Effect envelope under the consumer's pinned observer key."""
    optional = {"blobs", "expected_code_digest", "expected_invocation_binding"}
    case_id, artifacts, assessment = assessment_for(
        case, policy, CLAIM_TYPE, {"envelope", "observer_public_key"}, optional)
    key = _hex_key(assessment["observer_public_key"])
    raw, binding = bound(artifacts, artifact_root, assessment["envelope"], "assessment.envelope")
    scope = {"envelope": binding, "predicate_type": PREDICATE_TYPE, "observer_public_key": key,
             "limit": LIMIT}
    if raw is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "envelope_unavailable")
    blobs = _pinned_blobs(artifacts, artifact_root, assessment.get("blobs", []))
    if blobs is None:
        return decision(case_id, CLAIM_TYPE, scope, "not_established", "blob_unavailable")
    report = verify(raw, Policy(PREDICATE_TYPE, key, blobs, _pin(assessment, "expected_code_digest"),
                                _pin(assessment, "expected_invocation_binding")))
    check = report_check(report)
    if report.verdict != "valid":
        return decision(case_id, CLAIM_TYPE, scope, "contradicted", report.codes[0], [check])
    result = decision(case_id, CLAIM_TYPE, scope, "supported", "record_conforms", [check])
    result["vantage"] = ("independent" if report.effects_independently_observed
                         else "unestablished")
    return result
