# One name for one thing: trust bundle, journal loss, grants

Decision record, 24 Nov 2026. Deciding rule: a record format has one name, and one name has one format. Where two
formats answer the same question, one is kept, the other's consumers move to it, and the other is deleted. Nothing
keeps an alias.

## 1. Signing anchors live in the trust bundle

**Question.** Which keys may sign which evidence, from when to when, and is a key still good?

**Before.** Two answers. `verified_identities.TrustBundle` (version 1) pins request-credential keys per issuer, by RFC
7638 thumbprint, with roles and tenants. A separate anchor manifest (`anchors.json`) pins evidence signing anchors by
`sha256(raw key)`, with a role, a status, a window and the predicate types each may sign. Its verifier does
not enforce `not_after` at all ("an expired anchor still verifies"), and an anchor's revocation reaches a verifier
only in a new binary.

**Ruling.** One document, the trust bundle, version 2. A version-2 bundle has the six version-1 members and a seventh,
`anchors`; at least one of `issuers` and `anchors` is non-empty. There is no second "anchor manifest" and no version 1:
a version-1 document is refused, and a service that pinned one adds `"anchors": []` and writes `2`. Each anchor is
closed:

| Member | Meaning |
|---|---|
| `jwk` | the public Ed25519 key (OKP, Ed25519, `x`); no private member |
| `thumbprint` | its RFC 7638 thumbprint, recomputed by the reader and refused when it differs |
| `role` | a name for what the key signs (`kernel-substrate-signer`) |
| `status` | `active`, `retired` (signs nothing new) or `revoked` (verifies nothing) |
| `notBefore`, `notAfter` | the window in which a signature may have been made; `notAfter` may be `null` only for `active` |
| `predicateTypes` | the in-toto predicate types the key may sign; any other is refused |

A key has two derived names and the bundle states neither as an input: the thumbprint names it inside the bundle (as
every version-1 pin does), and `sha256(raw key)` names it everywhere a record already does (the DSSE `keyid`
agent-evidence-verify reports, and the `key` entries of a signed revocation list). Both are computed from `jwk`.

**Revocation is the signed list, not a new bundle.** The reader takes the `RevocationState` in force and refuses a
statement from a key whose `kind = "key"` entry was revoked at or before the statement's trusted signing time.
Status `revoked` in the bundle refuses everything, with or without a time.

**A time the signer cannot choose.** A statement's own timestamps are the signer's word. The only signing time this
reader trusts is an upper bound: the statement's bytes are a leaf of a C2SP checkpoint that the pinned witness quorum
cosigned (`witness.verify_note`), with an RFC 9162 inclusion proof, and the bound is the latest cosignature time of
the counted witnesses. Any honest counted witness saw the leaf no later than that. A statement under an anchor that
is `retired`, has a `notAfter`, or carries a `key` revocation verifies only with such a bound inside the window and
before the revocation; without one it is refused as `anchor_signing_time_unbound`. An `active` anchor with no
`notAfter` and no revocation needs no bound. A bound earlier than `notBefore` is refused: the statement provably
predates the anchor's window.

## 2. Loss is a signed record, never a silence

**Question.** Did the journal receive every record the producer made, and is its end where the writer left it?

**Before.** `journal.py` has `seq`, `prev` and a checkpoint of count and head. A producer that loses records says
nothing; a torn last line (a crash mid-write) is skipped by the writer and counted as a line by the verifier; a
checkpoint names no run, so a journal and checkpoint of another run under the same key verify.

**Ruling.** Three line kinds join the journal, each a signed statement in the same chain, with structural fields only
(record envelope v2 `kept` class: counts, positions and digests over our own bytes):

- **gap** (`tool-call-journal-gap`): `dropped` records the producer made and never wrote, after `afterSeq`, with a
  `reason`. The producer states the loss it knows of; the journal never infers one.
- **torn tail** (`tool-call-journal-torn-tail`): the writer that opens a journal whose last bytes are not a whole
  line truncates them under the lock and appends this statement first, with `bytes` and the `tornSha256` of what it
  removed and `afterSeq`. A torn tail is removed only by a signed statement that says it was there.
- **checkpoint**: gains `dropped` (the sum of every gap line), `gaps` (their `afterSeq` positions in order) and `run`,
  the run the journal belongs to. The verifier recomputes both from the lines and fails a mismatch; a verifier that
  pins a run fails a checkpoint for another.

The verifier reads a torn tail as `tornTail` in its report and never as a record; the verdict is never `PASS` with a
torn tail no checkpoint covers. A journal with gaps can pass: the loss is accounted for and reported (`dropped`), so a
reader sees how much is missing instead of reading a short journal as complete.

## 3. One grant model

**Question.** Did a pinned issuer authorize this exact call, and until when?

**Before.** Two public formats called "grant". `probity_records.grants` (capability grant, chain of narrowing grants
with `cnf`, then a per-call permit) admits a call at `notBefore <= at <= expiresAt`. agent-evidence-observer's
`grant_records` (profile `probity-protected-action-reference-v0`) signs one exact request with an issuer key and
treats `expiresAt` as exclusive. At the instant `expiresAt` the two answer the same question differently.

**Ruling.** The capability grant and its permit are the model. The observer record names one exact call, which is
what a permit is, so it is a permit that took the grant's name. It is deleted: an exact request is a capability grant
whose one tool's arguments are each fixed by an `eq` constraint and whose context fixes the run, attempt and request
ids, presented with a permit for the call. Every window is inclusive at both ends, as every records verifier already
reads it. The observer's consumers move to `probity_records` (the observer pins it), and `grant_records.py`, its
domain string and its profile name are removed with no alias.
