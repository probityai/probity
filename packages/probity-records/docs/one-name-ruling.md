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

**Ruling.** Two line kinds join the journal, each a signed statement in the same hash chain, with structural fields
only (record envelope v2 `kept` class: counts, positions, a digest over our own bytes):

- **gap** (`tool-call-journal-gap`, `Journal.gap`): `dropped` records the producer made and never wrote, lost after
  line `afterSeq`, with a `reason`. The producer states the loss it knows of; the journal never infers one.
- **torn tail** (`tool-call-journal-torn-tail`): a writer that finds a last line with no newline cuts those bytes under
  the lock and appends this statement first, with their `bytes` and `tornSha256` and `afterSeq`. A torn tail leaves
  the file only with a signed statement that it was there.

Both are lines of the chain, so the checkpoint's signed count and head already commit to them: stripping a gap line
breaks the chain, and no checkpoint member is needed for them. The checkpoint gains one member, `run`, when the writer
names its run; a verifier that pins a run (`verify_journal(..., run=...)`) fails a checkpoint that names another run or
none (`checkpoint_run_mismatch`). The verifier reports `dropped` (the sum of valid gap lines), `gaps` and `tornTails`,
and reads bytes after the last whole line as `tornTail`, never as a record, with the verdict held at `NOT_ESTABLISHED`.
A journal with gaps can pass: its loss is signed and counted, so a reader sees how much is missing instead of reading a
short journal as complete. The 100 signed checkpoints in the shared vectors and the TypeScript twin's journal verdicts
are unchanged by this; the twin's reading of gap and torn-tail shapes and of `run` is listed for the twin-parity lane.

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

**Retained runs (measured 2026-11-24 at `02df093b`).** 355 files carry the old profile
`probity-protected-action-reference-v0`: 349 of them in 20 retained interop experiments under
`packages/agent-evidence-observer/interop/`, 5 in the observer's own test and example fixtures. 20 interop readers
import `grant_records`. The retained packets pin `probity_observer/grant_records.py` by digest, and every pin (19)
names `a51c74997d81af6a046cb8336aa683b047c1967cd760a2bf08806cb80c20c990`, the bytes at `d1e92ccb7`; the live module
had already drifted to `680820e4...` (a docstring-only change at `eb1376ab4`), so the readers were re-verifying frozen
evidence against code the evidence never named. A retained packet is a record of a past run: it is re-verified
against the one source copy it pins, never the live module, and it is never re-signed. So the pinned bytes are kept
once, byte for byte, as a retained verifier the interop readers load after checking its digest against the pin; the
live API (`probity_observer.exact_grant` over `probity_records.grants`) is the only grant model for new records; the
observer's own fixtures that sign fresh grants are regenerated in the new model.
