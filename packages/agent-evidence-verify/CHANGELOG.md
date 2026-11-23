# Changelog

## 0.9.0 (unreleased)

A minor release: thirteen new claim types and three more suites in corpus mode; the decisions for every existing claim type are unchanged.

- `credential_reachability/v1` checks a signed probe record that says which ambient credential classes an agent's
  environment let it reach (SSH agents and key files, cloud metadata and configuration, registry files, browser
  cookie stores, environment tokens, cluster service-account tokens, git credentials, host keyrings). It applies the
  26 rules of the Credential Reachability predicate under the consumer's pinned signer keys, agent keys, environment,
  audience, challenge and time, and recomputes each class verdict and the result from the attempts. See
  [reference routes](docs/corpus-routes.md).
- `evidence_digest/v1`: checks that a manifest of digests binds the copies the consumer reads, N of N, under a
  declared canonical form (`rfc8785`, `cbor-deterministic`, `raw`). Refuses a repeated member, a digest that binds
  a copy the consumer does not read, a removed reference (`0 of N`) and a manifest signed by a key the consumer's
  key authority does not admit, and a `null` signature member; zero consumed items is `empty_denominator`. Doc:
  `docs/telemetry-evidence.md`.
- `event_log_completeness/v1`: checks that a session log is one contiguous, linked sequence inside the consumer's
  coverage boundary, ending at a retained signed head in the observer's ledger head format. Each of drop, swap,
  status flip, link rewrite, body edit and tail truncation fails with a named reason. Shares check order and reason
  codes with `cbor_receipt_chain/v1`.
- `lifecycle_binding/v1`: groups decision, control and execution records by (decision, instruction) and reports
  whether the authenticated execution names the action the authenticated control authorized, as one of five states
  per group; a duplicate identity is `indeterminate` in any order, a revoked binding is `not_evaluated`, a group
  with only a receiver-side control or with named action bytes unavailable is `missing`, an issuer-side control signed
  by an executing key is `failure` (`self_authorized`), and absent evidence is never `satisfied`. Pre-images use the six-tag `agent-evidence/lifecycle-binding/v1` registry. Doc:
  `docs/lifecycle-binding.md`.
- `aep_package/v1`: checks an action evidence package layer by layer (hash, canonical form, full-block RSA
  DigestInfo, receipt, ML-DSA-65, RFC 3161 time stamp), reporting every check after the first failure as
  `not_evaluated`. The RSA block is compared whole, so four blocks ending in the right digest (garbage prefix, bytes
  after the legacy prefix, SHA-512 OID, short padding) are refused; signer and time-stamp keys are admitted only under
  the consumer's authorities. The legacy response-only form leaves `metadata.json` unsigned and is `not_established`
  / `metadata_unbound`; an archive with bytes before, between or after its entries, a case-variant or path entry name,
  an RSA modulus under 2048 bits, a receipt field of another type, and a TSA signature over content that is not a
  TSTInfo are refused. Doc: `docs/aep-package.md`.
- `capability_credential/v1`: one verifier input for every agent capability credential format, under the consumer's
  trusted issuers, cosigner authorities, pinned clock and revocation list. Refuses a case-variant member, an escaped,
  non-ASCII or newline-terminated time, a non-canonical number such as `-0`, tamper after signing, expiry, revocation
  by the consumer's list, an untrusted issuer, and the signer-distinctness classes (a named key that does not sign,
  one key under two ids, the issuer's own key as cosigner, a threshold of one authority, a short count), and a spent
  use limit (`uses_exhausted`), each with its own code; a `revocation_ref` outside the consumer's `revocation_sources`
  and a use limit with no recorded count are `not_established`. Doc: `docs/capability-credential.md`.
- `dns_aid_sig/v1`: checks a DNS-AID discovery record's `sig` (compact JWS, ES256) against the served record
  under the `dns-aid-sig-binding/v1` profile (strict canonical base64url, I-JSON header and payload, `crit`
  refused, integer `port`/`iat`/`exp`, protocol bound from `proto` then `alpn`, `svcb1` over RFC 8785 with
  empty distinct from absent) and agrees only when the consumer's key authority authorises the key for the
  zone. A `jwks_url` is read as every common client reads it (a backslash, userinfo, control character or
  non-hostname host is refused), a `port` is 0 to 65535, and an inverted window is refused. Every verdict names
  the key-set fingerprint it read and the `fqdn` and `zone` the record claimed; malformed record input is a
  verdict, never an exception. Page: `docs/dns-aid.md`, example: `examples/dns-aid-sig/`.
- `dnssec_rrset/v1` and the `dnssec-chain` key-authority kind: offline DNSSEC validation (RFC 4034, RFC 4035;
  RSA, ECDSA, EdDSA; SHA-256 and SHA-384 DS) of an RRset from a pinned trust anchor, from a chain in DNS wire
  format. A missing record reads `not_established`, never validated; a key with the REVOKE bit validates no
  zone data, and the authority holds only when the zone that signed the key record contains the record's zone,
  so a delegated child zone never vouches for its parent. Example: `examples/dnssec-rrset/` (a real chain from
  the IANA root).
- `declared_versus_acted/v1`: joins an agent-evidence-observer trajectory of resolution and call events,
  verified against its witnessed head, with the bindings it relied on; a call to an undeclared endpoint, to an
  endpoint clients read differently, before the resolution it names, after `exp` or under an unauthorised key is
  `contradicted`, and the scope carries the call denominator. Lines end at `\n` only and the head signature is
  canonical base64. Example: `examples/declared-versus-acted/`.
- `catalog_trust_manifest/v1`: judges one signed object of an ARD catalog or an AI Catalog: which key signed which bytes
  under which of four closed constructions, and whether the signed subject binds the entry, its artifact and its vendored
  DSSE attestations, with every signing key admitted only through the consumer's key authority. Doc:
  `docs/catalog-trust-manifest.md`.
- `a2a_signed_card/v1`: judges one A2A Agent Card: which keys of the card's own DID signed its bytes, whether every `kid` is
  a key of that DID, and whether the consumer's key authority lets each key speak for it. A key served with the card or
  fetched from its `jku` is never authority by itself. Doc: `docs/a2a-signed-card.md`.
- `co_signed_receipt/v1`: judges one tool-call receipt: the admission member rules first, then the agent's signature and any
  co-signature, then each party's key under its own key authority, and reports the attribution as `co_signed`,
  `single_signed` or `unattributed_evidence`. Doc: `docs/co-signed-receipt.md`.
- `agent_audit_record/v1`: judges an agent audit record, a retained record with its dating check, or a set of records,
  under the consumer's trust document, and carries every field a member of `vectors-agent-audit-record` declares
  (verdict and first code, recomputed tier, `withinLimit`, dating, joint set result). Each time bound is kept apart
  (skew only on the future side, `maxAge` on the past, the OpenTimestamps allowance on both anchor bounds) and every
  integer is range-checked before arithmetic. All 235 corpus members agree, so the Action's reference stage can read
  M of M on that corpus. The assessment names the `shape` it holds (`envelope`, `retained` or `set`), never read off the
  record, so a retained record stripped of a failing retention entry cannot pass as an envelope. A time value is an
  RFC 3339 date-time only, and no input, signed or not, makes the reader raise: a lone surrogate, nesting past the
  stack, a 4300-digit integer, an `anchorWithin` no timedelta holds and an `issuedAt` in year 1 are each judged. A
  trust document the reader cannot read is refused as the consumer's error. Route and example:
  `docs/corpus-routes.md`, `examples/corpus-routes/audit-record/`.

A new claim type, `web_bot_auth/v1`: was this HTTP request signed, under Web Bot Auth (RFC 9421 with
`draft-ietf-webbotauth-httpsig-protocol-01`), by the agent the consumer pinned? It runs offline against a request
capture, a pinned key directory, the authority the consumer serves and the consumer's own instant. The verifying key
comes only from the pinned directory, a request with a body must cover a `Content-Digest` equal to the digest of the
received body (only the members the signature covers count), and a signature made for another host or signer is
`contradicted`. The directory's own `nbf`, `exp`, `use` and `key_ops` are honoured, a key published with its private part
signs nothing, the validity window is 24 hours unless the consumer pins another, every Web Bot Auth signature on a
request is judged on its own, and the record names the method, path or query a signature leaves uncovered. See
`docs/web-bot-auth.md`.

Corpus mode (`agent-evidence-verify corpus`) answers three more suites of agent-evidence-vectors with the verdict and
reason each corpus declares.

- `agent-payment-mandate/v1`: the payment evidence pack of an agent-initiated charge, card-side records and the 21
  x402 `exact` on EVM (EIP-3009) records. The signer is recovered from the EIP-712 signature under the requirement's
  token domain; no field that names a signer is read. 36 of 36 members.
- `status-receipt-binding/v1`: a credential status receipt held to the credential's bytes by digest, under an
  authority key the case supplies. 24 of 24 members.
- `actor-marker-survival/v1`: a chain of signed hop statements held to the corpus's twenty checks, with every
  writer's key and role read only from the corpus's `TRUST.json` once its SHA-256 matches the manifest. 30 of 30
  members.

## 0.8.0 (2026-11-21)

A minor release: a new claim type, `evidence_sufficiency/v1`. It decides what one conforming Observed Effect
record lets a verifier conclude (the question section 7.4 of the CoSAI WS4 containment paper asks), where
`observed_effect/v1` only decides whether the record conforms.

- `evidence_sufficiency/v1` judges three properties of one signed Observed Effect record under the consumer's own
  pinned context: `no_write_in_scope` (`supported`, `contradicted` on an observed write, or `not_established` naming
  the unmet obligation), `action_outcome` (`present`, `absent` or `pending`), and `observer_independence` (the
  three-condition test). A record the admission step refuses as malformed and an unsupported property raise
  `CaseError` with no verdict; a coherent record whose own rules refuse its claim is `not_established`.
  The 36 candidate cases of the WS4 containment paper's section 7.4 are its test vectors
  (`tests/data/evidence-sufficiency/cases`, byte for byte as published in cosai-oasis/ws4-secure-design-agentic-systems).

## 0.7.0 (2026-11-20)

A minor release: `agent-evidence-verify decision-record` refuses or holds four records 0.6.0 accepted. A consumer that
reads these dimensions can turn red.

- The decision-record reader holds the trust policy to its published closed schema (members, the `revoked_at` and
  `revocation_reason` pair, the two reasons). A member it does not know was skipped, so a misspelled revocation
  verified a key; it now refuses. An unknown relying-party source fails every strict dimension that reads a source, a
  corpus member naming an unknown member is not read, and the OCSF reader's corpus member follows the same rule.
- The `strict` profile refuses a seal dated before a stage the relying party observed, because the key's state was
  judged on a time the seal cannot have been made at.
- `jcs_canonical/v1` refuses number tokens no double holds: an integer a double does not hold exactly
  (9007199254740993) and a non-integer token whose double is another number (1e-400) have no canonical form, as
  RFC 8785 and RFC 7493 section 2.2 require, so a signature over rewritten bytes no longer reads as a signature over
  the original value. Exact large values such as 1E21 keep their form.

- Carried base64 (specification and bounds bytes, the seal's signature, a pinned certificate) is read only in its
  canonical spelling, through one shared `strictb64` module that is the corpus readers' definition byte for byte. A
  second spelling of a seal value (sixteen texts decode to one Ed25519 signature) fails `structural_validity`.
- `independent_timestamp` in the relying party's sources carries its own reading of a timestamp token (the SHA-256 it
  covers and its time). `time_assurance` reads the issuer's times against it as an upper bound only: `failed` when the
  issuer dates the attachment after it (and `baseline` refuses), `verified` within a day before it, `not_checked`
  further before it, so a backdated record anchored months later never reads as verified.
- A seal key superseded (or compromised) before it is read, signing at a stated time before its retirement, reads
  `unavailable` instead of `verified`: whoever holds a retired key can state any earlier time. An independent
  timestamp earlier than the retirement verifies it on the timestamp's time; a stated time at or after the retirement
  fails for either reason; a timestamp before the key's validity fails the key state.
- An identity source entry confirms a person only when it names the `source` it rests on, and a grant held by a person
  whose identity the source does not confirm no longer verifies `authority_independent`.
- A record whose `time` is OCSF's millisecond integer was read on the wrong axis: the integer was taken as
  seconds from 1970 while a key's RFC 3339 window is counted from 0001-01-01, so every such record fell before
  every key window. It is now read as milliseconds from 1970-01-01T00:00:00Z, the same instant as its RFC 3339
  spelling.
- An `action_id`, `action`, `disposition_id` or `disposition` that is a list or an object raised `TypeError`.
  It is now refused as `decision_consistency:failed`.

## 0.6.0 (2026-11-20)

A minor release: two new claim types and one new console script. The decisions for every existing claim type are
unchanged except `uncertain_effect/v1`, which now refuses two records it used to support (below).

- `uncertain_effect/v1`: ported to agent-evidence-vectors v0.37.0 (commit 7b8b97a7c), adding the corpus's crash,
  redelivery and rewind cases. Two checks join the order: `idempotency_key_follows_trigger` refuses a redelivery,
  replay or completion that runs the step under a key other than the operation's own, and `owner_effect_unaccounted`
  refuses a record whose owner holds more effects than the trail has attempts that could have made one. Before this,
  a record whose history was deleted after the effect (one owner effect, no attempt) was `supported` with
  `effect_held`, and five crash cases raised `CaseError` because `worker_crashed` was not a known reply. All 54
  members of the corpus now get the verdict it declares.

- `proof_of_control/v1`: checks a Proof-of-Control artifact (signed token, Merkle inclusion or consistency proof,
  token chain, canonical form) offline and passes all 171 cases of `poc-evidence-vectors` 0.1.0, which the `test`
  extra pins. Route and example: `docs/corpus-routes.md`, `examples/corpus-routes/proof-of-control/`.
- `token_grant_receipt/v1`: checks a signed receipt an identity provider wrote for a token exchange, client
  credentials or CIBA grant against the values the consumer expects, and optionally the recorder's whole hash-chained
  log. The Keycloak evidence hook in `integrations/keycloak-evidence-hook` writes these receipts. Page:
  `docs/token-grant-receipt.md`.
- `cbor_receipt_chain/v1`: checks that a stream of signed CBOR receipts is one whole, ordered chain under
  consumer-pinned keys, through a format profile the case pins. Refuses a repeated receipt, a re-issued authorization,
  swapped receipts and an unpinned signer, and reports a restart, an unpinned head, a missing effect or a missing
  revocation commitment as `not_established`. Doc: `docs/cbor-receipt-chain.md`, example: `examples/cbor-receipt-chain/`.
- `agent-evidence-verify ocsf-decision`: reads a stream of OCSF API Activity decision records (AID-EMIT-1, the
  Praxis Policy Engine `ocsf-audit` sink) and reports structure, ruling consistency, fingerprint, signature and key
  binding per record, and uniqueness, chain links, gaps and opening, stream sequence and opening, and the tail over the
  stream. A member named twice is not read; the unsigned key id never chooses a key; the tail is verified only against
  an independent head. Both published signed sample records verify. A `strict` profile requires signatures, a key
  named by the signed bytes, an anchored tail, the opening and interoperable numbers. Corpus mode answers the
  `ocsf-decision/v1` suite. Page: `docs/ocsf-decision.md`.
- `agent-evidence-verify decision-record`: reads an action-binding attachment (`dps-action-binding` 0.3.0) beside its
  decision record and reports each check as its own dimension, with `not_checked`, `unavailable` and `not_supported`
  explicit and no merged pass. Every published binding case of the format reads as its expected values. A `strict`
  profile adds approver independence, one effect per request, independent identity, authority and time, the latest
  attachment and a required signature. Corpus mode answers the `decision-record/v1` suite. Page:
  `docs/decision-record.md`.
- `agent-evidence-verify-poc`: reads one artifact on stdin and prints the corpus runner's verdict line, so
  `python3 -m poc_evidence_vectors.run_vectors --verifier agent-evidence-verify-poc` runs the corpus against this
  verifier.

## 0.5.1 (2026-11-07)

README: the downloads badge links PyPI until PePy has data for the new name; no code change. The decisions the verifier returns are the same as 0.5.0.

## 0.5.0 (2026-11-06)

The distribution was published as probity-verify through 0.4.1 and is now agent-evidence-verify. This is a major
rename for consumers: the import package is now agent_evidence_verify (was probity_verify), the console script is
agent-evidence-verify (was probity-verify), and the reference verifier identifier is
https://probityai.github.io/probity/verifiers/agent-evidence-verify, minted once and frozen from this release. Receipt
schema strings, predicate URIs and the verifier-service contract string are unchanged. The code and the decisions it
returns are the same as 0.4.1 apart from the verifier identifier carried in each decision.

## 0.4.1 (2026-11-04)

This is a minor release when cut: a consumer that requires `verdict_code` to be absent from the `execution_evidence`
check, or that reads a code from it it does not know, can turn red.

- An `adversarial_execution_evidence/v1` check now reports `verdict_code` beside `codes`: one of
  `NOT_PUBLICLY_VERIFIABLE`, `LEAF_HASH_MISMATCH`, `PROOF_BROKEN`, `CLAIM_NOT_BOUND`, `SUMMARY_MISMATCH`, `MALFORMED`
  or `NOT_RECONSTRUCTIBLE`, or `null` for a clean report. A failure takes the code of its primary code; a valid report
  takes the code of its worst row tier. `probity_verify.verdict_codes` raises `UnknownCode` for a code the registry
  does not name, so a code from a newer verifier is refused, never passed. The registry and one corpus vector per code
  are in agent-evidence-vectors, `docs/reference/verifier-contract.md`.

- `audit_principal/v1`: the principal an audit record names (the user or service the agent acted for), checked offline against rows PR1 to PR11 of agent-evidence-vectors.
- `agent-evidence-vocabulary` is now `>=0.8.0,<0.10`, so the verifier installs beside vocabulary 0.9.0 as well as
  0.8.x. No identifier the verifier reads moved, and the test suite passes against both.

## 0.4.0 (2026-11-03)

The verifier now judges four corpora of agent-evidence-vectors, so the Action's reference stage can report a count
over them instead of `0 of M`. [Reference routes](docs/corpus-routes.md) states what each check means.

- `uncertain_effect/v1`: one operation whose effect may have happened after its reply was lost.
- `restoration_record/v1` and `restoration_bundle/v1`: restoration-evidence records and bundles.
- `jcs_canonical/v1`: RFC 8785 canonical bytes, and the A2A Agent Card signing input.
- `observed_effect/v1`: a signed Observed Effect record under a key the consumer pins.

An input nested too deeply to walk now raises `CaseError` on every claim type, instead of a `RecursionError` or a
verdict about its bytes.

## 0.3.0

Bundles now name the release that wrote them, and bundles written by earlier releases replay again. This is a
minor release because the bundle format changed: a bundle written by 0.3.0 carries a `bundle.json` member that
0.2.x refuses as an unlisted member, so replay a 0.3.0 bundle with 0.3.0 or later.

- `probity-bundle create` writes `bundle.json`, `{"schema_version": "probity-bundle/v1", "verifier": {"id":
  <reference verifier id>, "version": <release>}}`, in canonical JSON. Replay refuses a record that is not
  canonical, names another verifier, carries another key or does not give a release number.
- Replay still compares the bundled decision byte for byte with its own. When they differ, the refusal now says
  which case it is. Under the release that wrote the bundle it is `bundled decision differs from replay`: the
  bundle was altered. Under another release it names both releases, because an honest decision may differ
  between releases, and says to rebuild the bundle or replay it with the release that wrote it.
- A bundle written before 0.3.0 has no `bundle.json`. It replays when its decision equals this release's
  decision byte for byte in the shape a release of that time wrote: the current shape (0.2.3 and 0.2.4) or the
  shape without `reference` (0.2.2 and earlier). Every other field, verdict and reason included, must still
  match, so an altered decision is refused. 0.2.3 and 0.2.4 refused every 0.2.2 bundle with `bundled decision
  differs from replay`, the message an altered bundle gets.
- The tests replay bundles written by the published 0.2.2 and 0.2.4 releases (`tests/data/bundles/`), so the
  next change to the decision envelope fails here before it ships.

## 0.2.4 (2026-10-29)

- A reference route for the Adversarial Execution Evidence predicate, version 0.7: claim type
  `adversarial_execution_evidence/v1` recomputes a statement's verdict, failure codes, result and per-row
  evidence tiers from its own bytes, under the substrate keys the consumer pins. It reads the predicate's
  strict I-JSON wire profile and judges each statement independently. Across all 288 members of the
  `vectors` corpus of agent-evidence-vectors (suite revision 32) it reaches every declared verdict, result
  and tier column under both key policies, and a primary code the corpus declares.

## 0.2.3 (2026-10-29)

- The decision envelope gained a field. Replay compares the bundled decision byte for byte, so 0.2.3 and 0.2.4
  refuse every bundle written by 0.2.2 or earlier with `bundled decision differs from replay`, though the verdicts
  are unchanged. This changed the decision shape in a patch release; 0.3.0 replays those bundles again.
- Every decision carries `reference.verifier.id`, the URI `https://probityai.github.io/probity/verifiers/probity-verify`,
  in its JSON and as a `Reference verifier:` line in the text packet. A conformance run that records the field
  names the verifier that produced the result. The done-receipt adapter's own `verifier.id` is unchanged.
- `docs/release-manifest.json` records the release's corpus digests, one digest over every vector's expected
  decision, the verifier identifier, and the build and publish workflow files with the actions they use.
  `scripts/build-release-manifest.py --check` fails when it is stale.

## 0.2.2 (2026-10-26)

- `agent-evidence-vocabulary` is now `~=0.8.0`, the release that adds open verdict classes. No identifier
  the verifier reads moved, and the full test suite passes against it.
- An import probe (`import_side_effects`) that exited 0 no longer supports `probe_observed/v1`: it reads
  `not_established` / `probe_import_unobserved`. Its "no change seen" report comes from the candidate's own
  process, which can forge it and redirect or close the protocol descriptor, so it is not evidence of a clean
  import. A probe that saw a change still contradicts. Contracts with an import probe stop accepting honest passes
  until the grade carries an import observed from outside the candidate's process.

## 0.2.1 (2026-10-26)

- `agent-evidence-vocabulary` is now a compatible-release range (`~=0.7.0`) instead of an exact pin, so the
  verifier installs beside the other packages of the family. 0.2.0 pinned `agent-evidence-vocabulary==0.5.0`, which
  no other current release of the family could share.

- Eight more done-check vectors (32 in all): a pytest run's own test cache between two runs, an
  agent-made directory on the import path, the shadow rule without a contract, and a held-out or visible
  command stopped at its limit.

## 0.2.0 (2026-10-20)

The verifier now reads DSSE envelopes, registers itself as `probity verify`, and judges completion
("done") receipts with separate outcome and integrity verdicts.

- `probity-verify` registers the `verify` subcommand of the `probity` command, installed by the `probityai`
  package. The `probity-verify` console script and `probity verify` share one implementation.
- The verifier reads its input as a case or a DSSE envelope. For an envelope it checks canonical base64 and
  the DSSE v1 pre-authentication encoding, tries every signature under every supplied Ed25519 key, checks the
  payload type, and then decides the case on the verified payload. A bundle that wraps a done receipt gives
  the same verdict as the bare receipt, with a `dsse_envelope` check first.
- A record can earn EXTERNAL witness scope only from a verified witness co-signature (two signatures,
  checkpoint, inclusion and consistency proofs), never from its own `witness_scope` field. Witness scope terms
  come from the released `agent-evidence-vocabulary` package, and a term it does not define is refused.
- Done receipts carry separate outcome and integrity verdicts, with `claims/v2`, `completion_claim/v1` and
  `probe_observed/v1`.
- A done claim is refused on the grader's dynamic visible-test findings and on the visible-test detectors on
  the integrity axis. The task pre-flight finding is attributed to the task and never refuses.
- A claimed run matches an observed one by program and canonical arguments, so honest spellings of a sealed
  command match. A contract may seal every absolute path of one acceptance executable, and a matching run's
  writes outside the workspace are output, not an edit.
- A completion assertion is backed by the agent's own sealed runs only, so honest agents are no longer read
  as claiming completion without a run.
- Out-of-tree tampering is read from the recorded run: execution-surface mutations, pytest configuration
  above the workspace, a failed import probe, and an in-process twin that passes a failed trusted replay.
- A sealed test that was collected but did not pass is refused: a command with sealed test ids must report
  as many passes as it has ids.
- Protected paths catch ancestor rename swaps and writes to loader files.
- Command tiers, contract strength, seal gates and native files are read. A failure only on synthesized
  commands is `not_established` (`generated_heldout_failed`) rather than `contradicted`.
- A run's own `__pycache__` no longer shadows its next run, a held-out probe stopped at its limit is
  `probe_timed_out`, and a done-record origin that is not text is refused.
- Twenty-four pinned done-check vectors run through the CLI in CI.
- Python 3.11 or newer is required.

## 0.1.1 (2026-10-20)

Packaging and documentation release. No verifier behaviour and no conformance case changed. The checked
sample files ship inside the wheel and the source distribution, and the generated recipe bindings are
refreshed.

## 0.1.0

First release on PyPI: the verifier implementation and its command line.
