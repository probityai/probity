# Changelog

## 0.13.0 (2026-11-26)

- **Witness soundness fixes, each pinned by `tests/test_witness_soundness_review.py` and
  `tests/test_witness_repair_attacks.py`.** A policy refuses a name listed in two groups (`policy_group_members`); an
  ML-DSA-44 line dated 0 is a subtree cosignature and is never made or counted as a checkpoint cosignature, so
  `sign_checkpoint(..., pq=...)` now needs a `timestamp`; a size-0 tree and an empty subtree carry only the empty-tree
  hash; the witness persists one fsynced `<hex SHA-256 of origin>.checkpoint` per log under a directory lock, reads a
  0.12.0 `.state` file as its floor, and refuses to start on state it cannot read (`witness_state_unreadable`) or to
  cosign what it cannot persist (`witness_state_unwritable`); the monitor copy holds only lines the witness verified or
  made; `sign-subtree` answers 400 for more than one signature and signs with the key that cosigned; the feed keeps
  one verified line per asked witness and treats any transport fault as that witness's error; unknown keys of any name
  length are ignored; the client refuses a non-UTF-8 reply (`witness_response_malformed`); the server checks
  `Content-Length`; the refusal lint reads the argument a raiser names and refuses a code composed at run time.

- **`probity_records.witness` is now the whole C2SP witness surface, and every refusal carries a registered code.**
  New cases, each pinned by `tests/test_witness_c2sp_surface.py` and the published examples in
  `vectors/shared/c2sp-conformance.json` (the c2sp.org/signed-note example, golang.org/x/mod sumdb notes, a Sigstore
  Rekor checkpoint, a Pixel transparency log checkpoint, a Static CT checkpoint, and the torchwood subtree table):
  - signature type 0x02, ECDSA on P-256, P-384 or P-521 over SHA-256 with the SPKI-hash key id (`VerifierKey.ecdsa`,
    `ecdsa_signature`), as Rekor and transparency-dev/witness sign;
  - signature type 0x05, the RFC 6962 `TreeHeadSignature` of c2sp.org/static-ct-api, ECDSA P-256 or RSA
    (`VerifierKey.rfc6962`, `rfc6962_signature`, `rfc6962_timestamp`); such a checkpoint carries no extension lines;
  - one constructor per type, `VerifierKey.ed25519`, `.cosignature_v1`, `.mldsa44`, `.ecdsa`, `.rfc6962`, and
    `VerifierKey.public_key()`; `parse_vkey` refuses a non-canonical DER key;
  - checkpoint extension lines (`Checkpoint.extensions`), kept by `parse_checkpoint`; `verify_note` refuses a
    checkpoint whose extension lines no verified 0x01 or 0x02 log line signs (`checkpoint_extensions_unsigned`);
  - `log_signature(text, name, signer)`, `sign_checkpoint(cp, signer, *, name=None, pq=None, timestamp=0)` taking an
    Ed25519 private key or any `SigningKey`, and `is_empty_root`;
  - ML-DSA-44 subtree cosignatures (`subtree_message(cosigner, timestamp, origin, start, end, hash)`, `cosign_subtree`,
    `verify_subtree_cosignature`), subtree hashes and subtree consistency proofs (`valid_subtree`, `subtree_hash`,
    `subtree_consistency_proof`, `verify_subtree_consistency`), and RFC 9162 inclusion proofs (`inclusion_proof`,
    `verify_inclusion`);
  - c2sp.org/tlog-proof (`TlogProof`, `parse_tlog_proof`, `verify_tlog_proof`);
  - `open_note`, the generic signed-note verifier: unknown keys ignored, a failing known key rejects;
  - `parse_policy` keeps the optional log and witness URLs (`Policy.log_urls`, `Policy.witness_urls`) and reads octets;
  - `Witness` holds ML-DSA-44 and Ed25519 keys (`key`, `more_keys`) and cosigns with each, answers `sign-subtree`, and
    keeps the latest cosigned checkpoint for the monitor endpoint `GET <hex SHA-256 of origin>/checkpoint`;
    `serve_witness` serves all three; clients `sign_subtree` and `fetch_checkpoint`;
  - `NoteError.code` and `WitnessRefused.code` return a code from `refusal_codes.json` (57 new codes); the text after
    the first `:` is detail. The refusal lint now covers the witness module.
  Minor, not patch: `subtree_message` takes the subtree start, `sign_checkpoint` takes keyword arguments after the
  signer, the 0.12 message texts are replaced by codes, and `Witness.add_checkpoint` returns one line per key.

## 0.12.0 (2026-11-26)

- **The C2SP note verifier agrees with the reference on three cases; two of them refuse input it accepted before.**
  A cosignature dated more than `max_skew` seconds after the verifier's clock (`verify_note` with `now`) is now skipped
  instead of rejecting the whole note, so a witness whose clock runs ahead neither vetoes a quorum the other
  witnesses meet nor completes one; before, `verify_note` raised `NoteError`. `parse_policy` now refuses any control
  character other than tab and newline (`NoteError`); before, such a policy parsed. `cosignature_message` now refuses a
  timestamp outside `0..2**63-1` (`NoteError`); before, it encoded any integer. `verify_line` is now public (it was
  `_verify_line`): it checks one signature line against one known key. Minor, not patch, because a policy or a
  timestamp that verified before is now refused. No wire format or shared vector changes.

## 0.11.1 (2026-11-26)

- **A writer killed mid-append no longer leaves a journal that cannot be read or appended to.** An append is durable
  on return, so the bytes after the last newline are an append that never returned and that nothing acted on.
  `Journal.statements()`, `verify_journal`, the `keys.jsonl` reader and `otel.export_journal` now read only whole
  lines (up to the last newline), as `Journal`'s own head refresh and `witness.journal_leaves` already did; before,
  `statements()` and `export_journal` raised `JSONDecodeError` on the torn tail, so a restarted authority could not
  catch up, and `verify_journal` and the keys reader counted it as a failed record. `Journal.append` and the
  session-key certificate writer cut a torn tail under the journal lock, and fsync the cut, before writing; before,
  the next line was glued onto the torn bytes and the file stayed unreadable. `verify_journal` reports the torn tail's
  length as `tornTailBytes` and no longer counts it in `records`, so the count agrees with a checkpoint the restarted
  writer signs; lines are split on `\n` only, as the writer and the witness tree split them. The witness feed cuts a
  torn entry from `checkpoints.log` before the next note, and writes its `witness-*.size` files whole (a kill mid-write
  left an empty file that stopped every later `Feed.publish`). The TypeScript twin's command line verifies only whole
  lines and reports `tornTailBytes`. No wire format or shared vector changes.

## 0.11.0 (2026-11-26)

- **Breaking: a canonical identity names every sponsor.** `CanonicalIdentity.sponsor: Ref | None` is replaced by
  `sponsors: tuple[Ref, ...]` (TypeScript: `sponsors: Ref[]`), sorted by each rendered ref with no entry twice, and
  empty when no sponsor answers for the agent; there is no `sponsor` attribute any more. An agent acting for no user
  still needs at least one sponsor, so `sponsors=()` there is refused `identity_attribute_missing`. In the string, the
  `sponsor` attribute lists the refs joined by `+`; one sponsor is written exactly as before, so a single-sponsor
  string and every access-list entry naming it are unchanged, and a reader that predates the list refuses a string
  with two. In the structured form, `sponsor` is now a non-empty list of refs even when it holds one, so a policy that
  read `identity.sponsor.subject` must iterate `identity.sponsor`; a rule that denies one sponsor then fires whatever
  others are named. The structured form's `version` is now 2 (`DOCUMENT_VERSION`; the string grammar stays version
  1), `document()` always writes it, and `from_document` refuses version 1 with `identity_version_unknown`. A policy
  consumer refuses a structured identity whose `version` is not 2, because a version 1 rule over `sponsor` is
  undefined on the list and would stop denying silently. `+` is never part of a ref (it is not unreserved, so it is
  written `%2B` inside a component), so the list always splits into the refs that were joined. New refusal codes: `identity_sponsor_order` (unsorted), `identity_sponsor_repeated` (a sponsor
  twice) and `identity_sponsor_malformed` (not a tuple, or a document member that is not a non-empty list).
  `vectors/shared/canonical_identity.json` adds CI11 to CI13 (two sponsors, and a sponsor whose subject holds `+`),
  CR29 to CR35 and CD6 to CD11, and every document vector carries version 2 and, where it names a sponsor, the list.
- `build_approval_binding` writes the members the agent-evidence-vectors 0.38 approval-binding reader judges, each from
  the party that holds it: `issued=` (keyword, required) is the server's issuance register, written as
  `issuedApprovalIds`; `enforcement=` (keyword, required, one of `ENFORCEMENT_MODES`: `enforce`, `observe`, `monitor`)
  is the mode the gate ran in. The approval body carries its own `outcome` (`approved`, `approved-with-corrections` or
  a refusal) and `requestId`, which the approver signs; an approval with no `requestId` is refused with
  `approval_request_id_missing`. Nothing is defaulted: an approval the server never issued is denied
  `approval_not_issued`, a refused one `approval_not_granted`, and one taken in observe or monitor mode
  `approval_not_enforced`. Every caller passes the two new keywords.
- `judge_approval_binding` denies a record the reader cannot read (a missing or mistyped member) with
  `approval_binding_malformed` (`BINDING_MALFORMED`), so one malformed binding is a failure of its line instead of an
  exception that ends `verify_journal`.
- The dependency range of `agent-evidence-vectors` is `>=0.38.0,<0.40`.
- The TypeScript twin `@probityai/records-verify` judges approval bindings with the 0.38 reader's twenty-two checks in
  its order. `vectors/shared/approvals.json` adds AV29 to AV37 (not issued, refused, approved with corrections,
  observe and monitor modes, one request answered twice, a lost request identifier, a retired key and a key used
  before its retirement), and every approval vector was regenerated under the 0.38 reader.

## 0.10.0 (2026-11-25)

This release changes the revocation list format, so a list written by 0.9.0 or earlier is refused by 0.10.0 and a
list written by 0.10.0 is refused by 0.9.0. Version 0.9.0 on PyPI is the cumulative format.

- Revocation lists are deltas. A list carries only the subjects it newly revokes, and a reader folds each list into
  the state it already holds, so applying one list costs what that list holds, not everything the chain has revoked.
  The list type is `agent-evidence-vectors/predicate/v2/revocation-list`; a list of the v1 (cumulative) type is
  refused as `revocation_list_shape`. `sign_revocations(..., entries=...)` takes the new entries only.
- A list that names a subject an earlier list in the chain revoked is refused with `revocation_entry_repeated`: an
  entry is published once, and its `revokedAt` and `reason` never change. `revocation_list_drops_entry` is removed,
  because a delta cannot drop an entry. An empty list is a freshness list: a new `seq` that revokes nothing new.
- A rotation successor that an earlier list revoked never becomes a root; a list it signs is refused as
  `revocation_list_signer_not_a_root`.
- A state's entries are a read-only view over a store shared along one chain. The state at the chain's tip extends
  the store in place; any other state copies the entries it sees once. An older state never sees later entries, and
  two lists applied to one state give two independent states.
- `vectors/shared/revocation.json`: every list is rewritten as a delta, so RL01 to RL19 and RL21 to RL47 have new
  list bytes, signatures and head digests (RL20 is unchanged). RL34 and RL35 now expect `revocation_entry_repeated`.
  New cases: RL48 (an empty list after a list with entries), RL49 (a v1 list is refused), RL50 (a root rotated to a
  revoked successor ends the chain), RL51 (a list that re-dates an earlier entry) and RL52 (the state after such a
  rotation holds no root). A reader that has not learned the v2 type refuses every case.
- `vectors/shared/effects.json`: EV4 and EV5 now expect `owner_effect_unaccounted`, not `duplicate_effect`. The owner
  holds two effects and the trail one attempt that could make one, and agent-evidence-verify 0.6.0 checks that before
  it checks for a duplicate; the committed cases had been written by an older reader. The TypeScript twin reads
  uncertain effects with the same checks.
- The journals in `vectors/shared/approvals.json`, `constraints.json`, `effects.json`, `grants.json` and
  `quorum.json` are recorded at one fixed instant, so `scripts/gen_shared_vectors.py` writes the same bytes on every
  run. Every journal line and checkpoint of those files changed; no verdict, record count or failure changed other
  than EV4 and EV5.

## 0.9.0 (2026-11-24)

- The revocation list names an identity provider's token-signing key with kind `idp-key`. Its id is the key's RFC 7638
  SHA-256 JWK thumbprint, exactly 43 characters of `[A-Za-z0-9_-]` with the two unused bits of the last character
  zero, so one key has one spelling; any other id is refused as `revocation_list_shape:entry_id_form:idp-key`. Kind
  `key` keeps its 64-hex ids and is still the only kind that may carry a `successor`. `RevocationState.idp_key_revoked`
  and the TypeScript `idpKeyRevoked` hold from the entry's `revokedAt` on; the TypeScript reader also gains
  `revokedAt(state, kind, id, at)`. The shared vectors in `vectors/shared/revocation.json` add RL40 to RL47, and RL02
  now names an `idp-key` entry, so its head digest changed: a reader that has not learned the kind refuses RL02.
- The dependency range of `agent-evidence-vectors` stays `>=0.36.3,<0.38`. The approval-binding reader in 0.38.0 also
  requires an issuance register, the approval's outcome and the enforcement mode, which `build_approval_binding` does
  not write, so it denies a record built here; the cap rises when the builder writes them. The range of
  `agent-evidence-verify` is `>=0.9.0,<0.12`.
- Session-key certificates are `probity-key-delegation/v2` ([docs/key-delegation.md](docs/key-delegation.md)). The
  root now signs the window key's scope as explicit members of the certificate body: `hierarchy` (`identity`,
  `authority` or `record`), `custody` (`ours`, `customer` or `custodian`; a record root is never `customer`), `tenant`
  and `windowS` (the declared window, which `[notBefore, notAfter)` may not exceed). `delegate(root, scope, now=...,
  lifetime=None)` takes a `DelegationScope`; `Delegation` carries `scope`. A deployment that carried the scope inside
  `rootProvenance` reads it from these members instead.
- `Delegation.covers` is half-open, `notBefore <= t < notAfter`: an instant at `notAfter` is outside. Version 0.8.0
  counted `notAfter` inside. A journal line or a permit stamped at `notAfter` now fails with
  `session_key_used_outside_its_certified_window` or does not verify.
- A v1 certificate is refused with `delegation_format_retired`; `verify_delegation` reports sixteen codes in one order
  (`DELEGATION_CODES`). The TypeScript twin `@probityai/records-verify/delegation` (`verifyDelegation`, `covers`)
  returns the same verdicts on the 31 cases of `vectors/shared/delegation.json`.
- The shared vectors in `vectors/shared/verified_identities.json` now carry what a receiver spends for a possession
  proof, not only its method. An accepted case's `proof` was the string `dpop` or `mtls`; it is now
  `possession_record` of the proof and, for DPoP, its single-use `key` (`proof_key(jkt, jti)`) and `expires` (the
  proof's `replay_exp`): `{"method": "dpop", "iat", "jkt", "jti", "key", "expires"}` or
  `{"method": "mtls", "x5t#S256"}`. A verifier that reported only the method no longer conforms. The TypeScript
  twin `@probityai/records-verify/verified` returns the same values from `verifyRequest` (`DpopProof`,
  `CertificateProof`, `proofKey`, `REPLAY_GRACE`), so a Node receiver spends the same key for the same window as a
  Python one. Two new cases: VI16 (a proof at the oldest accepted `iat`) and VI17 (a `jti` that is not ASCII).
- The refusal registry holds the agent browser's codes. Check `browser.signer`: `browser_target_unsignable` and
  `browser_stamp_missing`. Check `browser.session`: `browser_host_mismatch`, `browser_session_expired`,
  `browser_session_revoked`, `browser_session_value_in_request`, `browser_session_cookie_foreign`,
  `browser_session_no_grant`, `browser_release_unrecorded` and `browser_answer_unscrubbable`. Check `browser.proxy`:
  `browser_body_too_large`, `browser_upgrade_refused`, `browser_tunnel_refused` and `browser_upstream_failed`.
- `docs/verified-identities.md` describes the agent browser's signature: the `Probity-Stamp-Digest` field (an RFC 8941
  String holding `digests.stamp_digest`) and the Web Bot Auth profile that covers it.

## 0.8.0 (2026-11-23)

- A grant body now has one grammar, checked the same way by the Python verifier and the TypeScript verifier. Before
  this version the two refused different things with different text: Python carried library messages in its details
  (a Python `repr`, the cel-cpp message) that the TypeScript twin could not reproduce, a malformed quorum policy or
  an invalid regex crashed `verify_chain` in Python, and `{"spend": null}` passed validation and then crashed
  narrowing. `validate_body` now refuses every malformed body as a registered code with a fixed detail, in one
  order: `cnf`, times, tools, depth, context, budget, standing, issuer key.
- 23 new refusal codes: `grant_arg_constraint_invalid`, `grant_context_constraint_invalid`, `grant_when_invalid`,
  `grant_quorum_invalid` and `grant_issuer_key_invalid`; the constraint codes `constraint_unknown`,
  `constraint_member_missing`, `constraint_member_invalid`, `constraint_range_unbounded`, `constraint_regex_invalid`
  and `constraint_cidr_invalid`; the CEL codes `cel_expression_empty`, `cel_syntax_invalid` and
  `cel_type_check_failed`; and the quorum policy codes `quorum_policy_shape`, `quorum_roles_shape`,
  `quorum_role_invalid`, `quorum_roles_unsatisfiable`, `quorum_threshold_out_of_range`,
  `quorum_approver_key_shape`, `quorum_approvers_share_a_key`, `quorum_policy_without_approvers` and
  `quorum_proposer_bound_shape`. A caller that matched on the old free-text details changes to match on these codes.
- CEL expressions are checked for syntax at validation in both verifiers; the type check stays in `issue_grant`
  (`cel_type_check_failed`), because no TypeScript CEL engine exports one.
- Shared vectors `grant_bodies.json` (62 cases) and `grant_calls.json` (5 cases) hold both verifiers to these codes,
  and `grants.json` gains journal cases GV14 and GV15.

## 0.7.0 (2026-11-23)

- The refusal registry holds the receiver policy's codes (check `receiver.policy`): `receiver_policy_denied` (a
  deny rule or the route default refuses an identity the request presents) and `receiver_agent_rule_missing` (an
  agent caller, or a caller with no verified agent, matched only a rule that names no agent condition).

## 0.6.0

- Breaking: the agent stamp is an RFC 9421 HTTP message signature, label `probity`, in place of the
  `Probity-Agent-Stamp` JWS. A gateway sends four fields: `Probity-Principals` (the canonical identity, the agent
  client and the principals digest), `Content-Digest` (RFC 9530, sha-256), `Signature-Input` and `Signature`. The
  signature covers `@method`, `@target-uri`, `@authority`, `content-digest` and `probity-principals`, in that order,
  with `created`, `expires` (at most 300 s later), `nonce`, `keyid`, `alg="ed25519"` and `tag="probity-principals/v1"`.
  `verify_request` reads the stamp from `RequestFacts.headers` and returns its `nonce` and `expires` for a single-use
  store; `stamp` is no longer a token role. A stamp for another method, target, authority or body is refused as
  `stamp_forged` or `stamp_request_mismatch`. The fields are read by `agent_evidence_verify.structured_fields`, so the
  floor is agent-evidence-verify 0.9.0.
- The refusal registry holds the gateway's outbound credential codes (`exchange_*`, `outbound_*`,
  `release_unrecorded`).
- Record envelope v2 (`probity_records.erasure`) closes a length channel and gains two helpers. A schema may fix the
  plaintext size of a class (`Schema.fixed`, `Schema.size`); every ciphertext of that class is padded to exactly
  that size and a larger plaintext is refused (`payload_over_fixed_size`). With padding to a multiple of 256 alone,
  an approver whose name and principal crossed a boundary was re-linked across its votes from the ciphertext length
  after its key was destroyed. The lint refuses a malformed, duplicated or partial fixed size (`fixed_size_malformed`,
  `fixed_size_duplicate`, `fixed_size_partial`). A schema's JSON form now requires `fixed` (`{}` when nothing is
  fixed); a schema document written before this version without it is refused as `schema_malformed`. `open_sealed` refuses a signed
  ciphertext length that is not the blob's (`ciphertext_length_mismatch`) and `check_block` refuses a `bytes` that is
  not an integer of at least 28. New: `check_padding` (a keyless check that a writer padded), `reference` (a keyed
  per-leaf handle for a value inside a body its subject signs) and `personal_traces` (the canary lint over signed
  bytes). Shared vectors `erasure.json` gain S8 to S10, O12, P1 to P4, L4, L5, R1 to R3, T1 and T2.

## 0.5.0

Breaking changes from 0.4.0; callers change as each item says.

- **Breaking: the agent stamp has a new required `identity` member.** The `stamp` claim is now exactly `user`, `agent`,
  `principals`, `act`, `grants` and `identity`; `identity` is the canonical identity string of the request and must name the
  same user, agent, act digest and grant digest as the other members. A signer that builds a stamp without it produces a
  stamp this version refuses (`stamp_malformed`); a stamp whose `identity` names another user, agent, act claim or grant
  chain is refused as `stamp_identity_mismatch`. `Stamp` takes a sixth field, `identity`, and `Stamp.canonical_identity()`
  returns the parsed identity. Every stamp signer adds the member.
- **Breaking: the strict grade follows the gateway writer's rule.** A call no human approved is now strict without an
  approver (it was basic, so a strict writer refused the record that answers a pending approval). An approver principal
  that no approval counts is refused under every profile (`principal_approver_without_approval`); an approved call that
  does not name its approver is basic. `principals_below_strict` names what is missing (`act-absent`, `sponsor-absent`,
  `approver-absent`); `identity.strict_shortfall` returns it.
- **Breaking: grant times need a UTC offset.** `notBefore`, `expiresAt` and `reviewBy` parse in one RFC 3339 grammar in both
  verifiers. A grant time with no offset is refused (`grant_timestamp_offset_missing:<member>`) instead of raising
  TypeError out of `verify_chain`; any other form, an out-of-range field included, is refused
  (`grant_timestamp_invalid:<member>`), and a use time that names no instant is refused (`grant_use_time_invalid`). The
  TypeScript verifier no longer rolls a month 13 forward. Grants written without an offset must be rewritten.
- New: `probity_records.verified_identities` (`verified_identities`, `verify_request`, `RequestFacts`) turns the
  credentials a request presented, a pinned trust bundle and the time into canonical identities. The trust bundle is a
  new pinned document (`trust_bundle_malformed` when it is not exactly the bundle format); the public stamp format and
  the bundle are described in `docs/verified-identities.md`, with 53 shared vectors in
  `vectors/shared/verified_identities.json`.
- Eight refusal codes are registered for key-bound agent tokens and presented grant chains:
  `agent_cnf_not_the_registered_key`, `agent_credential_is_bearer`, `principal_issuer_not_scoped_for_role`,
  `principal_issuer_not_scoped_for_tenant` and `principal_lifetime_exceeds_ceiling` (identity.principals),
  `grant_holder_is_not_the_agent` (possession.proof), `grant_chain_header_malformed` (grants.chain) and
  `delegation_root_not_the_entry_agent` (delegation.hop).
- New refusal codes (the registry in `refusal_codes.json` lists each with its check and meaning): `grant_timestamp_invalid`,
  `grant_timestamp_offset_missing`, `grant_tool_shape`, `grant_use_time_invalid`, `grant_when_shape`,
  `identity_environment_mismatch`, `identity_evidence_malformed`, `identity_sources_mixed`, `identity_string_malformed`,
  `principal_user_token_not_issued_to_agent`, `principals_agent_revoked`, `stamp_identity_mismatch`, `stamp_key_mismatch`,
  `token_critical_unsupported`, `token_digest_mismatch`, `trust_bundle_malformed` and `unauthenticated_tenant`.
- Shared vectors for approvals, constraints, effects, grants, identities and quorum are regenerated with the new rules.

## 0.4.0

Breaking changes from 0.3.0; callers change as each item says.

- Standing grants and the autonomous principals profile (#404). A grant body may carry `sponsor` ({"issuer", "subject"})
  and `reviewBy`, together or not at all, with `notBefore < reviewBy <= expiresAt`; `issue_grant` takes `sponsor=` and
  `review_by=`. From `reviewBy` on, the grant and every grant delegated under it admit nothing (`grant_review_overdue`).
  A child keeps its sponsor and reviews no later than its parent (`child_changes_sponsor`,
  `child_review_later_than_parent`); a child of a plain grant never becomes one (`child_adds_sponsor`). New:
  `grants.is_standing`, `grants.chain_problem`, `grants.chain_digests`, `identity.sponsor_id`, and the `autonomous`
  principals grade (strict-equivalent), whose block carries `agent`, `sponsor`, `session` and `standingGrant` and never
  a `user` (`principals_autonomous_has_user`). `check_principals` takes `sponsors=` and `standing_grants=`; `Trust`
  gains `agent_sponsors` and `standing_grants`. Shared vectors `autonomous.json` and `standing_grants.json`.
- One refusal-code registry (#407). `probity_records.refusal_codes` and the packaged `refusal_codes.json` register every
  code a check reports, each with a stable identifier `REGISTRY/<code>`; `refusal_lint` refuses an unregistered
  refusal string in source. The detail of a refusal now follows a colon after the code. Renamed codes (breaking for
  any caller that matches the old text): `grant_approval_<x>` is `grant_approval_failed:<x>`; a grant that needs
  approval reports `grant_needs_approval:<reason>` and a denial `grant_deny:<reason>`; `<kind>_allow_without_authority_evidence`
  is `authority_evidence_missing:<kind>`; `<kind>_allow_but_no_trust_pinned` is `authority_trust_not_pinned:<kind>`;
  `exception_<x>` is `exception_quorum_failed:<x>` and `step_<x>` is `step_quorum_failed:<x>`;
  `step_missing_<f>` is `step_field_missing:<f>`; `no_<phase>_record` is `hop_record_missing:<phase>`,
  `<phase>_names_another_grant` is `hop_names_another_grant:<phase>` and `<phase>_arguments_differ` is
  `hop_arguments_differ:<phase>`; `seq_<n>_not_<i>` is `seq_mismatch:<n>:<i>`; a quorum that did not approve reports
  `quorum_refused` or `quorum_pending`; `grant_<cnf problem>` is the cnf problem code alone; a session key line
  reports `keys_line_<n>:session_key_delegation_invalid:<detail>`.
- Identity records that name the wrong party are refused. An issuer's pins written as one string pin nothing (a
  string that contained a thumbprint used to match it). `verify_token` refuses a token whose `typ` names another
  credential type than the principal's `source` (`token_type_mismatch`), and takes the record's time `at=` to refuse
  a token whose `nbf` is after it (`token_not_yet_valid`; the OIDC approval check passes its decision time). Under the
  strict profile an allow with no principals is refused (`principals_missing`). An intent, effect or re-issued allow
  that names other parties than the allow its permit rests on is refused (`principals_differ_from_permit`); a
  refreshed credential for the same parties is not. A revoked sponsor is refused for every block that names one, not
  only autonomous ones. An approver principal must name an approver the allow counts, not merely one whose binding
  it carries (a replayed approval no longer qualifies).
- Record envelope v2 (`probity_records.erasure`): a record whose fields are kept, pseudonymized or encrypted per
  data subject by a closed schema, so its signed bytes, its chain and its log proofs stay verifiable after a
  subject's key is destroyed. Seal, open, one-field disclosure, the schema lint and the erasability label a
  verifier prints. Spec in [docs/erasure.md](docs/erasure.md), 28 shared vectors in `vectors/shared/erasure.json`.
- ML-DSA-44 checkpoint cosignatures (c2sp.org/tlog-cosignature, signature type 0x06). `witness` parses 0x06
  vkeys, verifies 0x06 lines over the `subtree/v1` CosignedSubtree, and `cosign_mldsa` signs one (it refuses a
  checkpoint with extension lines, which the line would not cover). A tlog-policy may name a 0x06 witness key, and a
  0x06 log key named after the origin, the log's own post-quantum signature. `VerifiedCheckpoint.log_types` lists
  the log's valid signature types and `post_quantum(policy)` the counted 0x06 witnesses. Held to
  filippo.io/torchwood in both directions: `vectors/shared/mldsa44-xcheck.json`.
- The receipt map (`probity_records.receipt_map`): a sparse Merkle map keyed on (issuer key, permit id, stage),
  whose proofs show a record is the one receipt a log committed for that key, or that the key has none. Spec in
  [docs/receipt-map.md](docs/receipt-map.md), 16 proof cases, 4 keys and 5 refused keys in
  `vectors/shared/receipt-map.json`.
- `cryptography` 50 or later (ML-DSA-44); `agent-evidence-verify` already required it.

## 0.3.0

Breaking changes from 0.2.0; callers change as each item says.

- Proof of possession (#390). Every grant body carries `cnf` (RFC 7800) with one confirmation method, `jkt` (DPoP,
  RFC 9449) or `x5t#S256` (mTLS, RFC 8705). `issue_grant` needs `cnf=`; a grant without it is neither issued nor
  verified. New: `check_possession`, `check_dpop`, `check_client_certificate`, `cnf_for_jwk`, `cnf_for_certificate`,
  `cnf_for_signer`.
- Canonical identity string (#393). `probity_records.canonical_identity` parses and renders the `aid1!` identity
  string with an explicit actor kind (human-attested, agent, unknown, transport). Spec in
  [docs/canonical-identity.md](docs/canonical-identity.md), 53 shared vectors.
- One signed revocation list (#397). Seven subject kinds (agent, build, grant, key, permit, sponsor, stream), a chain
  of cumulative lists signed by pinned roots, root rotation, and one refusal code per failure (`REFUSAL_CODES`). This
  replaces the earlier revocation format. 39 shared vectors in `vectors/shared/revocation.json`.
- Identity digests (#396). `probity_records.digests` is the one definition of `principals_digest`,
  `act_chain_digest`, `grant_chain_digest` and `stamp_digest`. Spec in
  [docs/identity-digests.md](docs/identity-digests.md), 53 shared vectors.
- One injectable clock (#398). `probity_records.clock` holds `Clock`, `SystemClock`, `FixedClock` and `HighWater`.
  `Journal`, `AuditStream` and `Witness` take `clock=`, `delegate` takes `now=`, `seal_export` takes `sealed_at=`.
- `check_subject_id(kind, id)` is public: it raises `revocation_list_shape` unless a list entry can name `id` under
  `kind`, so an enforcement point never admits work under a subject no list can revoke.
- `agent-evidence-verify` may be any release before 0.10.
