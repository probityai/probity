# Changelog

## Unreleased

- The shared vectors in `vectors/shared/verified_identities.json` now carry what a receiver spends for a possession
  proof, not only its method. An accepted case's `proof` was the string `dpop` or `mtls`; it is now
  `possession_record` of the proof and, for DPoP, its single-use `key` (`proof_key(jkt, jti)`) and `expires` (the
  proof's `replay_exp`): `{"method": "dpop", "iat", "jkt", "jti", "key", "expires"}` or
  `{"method": "mtls", "x5t#S256"}`. A verifier that reported only the method no longer conforms. The TypeScript
  twin `@probityai/records-verify/verified` returns the same values from `verifyRequest` (`DpopProof`,
  `CertificateProof`, `proofKey`, `REPLAY_GRACE`), so a Node receiver spends the same key for the same window as a
  Python one. Two new cases: VI16 (a proof at the oldest accepted `iat`) and VI17 (a `jti` that is not ASCII).

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
