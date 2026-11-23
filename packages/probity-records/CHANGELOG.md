# Changelog

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
