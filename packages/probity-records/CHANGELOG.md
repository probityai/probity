# Changelog

## Unreleased

- **One grammar per received text, in both languages.** `grammar/*.json` states what a timestamp, an integer claim, a
  compact JWS member, a target URI, an X.509 certificate, a stamp field and the trust bundle are; both readers are
  tested against those files and the differential in `tests/parity_r6c` is generated from them. A timestamp is
  written in the digits 0 to 9 (Python's `\d` also read other scripts' digits) and is read for years 0001 to 9999
  (the TypeScript reader refused every year before 100); its value is integer microseconds, a `bigint` in
  TypeScript. An integer claim (`iat`, `exp`, `nbf`, a DPoP `iat`) beyond 2**53 - 1 is refused, and times are
  compared as integers. A DPoP `x5c` and a client certificate are read from their DER bytes by one outline walk
  (`certificate.py`, TypeScript `x509.ts`): PEM text, bytes after the certificate and a length that is not in its
  shortest form are refused, where Node's parser accepted the first two. A port is leading zeros and at most five
  digits. A header `alg` or `typ` that is not a string names nothing (TypeScript read a list holding `"EdDSA"` as
  `"EdDSA"`). A stamp's byte sequence with one base64 digit left over is refused in both readers, its three
  structured fields parse before its key is looked up, and a field value is trimmed of space and tab only.
  `TrustBundle.parse` refuses a pin whose roles hold a list or an object instead of raising, and
  `identity.token_segments` returns None for a signature in a second spelling instead of raising. A test counts
  text coercion (`str()`, `String()`) and platform text functions in reader code: the request readers have none.

- **A vote, a delegation and quorum evidence are read by type, in both languages.** A vote's `approver`,
  `onBehalfOf` and `role`, a delegation's `deputy`, `deputyKey` and `roles`, and the evidence's policy id and
  `proposer` count only when they are strings (`roles` a list of strings), and the TypeScript reader looks a name up
  among an object's own members only. Before, the TypeScript reader read a list holding `"carol"` as `"carol"`, found
  an approver, a policy and a proposer named `constructor` in every object, and took a proposer `[]` as present,
  while the Python reader raised on a `role` that was a list and on a vote with no `decision`. A vote whose
  `decision` is neither `"approve"` nor `"reject"` is now `vote_shape` in both readers, and a delegation whose `roles`
  is one text no longer delegates every role that text contains. Evidence whose `policy` is not an object names no
  pinned policy, and evidence whose `votes` are not a list is `quorum_vote_invalid:vote_shape`; the Python reader
  raised on both. `vectors/shared/quorum.json` adds QV6 to QV25.

- **One reading of a request target, of base64 and of a token segment, in both languages.** A DPoP `htu` and a stamp
  `@target-uri` are read by `possession.http_uri_parts` (TypeScript `httpUriParts`): text outside the RFC 3986 URI
  alphabet (a space, a control byte, a tab or line break, a backslash, a non-ASCII character), userinfo, an empty
  host and an empty, non-numeric or out-of-range port are refused before any parse. Before, `urlsplit` stripped a
  leading space or deleted a tab that WHATWG URL parsing kept or rewrote, so the two readers compared different
  targets. A DPoP `x5c` certificate, approval payloads, envelope payloads and an authority block's `argsB64`
  (`core.call_args_of`, TypeScript `callArgsOf`) are read as canonical padded base64 only (`core.unb64`), so missing
  or extra padding, a line break or the URL-safe alphabet is refused in both. The TypeScript principal token reader
  reads its header and claims through one strict reader (canonical base64url, `TOKEN_MAX_DEPTH`, jcs-admit), refuses
  a `crit` header as `token_critical_unsupported`, and reads its key through `publicJwk`. Every key reader refuses
  private key material through one guard (`identity.refuse_private`, TypeScript `refusePrivate`) inside
  `public_jwk` and `jwk_thumbprint`, and a test finds every reader rather than listing them; a passport holder key or
  a pinned JWKS carrying private material is now refused.

- **One list of private JWK members, and a differential that reaches every refusal code.** Every key reader refuses
  the members of `identity.PRIVATE_JWK_MEMBERS` (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`, `priv`); the naming
  registry, the principal reader and the DPoP header reader used to pass a key carrying `oth`. The key-bound tokens of
  one request must carry the same `cnf` as RFC 8785 bytes in both readers (Python took `true` for `1`, TypeScript
  never equated equal nested values), and `possession_record_problem` refuses a list or object `method` instead of
  raising. The differential in `tests/parity_r6c` now signs edited tokens and DPoP proofs again and judges
  `check_possession`, `possession_record_problem` and `duplicate_proofs` directly, so each of the 55 registered codes
  of `verified_identities` and `possession` is reached in both languages, and a code no case reaches fails the run.

- **A public key has one spelling.** `identity.public_jwk` reads a JWK's `x`, `y`, `n` and `e` only in their canonical
  base64url, an EC coordinate only at the full size of its curve (RFC 7518 section 6.2.1.2), an Ed25519 `x` only at
  32 bytes, and RSA `n` and `e` only without a leading zero octet (RFC 7518 section 2). `jwk_thumbprint` exists only
  for such a key, and the JWS checks (`identity`, `registry.verify_signature`) read keys through it. Before, a short
  EC coordinate verified as the same point under a second thumbprint, a trust bundle could pin a respelled key that
  the TypeScript reader then decoded leniently, and a respelled stamp key made `TrustBundle.stamp_key` raise. The
  TypeScript twin's `publicJwk` applies the same rule, and the differential in `tests/parity_r6c` now respells every
  bundle key of every shared row. A key's `kty` and `crv` name a curve only as strings: a `crv` of `["P-256"]` read as
  P-256 in TypeScript under a second thumbprint and made the Python lookup raise, and a `kty` of `"constructor"` made
  the TypeScript thumbprint raise; each is now `jwk_unsupported`.
- **Every document a stranger can hand the package is read by one strict reader, `core.admitted_loads`.** A repeated
  member, invalid UTF-8, a lone surrogate (raw or escaped), NaN, a number no double holds, nesting past the reader's
  depth (128 containers; 32 for a token segment or registry document, `core.TOKEN_MAX_DEPTH`) and, where a caller sets
  one, more than a byte bound are refused as `core.JsonRefused` (a `ValueError`; its `variant` names the cause). Before,
  these inputs went to `json.loads`: deep nesting raised `RecursionError` out of a verifier, a repeated member kept
  the last value, and a lone surrogate reached a canonicalizer and raised. The readers now behind it: the record
  bundle (envelope, payload, leaf, map commitment), the stamp window field, renewal requests, the anchored statement
  of a trust bundle, registry documents and tokens, identity-provider token segments (`verified_identities`,
  `identity.verify_token`), DPoP header and claims, OIDC approval claims, the call arguments of an exception or a
  grant allow, exports and seals, the journal verifier's key certificates and checkpoint provenance, the journal's
  own lines, sealed plaintext and the Vault answer. Each answers with its own registered refusal and never raises.
- **A token or DPoP segment has one spelling, and text a verifier cannot encode is a refusal.** `identity.unb64url`
  reads only the canonical unpadded base64url of a segment: a space, a newline, padding, a stray last digit or text
  outside ASCII is refused, where `base64.urlsafe_b64decode` skipped or accepted it, so one token had many spellings
  and digests. The TypeScript twin's `strictB64url` applies the same rule at every token and DPoP segment, which
  removes the one disagreement the differential found (`token_malformed` in Python, `token_signature_unverified` in
  TypeScript). `identity.verify_token` answers `token_malformed` for a token that is not ASCII, and `check_dpop`
  answers `dpop_malformed` for a proof that is not ASCII (checked before its size) and `dpop_ath_mismatch` for an
  access token that is not; before, each raised `UnicodeEncodeError`. Comparisons of received claims go through
  `core.same_text`, which never raises (`hmac.compare_digest` raised `TypeError` on text outside ASCII), and the
  witness note, checkpoint and policy readers, the receipt map key and the DSSE envelope's `payloadType` refuse a
  lone surrogate (`core.is_utf8_text`) instead of raising.
- **New refusal codes:** `anchor_statement_malformed` (the signed payload under a trust anchor is not admissible JSON),
  `jws_signature_not_low_s` and `passport_kb_critical` (see below). `identity.verify_token` now also answers
  `token_critical_unsupported` for a token header that demands an extension through `crit`, and `token_malformed` for a
  header or claim set that is not a JSON object. A hostile `argsB64` in an exception or grant allow is
  `authority_args_are_not_the_call_arguments`.
- **An ES256 token is read only in its low-S form (`s <= n/2`) by the registry verifier** (`jws_signature_not_low_s`):
  ECDSA `(r, s)` and `(r, n - s)` both verify, so one signed statement had two token texts and two digests. An ES256
  issuer of registry tokens must normalize `s` (`s = n - s` when `s > n/2`) before encoding. The single-use key of a
  validation is `Validation.spend_key`, `(issuer, jti)`, so the statement is spent once whatever its spelling.
  Third-party identity-provider tokens (`identity.verify_token`, `verified_identities`) are not held to low-S: about
  half of the ES256 tokens those providers issue are high-S, and their single-use keys are the `jti`, not the text.
- **A key binding JWT that demands an extension through `crit` is refused** (`passport_kb_critical`); the issuer JWT
  already was.
- **A record bundle's leaf is compared as canonical bytes, not as values.** A leaf spelling `"sequence":true` or `1.0`
  for sequence 1 compared equal before and is now `bundle_record_mismatch`; the map commitment's `coversSize` must be
  an integer.
- **`exports.parse_export` takes `max_bytes` (default `MAX_EXPORT_BYTES`, 128 MiB) and reads through the strict
  reader**: a repeated member is `jcs_refused:DuplicateMember`, no longer `export_has_duplicate_keys`. The
  `verify-export` and `compare-seals` commands report an unreadable seal as a failure (exit 1) instead of a traceback.
- **The TypeScript verifier reads token and DPoP segments the same way** (32 containers deep, strict UTF-8, no lone
  surrogate), so a segment the Python verifier refuses is refused there with the same code.

- **`approver` names every person an approval counted: one principal, or a list of at least two.** A principals block
  may now carry `approver` as a list of principals when an approval took several people (an M-of-N quorum); each member
  is a full principal checked as the single form is, and each must be a person the approval may name. The single form
  is unchanged and still means one approver. New refusals, under every profile: `principal_approver_duplicate` (a list
  names one subject twice) and `principal_approver_list_too_short` (a list of fewer than two: one approval takes the
  single form); a list member that fails the principal checks is refused `principal_approver:<code>`, and one that
  names a person the approval cannot name is refused `principal_approver_not_an_approval_signer`, as before.
- **Behaviour change, allows only: strict needs every counted approver named.** A human-session block whose ALLOW
  counted two or more people and that names only some of them is now `basic`, with the new shortfall
  `approvers-partial` (`identity.strict_shortfall`, and `principals_below_strict:approvers-partial` from a strict
  auditor); before, naming any one counted approver was strict. An autonomous block, which has no basic grade, is
  refused `principals_need_every_approver` in the same case. An intent or effect inherits its permit's allow. A block
  whose approval counted one person is graded as before.
- **A deny is graded as before.** A deny counts nobody: its approver principal may name any person whose binding it
  carries, and strict never needs each of them named. `identity.check_principals` and `strict_shortfall` take the
  people the approval counted (`counted`) apart from the people the block may name (`approvers`); for an allow they
  are one set, the default; for a deny `counted` is empty. So a deny resting on two people's bindings that names one
  of them stays strict (`approver-absent` still applies to a deny that names none), and an autonomous deny of that
  shape stays `autonomous`. `@probityai/records-verify` takes the same argument (`checkPrincipals(..., counted)`).
- **Behaviour change: a 0.12.0 schema with a rule on `principals.approver` is refused until it declares `members`.**
  Such a schema no longer lints (`approver_list_undeclared:principals.approver`), so `seal` refuses every record
  under it (`schema_refused`), lists or not. Add `members=True` to the approver rule; a record with no approver list
  then seals byte for byte as 0.12.0 sealed it. `erasure.seal` reads every subject key as bytes: a `bytearray` or a
  `memoryview` is its bytes (one key under two members is refused in any spelling), and a key that is not bytes-like
  is refused `subject_key_not_bytes` instead of raising `TypeError`.
- **Behaviour change: constraint values are compared by one key in both readers (`core.value_key`).** Python compared
  with `==` and `repr` and the TypeScript twin with a text form, so `true` and `1` were equal in one and different in the
  other. A `not_one_of` list, a `subset` or `contains` list, `exact` and `one_of`, and the narrowing proof for each now
  read two values as one when their RFC 8785 bytes are equal: `true` is never `1` (a `not_one_of [1]` now admits `true`,
  where it denied it), `3` and `3.0` are one number, and object member order is free. A value jcs-admit refuses equals
  nothing, so a `not_one_of` constraint denies it. New shared vectors: CV12 to CV16.
- **Behaviour change: an ID or access token is read by one strict rule in both readers.** `identity.verify_token`
  (and the OpenID Connect approval count) reads a token's header and claims with `identity.token_segments`: three
  base64url segments without padding, each of header and claims one JSON object that jcs-admit admits. A token with
  `NaN` or `Infinity`, a duplicate member, a header or claims that is not an object, or an `iat`, `exp` or `nbf` that
  is not an integer (a float such as `1794301200.0`, a string, a boolean, null) or an `iat` or `exp` outside years 1
  to 9999 is refused `token_malformed`. Before, Python truncated a float `iat`, read a string one, raised `TypeError`
  on a null one and counted a token with a `NaN` claim, and the TypeScript twin read each of these another way.
- **The approver list is a set: its order never changes a verdict or a digest.** A permit's parties are each role's
  issuer and subject; for a list they are its members' (issuer, subject) pairs in no order, so an intent naming the
  allow's approvers in another order, or after one approver's credential was refreshed, is the same parties (before,
  a list compared whole credentials in order, and both read as `principals_differ_from_permit`). Each party is
  compared by its RFC 8785 bytes with numbers read as IEEE doubles (`core.value_key`, `valueKey` in the TypeScript
  twin), so two readers give one answer: `1.0` and `1`, `1e16` and `10000000000000000`, and an object written with
  its members in another order are one value, and `true` is never `1`; a list is the same parties when its members
  match one for one.
  `digests.principals_digest` accepts an `approver` list of at least two principal objects and hashes its members
  sorted by their RFC 8785 bytes, so one set of approvers has one digest in any written order; a list of one, a list
  with a member that is not an object, and any other role given as a list are refused `identity_principals_malformed`.
  `identity.approver_principals` and `identity.approver_subjects` read either form.
- **Erasure seals an approver list per member, where the schema declares one.** A subject key is one person's. A
  rule declares that its approver field lists several people with `members` (`Rule(..., members=True)`; JSON
  `"members": true`, written only when set, so a schema without it serializes as before), and `lint_schema` refuses
  every rule that could seal the identity profile's approver list under one key (`approver_list_undeclared:<path>`):
  a non-kept rule on `principals.approver` that is not for the approver role with `members` (one for another
  subject, the user's included, would put every approver under that subject's key), and a non-kept rule on the whole
  `principals` block. It refuses `members` on any rule that is kept or not for the approver role
  (`members_outside_approver:<path>`). A list under a declared rule is sealed member by member:
  member `n` is the field `<path>.<n>` under the subject `approver.<n>`, with its own key and its own ciphertext group,
  and erasing one approver (destroying that member's key) leaves the others readable; the erased member opens as null
  in its place. A list under an approver rule without the flag is one approver's own value (the roles they voted in)
  and seals whole under the `approver` key, byte for byte as 0.12.0 does; the JSON type of a value never decides how
  many people it names. `erasure.seal` refuses, with `field_names_several_subjects`, a declared list whose members do
  not each have a key, two members passed one key, declared lists of different lengths in one record (member `n` of
  every list is one person), and a record with a declared list that also seals a field under the one `approver` key;
  it refuses an empty list (`approver_list_empty`). `check_block` refuses a member field under another member's
  subject and a list whose members are not 0 to N-1 (`roles_malformed`). A record with no approver list seals byte
  for byte as before. `erasure.member_subject(n)` names member n's subject. The erasure block of a record with a list
  shows how many approvers it has (one `<path>.<n>` entry and one ciphertext group per member).
- Shared vectors, every case released before this change byte for byte unchanged: `identity.json` adds ID41 to ID55
  (a list of two, strict; two counted and one named, basic; a subject twice; a list of one; an empty list; a member not
  counted; a member whose thumbprint does not recompute; a member that is not an object; a list with no approval;
  autonomous with both named; autonomous with one of two named; an empty list; a deny naming one of two, strict; a deny
  naming both; an autonomous deny naming one of two; the list in the other order). A vector may carry `counted` apart
  from `approvers`. `identity_digests.json` adds PD21 to PD25 (PD22: the other order, the same digest). The new family
  `approvers.json` holds nine journals under a 1-of-2 and a 2-of-2 policy (MA1 to MA9: both named, strict; one named;
  one named twice; a list naming a replayed approval; an intent naming both; an intent naming one; a deny of two naming
  one, strict; an intent naming both in the other order; an intent after one approver's credential refresh).
  `approvers.json` also holds MA10 and MA11 (an intent whose approver is two strings spelling the allow's approver,
  in either order: malformed, and not the parties of its permit, in both readers). `erasure.json` adds S11 to S17,
  O13 to O16 and L6 (the per-member seal and its refusals, one key under two members, one approver's own list sealed
  whole, a list beside a field under the one approver key, lists of different lengths, opening with every key, with
  one approver's key destroyed, a member under another member's subject, members not 0 to N-1, the `members` lint).
  `approvers.json` adds MA12 and MA13 (an issuer written `1.0` against `1`, and `1e16` against
  `10000000000000000`: one number, the same parties). `erasure.json` adds L7 and S18 (the 0.12.0 example schema:
  no longer lints, and a record under it is refused) and L8 and L9 (a `principals.approver` rule for the user's key,
  and a rule on the whole `principals` block, each refused). **Six released 0.12.0 erasure vectors give another
  output for their 0.12.0 inputs:** S1, S2, S4, S5 and S6 are now `schema_refused`, and L1 reports
  `approver_list_undeclared:principals.approver`, because their schema input is the 0.12.0 example schema. Those
  vectors now carry the example schema with `members` on its two approver rules, and under it each gives its 0.12.0
  output byte for byte; L7 and S18 keep the 0.12.0 schema as the vectors of its refusal. A reader that has not
  learned the list form refuses every vector that carries one; `@probityai/records-verify` learns it in the same
  change, so both releases go out together.
- `@probityai/records-verify` reads `TrustDoc.revocations` wherever the Python reader reads `Trust.revocations`: the
  record's signer key (`signer_key_revoked`) and permit (`permit_revoked`), the agent, sponsor and standing grant of
  a principals block (`principals_agent_revoked`, `principals_sponsor_revoked`, `principals_standing_grant_revoked`),
  a grant chain's issuer keys and grants (`grant_deny:grant_issuer_key_revoked:<depth>`,
  `grant_deny:grant_revoked:<depth>`) and approver keys (`approver_key_revoked`). Before, it read them for approver
  keys only and passed a journal the Python reader failed.
- Minor, not patch: this releases as 0.13.0. Vectors that turn a passing implementation red (an allow of several, one
  named, is now basic; six 0.12.0 erasure vectors whose schema no longer lints; tokens with a float or null time
  claim or a `NaN` claim, now refused), a schema 0.12.0 accepted that this release refuses, and a new accepted shape
  make this a minor release under strict semver.

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
