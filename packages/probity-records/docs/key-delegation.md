# Session-key certificates: probity-key-delegation/v2

A root key signs once per window and certifies a short-lived session key (a window key) that signs the hot path:
journal lines, permits, stamps. `delegate(root, scope, now=...)` issues the key and its certificate;
`verify_delegation(certificate, roots)` re-checks the certificate offline against the roots the verifier pinned.
The TypeScript twin is `verifyDelegation` and `covers` in `@probityai/records-verify/delegation`, and both readers
are held to the same verdicts by `vectors/shared/delegation.json`.

## What the root states

The root signs `"probity-key-delegation-v2" || 0x00 || JCS(body)` (RFC 8785 canonical JSON) with Ed25519. The
certificate is `{"body": {...}, "sig": "<base64>"}` and carries no other member. The body has exactly these members:

| Member | Value |
|---|---|
| `format` | `"probity-key-delegation/v2"` |
| `hierarchy` | the root hierarchy the window key belongs to: `"identity"`, `"authority"` or `"record"`. The three are disjoint: a key certified in one is never read as a key of another |
| `custody` | who holds the root: `"ours"` (the party that runs the records service), `"customer"` (the tenant) or `"custodian"` (a party that is neither). A record root is never `"customer"`: the record of what happened is never signed under a key the observed party holds |
| `tenant` | the one tenant the window key acts for: printable ASCII (0x21 to 0x7E), 1 to 256 characters |
| `windowS` | the deployment's declared window in whole seconds, an integer from 1 to 2^53 - 1 (a float, a boolean or text is refused) |
| `notBefore`, `notAfter` | the window, RFC 3339 in UTC with `Z` and at most six fraction digits. It is half-open, [notBefore, notAfter), non-empty, and never longer than `windowS` |
| `rootKeyId` | SHA-256 of the root's raw public key, hex |
| `rootProvenance` | a JSON object naming the root's backend (`{"backend": "aws-kms", "key": "arn:..."}`); it describes custody for people and selects nothing |
| `sessionKey` | the session key's raw 32-byte Ed25519 public key, canonical base64 |

The scope (hierarchy, custody, tenant, window) is in the signed body, so a verifier compares it with the scope its
own pin for that root gives. Nothing in the certificate selects a key, a hierarchy or a root: every pinned root is
tried, and the root that verifies must be the one `rootKeyId` names.

## The window is half-open

An instant `t` (a record's `at`, a permit's `issuedAt`) is inside the window when `notBefore <= t < notAfter`. An
instant at `notAfter` is outside. A successor window that starts at its predecessor's `notAfter` therefore never
shares an instant with it. This is RFC 7519's reading of `exp` ("on or after which"), and it is the rule for every
window a probity record states. `Delegation.covers(at)` and `covers(delegation, at)` read `at` in the shared
timestamp grammar (an explicit offset is required and may be other than `Z`); an `at` outside the grammar is not
covered.

## What a v1 certificate means

`probity-key-delegation/v1` (probity-records 0.8.0 and earlier) stated no hierarchy, custody or tenant; a deployment
that needed them carried them inside `rootProvenance`, where the format gave them no meaning. Its readers also
counted the `notAfter` instant inside the window. This version refuses a v1 certificate with
`delegation_format_retired` and does not read it. A journal whose `keys.jsonl` holds one fails with
`session_key_delegation_invalid:delegation_format_retired` on that line. Re-issue the session key under v2; a
journal signed under v1 is verified with probity-records 0.8.0.

## Refusals

`verify_delegation` raises `ValueError` with the first refusal, in this order; the TypeScript reader returns the
same code.

| # | Code | Meaning |
|---|---|---|
| 1 | `delegation_shape` | the certificate is not `{"body": object, "sig": canonical base64}` |
| 2 | `delegation_format_retired` | the body is `probity-key-delegation/v1` |
| 3 | `delegation_format_unknown` | the body names no format this reader knows |
| 4 | `delegation_members_invalid` | a member is missing or the body carries one the format does not define |
| 5 | `delegation_hierarchy_invalid` | `hierarchy` is not one of the three |
| 6 | `delegation_custody_invalid` | `custody` is not one of the three |
| 7 | `delegation_record_root_customer_custody` | a record root in the customer's custody |
| 8 | `delegation_tenant_invalid` | `tenant` is not 1 to 256 printable ASCII characters |
| 9 | `delegation_window_invalid` | `windowS` is not an integer from 1 to 2^53 - 1 |
| 10 | `delegation_time_invalid` | `notBefore` or `notAfter` is outside the grammar or not in UTC `Z` |
| 11 | `delegation_window_empty` | `notAfter` is not after `notBefore` |
| 12 | `delegation_window_exceeds_declared` | the window is longer than `windowS` |
| 13 | `delegation_root_provenance_invalid` | `rootProvenance` is not an object |
| 14 | `delegation_session_key_invalid` | `sessionKey` is not a 32-byte key in canonical base64 |
| 15 | `delegation_unverified` | no pinned root signed the body |
| 16 | `delegation_root_key_id_mismatch` | the pinned root that signed it is not the root `rootKeyId` names |
