# `capability_credential/v1`: one verifier input for every agent credential format

Agent credential formats differ in member names and envelopes and fail in the same few ways. The
`capability-credential/v1` profile (the `capability_credential` term in agent-evidence-vocabulary) is one input a
format-specific reader maps its record into; `capability_credential/v1` then applies one set of rules to it.

```json
{"schema_version": "capability-credential/v1", "id": "cred-1", "issuer": "issuer-a", "subject": "agent-7",
 "capabilities": ["db:read", "db:write"], "issued_at": "2026-11-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z",
 "revocation_ref": "list-1", "max_uses": 5, "cosigners_required": 2,
 "signatures": [{"kid": "issuer-a", "value": "<base64url Ed25519>"}, {"kid": "cos-1", "value": "..."}]}
```

Each signature is Ed25519 over `capability-credential/v1 || 0x00 || RFC 8785 (the credential without
signatures)`. The verifier state is the consumer's: `trusted_issuers` (`{issuer: hex key}`), `cosigners`
(`{kid: {public_key, authority}}`), a pinned clock `at` and a `revoked` list of credential ids. Nothing the
credential says about itself (a `revoked` flag, its own key) is an input.

| Code | Refused when |
|---|---|
| `duplicate_member` | a member repeats, at any depth |
| `unknown_member` | a member the profile does not define, including a case variant (`Capabilities`, `Revoked`) a case-insensitive decoder would read as the signed list or as a flag outside the signed bytes |
| `noncanonical_number` | a number token is not its own canonical spelling (`-0`, signed either way; `5.0`; `1e2`) |
| `timestamp_grammar` | a time carries a JSON escape, non-ASCII digits, a trailing line feed, or is not `YYYY-MM-DDTHH:MM:SSZ` |
| `issuer_untrusted` | the consumer trusts no such issuer |
| `signature_invalid` | the issuer's signature is absent or does not verify (tamper after signing) |
| `key_named_not_signing` | a named cosigner's signature does not verify, or two signatures name one key id |
| `own_key_as_cosigner` | the issuer's own key is listed as a cosigner, whatever the count |
| `one_key_two_ids` | the required count is met only by one key listed under two ids |
| `one_authority_threshold` | the required count is met only by keys of one authority |
| `below_threshold` | fewer distinct cosigner keys sign than required |
| `cosigner_untrusted` | the consumer knows no cosigner key by that id |
| `not_yet_valid`, `expired` | the pinned clock is outside `[issued_at, not_after)` |
| `revoked` | the credential id is on the consumer's revocation list |

Otherwise `supported` / `credential_valid`. The verdict does not show that a capability was used as granted.
