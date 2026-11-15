# Check an identity provider's token grant receipt

Use `token_grant_receipt/v1` to check one signed receipt an identity provider wrote for a token grant against the values you expect. The [Keycloak evidence hook](../../../integrations/keycloak-evidence-hook/README.md) writes these receipts for token exchange, client credentials and CIBA grants. The receipt is a DSSE envelope over an in-toto Statement whose `predicateType` is `https://w3id.org/agent-evidence/predicate/v1/token-grant-receipt`; the [design note](../../../integrations/keycloak-evidence-hook/docs/design.md) lists its members.

## Inputs

The case binds the envelope (one line of the recorder's log) and, optionally, the whole log. The assessment has:

- `claim_type`: `token_grant_receipt/v1`
- `envelope`: the case artifact holding the envelope
- `recorder_public_key`: the recorder's raw Ed25519 public key, 64 lowercase hex characters, from your own trust decision
- `expected`: `issuer`, `grant_type`, `actor_client_id` and `access_token_id_sha256` (the SHA-256 of the `jti` of the token you hold), and optionally `subject_user_id`, `subject_token_sha256`, `audience` and `scope_allowed`
- `log` (optional): the case artifact holding the recorder's JSONL log

## Decisions

| decision | reason | when |
| --- | --- | --- |
| `supported` | `grant_recorded_as_expected` | the pinned key signed the receipt and every expected value matches; the receipt's scope is within `scope_allowed` |
| `contradicted` | `grant_issuer_mismatch`, `grant_type_mismatch`, `grant_actor_mismatch`, `grant_token_mismatch`, `grant_subject_mismatch`, `grant_subject_token_mismatch`, `grant_audience_mismatch`, `grant_scope_exceeds_expected` | the first expected value the authentic receipt does not match |
| `not_established` | `receipt_signature_unverified` | no signature verifies under the pinned key |
| `not_established` | `receipt_log_unestablished`, `receipt_log_unavailable` | a supplied log has a line the key did not sign, a broken chain link, or does not contain the envelope |
| `not_established` | `envelope_unavailable` | the envelope artifact is not present |

A receipt the key signed but whose statement is malformed (a repeated member, a float, a member outside the closed set, an unsorted list, a key id naming another key) is invalid input: exit 2, no verdict. Every comparison is reported as a check with its expected and observed value.

## What it does not establish

A supported decision means the holder of the pinned key recorded this grant with these values. It does not establish that the identity provider's policy allowed the grant, that the recorder saw every grant, or who holds the key. A log check shows the chain is intact between its first and last line; to detect a removed head or tail, retain the `head_sha256` the check reports and compare it on the next run.
