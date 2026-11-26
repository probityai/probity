# Signing anchors in the trust bundle

`probity_records.trust_bundle` reads the `anchors` member of a version 2 trust bundle
([verified-identities.md](https://github.com/probityai/probity/blob/main/packages/probity-records/docs/verified-identities.md))
and verifies a DSSE-signed in-toto statement under one. Why anchors live in the bundle, and not in a manifest of their
own: [one-name.md](https://github.com/probityai/probity/blob/main/packages/probity-records/docs/one-name.md).

```json
{
  "jwk": {"kty": "OKP", "crv": "Ed25519", "x": "..."},
  "thumbprint": "<RFC 7638 thumbprint of jwk>",
  "role": "kernel-substrate-signer",
  "status": "retired",
  "notBefore": "2026-06-10T00:00:00Z",
  "notAfter": "2026-09-01T00:00:00Z",
  "predicateTypes": ["https://probityai.github.io/agent-evidence-vectors/predicate/v2/kernel-substrate"]
}
```

Every member is required and no other is allowed. `status` is `active`, `retired` or `revoked`; `notAfter` is `null`
only for an active anchor; times are RFC 3339 with an offset; `predicateTypes` is a non-empty list of distinct https
URIs. The reader recomputes the thumbprint and refuses a mismatch, a private member, a key that is not Ed25519 and a key
listed twice, each as `trust_bundle_malformed`.

## Verifying a statement

```python
from probity_records.trust_bundle import WitnessedTime, verify_anchored

verdict = verify_anchored(envelope, bundle, revocations=state, witnessed=WitnessedTime(note, policy, index, proof))
verdict.statement, verdict.anchor.role, verdict.signed_no_later_than
```

Each listed anchor key is tried against the envelope; its unsigned `keyid` is never read. In order:

| Check | Refusal |
|---|---|
| no anchor key verifies the signature | `anchor_unknown` |
| the anchor's status is `revoked` | `key_revoked` |
| the statement's `predicateType` is not one the anchor may sign | `anchor_predicate_not_authorized` |
| the anchor is `retired`, has a `notAfter`, or its key is on the signed revocation list, and no witnessed tree head bounds the signing time | `anchor_signing_time_unbound` |
| the witnessed bound is before `notBefore` or after `notAfter` | `anchor_signed_outside_window` |
| the key's `revokedAt` on the list is at or before the witnessed bound | `key_revoked` |

**The witnessed bound.** `WitnessedTime` carries a C2SP checkpoint note, the c2sp.org/tlog-policy the verifier pins,
and the RFC 9162 inclusion proof of the envelope at `index`. The leaf is the envelope as one journal line (JSON, sorted
keys, no spaces). The note must verify under the policy and meet its quorum (`quorum none` gives no bound), and the
leaf must be in the cosigned tree. The bound is the latest cosignature time of the counted witnesses: an honest counted
witness saw the statement no later than that. It is an upper bound only, so it can prove a signature came too late or
before a revocation, never that it came after `notBefore`; a bound before `notBefore` proves the statement predates the
window.

**Two names for a key, both derived.** The bundle names an anchor by its RFC 7638 thumbprint; signatures and the
signed revocation list (`kind = "key"`) name it by `sha256(raw key)`, which `Anchor.key_id` computes. Neither is read
from input.
