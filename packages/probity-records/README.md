# probity-records

Signed records of agent tool calls that anyone can check offline: a single-use permit bound to the
exact call arguments, the human approval it rests on, and what the call did, including a lost reply.

It is for framework integrations (Temporal, Pydantic AI) that write those records, and for the
auditor who verifies them without access to the system that ran the agent.

Install: `pip install probity-records`

```python
from probity_records import Journal, Signer, verify_journal
from probity_records.clock import SystemClock

signer = Signer.generate()
journal = Journal("records", signer, clock=SystemClock())
journal.append("https://example.org/predicate/v1/note", "note", "00" * 32, {"text": "hello"})
report = verify_journal("records", [signer.public_pem()], journal.checkpoint())
print(report["verdict"], report["verified"], "of", report["records"])
```

It prints `PASS 1 of 1`.

Every producer takes its time from a `probity_records.clock.Clock` passed in at construction; a test or a
verifier passes a `FixedClock`, and `python -m probity_records.clock_lint SRC` refuses any direct clock read.

Each tool-call record carries two published contracts, and their published readers judge them:
`approval-binding/v1` by `agent_evidence_vectors.approvalbinding`, and `uncertain_effect/v1` by
`agent-evidence-verify`.

## Key custody and the customer-held witness key

The signing key can live in Vault transit, AWS KMS or Cloud KMS, and the customer runs the witness key. [Key custody and the witness](https://github.com/probityai/probity/blob/main/packages/probity-records/docs/key-custody.md) has the details. A root certifies short-lived session keys for one hierarchy, custody, tenant and half-open window; [the certificate format](https://github.com/probityai/probity/blob/main/packages/probity-records/docs/key-delegation.md) is `probity-key-delegation/v2`.

## Authority beyond one approval

| Module | What it records and checks |
|---|---|
| `grants` | Signed capability grants: per-tool, closed-world argument constraints (17 types, from `range` and `subpath` to `url_safe` and `shlex`), delegation that can only narrow, the grant digest in the permit, and the holder confirmation key (`cnf`, RFC 7800) every grant must name |
| `possession` | Proof that the presenter holds the grant's key, checked statelessly: DPoP proofs (RFC 9449, ES256 or EdDSA) or a mutual TLS client certificate (RFC 8705) against the issuer-signed `cnf`; the possession record an allow carries; and the offline check that no DPoP proof was spent by two permits inside its lifetime, so any verifier catches replay from the journal alone |
| `quorum` | M-of-N approvals, one key per approver, bound to the request hash, fetched and retried while pending |
| `revocation` | Signed revocation lists for keys, permits and grants, each list carrying only what it newly revokes; root rotation; a last-known-good cache that fails closed |
| `governance` | Exceptions with owner, rationale and expiry under a quorum; intake, risk routing, approval, attestation and sign-off as signed steps |
| `exports` | `python -m probity_records seal-export`: a signed census of a governance platform export that anyone re-checks offline |

`verify_journal(path, keys, checkpoint, trust=Trust(...))` re-runs the grant, quorum, revocation and
governance checks from the records and the trust the auditor pins, and re-counts every human approval
(M of N) under the approver keys and threshold the auditor pinned, re-verifying each approver's own
signature. An export seal is re-checked with `verify_export_seal` or `python -m probity_records
verify-export`.

## Where each identity piece lives

`identity`, `canonical_identity`, `grants`, `possession`, `revocation` and `quorum` each have one module, and a TypeScript twin in `node/probity-records-verify` where one exists. [The table](docs/identity-homes.md) names every file.
