# probity-records

Signed records of agent tool calls that anyone can check offline: a single-use permit bound to the
exact call arguments, the human approval it rests on, and what the call did, including a lost reply.

It is for framework integrations (Temporal, Pydantic AI) that write those records, and for the
auditor who verifies them without access to the system that ran the agent.

Install: `pip install probity-records==0.2.0`

```python
from probity_records import Journal, Signer, verify_journal

signer = Signer.generate()
journal = Journal("records", signer)
journal.append("https://example.org/predicate/v1/note", "note", "00" * 32, {"text": "hello"})
report = verify_journal("records", [signer.public_pem()], journal.checkpoint())
print(report["verdict"], report["verified"], "of", report["records"])
```

It prints `PASS 1 of 1`.

Each tool-call record carries two published contracts, and their published readers judge them:
`approval-binding/v1` by `agent_evidence_vectors.approvalbinding`, and `uncertain_effect/v1` by
`agent-evidence-verify`.

## Key custody and the customer-held witness key

The signing key does not have to live next to the agent. `VaultTransitKey`, `AwsKmsKey` and `GcpKmsKey` sign
through HashiCorp Vault transit, AWS KMS or Cloud KMS Ed25519, so the private key never leaves the service.
Each pins its public key at construction and refuses a service that answers with another one. `delegate`
issues a short-lived session key signed by a root key, and `verify_delegation` re-checks the certificate
offline. The key's provenance travels in every permit and checkpoint it signs.

In `probity-temporal`, `AuthorityService` serves the authority from its own uid on a Unix socket. It checks
the caller's uid with `SO_PEERCRED` against an allowlist and offers no raw-sign operation: a worker can ask
for a permit only with a real approval. With the worker as `nobody`, a measured run was denied the key file and
the journal, got `op_unknown` for sign, `approval_missing` with no approval and `approval_signature_invalid`
with a forged one.

The witness key belongs to the customer. The journal publishes a C2SP tlog checkpoint feed. A witness the
customer runs, with a key we never hold, cosigns each checkpoint over an RFC 9162 consistency proof and refuses a
split view with HTTP 422. `Witness` and `serve_witness` are the server, `Feed` the client. The auditor pins a
`c2sp.org/tlog-policy` naming that witness, and `verify_journal` then fails with `witness_quorum_not_met`
unless the journal carries the cosignature. An independent witness built only from `golang.org/x/mod`,
`transparency-dev/formats` and `transparency-dev/merkle` completes the same handshake
(`interop/go-witness/interop.py`).

## Authority beyond one approval

| Module | What it records and checks |
|---|---|
| `grants` | Signed capability grants: per-tool, closed-world argument constraints (17 types, from `range` and `subpath` to `url_safe` and `shlex`), delegation that can only narrow, the grant digest in the permit |
| `quorum` | M-of-N approvals, one key per approver, bound to the request hash, fetched and retried while pending |
| `revocation` | Signed, append-only revocation lists for keys, permits and grants; root rotation; a last-known-good cache that fails closed |
| `governance` | Exceptions with owner, rationale and expiry under a quorum; intake, risk routing, approval, attestation and sign-off as signed steps |
| `exports` | `python -m probity_records seal-export`: a signed census of a governance platform export that anyone re-checks offline |

`verify_journal(path, keys, checkpoint, trust=Trust(...))` re-runs the grant, quorum, revocation and
governance checks from the records and the trust the auditor pins, and re-counts every human approval
(M of N) under the approver keys and threshold the auditor pinned, re-verifying each approver's own
signature. An export seal is re-checked with `verify_export_seal` or `python -m probity_records
verify-export`.
