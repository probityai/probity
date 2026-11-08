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
