# probity-records

Signed records of agent tool calls that anyone can check offline: a single-use permit bound to the
exact call arguments, the human approval it rests on, and what the call did, including a lost reply.

It is for framework integrations (Temporal, Pydantic AI) that write those records, and for the
auditor who verifies them without access to the system that ran the agent.

Install: `pip install probity-records==0.1.0`

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
