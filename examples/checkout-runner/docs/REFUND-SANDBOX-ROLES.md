# Refund sandbox roles: who decides, who signs, who executes, and what binds each step

This page defines the role contracts for the bounded refund sandbox in [aeoess/agent-governance-vocabulary#193](https://github.com/aeoess/agent-governance-vocabulary/issues/193), contract revision `review-2026-10-23`. Each role states what it receives, what it emits, what it must re-check rather than trust, and what the next role checks. Record formats and signing domains are the contract's (sections 5 to 10); this page adds the boundaries between the parties that hold them.

The rule behind every row: a role that did not make a decision may carry it forward only by re-deriving every reference it signs or acts on from the bytes it was handed. A role that accepts a digest, a summary or a callback in place of those bytes has become a stamp, and the next role cannot tell.

| Role | Receives | Emits | Must re-check, never trust | Next role checks |
|---|---|---|---|---|
| Admission | Native APS approval, decision and intent files; the runner's PIC verification result; `trust/aps-consumption.json` | Committed `refund-sandbox-admission/0.1` record; `admission_ref = sha256(JCS(record))` | Native signatures, the exact refund tuple, the merchant decision, approval-signer trust at the consumption instant | The signer recomputes `admission_ref` from the full record |
| Admission signer (handoff) | The full committed admission record, the configured issuance trust snapshot and the signer key | `refund-sandbox-handoff/0.1` envelope, Ed25519 over `ASCII(type) 0x00 JCS(payload)` | Closed record shape and `state` `committed`; every file reference is well formed; key role `admission-signer`, issuer, workflow and provider scope; key validity and revocation at issuance; `valid_until` no later than the record's, the key's or 600 s after issuance | The executor verifies the envelope against the record and the selected trust, then current dispatch authorization (section 7) |
| Resolution generation | Admission's verdict that a reissued receipt with new matching PIC evidence resolves to an existing operation; the original committed record as stored; the new input file hashes | The closed `refund-sandbox-resolution/0.1` payload, `disposition` `resolved_existing`, `dispatch_authorized` false | The original record is hashed as stored, never rewritten; the presented receipt differs from the original; the presented input set is closed | The signer signs it; the reader verifies both native input sets |
| Resolution signer | The resolution payload and the same trust and key as the handoff signer | Signed resolution envelope under its own domain | As for the handoff, plus the domain is selected from the expected record type, so a resolution never verifies as a handoff | Reader; an executor treats a resolution as never authorizing dispatch |
| Execution | Handoff envelope, committed record, issuance and evaluation trust | The four JSONL streams; one simulator effect per operation | Signature, domain, role, time window and revocation before every effecting dispatch; scoped idempotency key; exact stored arguments | The runner seals the streams; the reader re-derives every claim |
| Runner | Every component's pinned output | Sealed bundle, report context | Pins and digests of every component, the PIC result channel | Reader |
| Reader | The sealed bundle | Per-claim ESTABLISHED, CONTRADICTED or NOT_ESTABLISHED | Everything above, from retained bytes | None |

Independence. The admission decision (Horizon Shield's door) and the downstream reader (default-settlement-verifier) are held by parties other than the signer and the runner. The handoff and resolution signer, the resolution generation step and the runner sit in this repository, so checks between them are one project's own consistency, never independent verification; only the reader's result can be independent evidence about them.

## Reference implementation

`src/checkout_runner/sandbox_signer.py` implements the admission signer, resolution generation and the resolution signer, with JCS and Ed25519 from the pinned `agent-evidence-vectors` package. `tests/test_sandbox_signer.py` covers the positive handoff and resolution, the contract's signing bytes, a bare digest refused, uncommitted, open or float-valued records refused, unknown, wrong-role and revoked keys, key material that does not match the selected key, a record changed after signing, a re-pointed `key_id`, handoff and resolution domains that do not cross, a resolution for the original receipt, and a late re-sign that cannot extend the record window. All fixtures are synthetic test keys; nothing here is a connected run.

`src/checkout_runner/sandbox_executor.py` implements the execution role against section 10, over the synthetic provider in `src/checkout_runner/sandbox_sim.py`. Before every effecting dispatch it verifies the handoff against the full committed record and the selected issuance trust, checks the selected evaluation trust (accepted issuance snapshot, no rebound key, revocation at the unrounded dispatch instant), hashes every original evidence file against the record, requires the PIC `args_digest` to equal the execution `arguments_digest`, and dispatches only inside L <= now < U, where L and U are the inward whole-second conversions of every applicable bound. It persists the scoped operation, stored arguments and idempotency key before calling the provider, writes the four closed JSONL streams, retains the provider's raw readback for every observation, and promotes an outcome to `observed_success` only when the observed effect binds to this operation, its idempotency key, its exact arguments and its original dispatch attempt. Anything else stays `unresolved` with a `local-effect-binding-mismatch` diagnostic. `result_at_cutoff` applies the report-context cutoff to both `observed_at` and `recorded_at`.

`tests/test_sandbox_executor.py` carries one test per fixture id for the section 11 cases the executor owns, each refusal checked against the provider's request log as well as its effect count, plus the controls that would refute each result:

| Case | Fixture ids | Control |
|---|---|---|
| J12 | j12a changed record, j12b forged signature, j12c unknown key, j12d wrong-role key, j12e key rebound in evaluation trust | valid delivery dispatches once |
| J13 | j13 signer revoked before dispatch: integrity and recorded attempt ESTABLISHED, new dispatch forbidden | no recorded exact time gives NOT_ESTABLISHED |
| J15 | j15 later trust without applicable revocation dispatches | issuance snapshot not accepted is refused |
| J16 | j16a changed, string, boolean, float and missing arguments; j16b conflicting operation reuse | key-order-only arguments dispatch |
| J17 | j17 duplicate and key-rotated delivery recover one operation and one effect | |
| J18 | j18 lost response unresolved until a reconcile_lookup binds the same effect to its original dispatch | |
| J19 | j19 pre-dispatch failure: no request in the provider log, no effect | a received request stays unresolved |
| J20 | j20 expiry while unresolved: dispatch refused, lookup allowed | lookup after expiry can still confirm an earlier effect |
| J21 | j21a .900 observation against a .500 cutoff; j21b earlier observation recorded after the cutoff | later cutoffs include them |
| J22 | j22 same argument digest, wrong `effect.operation_id` | changed arguments or attempt also refuse promotion |
| J23 | j23a unchanged, j23b key-order-only | |
| J24 | j24a inward conversion at both bounds and equality to U, j24b empty window, j24c no extension past the handoff, j24d the section 8 12:00:09.500 example | |

J14 (APS approval signer revoked before consumption) is admission's check, not the executor's; the executor never consumes an APS approval.

Not covered here: admission itself, a native PIC or APS result format (the PIC result file is a synthetic stand-in carrying `arguments` and `args_digest`), a connected run against other participants' producers, and admission restart, which stays NOT_ESTABLISHED. The signer, the executor and the runner all sit in this repository, so their agreement is one project's own consistency; only the downstream reader's result is independent evidence.
