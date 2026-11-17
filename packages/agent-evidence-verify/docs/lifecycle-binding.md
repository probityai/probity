# `lifecycle_binding/v1`: was what was authorized what was executed?

`lifecycle_binding/v1` answers one question about runtime evidence: does the authenticated execution report name
the action the authenticated control authorized, for one decision and one instruction? It is the reader for the
`lifecycle_binding` term in agent-evidence-vocabulary and the `vectors-lifecycle-binding` corpus in
agent-evidence-vectors.

Most runtime evidence answers this by matching one authorization with one execution. Each of these defeats that:

| Vector | What a first-pair reading returns | This claim type |
|---|---|---|
| An execution of instruction 2 matched against the authorization of instruction 1 | satisfied | `not_evaluated` |
| The issuing side authorized X, the receiving side recorded Y, the executor reports X | satisfied | `failure` |
| Two executions share one record id, one reporting X and one Y | depends on array order | `indeterminate`, in either order |
| A valid signature under an executor key whose binding is revoked | satisfied | `not_evaluated` |
| An execution sealed by a key nobody bound, or unsigned with a valid self-hash | satisfied | `failure` |
| Only a receiver-side control, written by the executor's side | satisfied | `missing` (no issuer-side control) |
| An issuer-side control signed by the executor's key, under its own name or a second one | satisfied | `failure` (`self_authorized`) |
| Action bytes the consumer named are unavailable | satisfied | `missing` |

## Assessment

```json
{
  "claim_type": "lifecycle_binding/v1",
  "records": "records.json",
  "bindings": "bindings.json",
  "revocation": "revocation.json",
  "actions": {"e-1": "action.json"},
  "pointer_conventions": {"authorized_action_digest": "jcs", "executed_action_digest": "jcs"}
}
```

`records` is a JSON array of decision, control and execution records. `bindings` maps each producer to
`{public_key_hex, suite}`; `revocation` maps each producer to `{state: active|revoked}` and is required. `actions`
optionally names the published action bytes of a record; each is hashed by the convention declared for its pointer
(`jcs`, the default, or `raw`) and compared with the record's digest. A named record that is not in the set is a case
error, and named bytes that are unavailable make the group `missing`. A binding's `public_key_hex` is 64 lowercase hex
characters and its `suite` a string, or the case is refused before any verdict.

## Records and pre-images

Every record carries `lifecycle_version` (`v1`), `artifact_type` (`decision`, `control` or `execution`),
`record_id`, `producer` and `integrity` (`current`, `signature.value` in hex, `signature.alg` informative only).
Controls and executions carry `decision_ref.record_id` and `instruction_id`; a control carries `boundary_side`
(`issuer` or `receiver`) and `authorized_action_digest`; an execution carries `executed_action_digest`.

Pre-images use a closed registry of six ASCII tags, `agent-evidence/lifecycle-binding/v1/TYPE/PURPOSE` with TYPE
`decision`, `control` or `execution` and PURPOSE `hash` or `signature`: the tag bytes, 0x0A, then the canonical
bytes. The hash covers the RFC 8785 form of the record without `integrity.current` and `integrity.signature`. The
signature covers the RFC 8785 form of `{"current", "suite"}`, where the suite is the one the producer's key binding
names. An unregistered type or version, or a tag in another case, is refused (`unregistered_tag`) and never
matched to the nearest registered tag.

## States and order

Records are grouped by (decision record id, instruction id). In each group, in this order: a shared identity
anywhere in the set gives `indeterminate`; an execution with no control gives `not_evaluated`; a missing issuer-side
control, execution or cited decision gives `missing` (a receiver-side control alone records what the executor's side
received, never what was allowed); an artifact that does not authenticate gives `failure`; an inactive binding gives
`not_evaluated`; an issuer-side control signed by a key that signs an execution in the group gives `failure`
(`self_authorized`); published action bytes that do not hash to their pointer give `failure`, and named bytes that are
unavailable give `missing`; then every authorized digest must equal every executed digest (`satisfied`) or the group
is a `failure`. The set's decision is `contradicted` when any group fails, else `not_established` with the
first of `indeterminate`, `not_evaluated`, `missing`, else `supported` / `satisfied`. Absent evidence is never
`satisfied`. The scope reports the count of each state and `does_not_establish`: the claim is about records and
never says that the executed bytes were observed.

Head-witness attacks (a witness signature replayed as a record signature, freshness replay, witness version and
suite substitution) need head witnesses, which this version does not read.
