# Reference routes for the agent-evidence-vectors corpora

The agent-evidence-vectors GitHub Action runs this package as its reference stage and prints
`reference-checked conformance N of M`. N counts the members whose declared verdict this verifier
reached on its own; M counts every member. A corpus with no claim type here reads `0 of M`. This page
says what a reference check means for each corpus this package judges, which claim type it uses, and
how the corpus's declared verdict maps onto the three decisions.

## The rule every route follows

A member is one record, or one bundle of records, plus the verdict its corpus declares. The route
binds the member's bytes into a case (path, length, SHA-256), names the claim type in the consumer
policy, and calls `probity_verify.adjudicate`. The claim each type checks is that the bound record
satisfies its contract. The verifier reads only the record bytes, never the expected verdict.

| Verifier outcome | Meaning | Corpus verdict it must match |
| --- | --- | --- |
| `supported`, reason = the contract's accepted reason | every rule of the contract holds | accept / allow / MUST-ACCEPT |
| `contradicted`, reason = the first rule that fails | the record's own bytes refute the claim | reject / deny / MUST-REJECT, with the same reason |
| `not_established` | a bound artifact is missing or unbound | never a corpus verdict; always a disagreement |
| `CaseError` (CLI exit 2) | the case or policy is malformed | never a corpus verdict; always a disagreement |

A route agrees with a member only when the decision and the reason both match. A rule failure is
`contradicted` and never `not_established`: the record was read, and it fails the contract.

## The claim types

### `uncertain_effect/v1` (`vectors-uncertain-effect`)

The assessment names one artifact, `record`. The claim: the trail is consistent with at most one
effect for the operation, and the outcome the runtime reported is one the effect owner's answers
support. The thirteen checks run in the corpus's order (`contract_id_missing` to
`stop_straddle_reported_settled`). All pass: `supported` / `effect_held`. Otherwise `contradicted`
with the first failing check. Corpus `allow` maps to `supported`, `deny` to `contradicted`.

### `restoration_record/v1` and `restoration_bundle/v1` (`vectors-restart-records`)

`restoration_record/v1` takes one artifact, `record`: a decoded in-toto Statement whose
`predicateType` names one of the five restoration-evidence predicates. Strict JSON first, then the
predicate document's rules in table order. Accepted reasons are the predicate's own
(`authorization-recorded`, `sweep-recorded`, `decision-recorded`, `joint-authority-recorded`,
`boundary-recorded`); a failure is `contradicted` with the rule code.

`restoration_bundle/v1` takes `records`, a list of artifact names, and applies B1 (every record
passes its document) through B7 of the restoration-evidence/v1 profile. `bundle-consistent` is
`supported`. The route sends `shape: record` members to the first type and `shape: bundle` members to
the second. Corpus `accept` maps to `supported`, `reject` to `contradicted`.

### `jcs_canonical/v1` (`vectors-a2a-jcs-v01`)

The assessment names `target` (`rfc8785` or `card-signing-input`), an `input` artifact (JSON text)
and a `claimed` artifact (bytes). The claim: `claimed` is the canonical form of `input` for the
target. For `card-signing-input` that is the card without its top-level `signatures` member,
canonicalized per RFC 8785 (A2A specification 8.4.1 rules 2 and 3).

- Equal bytes: `supported` / `canonical_bytes_match`.
- Input with no canonical form (a lone surrogate, NaN or Infinity, a duplicate member, text that is not
  JSON, an integer outside the double range): `contradicted` / `no_canonical_form`.
- Different bytes: `contradicted` / `canonical_bytes_differ`.

The route builds the claim from each vector. A MUST-ACCEPT vector claims its
`expected.canonical_utf8_hex` bytes for its input, with every number token as the file spells it, and
must be `supported`. A MUST-REJECT vector claims that its `input_raw` bytes are their own canonical
form, and must be `contradicted`: with `no_canonical_form` for the RFC 8785 clauses, and with
`canonical_bytes_differ` for the rule-3 vectors, whose input still carries `signatures`. The default
target is `card-signing-input`, which owns every vector.

## Why the rules are ported, not imported

The rule code of each claim type is a port of the corpus's own reader, at the commit named in each
module's docstring. The verifier depends on no corpus package, so a corpus release cannot change the
reference verdicts, and a disagreement between the two readers shows up as `N < M` in the Action. The
tests run every member of each corpus, copied under `tests/data/`, through the kernel.

## What a reference check does not establish

The same limits as each corpus: that a producer recorded truthfully, that clocks agree, that a
signature key belongs to anyone. The restart-records members are unsigned Statements, so signature
checking is out of scope for both restoration types.
