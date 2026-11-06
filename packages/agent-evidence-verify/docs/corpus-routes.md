# Reference routes for the agent-evidence-vectors corpora

The agent-evidence-vectors GitHub Action runs this package as its reference stage and prints
`reference-checked conformance N of M`. N counts the members whose declared verdict this verifier
reached on its own; M counts every member. A corpus with no claim type here reads `0 of M`. This page
says what a reference check means for each corpus this package judges, which claim type it uses, and
how the corpus's declared verdict maps onto the three decisions.

## The rule every route follows

A member is one record, or one bundle of records, plus the verdict its corpus declares. The route
binds the member's bytes into a case (path, length, SHA-256), names the claim type in the consumer
policy, and calls `agent_evidence_verify.adjudicate`. The claim each type checks is that the bound record
satisfies its contract. The verifier reads only the record bytes, never the expected verdict.

| Verifier outcome | Meaning | Corpus verdict it must match |
| --- | --- | --- |
| `supported`, reason = the contract's accepted reason | every rule of the contract holds | accept / allow / MUST-ACCEPT |
| `contradicted`, reason = the first rule that fails | the record's own bytes refute the claim | reject / deny / MUST-REJECT, with the same reason |
| `not_established` | a bound artifact is missing or unbound | never a corpus verdict; always a disagreement |
| `CaseError` (CLI exit 2) | the case or policy is malformed, or an input nests too deeply to walk | never a corpus verdict; always a disagreement |

A route agrees with a member only when the decision and the reason both match. A rule failure is
`contradicted` and never `not_established`: the record was read, and it fails the contract.

## The claim types

### `uncertain_effect/v1` (`vectors-uncertain-effect`)

The assessment names one artifact, `record`. The claim: the trail is consistent with at most one
effect for the operation, and the outcome the runtime reported is one the effect owner's answers
support. The thirteen checks run in the corpus's order (`contract_id_missing` to
`stop_straddle_reported_settled`). All pass: `supported` / `effect_held`. Otherwise `contradicted`
with the first failing check. Corpus `allow` maps to `supported`, `deny` to `contradicted`.

The record is strict JSON (no repeated member, no NaN), and each carried field stays in the contract's
domain: `ownerEffects` is a non-negative integer, `final`, `deduplicatesByKey` and `charged` are booleans,
and `reply`, `result`, `reported.outcome`, `stop.reported` and each authority check's `result` are words
from closed lists. Anything else raises `CaseError` before a check runs, because the checks branch on
truthiness and on those lists: `"final": "no"` would read as final, and a repeated `ownerEffects` would
read as whichever copy the parser kept. A pass that rests on such a value is not a pass.

### `restoration_record/v1` and `restoration_bundle/v1` (`vectors-restart-records`)

`restoration_record/v1` takes one artifact, `record`: a decoded in-toto Statement whose
`predicateType` names one of the five restoration-evidence predicates. Strict JSON first, then the
predicate document's rules in table order. Accepted reasons are the predicate's own
(`authorization-recorded`, `sweep-recorded`, `decision-recorded`, `assignment-recorded`,
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

### `observed_effect/v1` (`vectors-observed-effect`)

The assessment names an `envelope` artifact (a DSSE envelope) and the `observer_public_key`, plus
optional `blobs`, `expected_code_digest` and `expected_invocation_binding`. Every trust input comes
from the consumer's policy, never from the record. The claim: the envelope is a conforming Observed
Effect record under that key. The rules run in the corpus's order and the first refusal is the code.

A conforming record is `supported` / `record_conforms`, and the decision's `vantage` is `independent`
only when the record's effects were independently observed. Both refusals are `contradicted` with the
code as the reason. The check keeps the corpus's verdict (`valid`, `invalid` or `malformed`), because
the corpus scores a verifier that collapses the last two as wrong. It also carries what a consumer may
read: `derived_tier`, recomputed and never copied, `effects_independently_observed` and
`absence_established`. The route compares those, the verdict and the codes. The one `indeterminate`
member agrees when the verdict is among its declared readings.

A pin in `expected_code_digest` or `expected_invocation_binding` is a lowercase SHA-256. Any other value
is the policy's defect and raises `CaseError`; it never refuses the record.

Four rules are not forced by any member, because none carries `codeDigest` or `invocationBinding`:
`code-digest-shape`, `code-digest-policy`, `invocation-binding-shape` and `invocation-binding-policy`.
`tests/test_corpus_routes.py` forces them with a member re-signed under a test key.

### `audit_principal/v1` (`vectors-agent-audit-record`, rows PR1 to PR11)

The assessment names an `envelope` artifact (a DSSE envelope holding an agent audit record) and the
`observer_public_key`, both from the consumer's policy. The claim: the record's `principal` member
(the identity provider's authenticated principal) is well formed and bound to the record. `tokenDigest`
equals `agent.credentialDigest`, the subject matches the delegation, the token's lifetime covers the
decision, and the issuer key's RFC 7638 thumbprint is the recorded one. The rules run in the corpus's
order, the first refusal is the code, and the signature is checked last.

A conforming principal under a valid signature is `supported` / `principal_conforms`. A record with no
`principal` member is `not_established` / `principal_absent`. Any refusal is `contradicted` with its code
as the reason, and the check keeps the corpus's verdict (`valid`, `invalid` or `malformed`). The check
does not establish that the identity provider issued the token: the token and the issuer's key set are
not carried.

## Why the rules are ported, not imported

The rule code of each claim type is a port of the corpus's own reader, at the commit named in each
module's docstring. The verifier depends on no corpus package, so a corpus release cannot change the
reference verdicts, and a disagreement between the two readers shows up as `N < M` in the Action. The
tests run every member of each corpus, copied under `tests/data/`, through the kernel.

## What a reference check does not establish

The same limits as each corpus: that a producer recorded truthfully, that clocks agree, that a
signature key belongs to anyone. The restart-records members are unsigned Statements, so signature
checking is out of scope for both restoration types.
