# Evaluation claims

`evaluation_claim/v1` answers one question: is this evaluation claim record admitted under my
acceptance rule? A record says how an implementation fared against a case set. It carries six
coordinates, each with a value or a reason the pinned profile allows for "not applicable":

| Coordinate | What it binds |
|---|---|
| applicability | the case set by digest, the applicable cases, and the optional cases excluded under an allowed reason |
| population | every applicable case as passed, failed or not run, and the denominator that counts them |
| vantage | who observed the run, and whether from the substrate or from the artifact |
| bytes | the implementation, the case set and the verifier, each by digest |
| epoch | the authority state the run acted under and every transition during it |
| settlement | whether each side-effecting action settled on bound evidence |

## Assessment

```json
{
  "claim_type": "evaluation_claim/v1",
  "record": "record.json",
  "rule": {
    "schema": "aev-claim-acceptance-rule/v1",
    "profile": {"id": "conformance/v1", "digest": "sha256:..."},
    "case_sets": ["sha256:..."],
    "accept_vantage": ["substrate"]
  },
  "profiles": ["conformance-profile.json"],
  "case_sets": ["case-set.json"]
}
```

The rule is the consumer's own and is written in the policy, never taken from the producer. It pins
the profile by digest, so a record that names a weaker profile is refused, and it lists the case-set
digests it accepts, so a reduced case set is refused. Profiles and case sets are resolved by the
SHA-256 of their RFC 8785 bytes from the case artifacts the assessment names; a supplied file that
hashes to nothing the rule pins resolves nothing.

When a case set's cases carry their expected outcome as an `expect` member (an expectation table,
a baseline of expected failures, a proof tool's verified-or-falsified target), the digest binds the
expectation. Flipping one expected outcome so a regression reads as a pass changes the digest, and
the record is refused with `CASE_SET_NOT_ACCEPTED`.

## Decisions

| Reader outcome | Decision | Reason |
|---|---|---|
| admitted, verdict `pass` | `supported` | `claim_admitted_pass` |
| admitted, verdict `fail` | `not_established` | `claim_admitted_fail` |
| admitted, verdict `incomplete` | `not_established` | `claim_admitted_incomplete` |
| refused | `contradicted` | the first refusal code |
| record not bound | `not_established` | `record_unavailable` |

The check `evaluation_claim` lists every refusal code with where it applies. The codes, in the
order they are reported: `MALFORMED_RECORD`, `PROFILE_UNRESOLVED`, `PROFILE_MISMATCH`,
`MISSING_COORDINATE`, `UNRESOLVED_COORDINATE`, `UNAUTHORISED_NOT_APPLICABLE`,
`INVALID_REFERENTIAL_PIN`, `CASE_SET_NOT_ACCEPTED`, `CASE_SET_UNRESOLVED`, `APPLICABILITY_MISMATCH`,
`POPULATION_MISMATCH`, `ABSENCE_READ_AS_CLEAN`, `VERDICT_CONTRADICTED`, `VANTAGE_NOT_ACCEPTED`,
`BYTES_MISMATCH`, `STALE_EPOCH`, `UNSETTLED_OUTCOME`, `UNSETTLED_ACROSS_EPOCH`.

The record is read with the package's strict I-JSON reader under the integer-only profile: a
repeated member, a lone surrogate, bytes that are not UTF-8, a fraction or an integer outside
+-(2**53 - 1) make it `MALFORMED_RECORD`. The adapter does not re-run the cases, authenticate the
observer or check a signature over the record.

The reference reader and its corpus are in
[agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors/tree/main/packaging/agent_evidence_vectors/claim_record).
