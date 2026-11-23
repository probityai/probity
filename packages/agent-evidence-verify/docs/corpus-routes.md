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
support. The fifteen checks run in the corpus's order (`contract_id_missing` to
`stop_straddle_reported_settled`), including `idempotency_key_follows_trigger` (a redelivery, replay or
completion that runs the step under a key other than the operation's own) and `owner_effect_unaccounted`
(the owner holds more effects than the trail has attempts that could have made one, as when the attempt was
lost with a checkpoint or deleted with the history). All pass: `supported` / `effect_held`. Otherwise `contradicted`
with the first failing check. Corpus `allow` maps to `supported`, `deny` to `contradicted`.

The record is strict JSON (no repeated member, no NaN), and each carried field stays in the contract's
domain: `ownerEffects` is a non-negative integer, `final`, `deduplicatesByKey` and `charged` are booleans,
and `reply`, `result`, `reported.outcome`, `stop.reported` and each authority check's `result` are words
from closed lists; an attempt's `trigger`, when carried, is an object whose `kind` is a string. Anything else raises `CaseError` before a check runs, because the checks branch on
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

### `proof_of_control/v1` (`poc-evidence-vectors`, 171 cases)

The assessment names one `input` artifact: a Proof-of-Control artifact as the `poc-evidence-vectors` corpus writes
it (a signed token, a Merkle inclusion or consistency proof, a token chain, or a canonical-form check). The check
parses it strictly (duplicate keys, lone surrogates and non-canonical numbers are refused), verifies Ed25519
signatures, recomputes RFC 6962 inclusion and consistency proofs, walks the chain against the expected measurement
and anchor, and recomputes the JCS digest. A chain anchor's `index` counts steps from genesis: 0 names the genesis
head, and an index below 0 or not a JSON integer is malformed (the corpus's reference twin reads `records[index -
1]`, which counts an index of 0 or below from the end of the chain; no corpus case uses one). A verifying artifact is `supported` / `artifact_verifies`; any refusal is
`contradicted` with the corpus's code as the reason. The same rules run as `agent-evidence-verify-poc`, which reads
one artifact on stdin and prints `{"result": "accept"}` or `{"result": "reject", "code": ...}`, the interface the
corpus runner calls: `python3 -m poc_evidence_vectors.run_vectors --verifier agent-evidence-verify-poc` passes all
171 cases. A signed artifact (a token or a chain) carries its own public key, which proves nothing alone, so its
verdict also needs that key authorised under the assessment's `key_authority` ([key authority](key-authority.md)):
an unauthorised key is `contradicted` with the authority's reason, and a key no authority decides is
`not_established`. The authority is asked for each signed statement with its `iss` and `iat`, so a registry or
key-transparency authority can decide; a DID document or an inclusion proof is a case artifact the policy names. The roots of an inclusion or consistency proof are the artifact's own and carry no trust outside
it.

### `credential_reachability/v1` (`vectors-credential-reachability`, 58 cases)

The assessment names an `envelope` artifact (a DSSE envelope holding a Credential Reachability statement) and
every trust input, all from the consumer's policy and none from the record: `trusted_signers` and `agent_keys`
(each `{keyid: base64 raw Ed25519 key}`, a keyid being the SHA-256 of its key), `environment` (`name` and
`sha256` of the environment contract), `audience`, `challenge`, `judged_at`, `max_age_seconds`, `payload_type`,
and optionally `probe_digests`. The claim: the record is a conforming probe result for that environment, bound
to that audience and challenge, fresh at `judged_at`, signed by a trusted signer, and every class verdict and
the result are the ones its attempts derive. The 26 rules run in the contract's order and the first refusal is
the reason.

A signature is checked only under the key of `trusted_signers` that the envelope's `keyid` names. A key the
agent holds is used only to refuse: any signature that verifies under one, whatever `keyid` it names, is
`contradicted` / `signed_by_agent_key`. A policy that lists one key in both tables, names a keyid that is not the
SHA-256 of its key, or carries a malformed pin raises `CaseError`.

A record that passes every rule is `supported` with the reason `contained_verified`, `exposed_verified` or
`incomplete_verified`; a supported `exposed` record is a verified finding, and only `contained` supports "no
credential other than one issued to the agent is reachable" for the listed classes, at `probedAt`, from the agent's
vantage. Every other rule failure is `contradicted` or `not_established` as the contract states, with its
code as the reason. The corpus's two `no_verdict` members (an envelope that is not JSON, a signature that is
not base64) map to `contradicted` / `malformed_envelope`, because the kernel has three decisions.

The corpus is unreleased until agent-evidence-vectors v0.38.0, so `tests/data/credential-reachability` holds a
copy of its 58 members with the MANIFEST's digest pinned in `tests/test_credential_reachability.py`; the
adversarial tests there re-sign a member to try a forged payload byte, a swapped key naming the trusted keyid, an
agent co-signature, a replayed challenge, an expired result, another audience and a class-set downgrade.
## Corpus-mode routes

These suites are judged by `agent-evidence-verify corpus DIR`, which prints one verdict line per member in the
shared verdict-line format, and not yet by a claim type.

### `agent-payment-mandate/v1` and `status-receipt-binding/v1`

The corpus's `accepted` and `accept` read as `accept`, `rejected` and `reject` as `reject`, and the reason is the
corpus's refusal code.

- `agent-payment-mandate/v1` (`vectors-agent-payment-mandate`, 36 members). A card-side record is held to its mandate
  digest, the credential's binding, expiry, ceiling, currency, merchant, token, receipt and post-checkout actions. An
  x402 record (`scheme: x402-exact-evm-eip3009`) carries the facilitator request in v2 field names. The reader
  recomputes the EIP-712 digest of the EIP-3009 authorization under the requirement's token domain and recovers the
  signer from the signature; `payload.signer` and any other field naming a signer are never read. It then holds the
  authorization to the requirement and the mandate, and the settled transfer, the consumed nonce and the
  facilitator's response to the authorization. The first failing rule is the reason, in the order of
  `PROFILE_CHECKS` (18 codes). Permit2, ERC-7710, `upto` and smart-wallet signatures are outside the corpus.
- `status-receipt-binding/v1` (`vectors-status-receipt-binding`, 24 members). The receipt's one signature is
  verified under the authority key the case supplies, never a key the receipt or the credential names. The receipt
  must name the credential by the SHA-256 of its payload, so a swapped capability set or key list is refused even
  when the credential's own signature verifies. Ten checks run in order, `receipt_malformed` to
  `credential_not_active`, and a case that passes all of them is `credential_bound`.

A member whose bytes the strict reader refuses (a repeated member, an integer outside the double range) is an `error`
line, never an accept.

### `actor-marker-survival/v1` (`vectors-actor-marker-survival`, 30 members)

Each member is `cases/<id>/record.json`: a chain of signed statements in which an origin issuer states the token it
sent and each hop states the token it received and the token it sent (RFC 8693 nested `act`, or the `actorChain`
member proposed in a2aproject/A2A issue 2028). Before any member is read, the route loads the corpus's `TRUST.json`
and refuses the whole corpus (exit 2, `NOT RUN`) unless its SHA-256 is the manifest's `trustSha256`. Each writer's
Ed25519 key and its role (`origin`, `agent`, `relay`) come only from that bundle and never from the record. The
record is strict JSON: a repeated member, NaN or a lone surrogate is `record_malformed`. The twenty checks then run
in the corpus's order, and the first that fails is the reason. A chain that passes them all is `accept` /
`marker_survives`. The reader (`actor_marker.py`) is written from the contract and shares no code with the corpus's
Python or Go readers. The tests judge every member, copied under `tests/data/actor-marker-survival/`, and show that
every reader check is the reason of some member.

## Why the rules are ported, not imported

The rule code of each claim type is a port of the corpus's own reader, at the commit named in each
module's docstring. The verifier depends on no corpus package, so a corpus release cannot change the
reference verdicts, and a disagreement between the two readers shows up as `N < M` in the Action. The
tests run every member of each corpus, copied under `tests/data/`, through the kernel.

## What a reference check does not establish

The same limits as each corpus: that a producer recorded truthfully, that clocks agree, that a
signature key belongs to anyone. The restart-records members are unsigned Statements, so signature
checking is out of scope for both restoration types.
