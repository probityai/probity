# Check a past decision against an agent's signed identity history

Use `agent_identity_statement/v1` to check, after the fact, that the key an agent signed with was in force and the agent was active at the instant you acted on it. The issuer keeps the agent's identity document as a signed history: one DSSE-signed in-toto Statement per version, of predicate type `https://w3id.org/agent-evidence/predicate/v1/agent-identity-statement`. Each version names the agent, its number, the key set in force, a status (`active`, `suspended` or `revoked`), when it was issued and when it takes effect, and the SHA-256 of the previous version's signed payload. The check runs offline from bytes you hold and pins you keep.

## Inputs

The case binds the history and, when you hold it, the decision envelope the agent signed. The assessment has:

- `claim_type`: `agent_identity_statement/v1`
- `history`: the case artifact holding the history, a JSON list of DSSE envelopes in any order
- `issuer_keys`: the issuer's Ed25519 public keys you pin, as 64-character lowercase hex
- `agent`: the agent you pin, exactly `{"issuer": <https URL>, "subject": <text>}`
- `head_sha256`: the SHA-256 of the newest version's signed payload, as you last fetched it
- `at`: the instant you acted, `YYYY-MM-DDTHH:MM:SSZ`; the check never reads the machine clock
- the key you relied on, by exactly one of `key_sha256` (the SHA-256 of the raw key, the key id the predicate and the revocation list use) or `jwk_thumbprint` (its RFC 7638 thumbprint as an OKP JWK, the `keyid` a Web Bot Auth signature carries)
- `decision` (optional): the case artifact holding the DSSE envelope the key signed for this decision, with exactly one signature; its unsigned `keyid` is not read

The issuer's keys verify every version, and the key you name is looked up in the versions' own key sets. A key, issuer or URL a version or an envelope names is never fetched or trusted.

`jwk_thumbprint` is the join with [`web_bot_auth/v1`](web-bot-auth.md): a request that check found signed by key `K` at time `t` can be checked here with `jwk_thumbprint: K` and `at: t`, so you learn whether the issuer still listed `K` for that agent at `t` and had not suspended or revoked it.

## The checks

The checks run in this order, and the first that fails names the reason. They are the 25 checks of the corpus reader in agent-evidence-vectors, with the same codes:

1. `history_malformed`: the history is a non-empty strict JSON list of DSSE envelopes with payload type `application/vnd.in-toto+json`.
2. `statement_signature`: every envelope is signed by a pinned issuer key.
3. `statement_malformed`, `statement_type_wrong`, `predicate_type_wrong`, `subject_malformed`, `predicate_malformed`: each payload is an in-toto Statement v1 of this predicate type with one subject and a well-formed predicate (keys sorted and distinct, `previous` present exactly when the version is above 1, times in whole UTC seconds).
4. `active_without_keys`, `effective_after_issued`: no version is active with no keys, or takes effect after it was issued.
5. `agent_mismatch`: every version names the agent you pinned.
6. `history_no_genesis`, `history_forked`, `history_previous_missing`, `version_not_incremented`, `version_gap`, `history_time_reversed`, `revoked_is_final`: the versions form one chain from version 1, with no fork, missing link, gap, backwards time, or version after a revocation.
7. `history_head_mismatch`: the chain ends at the head you pinned.
8. `decision_malformed`, `key_unknown`, `decision_signature`: the decision envelope is well formed, the key you name is listed in some version, and it signed the envelope.
9. `decision_before_history`, `agent_suspended`, `agent_revoked`, `key_not_in_force`: at `at` a version was in force (the highest version whose `effectiveAt` is not after `at`), the agent was neither suspended nor revoked in it, and the key was in its key set.

A revocation may be backdated: its `effectiveAt` may precede its `issuedAt`, so a decision made after the effective instant is refused even when the revocation was signed later.

## Decisions

| decision | reason | when |
| --- | --- | --- |
| `supported` | `key_in_force` | every check holds |
| `contradicted` | the first failing check | the history, or the decision envelope, refutes the claim |
| `not_established` | `history_unavailable`, `decision_unavailable` | a bound artifact is not present |

`scope` carries the pins, the key under both names (`key_sha256` and `jwk_thumbprint`) once it is found, and `version_in_force` (`version`, `sha256`, `status`, `effectiveAt`) once the instant is placed. Without a decision envelope, `decision_malformed` and `decision_signature` are reported `not_applicable`. An assessment value that is malformed, or that names the key twice or not at all, is invalid input: exit 2, no verdict.

## Corpus mode

`agent-evidence-verify corpus <dir>` judges `corpora/vectors-agent-identity-statement` member by member through the same checks: each member's `context.json` holds the pins, `history.json` the history and `decision.json` the instant and the envelope, whose one signature names its key by `keyid`. Pins that cannot be read are refused with `history_malformed`, as the corpus reader refuses them. See [reference routes](corpus-routes.md).

## What it does not establish

A supported decision means the issuer's history, as far as your pinned head, listed the key for that agent at that instant and did not suspend or revoke it. It does not establish that your head is the issuer's newest version (it is as fresh as your last fetch), that the key was not revoked in a separate revocation list, or what the decision was about: the envelope is checked only for the key's signature over its bytes.

Strict JSON here is I-JSON: a repeated member, NaN, a lone surrogate or an integer outside plus or minus (2^53 - 1) is refused where it is read. The corpus reader accepts a larger integer and a lone surrogate before its own rules refuse the record, so for such bytes the two readers can name different first checks; both refuse.
