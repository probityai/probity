# Trust boundary

What a decision from agent-evidence-verify tells you, what it leaves open, and what you can check without trusting anyone.

| Topic | Reports | Does not prove | Needs no trust in |
| --- | --- | --- | --- |
| The claim | One decision for one stated claim: `supported`, `contradicted` or `not_established`, with a reason code | That a different claim about the same run holds | The party making the claim |
| The evidence | Every artifact binding and check, against the bytes you supplied and pinned | That those bytes are complete, or a true account of what happened; it checks supplied bytes only and fetches no URL | Whoever produced or sent the bytes: a changed byte changes the binding |
| The policy | The SHA-256 of the policy the decision was made under | That the policy is the right one for your use | A policy you did not pin: the digest shows which one ran |
| Authority | Whether the supplied records meet the authority checks the policy names | Who the named authority really is; the verifier does not authenticate it | An authority's own report of its decision |
| Observation | The producer and vantage the consumer pinned, for adapters that carry them ([observation vantage](observation-vantage.md)) | That an observer was independent of the operator, unless a witness with separate keys says so | The agent's own account of what it did |
| Running the check | The same decision on every replay of the same inputs, version and policy | That your application should act: authorization stays with your application | A network, a hosted service, or the issuer's code: it runs offline from a pinned release |

A `supported` decision means the stated claim passes the pinned policy's checks. Read it as that, and as nothing wider.
