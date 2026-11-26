# Choose a claim check

Choose a task, then install the same source snapshot as its recipe index in a [separate environment](install.md#use-this-checkouts-recipe-index).
All examples are authored synthetic records. They do not establish independent operation or live framework execution.

| Task | Claim type | Expected decision | Scope |
| --- | --- | --- | --- |
| [Check a selected passage against a retained report](running.md) | `source_text_coverage/v1` | `contradicted` | Synthetic source and report; local bytes only. |
| [Find missing evidence for an earlier source date](running.md) | `source_text_coverage/v1` | `not_established` | Synthetic June capture; April policy remains unresolved. |
| [Check a complete retained report](running.md) | `source_text_coverage/v1` | `supported` | Synthetic complete report; selected passages only. |
| [Check an output against the operands used](adapters.md) | `operand_lineage/v1` | `supported` | Synthetic local execution record; declared operands only. |
| [Check a claim against a captured authority](adapters.md) | `authority_anchor/v1` | `supported` | Synthetic authority capture; no source authentication or live fetch. |
| [Check bounded absence in a declared interval](adapters.md) | `event_absence/v1` | `supported` | Synthetic observation; consumer-selected interval and producer. |
| [Check absence within a selected observation vantage](observation-vantage.md) | `event_absence/v2` | `supported` | Synthetic selected scope; outside effects remain uncovered. |
| [Detect an observed write that contradicts absence](observation-vantage.md) | `event_absence/v2` | `contradicted` | Synthetic target observation; selected write only. |
| [Keep a self-reported write separate from observation](observation-vantage.md) | `event_absence/v2` | `not_established` | Synthetic self-report; no separately observed target effect. |
| [Replay a budget reservation journal](spend-reservation.md) | `spend_reservation/v1` | `supported` | Synthetic prices and journal; no provider billing execution. |
| [Check broker-recorded file completion](brokered-file-write.md) | `brokered_file_write/v1` | `supported` | Synthetic signed broker records; public fixture keys; PEER scope only. |
| [Check that an agent left its protected tests alone](done-receipt.md) | `protected_paths/v1` | `supported` | Synthetic observer records; PEER scope; recorded paths only. |
| [Detect a planted conftest.py in a protected test directory](done-receipt.md) | `protected_paths/v1` | `contradicted` | Synthetic observer records; PEER scope; recorded paths only. |
| [Keep protected-path absence open when observer events were lost](done-receipt.md) | `protected_paths/v1` | `not_established` | Synthetic observer records with unknown coverage. |
| [Check acceptance graded outside the agent on its final tree](done-receipt.md) | `acceptance_observed/v1` | `supported` | Synthetic grade and tree records; PEER scope. |
| [Detect acceptance that fails when the verifier reruns it](done-receipt.md) | `acceptance_observed/v1` | `contradicted` | Synthetic grade and tree records; PEER scope. |
| [Refuse support from a contract that killed no mutant](done-receipt.md) | `acceptance_observed/v1` | `not_established` | Synthetic contract with zero mutation adequacy. |
| [Match a claimed test run to an observed exec after the last edit](done-receipt.md) | `tool_claim_match/v1` | `supported` | Synthetic observer records; exact argv; PEER scope. |
| [Detect a claimed test run that never executed](done-receipt.md) | `tool_claim_match/v1` | `contradicted` | Synthetic observer records; exact argv; PEER scope. |
| [Keep a claimed run open when observer events were lost](done-receipt.md) | `tool_claim_match/v1` | `not_established` | Synthetic observer records with unknown coverage. |
| [Accept done, ungamed work from a receipt whose two verdicts derive again](done-receipt.md) | `done_receipt/v2` | `supported` | Synthetic records and an unsigned receipt Statement; PEER scope. |
| [Refuse work that passed its tests while the agent tampered with the grader](done-receipt.md) | `done_receipt/v2` | `contradicted` | Synthetic records and an unsigned receipt Statement; PEER scope. |
| [Refuse unfinished work an honest agent did not claim done](done-receipt.md) | `done_receipt/v2` | `contradicted` | Synthetic records and an unsigned receipt Statement; PEER scope. |
| [Check an agent's completion assertion against the runs the observer saw](done-receipt.md) | `completion_claim/v1` | `contradicted` | Synthetic observer records; PEER scope. |
| [Check a contract's oracle-free probes on a split whose behavioural tests passed](done-receipt.md) | `probe_observed/v1` | `supported` | Synthetic verifier grade; PEER scope. |
| [Detect a done receipt that reports verdicts its records do not give](done-receipt.md) | `done_receipt/v2` | `contradicted` | Synthetic records and an unsigned receipt Statement; PEER scope. |
| [Check an adversarial execution evidence statement](adapters.md) | `adversarial_execution_evidence/v1` | `supported` | Conformance-corpus statement signed with a published test key; the key carries no trust outside the corpus. |
| [Check a trail whose effect may have happened after a lost reply](corpus-routes.md) | `uncertain_effect/v1` | `supported` | Authored synthetic corpus member; it does not establish that the trail was recorded truthfully. |
| [Check one restoration-evidence record](corpus-routes.md) | `restoration_record/v1` | `supported` | Authored synthetic corpus member; unsigned, and a pass is no finding that the decision was right. |
| [Check a restoration-evidence bundle](corpus-routes.md) | `restoration_bundle/v1` | `supported` | Authored synthetic corpus member; unsigned, and a pass is no finding that the decision was right. |
| [Check canonical bytes for an A2A Agent Card signature](corpus-routes.md) | `jcs_canonical/v1` | `supported` | Vector A2-001 of a2aproject/a2a-tck; it recomputes bytes and checks no signature. |
| [Check a signed Observed Effect record](corpus-routes.md) | `observed_effect/v1` | `supported` | Authored synthetic corpus member; signed with a published test key that carries no trust outside the corpus. |
| [Check the principal an agent audit record names](corpus-routes.md) | `audit_principal/v1` | `supported` | Authored synthetic corpus member; signed with a published test key that carries no trust outside the corpus. |
| [Check an agent audit record, its retention entry and its dating](corpus-routes.md) | `agent_audit_record/v1` | `supported` | Authored synthetic corpus member (R17 of vectors-agent-audit-record); signed with a published test key that carries no trust outside the corpus. |
| [Check a Proof-of-Control token chain, inclusion proof or canonical form](corpus-routes.md) | `proof_of_control/v1` | `supported` | Member of the poc-evidence-vectors corpus; its keys and roots carry no trust outside the corpus. |
| [Check that a stream of signed CBOR receipts is one whole, ordered chain](cbor-receipt-chain.md) | `cbor_receipt_chain/v1` | `supported` | Authored synthetic stream; signed with a published test key that carries no trust outside the example. |
| [Reconcile the principal each signed agent audit record names with identity-provider log events](adapters.md) | `idp_log_witness/v1` | `supported` | Authored synthetic identity-provider export over two corpus members; signed with a published test key that carries no trust outside the corpus. |
| [Check an identity provider's signed token grant receipt against the grant you expect](token-grant-receipt.md) | `token_grant_receipt/v1` | `supported` | Recorded Keycloak client-credentials grant from the hook's end-to-end run; the recorder key signs only that run and carries no trust outside it. |
| [Check that an evaluation claim record is admitted under my acceptance rule](evaluation-claim.md) | `evaluation_claim/v1` | `supported` | Record, profile and case set from the agent-evidence-vectors claim_record corpus; the implementation and verifier digests name example bytes. |
| [Decide what a signed Observed Effect record lets a verifier conclude](adapters.md) | `evidence_sufficiency/v1` | `supported` | Authored synthetic corpus member and a stipulated consumer context; it does not establish who holds the observer key. |
| [Check that a request was signed by the agent you pinned, under Web Bot Auth](web-bot-auth.md) | `web_bot_auth/v1` | `supported` | Synthetic signed request and fixture key; pinned directory; no live fetch, no replay state. |
| [Check that no credential is reachable from the agent's environment](corpus-routes.md) | `credential_reachability/v1` | `supported` | Authored synthetic corpus member; signed with a published test key that carries no trust outside the corpus. |
| [Check that the copy a consumer read matches its published digests](telemetry-evidence.md) | `evidence_digest/v1` | `supported` | Authored synthetic record signed or built with test keys that carry no trust outside this example. |
| [Check that an event log is complete against its retained head](telemetry-evidence.md) | `event_log_completeness/v1` | `supported` | Authored synthetic record signed or built with test keys that carry no trust outside this example. |
| [Check that the action an authority released is the action that ran](lifecycle-binding.md) | `lifecycle_binding/v1` | `supported` | Authored synthetic record signed or built with test keys that carry no trust outside this example. |
| [Check an action evidence package layer by layer](aep-package.md) | `aep_package/v1` | `supported` | Authored synthetic record signed or built with test keys that carry no trust outside this example. |
| [Check that an agent capability credential is valid and not exhausted](capability-credential.md) | `capability_credential/v1` | `supported` | Authored synthetic record signed or built with test keys that carry no trust outside this example. |
| [Check who signed an AI Catalog trust manifest and that it binds its entry](catalog-trust-manifest.md) | `catalog_trust_manifest/v1` | `supported` | Catalog, DID documents and artifact of the accept-aic-publisher case of the agent-evidence-vectors catalog-trust-manifest corpus; the consumer pins the publisher's ES256 key, so the verdict says who signed and what the signature binds, not that the artifact is safe. |
| [Check that a DNS-AID record's sig binds it to a key the zone owner published under DNSSEC](dns-aid.md) | `dns_aid_sig/v1` | `supported` | Record and JWKS signed by the dns-aid-core signer at 825ccea; the DNSSEC chain is a test root signed by dnspython, whose DS the policy pins. |
| [Check that a DNS answer I hold offline validates under DNSSEC from the root](dns-aid.md) | `dnssec_rrset/v1` | `supported` | The HTTPS RRset of cloudflare.com and its chain from the IANA root, captured 2026-11-17 and checked at that instant. |
| [Check that every call an agent made went to an endpoint a verified discovery record declared](dns-aid.md) | `declared_versus_acted/v1` | `contradicted` | A trajectory written by agent-evidence-observer's recorder with one declared call and one planted call to an undeclared host; witness key from a fixed test seed. |
| [Check that an A2A Agent Card was signed by a key of its own DID that the consumer trusts](a2a-signed-card.md) | `a2a_signed_card/v1` | `supported` | The valid-conformance-extension card of tests/data/a2a-signed-card; the consumer pins the owner's Ed25519 key under its kid, so the verdict says which key of the card's DID signed the card and that the card names its conformance corpus and verifier inside the signature, not that the agent behaves as the card says. |
| [Check which parties a co-signed tool-call receipt binds and that both keys may speak for them](co-signed-receipt.md) | `co_signed_receipt/v1` | `supported` | The valid-co-signed receipt of tests/data/co-signed-receipt; the consumer pins the agent's and the caller's Ed25519 keys, so the verdict says both parties signed the same bytes, not that the receipt is true or that the parties are independent. |
| [Check that the key a past decision was signed with was in force, and the agent active, in the issuer's signed history](agent-identity-statement.md) | `agent_identity_statement/v1` | `supported` | Synthetic issuer history with a key rotation and fixture keys; pinned issuer keys and head; no revocation list, no live fetch. |

## Retrieve a command

The [JSON recipe index](recipes.json) gives complete case and policy paths, argument arrays, expected reasons and digests.
Every recipe uses the `agent-evidence-verify` distribution and CLI. These source-checkout fixtures need no extra framework package.
`probity-recipes/v2` is a project convention, not a discovery standard.

The JSON `distribution.status` describes package-name availability: `agent-evidence-verify` has a public PyPI release.
It does not assert that the source candidate bound by `package_metadata` has been uploaded.
The separate `fixture_scope` describes where the indexed case and policy files live.

The [pinned registry recipe](install.md#install-the-published-package) pairs version 0.10.0 with the sample inputs its wheel carries.
For this index, install its own checkout, then use the index's `argv` from that checkout root.
Replace its first argument with your installed executable's path when the environment is separate.
The index binds its inputs and implementation to exact bytes.
From the package manifest it binds only the keys that decide the installed command: the build system, name, version, Python requirement, runtime dependencies, scripts and setuptools layout.
Optional extras, URLs, descriptive text and test or lint settings do not reach a recipe decision and are not bound.
Use the index with the source snapshot from which it was generated; a later index may describe newer examples.

All valid decisions exit zero. Malformed inputs exit two without a verdict.
Select your own consumer policy for actual evidence. An example policy is not an authority choice for your deployment.

## Maintain the index

Edit task text and expected decisions in [recipe-source.json](recipe-source.json).
From the repository root, run `uv run --directory packages/agent-evidence-verify python scripts/build-recipes.py` to regenerate both this page and the JSON index.
CI runs the same script with `--check`. When it fails, it names each changed binding and prints that command.

The generator runs actual registered adapters against pinned artifacts.
It refuses an unexpected decision, an incorrect claim, an escaped path or a missing adapter recipe.
CI checks exact generated bytes. Changed code or inputs need a new reviewed index. Keep source fixtures immutable.
