# agent-evidence-a2a

Verify A2A agent card signatures over the bytes the server sent, and score any card verifier, canonicaliser or webhook SSRF judge on shipped corpora.

It is for authors of A2A agents, SDKs and conformance suites who need a card verdict that matches the wire, not a parsed object.

```sh
pip install agent-evidence-a2a==0.1.0
```

```python
from agent_evidence_a2a import TrustStore, check_canonicaliser, verify_served_card
from agent_evidence_a2a.vectors import reference_canonicalize

report = check_canonicaliser(reference_canonicalize)
print(report.passed, "of", report.total)

verdict = verify_served_card(open("card.json", "rb").read(), TrustStore.from_file("trust.json"))
print(verdict.accepted)
```

The first print shows `57 of 57`. The same check runs from the shell, and exits 1 when your canonicaliser fails a vector:

```sh
agent-evidence-a2a canonicaliser --impl yourpkg.jcs:canonicalize
agent-evidence-a2a corpus --verifier yourpkg.cards:accepts
agent-evidence-a2a ssrf --judge yourpkg.webhooks:refuses
```

## Status

Version 0.1.0, alpha. The verifier, the 57 `a2a-jcs-v01` vectors, the 43-card corpus and the 42-URL webhook corpus are complete. The packaged verifier rejects all 28 attack cards and accepts all 11 controls; 4 probes wait on the spec text of [A2A#2122](https://github.com/a2aproject/A2A/issues/2122) and are never scored. The reference judge refuses all 30 unsafe webhook URLs and none of the 6 safe ones.

## What is in the package

| Piece | What it does |
| --- | --- |
| `verify_served_card` | Recomputes the signed payload from the served bytes (RFC 8785), rejects a repeated member name or an appended member, checks every `kid` against a pinned trust store with validity windows, and applies a signer threshold. |
| `check_canonicaliser` | Runs the 57 vectors against your canonicaliser, and against your card-to-signing-bytes function when you pass one. |
| `score_card_verifier` | Scores any `served bytes -> accepted` function on the card corpus: the cards it must accept, the cards it must reject, and the probes whose verdict waits on the spec. |
| `score_ssrf_judge` | Scores a webhook URL judge on 42 URLs with resolved ground truth. |
| `judge_url` | A reference judge: refuses a URL whose host, by RFC 3986, is or resolves to a non-global address (obfuscated IPv4, IPv4-mapped IPv6, `localhost`, userinfo tricks). |
| `probe` | Judges AUTH-TLS-001, AUTH-TLS-002 and AUTH-SERVER-001 for an endpoint: `agent-evidence-a2a tls https://agent.example/a2a`. |

Exit 0 means the card was accepted, the posture passed or the score is clean; 1 means it was not.

## Documentation

| page | read it for |
| --- | --- |
| [Card answer key](https://github.com/probityai/probity/blob/main/packages/agent-evidence-a2a/src/agent_evidence_a2a/data/answer_key.tsv) | what each card breaks and which check catches it |
| [Data checksums](https://github.com/probityai/probity/blob/main/packages/agent-evidence-a2a/src/agent_evidence_a2a/data/MANIFEST.json) | the SHA-256 of every shipped data file |
| [Schema table script](https://github.com/probityai/probity/blob/main/packages/agent-evidence-a2a/scripts/agent_card_schema.py) | rebuilding the Agent Card field table from a2a-sdk |
| Command line | `agent-evidence-a2a --help` |
