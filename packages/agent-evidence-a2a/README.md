# agent-evidence-a2a

Verify A2A agent card signatures over the bytes the server sent, and score any card verifier, canonicaliser or webhook SSRF judge on shipped corpora.

It is for authors of A2A agents, SDKs and conformance suites who need a card verdict that matches the wire, not a parsed object.

```sh
pip install agent-evidence-a2a
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
| `judge_signature` | Judges one member of a card's `signatures` array (CARD-SIGN-001 to 004) and names the non-JCS form a failing signature verifies over. `lookup` takes any `kid -> key` function. |
| `settle_signatures` | Applies the card's signer policy (distinct-signer threshold, required signers, key rotation) to the judgements of all its signatures. `verify_served_card` is `read_signed_card`, then `judge_signature` per signature, then this, so a verifier that calls the three reaches the same verdict on every card. |
| `read_signed_card` | Reads a served card's signatures, signing payload and non-JCS forms from one parse, and says which of three things a card with nothing to judge is: unsigned, a `signatures` member that is not an array, or no RFC 8785 form. |
| `verify_detached` | The byte-level detached JWS check under `judge_signature`, for a caller that resolves its key another way (an `x5c` leaf). |
| `check_canonicaliser` | Runs the 57 vectors against your canonicaliser, and against your card-to-signing-bytes function when you pass one. |
| `score_card_verifier` | Scores any `served bytes -> accepted` function on the card corpus: the cards it must accept, the cards it must reject, and the probes whose verdict waits on the spec. |
| `score_ssrf_judge` | Scores a webhook URL judge on 42 URLs with resolved ground truth. |
| `judge_url` | A reference judge: refuses a URL whose host, by RFC 3986, is or resolves to a non-global address (obfuscated IPv4, IPv4-mapped IPv6, `localhost`, userinfo tricks). |
| `probe` | Judges an endpoint's transport: the scheme is `https`, the session reaches TLS 1.3, and the server's certificate chain verifies for its host name: `agent-evidence-a2a tls https://agent.example/a2a`. |

Exit 0 means the card was accepted, the posture passed or the score is clean; 1 means it was not.

## Documentation

| page | read it for |
| --- | --- |
| [Card answer key](https://github.com/probityai/probity/blob/main/packages/agent-evidence-a2a/src/agent_evidence_a2a/data/answer_key.tsv) | what each card breaks and which check catches it |
| [Data checksums](https://github.com/probityai/probity/blob/main/packages/agent-evidence-a2a/src/agent_evidence_a2a/data/MANIFEST.json) | the SHA-256 of every shipped data file |
| [Schema table script](https://github.com/probityai/probity/blob/main/packages/agent-evidence-a2a/scripts/agent_card_schema.py) | rebuilding the Agent Card field table from a2a-sdk |
| Command line | `agent-evidence-a2a --help` |
