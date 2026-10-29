# Evaluator Replay Kit: specification v0.1

An evaluator receives an action record from a lab: the ordered list of things an agent did during an evaluation run. The evaluator wants to know two things before reading any of it. Is every byte the lab wrote still the byte it wrote (no tamper), and is every step the lab wrote still present (no gap)? This kit answers both offline, from the record and a small pin the evaluator holds, without trusting the lab's tooling.

The kit does not decide whether the agent behaved well, whether a signature is genuine, or whether the lab told the truth about what it left out. It decides whether the record the evaluator holds is the whole record the pin describes.

## 1. Terms

- **Record**: a UTF-8 file of lines, one JSON object per line, in the order the lab wrote them (`record.jsonl`).
- **Step**: one line of the record.
- **Line digest**: the lowercase hex SHA-256 of a step's line bytes, without its line terminator.
- **Pin**: bytes the evaluator holds outside the lab's reach, in `pin.json` (section 5). Every member of a pin is optional; each one that is present enables the checks it names.

## 2. Record format

The record format is the sidecar chain of the AI Agent Action predicate (in-toto/attestation#588), so a record that predicate's writers produce replays here unchanged.

1. Each line is the RFC 8785 (JCS) canonicalization of one JSON object, encoded as UTF-8, followed by `\n`. Every number is an integer of magnitude below 2^53. A line that parses but whose bytes differ from the canonical form of what it parses to is not canonical (section 4, `line_not_canonical`).
2. Each object has a string member `id`, unique in the record, and a string member `previousHash`.
3. The first step carries `previousHash` of the literal `genesis`. Every later step carries the line digest of the step before it.
4. All other members are opaque to the kit. They are covered by the line digest, so changing any of them changes the digest.

The canonical form and the integer rule are taken from `agent_evidence_vectors.auditrecord.canonical_bytes`, the reference implementation in `agent-evidence-vectors`. The kit adds no canonicalizer of its own.

## 3. Verdicts

A replay returns one verdict, a list of findings, and an end statement.

| verdict | meaning | CLI exit |
| --- | --- | --- |
| `intact` | no finding | 0 |
| `tampered` | at least one tamper finding | 1 |
| `gap` | no tamper finding, at least one gap finding | 1 |
| `broken` | the chain does not link and no pin explains why | 1 |
| `invalid` | the input cannot be read as a record | 2 |

`tampered` outranks `gap`, which outranks `broken`. Each finding has `code`, `class` (`tamper`, `gap` or `unresolved`), `index` (zero-based line, or null), `id` (or null) and `detail`.

The end statement is `proven` when the pin's `head` equals the last line's digest, and `unproven` otherwise. A record with an intact chain and no head is a prefix: nothing in it shows that the lab did not stop writing early. `--require-end` turns `unproven` into the finding `end_unproven` (class `gap`).

## 4. Checks

The kit reads the whole record before it judges any of it. Checks run in this order and none stops the others.

1. **Readable.** The file is UTF-8; every line is a JSON object with no duplicate member, no fraction or exponent, no integer at or above 2^53; `id` and `previousHash` are strings. Any failure is `invalid`, with the line index. The kit does not guess what a broken line meant.
2. **`line_not_canonical`** (tamper). A line's bytes differ from the canonical form of its parsed object. A log shipper that re-serializes JSON triggers this by design: the line digest no longer matches what the lab computed.
3. **`id_duplicate`** (tamper). Two steps share an `id`. Two steps with one identifier and different digests are a fork.
4. **`genesis_missing`** (unresolved). The first step's `previousHash` is not `genesis`.
5. **`link_broken`** (unresolved until classified below). Step *i* names a `previousHash` other than the digest of step *i-1*.
6. **Pinned records.** When the pin carries `records` (a map of `id` to line digest):
   - `step_missing` (gap): a pinned `id` is absent from the record.
   - `digest_mismatch` (tamper): a pinned `id` is present with another digest.
   - `step_unpinned` (tamper): the record holds an `id` the pin does not list.
7. **Pinned end.** When the pin carries `count` and `head`:
   - `tail_truncated` (gap): the record has fewer steps than `count`, or `head` equals the digest of an earlier step.
   - `head_mismatch` (tamper): `head` equals the digest of no step.
   - `count_mismatch` (tamper): the record has more steps than `count`.
8. **Classify `link_broken`.** A broken link is a symptom, not a cause. When the pin supports it, the finding takes the class of its cause: if step *i*'s `previousHash` equals the pinned digest of an `id` that is absent, the class is `gap` (`step_missing` explains it); if it equals the pinned digest of a present step whose digest differs, the class is `tamper` (`digest_mismatch` explains it). Otherwise it stays `unresolved`. Without a pin the kit can say the chain is broken and where; it cannot say whether a step was removed or altered, and it does not pretend to.

## 5. Pin

```json
{
  "schema": "evaluator-replay-pin/v1",
  "count": 3,
  "head": "<line digest of the last step>",
  "records": { "<id>": "<line digest>" }
}
```

`evaluator-replay pin RECORD` writes a pin from a record. Write it when you first receive a record you trust, from a channel the lab does not control, and keep it elsewhere. A pin taken from the same bundle you are checking proves nothing: whoever altered the record altered the pin.

## 6. What this does not establish

- Authorship. The chain is unsigned. Whoever writes a whole new consistent chain makes an `intact` record. Verify the lab's signature or witness separately, then replay.
- Completeness against the world. A pinned record shows no step was lost since the pin was taken. It does not show the lab recorded every action the agent took.
- Behaviour. Replaying the digest chain does not re-run any tool call. Re-execution of recorded actions in a sandbox is the next layer (section 8).

## 7. Relation to other tools

- `agent-evidence-vectors` supplies the canonicalization used here and the conformance records the tests replay.
- `probity-verify` judges claims an agent made against bytes a consumer pinned (for example a done receipt). This kit judges the record of actions itself. An evaluator can run both: this kit first, to know the record is whole, then the claim check on what the record says.

## 8. Planned layers

1. ZIP bundles holding `record.jsonl`, `pin.json` and the artifacts a step names by digest (`artifactSha256`): a changed artifact is tamper, an absent one is a gap.
2. Signed pins (DSSE) and witness heads.
3. Re-execution of recorded tool calls against a recorded environment, flagging divergence.
