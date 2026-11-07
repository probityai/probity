# agent-evidence-replay

Replay a lab-produced agent action record: recompute its digest chain and flag a changed step (tamper) or a missing one (gap).

It is for evaluators and auditors who receive an action record from an AI lab and need to know the record is whole before they read it.

```sh
pip install "git+https://github.com/probityai/probity@agent-evidence-replay-v0.1.0#subdirectory=packages/agent-evidence-replay"
git clone --branch agent-evidence-replay-v0.1.0 https://github.com/probityai/probity && cd probity/packages/agent-evidence-replay
agent-evidence-replay verify tests/fixtures/accept-3
agent-evidence-replay verify tests/fixtures/gap-2 --pin tests/fixtures/accept-3/pin.json
```

The first record is a real three-step chain from the AI Agent Action conformance suite. It replays intact and the pin proves where it ends. The second is that chain with its middle step removed:

```text
intact: 3 steps, end proven
gap: 2 steps, end proven
  link_broken [gap] line 1 r3: previousHash is '7c6c5a39...', expected 'd85166b0...'; the pin names step 'r2' here
  step_missing [gap] r2: a pinned step is absent
```

Exit 0 means intact, 1 means tampered, gap or broken, 2 means the record cannot be read. `--json` prints the findings as JSON.

## How to use it

1. When you first receive a record, make a pin and keep it where the lab cannot reach: `agent-evidence-replay pin record.jsonl > pin.json`.
2. Replay every later copy against that pin: `agent-evidence-replay verify record.jsonl --pin pin.json --require-end`.
3. A pin made from the bundle you are checking proves nothing. Whoever changed the record changed the pin.

A chain with no pin can still say where it breaks, but not whether a step was removed or altered. With a pin it names the cause.

## Status

Version 0.1.0. The digest chain, the pin and the tamper and gap findings work and are tested against a real record and edits of it. The chain is unsigned, so a whole new consistent chain replays intact; check the lab's signature separately. Re-running the recorded tool calls is not built yet.

## Documentation

| page | read it for |
| --- | --- |
| [Specification](https://github.com/probityai/probity/blob/main/packages/agent-evidence-replay/SPEC.md) | the record format, every check and finding code, the pin, and what a replay does not establish |
| [Fixtures](https://github.com/probityai/probity/blob/main/packages/agent-evidence-replay/tests/fixtures/README.md) | where the test records come from |

## Next

- ZIP bundles that also pin the artifacts a step names (SPEC section 8, layer 1): `agent-evidence-replay verify bundle.zip`.
- Signed pins and witness heads (layer 2).
- Re-execution of recorded tool calls against a recorded environment (layer 3).
