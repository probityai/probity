# Trajectory chain

`TrajectoryRecorder` wraps an `emit()`-style telemetry call. Each event is
written as one JSONL entry `{"seq", "prev", "event"}`:

- `seq` counts from 1 per trajectory, with no gaps;
- `prev` is the SHA-256, in lowercase hex, of the RFC 8785 bytes of the
  previous entry; the first entry names `0` repeated 64 times;
- `event` is the caller's JSON object, unchanged.

The entry digest has no domain prefix, so any RFC 8785 library recomputes
every link. The bytes follow the observer's JSON profile: integers below 2^53,
no floats, ASCII member names. That is the `jcs_integer_only_v1` value of the
agent-evidence vocabulary term
[`canonicalization`](https://w3id.org/agent-evidence/vocab/v1/canonicalization);
on that input the bytes equal plain `rfc8785`, so either declaration is
accepted and every other value is refused.

```python
from pathlib import Path
from probity_observer import SigningKey, TrajectoryRecorder, verify_trajectory

recorder = TrajectoryRecorder(Path("trajectory.jsonl"))
recorder.emit({"type": "tool.call", "tool": "lookup", "status": "ok"})
head = recorder.close(witness_key)          # witness_key is held outside the agent
verify_trajectory(Path("trajectory.jsonl"), head, pinned_witness_public_hex)
```

`close(witness)` writes a head in the `probity-witness-ledger-head-v0` format
used by the [witness ledger](WITNESS-LEDGER.md): `format`, `count`, `head`
(the last entry's digest), `keyid` and an Ed25519 `signature`. The recorder
never holds the witness key; `head_payload()` gives the unsigned payload when
the signer lives in another process.

`verify_trajectory(path, retained_head, pinned_witness_key, canonicalization=...)`
refuses, each with a named reason:

| Edit | Reason |
|---|---|
| an entry dropped | seq is not contiguous, or (relinked) tail missing |
| two entries swapped | seq is not contiguous, or (relinked) last entry differs from the witnessed head |
| a status flipped or a body edited | prev does not link, or (relinked) last entry differs from the witnessed head |
| a `prev` rewritten | prev does not link |
| the tail truncated | tail missing |
| entries appended after close | entries past the witnessed head |
| the log rewritten and a head re-signed with another key | head key differs from the pinned witness key, or the signature does not verify |

The chain alone fixes the start and the middle of a trajectory. Only the
witnessed head fixes the end, and only when the consumer pins a witness key
the producer does not hold (the `witnessed` value of the vocabulary term
`trajectory_head`). A head signed by the producer's own key fixes the end
against a third party who edits storage, never against the producer. A
verified trajectory says the entries are the ones the witness counted at
close; it does not say who produced the events or that they are true.
