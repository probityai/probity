# Trajectory chain

`TrajectoryRecorder` wraps an `emit()`-style telemetry call. A trajectory has
an identifier the consumer knows before it reads anything (its session or run
id). Each event is written as one JSONL entry `{"seq", "prev", "event"}`:

- `seq` counts from 1 per trajectory, with no gaps;
- `prev` is the SHA-256, in lowercase hex, of the RFC 8785 bytes of the
  previous entry; the first entry names the genesis of the identifier, the
  SHA-256 of the RFC 8785 bytes of
  `{"format": "probity-trajectory-genesis-v1", "trajectory": <id>}`;
- `event` is the caller's JSON object, unchanged.

Each entry is its canonical bytes followed by one LF (`0x0A`); the file ends
with an LF and holds no other bytes, so CR, CRLF and blank lines are refused.

No digest has a domain prefix, so any RFC 8785 library recomputes every link. The bytes follow the observer's JSON profile: integers below 2^53,
no floats, ASCII member names. That is the `jcs_integer_only_v1` value of the
agent-evidence vocabulary term
[`canonicalization`](https://w3id.org/agent-evidence/vocab/v1/canonicalization);
on that input the bytes equal plain `rfc8785`, so either declaration is
accepted and every other value is refused.

```python
from pathlib import Path
from probity_observer import TrajectoryRecorder, TrajectoryWitness, verify_trajectory

witness = TrajectoryWitness(witness_key, Path("witness-registry"))   # runs where the agent cannot reach either
recorder = TrajectoryRecorder(Path("trajectory.jsonl"), trajectory_id="run-42", witness=witness)
recorder.emit({"type": "tool.call", "tool": "lookup", "status": "ok"})
head = recorder.close()
verify_trajectory(Path("trajectory.jsonl"), head, pinned_witness_public_hex, trajectory_id="run-42")
```

The witness counts the trajectory itself. `TrajectoryWitness.open(id)`
registers an identifier once and never again, `observe(id, entry)` takes each
entry as the recorder writes it and checks `seq` and `prev` against the
witness's own count and last digest, and `close(id, claimed)` signs the head
the witness counted, refusing a claim whose identifier, count or last digest
differs. A producer that drops the tail, swaps or rewrites an entry the witness
already saw, or opens the identifier again to start over, gets no head for it.
The witness records each identifier it opens as a file in its registry
directory, created exclusively, so the refusal holds across a restart and
across every witness instance that shares the directory. A registry records
the public key it belongs to and refuses a witness under another key. Every
instance of one witness key must use the same registry: a second registry
under the same key would let an identifier open twice. The recorder hands each
entry to the witness before it writes it, so an entry the witness refuses never
reaches the file, and a write that fails after the witness counted the entry
leaves the recorder broken, with no head to be had.
That holds against the producer only when the witness runs in a process or
account the producer cannot reach; in the agent's own process it holds against
a third party who edits storage.

`close()` returns a head in the `probity-trajectory-head-v1` format:
`format`, `trajectory` (the identifier), `count`, `head` (the last entry's
digest, or the genesis for an empty trajectory), `keyid` and an Ed25519
`signature` over the first four, in the `probity-trajectory-head-v1` signing
domain. The domain is not the [witness ledger](WITNESS-LEDGER.md)'s
`probity-witness-ledger-head-v0`, so a witness that signs both never has a
ledger head read as a trajectory head. The recorder never holds the witness
key; `head_payload()` is only its claim, which the witness compares and never
signs.

`verify_trajectory(path, retained_head, pinned_witness_key, trajectory_id=..., canonicalization=...)`
takes the identifier from the consumer, never from the producer's files, and
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
| another trajectory's file and head handed over | head names another trajectory, or (relabelled) the signature does not verify |
| another trajectory's entries under a head for this one | entry 1: prev does not link |
| a witness-ledger head offered as a trajectory head | invalid fields, unsupported format, or the signature does not verify |
| entries separated by CR or CRLF, or a blank line | invalid JSON document, or JSON document is not canonical |

The chain alone fixes the start and the middle of a trajectory. Only the
witnessed head fixes the end, and only when the consumer pins a witness key
the producer does not hold (the `witnessed` value of the vocabulary term
`trajectory_head`). A head signed by the producer's own key fixes the end
against a third party who edits storage, never against the producer. A
verified trajectory says the entries are the ones the witness counted at
close; it does not say who produced the events or that they are true.
