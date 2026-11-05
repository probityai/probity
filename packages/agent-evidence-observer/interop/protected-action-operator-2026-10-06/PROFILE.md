# Protected action with separate operator processes

A company permits one exact agent action. The gateway checks that approval, writes
the target, and saves the result. A reply can disappear after the write. The operator
then needs a safe answer: return a recorded completed result, or refuse another
attempt when the history leaves the outcome unresolved.

This route uses the protected dispatcher and the native witness protocol. The gateway
receives public witness clients and holds the observer key; the witness key stays with
a separate service. A separate consumer checks the approval and native history,
retains signed prefixes, and records one admission. The actual substrate is one local
file replacement. The operator's runtime runs the five-role route (issuer, gateway,
witness, consumer, workload) under distinct process identities; the packet it
produced is retained under `retained/`.

## Replay the retained packets

```sh
python interop/protected-action-operator-2026-10-06/verify_retained.py
```

The driver replays two packets with public code only and compares the retained report
bytes. The witness packet under `retained/existing-native` goes through the
[witness operator reader](../witness-operator-2026-10-03/PROFILE.md). The protected
packet under `retained/native` goes through `probity_protected_operator.reader`: for
each of nine cases it checks the authorization journal against the consumer's initial
outside checkpoint, the native ledger against its initial head, and the candidate heads
against the witness's exported histories. For the two admitted cases it also replays
the full grant-to-native dispatch relation. The wheels and the embedded source files
that are no longer part of this tree are listed with their digests in
`retained/WITHHELD-SOURCES.json`.

| Case | What the retained packet records |
| --- | --- |
| Completion | One target replacement; matching bytes; one consumer admission |
| First workload reply lost | The target completes, the consumer admits, restart replays without replacement |
| Authorization acknowledgment lost, before or after the effect | Witness exit after retention; the target effect is absent or present as recorded |
| Native acknowledgment lost, before or after the effect | Witness exit after retention; the target effect is absent or present as recorded |
| Native witness unavailable | No target effect; automatic restart retry is refused |
| Target crash before or after replacement | Real process exit around the durable write; pending retry is refused |

## Commands and limits

`agent-evidence-authorization-witness init|serve` takes an absolute configuration file
and its SHA-256 selected outside the request channel; see
[`AuthorizationConfiguration.read`](probity_protected_operator/store.py) for the fields.
The service admits only the three journal phases: creation, signed prior relation,
and recorded completion. Requests carry bounded history bytes and a digest. They cannot
select a server pathname, replace a key or reset a store. Restart requires existing
keys, stores, exact configuration and retained signed prefixes.

Use the retained consumer prefix when checking a new candidate. A checkpoint bundled
only with the current candidate cannot detect an earlier rollback.

The route remains `PEER` with evidence vantage `artifact`. The witness signs recorded
histories; its signature alone does not prove target truth, clock truth, complete
capture or global consensus. The recorded run has zero outside human operators and
establishes no provider refund, payment, customer, or SLA.
