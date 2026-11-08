# probity-temporal

A Temporal plugin that lets an agent's gated activity run only under a single-use permit bound to its exact arguments, and writes a signed record of what ran that anyone can verify offline.

It is for teams running agent tool calls as Temporal activities who need a human approval, or M of N approvals, enforced and provable.

Install: `pip install probity-temporal==0.1.0`

```sh
probity-temporal demo run --dir demo-out
probity-temporal verify demo-out --key demo-out/authority.pub --checkpoint demo-out/checkpoint.json --policy demo-out/policy.json
```

The demo starts a local Temporal dev server, pauses a $40 refund for approval, refuses an edit made after approval, refuses another run's approval, kills the worker after the bank commits, and then verifies the journal with the network disabled. The verify command prints `PASS: 7 of 7 records verified` style output and exits 0 only on PASS.

```python
from temporalio.worker import Worker
from probity_temporal import LocalAuthority, ProbityPlugin

authority = LocalAuthority(root, {"human:ops-lead": approver_public_pem})
plugin = ProbityPlugin(authority, gated_activities=[refund_payment])
Worker(client, task_queue="refunds", workflows=[RefundWorkflow], activities=[refund_payment], plugins=[plugin])
```

## What it enforces

- One permit per call, bound to the argument digest; a second use, edited arguments or another run's approval is refused.
- M of N approvals, each by a distinct approver, with revocation that fails closed when stale.
- A call whose reply is lost is reconciled with the system of record before any resend; a committed call comes back as success.
- 30 stable `PROBITY_*` error codes with a stated retry split; shadow mode records decisions without blocking.
- Local-activity blocking, signal and update allowlists, Nexus gating, continue-as-new principal, async completion, OpenTelemetry spans and metrics with bounded labels.

## Status

Version 0.1.0. Tests run against a real Temporal dev server.

| Doc | Content |
|---|---|
| [probity-records](../probity-records/README.md) | the record format and the offline verifier |
| [probity-guard](../probity-guard/README.md) | inline content guard for the same calls |
