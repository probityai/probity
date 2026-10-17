# Spend reservations

`spend_reservation/v1` replays a budget journal against three separately
selected inputs: the budget policy, its price table, and the trace. It checks
that each dispatch has one affordable reservation for that exact call and
attempt. Verify imports no Admission code.

Use [this tested source](https://github.com/probityai/probity-verify/tree/49539af7265ae516934123e2f310f7206f520da2)
for the adapter and generated examples:

```sh
git checkout 49539af7265ae516934123e2f310f7206f520da2
uv run probity-verify examples/spend-reservation/accepted/case.json \
  --policy examples/spend-reservation/accepted/policy.json --json
```

The examples use invented records and `fixture-credit` prices. Regenerate
them with `python examples/spend-reservation/generate.py`; `--check` verifies
their exact bytes and bindings.

| Example | Decision | Budget record |
| --- | --- | --- |
| `accepted` | `supported` | Reserve 27, dispatch once, settle 12, refund 15. |
| `pending` | `supported` | Keep 27 reserved while the dispatch receipt is missing. |
| `refused-overshoot` | `supported` | Refuse the 107 maximum against a 100 budget before dispatch. |

Here, `supported` covers the supplied journal's budget rules. A correct
refusal is a passing record. It does not authorize the refused call. Pending
dispatches stay charged at their full maximum; their executed cost and
outcome remain unestablished. The packet reports held maxima, recorded
settlements, and the conservative remaining budget separately.

## Consumer selection

Use the existing `probity-case/v1` and `probity-policy/v1` envelopes. The
assessment has these exact fields:

```json
{
  "claim_type": "spend_reservation/v1",
  "budget_id": "budget-1",
  "budget_policy_witness": "budget",
  "price_table_witness": "prices",
  "trace_witness": "trace"
}
```

Each witness selects a distinct artifact with `artifact`, `sha256`, and
`authority`. Case bindings also give its relative path and byte length.
Missing files or bindings that fail the consumer pin return
`not_established`. Duplicate JSON members, non-finite numbers, wrong fields,
and malformed records exit 2 without a verdict.

The budget policy is `probity-spend-policy/v1`; the journal is
`probity-spend-trace/v1`. All policy, price, and call identity hashes use
sorted compact ASCII JSON **without a trailing newline**. Artifact pins
hash the actual file bytes, including their newline.

## Replay rules

- Price the input limit, output limit, and fixed cost before reserving.
- Bind provider, model, target, argument digest, call id, attempt, limits,
  and selected price version through the dispatch.
- Keep event sequences contiguous and the host clock monotonic. Check
  policy and price windows at reservation and dispatch.
- Count every concurrent reservation against the same budget. A used
  reservation cannot authorize another dispatch.
- Settle only a dispatched call. Reject a settlement above its reserved
  bound, even if its producer freezes future admissions.
- Refund unused cost after settlement. Cancellation can release only a
  reservation that was never dispatched. A missing settlement refund is
  `not_established` and leaves the maximum held in the packet.
- Check each refusal reason and balance; a refusal cannot release money.

These are checks over pinned records. Establish the host clock, price
source, tool cost bounds, settlement receipt and trace capture separately.
An Observer checkpoint can bind its captured bytes upstream; this adapter
does not authenticate that signature or prove a provider's bill.

The [S005 source sweep](https://github.com/piiiico/agent-errata/blob/e9a247004c84aa505e8df0dbfc5fbbdae5924298/studies/S005.md)
is a useful target: distinguish a stop after a reported charge from a
reservation before the next call. Its measurements use a stand-in API.
These examples are separate finite controls, with no real provider quote
or billing run.
