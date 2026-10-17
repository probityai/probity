# Check a customer offer before approval

Use this worked example when an agent proposes a discount to a customer. The
consumer checks the proposed offer against selected customer records, company
rules and, for an exception, an exact manager approval.

The report, including its GREEN status and score of 94, is synthetic and
advisory. It cannot override the company limit or supply missing authority.

## Run the example

From a checkout, install its own environment:

```sh
uv sync --frozen --extra test
uv run --frozen python examples/customer-support-action/consumer.py \
  examples/customer-support-action/cases/green-over-limit/case.json \
  --policy examples/customer-support-action/cases/green-over-limit/policy.json \
  --json
```

The output is:

```json
{"action":"BLOCK","decision":"contradicted","reason":"discount_exceeds_maximum"}
```

| Case directory | Result | Reason |
| --- | --- | --- |
| `routine` | APPROVE | 12% matches the routine rule. |
| `green-over-limit` | BLOCK | 24% exceeds the 18% company maximum. |
| `needs-manager` | HOLD_FOR_REVIEW | The 16% exception lacks selected approval bytes. |
| `exact-manager` | APPROVE | The selected grant matches the request, action, recipient, plan, amount and draft. |

All four cases are independently authored records. They contain no sealed
event inputs. Run `uv run --frozen python
examples/customer-support-action/generate.py --check` to rederive their bytes
and bindings. Edit the generator when changing these examples.

## Carry the decision to another machine

Add `--bundle /tmp/support-decision.zip` to a case command. Bundle creation
carries every declared artifact, the consumer policy and the full decision.
It refuses a declared artifact whose bytes are absent or do not match.

Replay the ZIP in a directory with no original company files:

```sh
uv run --frozen python examples/customer-support-action/consumer.py \
  --replay /tmp/support-decision.zip --json
```

The application supplies the adapter through the
[explicit Python API](adapter-api.md). The ZIP never selects executable code.
Replay uses the carried records and recomputes the decision. It refuses a
changed decision, policy binding or artifact. This is the existing
[bundle format](bundles-and-index.md), with an explicit consumer adapter.

## Read the decision

Without `--json`, the packet shows separately:

- Evidence support: whether the selected records support the offer and draft.
- Authorization: whether company rules or the selected exact grant permit it.
- Action permission: APPROVE, BLOCK or HOLD_FOR_REVIEW.
- Observed effect: `not_established`; the example does not send email.

The adapter derives every check from raw bytes. It refuses a policy whose
necessary check inventory is incomplete with a HOLD decision. An unknown or
duplicate check name is malformed input and exits 2 without a verdict.

The draft follows one exact renderer for a structured discount action. This
contract does not establish arbitrary factual truth or interpret general prose.
The manager grant must bind the exact action and draft, contain the selected
clock in its validity interval, and be absent from the selected consumed-ID
snapshot. Records, clock and authority identities remain consumer trust roots.
Offline replay does not authenticate them or atomically consume a live grant.

The external `--json` projection exposes decision, reason and action for an
independent corpus reader. The full bundle retains source and policy hashes,
even when a changed input produces the same action permission.
