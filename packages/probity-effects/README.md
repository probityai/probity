# probity-effects

[![PyPI](https://img.shields.io/pypi/v/probity-effects.svg)](https://pypi.org/project/probity-effects/)

Keep one effect per agent tool call when its reply is lost: the guard asks the service that owns
the effect before anything is sent again, records each operation as an `uncertain-effect/v1`
record, and tests your tools against eight lost-reply scenarios in CI.

It's for teams whose LangGraph agents create orders, move money or open tickets, and who cannot
afford a retry policy, a resumed thread or a model calling again to repeat the write.

Install the released package: `pip install probity-effects==0.1.0`.

## Quick start

Python 3.11 or later. This example needs no network: the stand-in owner commits each write and
loses the reply.

```python
from probity_effects import EffectGuard, EffectOwner, Lookup

ledger = {}

def send(call):
    ledger[call.key] = call.args          # the write commits ...
    raise TimeoutError("reply lost")      # ... and its reply never arrives

owner = EffectOwner("orders", lookup=lambda key: Lookup(present=key in ledger))
guard = EffectGuard(owner)
for _ in range(3):                         # a retry, a resumed run, a model calling again
    result = guard.perform("create_order", {"sku": "A-1", "quantity": 1}, send=send)
    print(result.outcome, result.sent)
print(len(ledger), "effect")
```

It prints:

```text
committed 1
committed 0
committed 0
1 effect
```

The first call loses its reply, asks the owner, and finds the order. The next two read the
journal and send nothing.

## In a LangGraph agent

```python
from probity_effects import EffectCall, EffectOwner, Journal
from probity_effects.langgraph import effect_tool

orders = EffectOwner("orders", lookup=find_order_by_key)   # your lookup, by idempotency key

@effect_tool(orders, journal=Journal.open("effects.jsonl"))
def create_order(sku: str, quantity: int, effect: EffectCall) -> dict:
    """Create an order."""
    reply = httpx.post(ORDERS, json={"sku": sku, "quantity": quantity},
                       headers={"Idempotency-Key": effect.key}, timeout=5.0)
    reply.raise_for_status()
    return reply.json()
```

Pass `create_order` to `ToolNode` or `create_react_agent` as usual. A lost reply never reaches
LangGraph's retry machinery as an exception; an outcome the owner cannot confirm comes back to
the model as `outcome unknown`, and calling again sends nothing until the owner answers.

## In CI

```python
from probity_effects.testing import LANGGRAPH_VARIANTS, run_langgraph_scenario

@pytest.mark.parametrize("variant", LANGGRAPH_VARIANTS)
def test_survives_lost_replies(lost_reply_scenario, variant):
    verdict = run_langgraph_scenario(make_tools, lost_reply_scenario, variant=variant)
    assert verdict.passed, verdict.problems
```

`pip install probity-effects[testing]` adds the scenarios from agent-evidence-vectors. `make_tools(owner, journal)`
builds your tools; each scenario runs on four LangGraph paths and is judged by the owner's counts,
the reference reader's verdict on the record, and the journal's agreement with the owner.

## Status

Version 0.1.0, alpha; its first PyPI release is pending. The LangGraph adapter ships first; the
OpenAI Agents SDK and AG2 follow.

## Documentation

| page | read it for |
| --- | --- |
| [Design](https://github.com/probityai/probity/blob/main/packages/probity-effects/docs/DESIGN.md) | the shape, the policy, the record and every decision |
| [Measurements](https://github.com/probityai/probity/blob/main/packages/probity-effects/docs/MEASUREMENTS.md) | a plain LangGraph tool against the guarded one on every scenario and path |
| [Releasing](https://github.com/probityai/probity/blob/main/packages/probity-effects/docs/RELEASING.md) | cut a release of this member |

## License

Apache-2.0.
