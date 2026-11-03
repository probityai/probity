# Design: one effect per tool call when the reply is lost

## The shape

A tool call writes to a service that owns the effect: it creates an order, charges a card,
opens a ticket. The write commits at that service, and the reply never reaches the caller:
the read times out, the connection drops, the worker loses its lease. The caller now holds
an uncertain outcome. The effect may or may not have happened, and only the service that owns
it can say which.

Agent frameworks have no state for that. A lost reply surfaces as a tool exception, and every
path the framework offers from there goes wrong for one class of scenario or another:

- a retry policy, a resumed thread or a model that calls the tool again sends the write a
  second time, and a service that does not deduplicate now holds two effects;
- a run that stops on the error reports that the write did not happen, which is false when it
  committed.

Neither reading is safe in general, because the framework cannot tell a commit with a lost
reply from a call that never arrived. The fix is the step none of them provides: before
anything is sent again, ask the owner what it holds.

## What ships

One structure does all three jobs. The journal of attempts, keyed by the operation's
idempotency key, is:

1. the guard's memory: before any dispatch it is read, so a retry policy, a resumed thread in
   a new process, or a model calling the tool again finds the earlier unknown attempt and
   reconciles instead of resending;
2. the record: each operation exports as an `uncertain-effect/v1` record, whose `contractId`
   is `https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect`, the
   format the agent-evidence-vectors corpus and its readers check;
3. the test oracle: in CI the same journal is compared with what a counting owner saw.

| Part | Job |
| --- | --- |
| `EffectOwner` | The port to the service that owns the effect: `lookup` by idempotency key, optional `lease`, optional `send`, how failures classify, whether it deduplicates by key. |
| `EffectGuard` | Reconcile before resend, over a journal. Synchronous and asynchronous drivers share one policy. |
| `Journal` | Append-only events, in memory or a JSON-lines file written ahead of every dispatch. Exports records. |
| `probity_effects.langgraph.effect_tool` | Turns a tool body into a LangChain tool that never lets a lost reply escape as an exception. |
| `probity_effects.openai_agents.effect_function_tool` | The same for an OpenAI Agents SDK function tool. |
| `probity_effects.testing` and the pytest plugin | Drive your tool through the framework's own paths against the eight lost-reply scenarios that agent-evidence-vectors ships, and judge each run three ways. |

## The policy

For one operation, identified by its idempotency key:

1. A key already used with other arguments is refused without sending.
2. An operation the journal already holds as confirmed, or found present, returns committed
   without sending.
3. An earlier attempt whose reply was lost is reconciled first: the owner is asked until it
   gives a final answer. Present is committed. A final absent permits a send. No answer, or
   only answers that are not final, is unknown, and nothing is sent. An owner that
   deduplicates by key inside its retention window is the one exception: the same key is sent
   again and the owner returns the first effect.
4. Before each send, a worker that holds a lease checks it. A lost lease sends nothing.
5. The attempt is written to the journal before it is sent. A confirmed reply is committed;
   a definite no-effect answer (`NoEffect`, or a refusal the classifier knows) is not run; a
   lost reply goes back to step 3.

The outcome is reported as the owner's answers settle it, so the exported record passes the
reader's checks for the run the guard actually performed.

## Decisions

| Topic | Decision | Reason |
| --- | --- | --- |
| Home | A member of this repository, `packages/probity-effects`. | It ships through the same release path, checks and trusted publisher as the other members, beside the verifier that reads its records. |
| Not inside agent-evidence-observer | Separate distribution. | The observer needs Python 3.12 and carries a broker, witness and launcher; this guard runs inside a tool, wherever the framework runs. |
| Python | 3.11 and later. | Python 3.10 reached end of life in October 2026, and agent-evidence-vectors needs 3.11. |
| Canonical form | `jcs-admit` for RFC 8785 bytes of the arguments digest. | Verifiers in other languages recompute the same digest. |
| Default key | SHA-256 over the canonical scope (the thread), tool name and arguments; `key_from` names an argument that carries a business key instead. | A model that calls the tool again with the same arguments, or a resumed thread, lands on the same key. Two intended identical writes in one thread need an explicit key. |
| No thread and no key | Refused with `UnnamedOperation`; nothing is sent. | A key made from the tool and its arguments alone is the same for everyone, so the second person to ask for an identical write would be told it was committed when it was never sent. |
| Unknown | Reported to the model as a tool result that says not to call again; `on_unknown="raise"` stops the run instead. | An exception would hand the decision back to the retry machinery that caused the duplicate. |
| Owner count | `Journal.record(key, owner_effects=n)` takes the owner's own count; `Journal.trail(key)` exports the runtime's half alone. | Only the owner's ledger knows how many effects it holds; the journal does not invent it. |

## What a pass establishes

In CI, a pass on a scenario means: the counting owner holds an accepted number of effects and
the reported outcome is accepted with it; the exported record is allowed by the reference
reader; and the journal recorded exactly the attempts and lookups the owner saw.

It does not establish that your own `send` and `lookup` code talk to your service correctly:
the scenarios stand in for the owner. Test those against your service's sandbox.

## Lock

This package keeps its own `uv.lock` and stays outside the root workspace: it targets Python 3.11 and later and its only runtime dependency is jcs-admit, so one root lock would only narrow it.
