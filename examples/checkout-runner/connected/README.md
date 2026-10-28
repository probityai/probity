# Connected refund run (J01 and negatives)

One command drives each pinned component's own code for the bounded refund sandbox in [aeoess/agent-governance-vocabulary#193](https://github.com/aeoess/agent-governance-vocabulary/issues/193) (contract `review-2026-10-23`), handing each component the bytes the previous one wrote, and keeps every input, output, hash and exit status.

```sh
connected/setup.sh work <checkout-runner commit>
. work/env.sh
uv run --frozen --project "$CONNECTED_RUNNER" python connected/run_connected.py --out run --run-id <id> \
  --node "$CONNECTED_NODE" --pic-python "$CONNECTED_PIC_PYTHON" --pic-checkout "$CONNECTED_PIC_CHECKOUT" \
  --horizon-checkout "$CONNECTED_HORIZON_CHECKOUT" --runner-checkout "$CONNECTED_RUNNER/../.."
```

It exits 0 only when every row of `VERDICTS.md` is ESTABLISHED.

## The chain

| Step | Code that runs | Pin |
|---|---|---|
| APS native inputs: intent, approval, action, payload, four decision components, consumption trust | `aps_inputs.mjs` calling APS SDK 8.0.1, loaded through Horizon Shield's tree-pinned `pinnedSdk()` | `agent-passport-system` 8.0.1 (`56e7b29`) |
| PIC proposal naming the actual APS `receipt_id` and `decision_id` | pic-standard `examples/refund-sandbox/make_fixture.py` | `6856f36`, SDK `330fdd8` |
| PIC verification, closed section 4 result | pic-standard `examples/refund-sandbox/pic_result.py` | `6856f36`, SDK `330fdd8` |
| Admission input checks, steps 0 to 8 | horizon-shield `adapter_aps_receipt.mjs` | `12a48bb` |
| Admission state: decision to operation, single use, replay, reissue, committed record | stand-in in `run_connected.py` (the admission door is not built yet) | this directory |
| Handoff and resolution signing | `checkout_runner.sandbox_signer` | the runner commit |
| Execution, observation, reconciliation | `checkout_runner.sandbox_executor` over `sandbox_sim` | the runner commit |

## Cases

`J01` is the exact original approval end to end. The negatives are `N1a` (amount changed in the signed PIC proposal), `N1b` (amount changed in the APS payload), `N1c` (amount changed at dispatch), `N2` (replayed admission, duplicate and re-signed handoff), `N3` (reissued approval with new matching PIC evidence), `N3b` (new APS receipt with the old PIC proposal) and `N4` (provider commits, response lost, retry, reconcile).

## What a run is and is not

One operator runs every step. The PIC, Horizon Shield and APS code is each project's own pinned code, but none of those projects operated it here, the APS inputs are built with the APS SDK and public test keys rather than produced by APS, and the admission state is a stand-in for a door that is not built. All keys are public test keys and the provider is a local simulator. The signer, executor and simulator are this repository's, so their agreement is one project's own consistency; an independent reader of the retained run is the evidence about them. Admission restart stays NOT_ESTABLISHED.
