# Operand-lineage vectors

Ten synthetic `operand_lineage/v1` cases bind separate source and execution
artifacts to a consumer policy. `MANIFEST.json` pins the fixture bytes and the
expected decision and reason.

| Case | Decision | What it checks |
| --- | --- | --- |
| complete | supported | Every operand and step reaches the stated figure. |
| compensating-operands | contradicted | Two changed inputs cancel but neither matches the source. |
| incorrect-intermediate | contradicted | A fabricated result propagates to the figure. |
| incorrect-figure | contradicted | The figure differs from the final step. |
| dead-step | contradicted | A valid step does not feed the figure. |
| unused-constant | contradicted | A declared constant does not feed the figure. |
| missing-source-reference | not_established | A named source value is absent. |
| rounding-unspecified | not_established | Division needs a rounding rule. |
| execution-absent | not_established | The pinned trace was not supplied. |
| self-hashed-source-swap | not_established | Changing the case digest does not change the consumer pin. |

Run all cases against a CLI implementing the `probity-verify` contract:

```sh
uv run --extra test python vectors-operand-lineage/check_vectors.py \
  --verifier 'probity-verify'
```

Regenerate with `python3 vectors-operand-lineage/gen_vectors.py`. Passing this
corpus checks internal consistency of a pinned trace. It does not establish
who observed the execution or whether the declared operation was appropriate.
