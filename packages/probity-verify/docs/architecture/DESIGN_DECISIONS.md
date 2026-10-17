# Design decisions

## Explicit consumer adapters

The adjudication and bundle APIs accept a keyword-only adapter mapping for one
consumer call. They preserve the built-in registry and existing positional
arguments. Bundles carry records, not executable code. The kernel checks the
common envelope and rejects mutations to selected control objects.

`core.adjudicate` has measured cyclomatic complexity 19. It coordinates
selection, immutable control bindings, a trusted callback and the common
envelope checks. Each refusal preserves a different boundary; these branches
remain explicit rather than moving them into an opaque predicate.

## Customer support example

The local adapter keeps company-specific checks outside the generic kernel.
It follows ordered phases: schema validation, byte and consumer bindings,
necessary checks, factual checks, then exact manager authority. Its main
function has inherent orchestration branches because refusal, absence,
contradiction and authorization are distinct states. `_raw` dispatches a fixed
closed schema by field type. These branches are intentional; hiding them in a
generic rule engine would make precedence harder to audit.

The synthetic report is advisory. Exact rendering keeps the language claim
finite. A selected consumed-ID snapshot records one retained state and does
not provide atomic live grant consumption.

| Function | Measured complexity | Reason |
| --- | ---: | --- |
| `adapter.adjudicate` | 33 | Ordered validation and decision phases preserve refusal, unavailable evidence, contradictions and exact authority as distinct states. |
| `adapter._raw` | 22 | Closed-schema field dispatch selects scalar, range, timestamp and identity checks. |
| `consumer.main` | 14 | Coordinates direct decisions, portable bundle creation and replay with separate malformed-input exits. |
