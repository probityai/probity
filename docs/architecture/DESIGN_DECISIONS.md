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
