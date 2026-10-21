# Changelog

## 0.2.0 (2026-10-20)

The verifier now reads DSSE envelopes, registers itself as `probity verify`, and judges completion
("done") receipts with separate outcome and integrity verdicts.

- `probity-verify` registers the `verify` subcommand of the `probity` command, installed by the `probityai`
  package. The `probity-verify` console script and `probity verify` share one implementation.
- The verifier reads its input as a case or a DSSE envelope. For an envelope it checks canonical base64 and
  the DSSE v1 pre-authentication encoding, tries every signature under every supplied Ed25519 key, checks the
  payload type, and then decides the case on the verified payload. A bundle that wraps a done receipt gives
  the same verdict as the bare receipt, with a `dsse_envelope` check first.
- A record can earn EXTERNAL witness scope only from a verified witness co-signature (two signatures,
  checkpoint, inclusion and consistency proofs), never from its own `witness_scope` field. Witness scope terms
  come from the released `agent-evidence-vocabulary` package, and a term it does not define is refused.
- Done receipts carry separate outcome and integrity verdicts, with `claims/v2`, `completion_claim/v1` and
  `probe_observed/v1`.
- A done claim is refused on the grader's dynamic visible-test findings and on the visible-test detectors on
  the integrity axis. The task pre-flight finding is attributed to the task and never refuses.
- A claimed run matches an observed one by program and canonical arguments, so honest spellings of a sealed
  command match. A contract may seal every absolute path of one acceptance executable, and a matching run's
  writes outside the workspace are output, not an edit.
- A completion assertion is backed by the agent's own sealed runs only, so honest agents are no longer read
  as claiming completion without a run.
- Out-of-tree tampering is read from the recorded run: execution-surface mutations, pytest configuration
  above the workspace, a failed import probe, and an in-process twin that passes a failed trusted replay.
- A sealed test that was collected but did not pass is refused: a command with sealed test ids must report
  as many passes as it has ids.
- Protected paths catch ancestor rename swaps and writes to loader files.
- Command tiers, contract strength, seal gates and native files are read. A failure only on synthesized
  commands is `not_established` (`generated_heldout_failed`) rather than `contradicted`.
- A run's own `__pycache__` no longer shadows its next run, a held-out probe stopped at its limit is
  `probe_timed_out`, and a done-record origin that is not text is refused.
- Twenty-four pinned done-check vectors run through the CLI in CI.
- Python 3.11 or newer is required.

## 0.1.1 (2026-10-20)

Packaging and documentation release. No verifier behaviour and no conformance case changed. The checked
sample files ship inside the wheel and the source distribution, and the generated recipe bindings are
refreshed.

## 0.1.0

First release on PyPI: the verifier implementation and its command line.
